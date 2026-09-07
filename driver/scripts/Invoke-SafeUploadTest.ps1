#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys and validates the SafeUpload minifilter. Runs on the TARGET VM
    only.

.DESCRIPTION
    Automates part B of DEPLOY.md: preflight, fetch, swap the driver binary,
    load the filter and run the smoke test end to end.

    Before doing anything it verifies the machine is actually able to load a
    test-signed driver. Every one of those checks corresponds to a failure
    that has already cost an afternoon: test signing off, certificate not
    imported, stale binary silently left in place.

    The smoke test proves the three behaviours that matter:

      1. Allowed   - a file outside the block rule opens normally.
      2. Blocked   - a file matching the rule is denied by the kernel.
      3. RN-013    - with the inspector stopped, the same file opens again.
                     Failure to inspect must never turn into a block.

    NEVER run this on a machine you care about. It replaces a kernel driver
    and expects a snapshot to exist.

.PARAMETER SourceUrl
    Base URL where Publish-SafeUpload.ps1 is serving the package, for
    example http://192.168.122.132:8000

.PARAMETER StagingDirectory
    Local directory the artifacts are downloaded into.

.PARAMETER TestDirectory
    Directory the smoke test files are created in.

.PARAMETER SkipDownload
    Use whatever is already in the staging directory.

.PARAMETER SkipSmokeTest
    Deploy and load, but stop before exercising the filter.

.EXAMPLE
    .\Invoke-SafeUploadTest.ps1 -SourceUrl http://192.168.122.132:8000

.EXAMPLE
    .\Invoke-SafeUploadTest.ps1 -SkipDownload
#>
[CmdletBinding()]
param(
    [string] $SourceUrl,

    [string] $StagingDirectory = 'C:\safeupload',

    [string] $TestDirectory = 'C:\safeupload-teste',

    [string] $SourceDirectory = 'C:\safeupload-origem',

    [string] $OutOfScopeDirectory = 'C:\safeupload-fora',

    [switch] $SkipDownload,

    [switch] $SkipSmokeTest,

    [switch] $ReproduceUnloadLeak,

    [switch] $KeepLoaded,

    [int] $StressProcesses = 8
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$FilterName = 'SafeUpload'
$DriverFileName = 'SafeUpload.sys'
$InspectorFileName = 'SafeUpload.Inspector.exe'
$InstalledDriverPath = Join-Path $env:SystemRoot "System32\drivers\$DriverFileName"
$BlockToken = 'BLOQUEAR_TESTE'
$AdministratorsSid = '*S-1-5-32-544'

$script:Results = @()

function Write-Step {
    param([string] $Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

function Add-Result {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [bool] $Passed,
        [string] $Detail
    )

    $script:Results += [pscustomobject]@{
        Name   = $Name
        Passed = $Passed
        Detail = $Detail
    }

    if ($Passed) {
        Write-Host "  [ok]    $Name" -ForegroundColor Green
    }
    else {
        Write-Host "  [FALHA] $Name" -ForegroundColor Red
    }

    if ($Detail) {
        Write-Host "          $Detail" -ForegroundColor DarkGray
    }
}

function Stop-WithMessage {
    param([string] $Text)

    # Never leave the inspector running behind us. It holds the port, which
    # makes the next unload fail, and it holds its own image open, which
    # makes the next download fail with a sharing violation - a failure that
    # looks nothing like its cause.
    try { Stop-Inspector | Out-Null } catch { }

    Write-Host ''
    Write-Host "ERRO: $Text" -ForegroundColor Red
    exit 1
}

function Test-FilterLoaded {
    $output = & fltmc.exe filters 2>&1
    return [bool] ($output | Select-String -SimpleMatch $FilterName -Quiet)
}

function Stop-Inspector {
    <#
        The driver declines a voluntary unload while a client holds the port,
        so the inspector has to go first. Killing it is fine: it owns no
        state that outlives the process.
    #>
    $processes = @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($InspectorFileName)) -ErrorAction SilentlyContinue)

    foreach ($process in $processes) {
        Write-Host "  Encerrando inspetor (pid $($process.Id))."
        $process | Stop-Process -Force
    }

    if ($processes.Count -gt 0) {
        Start-Sleep -Milliseconds 500
    }

    return $processes.Count
}

$InspectorReadyEventName = 'Global\SafeUploadInspectorReady'

function Start-Inspector {
    <#
        Starts the inspector and waits until it reports the port connected.

        The wait is on a named event, not on the contents of the log file.
        Polling the log would be file I/O, and file I/O on this machine goes
        through the very filter the inspector answers for: the watcher ends
        up waiting on the inspector that is waiting on the watcher. That
        deadlock is bounded by the driver's verdict timeout rather than
        fatal, which makes it look like a hang rather than a bug.
    #>
    param([Parameter(Mandatory)] [string] $LogPath)

    Remove-Item $LogPath -Force -ErrorAction SilentlyContinue

    # Created before the process exists so the signal cannot be missed.
    $ready = New-Object System.Threading.EventWaitHandle(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        $InspectorReadyEventName)

    try {
        $process = Start-Process -FilePath (Join-Path $StagingDirectory $InspectorFileName) `
            -NoNewWindow -PassThru -RedirectStandardOutput $LogPath

        if ($ready.WaitOne([TimeSpan]::FromSeconds(20))) {
            return $process
        }

        if ($process.HasExited) {
            Write-Host "  O inspetor terminou sozinho (codigo $($process.ExitCode))." -ForegroundColor Red
            Write-Host '  Codigo -1073741515 e STATUS_DLL_NOT_FOUND: binario com CRT dinamico.' -ForegroundColor Red
        }

        Stop-WithMessage 'O inspetor nao conectou na porta.'
    }
    finally {
        $ready.Dispose()
    }
}

function Wait-InspectorLine {
    <#
        Waits for a REQUEST line matching Pattern to appear in the inspector
        log, and returns the index of that line, or -1.

        Pattern is a regular expression and must be anchored to the request
        format, because the log also carries startup banner lines - and the
        banner prints the very paths the policy monitors. A loose match
        finds the banner and reports success without a single request having
        arrived, which is a test that can only ever pass.

        Reading the log is file I/O, which goes through the filter - but a
        .log is not a monitored extension, so the cheap gate in pre-create
        rejects it before anything expensive happens. That is what makes
        polling here safe, and it is worth knowing that it depends on the
        policy not listing .log.
    #>
    param(
        [Parameter(Mandatory)] [string] $LogPath,
        [Parameter(Mandatory)] [string] $Pattern,
        [int] $TimeoutSeconds = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {

        Start-Sleep -Milliseconds 200

        $lines = @(Get-Content $LogPath -ErrorAction SilentlyContinue)

        for ($i = 0; $i -lt $lines.Count; $i += 1) {
            if ($lines[$i] -match $Pattern) {
                return $i
            }
        }
    }

    return -1
}

# ---------------------------------------------------------------------------
# 1. Preflight
# ---------------------------------------------------------------------------

Write-Step 'Verificacoes previas'

$bcdOutput = & bcdedit.exe /enum '{current}' 2>&1
$testSigningOn = [bool] ($bcdOutput | Select-String -Pattern 'testsigning\s+Yes' -Quiet)

if (-not $testSigningOn) {
    Write-Host '  Modo de teste desligado.' -ForegroundColor Red
    Write-Host '  Rode:  bcdedit /set testsigning on   e reinicie.' -ForegroundColor Red
    Write-Host '  Confira tambem que o Secure Boot esta desligado no firmware da VM:' -ForegroundColor Red
    Write-Host '  com Secure Boot ativo o testsigning e ignorado.' -ForegroundColor Red
    Stop-WithMessage 'Sem modo de teste o driver nao carrega (0xC0000428).'
}

Write-Host '  Modo de teste ligado.'

foreach ($storeName in @('Root', 'TrustedPublisher')) {
    $found = @(Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like '*SafeUpload*' })

    if ($found.Count -eq 0) {
        Write-Host "  Certificado de teste ausente em $storeName." -ForegroundColor Red
        Write-Host "  Rode:  certutil -addstore -f $storeName $StagingDirectory\SafeUploadTest.cer" -ForegroundColor Red
        Stop-WithMessage 'Sem o certificado importado a assinatura nao e aceita.'
    }

    Write-Host "  Certificado presente em $storeName."
}

# ---------------------------------------------------------------------------
# 1b. Reproduce the unload pool leak
# ---------------------------------------------------------------------------

if ($ReproduceUnloadLeak) {

    # Deliberately touches nothing on disk: no download, no binary swap. The
    # point is to reproduce a bugcheck in the driver that is already
    # installed, and replacing it would change the thing under test.
    #
    # Bugcheck 0xC4 subcode 0x62 is raised by Driver Verifier when a driver
    # unloads with pool still allocated. Reproducing it needs the conditions
    # the original crash had, and a gentle load does not have them:
    #
    #   - MANY messages in flight at once. The inspector answers one request
    #     at a time, so concurrency comes from several processes issuing
    #     creates simultaneously and queueing up inside FltSendMessage.
    #
    #   - The port torn down WHILE they are in flight, not after. Killing the
    #     inspector mid-burst is what forces every blocked thread through the
    #     failure path at once, which is where a missed free would hide.
    #
    # Run it with a kernel debugger attached: the machine breaks into the
    # debugger instead of bugchecking, and the pool block is still readable.

    Write-Step 'Reproduzindo o vazamento de pool no unload'

    if (-not (Test-FilterLoaded)) {
        Write-Host '  Carregando o filtro.'
        & fltmc.exe load $FilterName 2>&1 | ForEach-Object { Write-Host "  $_" }

        if (-not (Test-FilterLoaded)) {
            Stop-WithMessage 'O filtro nao carregou.'
        }
    }

    Write-Host '  Filtro carregado.'

    if (-not (Test-Path $TestDirectory)) {
        New-Item -ItemType Directory -Path $TestDirectory -Force | Out-Null
    }

    $stressFile = Join-Path $TestDirectory 'normal.txt'
    Set-Content -Path $stressFile -Value 'conteudo de teste' -Encoding UTF8

    $inspectorLog = Join-Path $StagingDirectory 'inspector.log'

    Write-Host '  Subindo o inspetor.'
    Start-Inspector -LogPath $inspectorLog | Out-Null

    Write-Host "  Inspetor conectado. Disparando $StressProcesses processos de carga."

    # Separate processes, not threads: each one issues its own creates, which
    # is exactly the shape of the traffic that produced 33 simultaneous
    # allocations when the driver still hooked reads.
    $stressCommand = "for /l %i in (1,1,100000) do @type `"$stressFile`" >nul 2>&1"

    # Not $stressProcesses: PowerShell variable names are case insensitive,
    # so that would overwrite the $StressProcesses parameter with an array
    # and the loop bound below would stop being a number.
    $loadProcesses = @()

    foreach ($index in 1..$StressProcesses) {
        $loadProcesses += Start-Process -FilePath 'cmd.exe' `
            -ArgumentList '/c', $stressCommand -WindowStyle Hidden -PassThru
    }

    Start-Sleep -Seconds 3

    # Peak so far tells us whether the burst actually built up a queue. If it
    # stayed at one, the stress did not stress anything and a clean unload
    # afterwards proves nothing.
    $peakDuring = [regex]::Match((& verifier.exe /query 2>&1 | Out-String),
                                 'Peak Pool Allocations:\s*\(\s*(\d+)')

    if ($peakDuring.Success) {
        Write-Host "  Pico de alocacoes durante a carga: $($peakDuring.Groups[1].Value)"

        if ([int] $peakDuring.Groups[1].Value -le 1) {
            Write-Host '  A carga nao gerou concorrencia. Um unload limpo agora nao provaria nada.' -ForegroundColor Yellow
        }
    }

    Write-Host '  Matando o inspetor NO MEIO da rajada.' -ForegroundColor Yellow
    Stop-Inspector | Out-Null

    Write-Host ''
    Write-Host '  Descarregando imediatamente. Se o vazamento existir, o bugcheck e agora.' -ForegroundColor Yellow
    Write-Host ''

    & fltmc.exe unload $FilterName 2>&1 | ForEach-Object { Write-Host "  $_" }

    foreach ($process in $loadProcesses) {
        $process | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    if (Test-FilterLoaded) {
        Write-Host '  O filtro continua carregado - o unload foi recusado.' -ForegroundColor Red
    }
    else {
        Write-Host '  Descarregado sem bugcheck.' -ForegroundColor Green

        if ($peakDuring.Success -and [int] $peakDuring.Groups[1].Value -gt 1) {
            Write-Host "  Com pico de $($peakDuring.Groups[1].Value) alocacoes simultaneas e a porta fechada" -ForegroundColor Green
            Write-Host '  no meio delas, este e um resultado com valor.' -ForegroundColor Green
        }
    }

    return
}

# ---------------------------------------------------------------------------
# 2. Fetch and verify
# ---------------------------------------------------------------------------

if (-not (Test-Path $StagingDirectory)) {
    New-Item -ItemType Directory -Path $StagingDirectory -Force | Out-Null
}

# Before the download, not after: the inspector keeps its own image open, so
# a leftover process from an earlier run makes overwriting the .exe fail with
# a sharing violation.
Write-Step 'Encerrando execucao anterior'

if ((Stop-Inspector) -eq 0) {
    Write-Host '  Nenhum inspetor pendente.'
}

if (-not $SkipDownload) {

    if (-not $SourceUrl) {
        Stop-WithMessage 'Informe -SourceUrl, ou use -SkipDownload para reaproveitar o que ja esta em disco.'
    }

    Write-Step "Baixando de $SourceUrl"

    function Get-PackageFile {
        param(
            [Parameter(Mandatory)] [string] $Name,
            [string] $ExpectedHash
        )

        $destination = Join-Path $StagingDirectory $Name

        # Skip what is already here and already correct. Most of a package
        # does not change between runs - the INF, the catalog and the
        # certificate usually survive many builds - and re-fetching them
        # costs time and, worse, re-opens files the system may be holding.
        if ($ExpectedHash -and (Test-Path $destination)) {

            if ((Get-FileHash $destination -Algorithm SHA256).Hash -eq $ExpectedHash) {
                Write-Host "  $Name (ja atualizado)"
                return
            }
        }

        try {
            Invoke-WebRequest -Uri "$SourceUrl/$Name" -OutFile $destination -UseBasicParsing -TimeoutSec 30
            Write-Host "  $Name"
        }
        catch {
            Stop-WithMessage "Falha ao baixar $Name : $($_.Exception.Message)"
        }
    }

    # The manifest drives the download: it is the package telling us what it
    # contains. A hard-coded list here would drift the moment the publisher
    # adds or renames an artifact.
    Get-PackageFile -Name 'manifest.json'

    $downloadManifest = Get-Content (Join-Path $StagingDirectory 'manifest.json') -Raw | ConvertFrom-Json

    foreach ($file in $downloadManifest.files) {
        Get-PackageFile -Name $file.name -ExpectedHash $file.sha256
    }
}

Write-Step 'Conferindo o manifesto'

$manifestPath = Join-Path $StagingDirectory 'manifest.json'

if (-not (Test-Path $manifestPath)) {
    Stop-WithMessage "manifest.json nao encontrado em $StagingDirectory."
}

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

Write-Host "  Pacote $($manifest.configuration), gerado em $($manifest.builtUtc) UTC."

foreach ($expected in $manifest.files) {
    $path = Join-Path $StagingDirectory $expected.name

    if (-not (Test-Path $path)) {
        Stop-WithMessage "Artefato ausente: $($expected.name)"
    }

    $actualHash = (Get-FileHash $path -Algorithm SHA256).Hash

    if ($actualHash -ne $expected.sha256) {
        Write-Host "  $($expected.name)" -ForegroundColor Red
        Write-Host "    esperado: $($expected.sha256)" -ForegroundColor Red
        Write-Host "    obtido  : $actualHash" -ForegroundColor Red
        Stop-WithMessage 'Artefato corrompido ou desatualizado. Rebaixe o pacote.'
    }

    Write-Host ("  {0,-26} ok" -f $expected.name)
}

# ---------------------------------------------------------------------------
# 3. Swap the driver
# ---------------------------------------------------------------------------

Write-Step 'Descarregando o filtro'

Stop-Inspector | Out-Null

if (Test-FilterLoaded) {
    & fltmc.exe unload $FilterName 2>&1 | ForEach-Object { Write-Host "  $_" }

    if (Test-FilterLoaded) {
        Stop-WithMessage 'O filtro continua carregado. Nao da para trocar o binario em uso.'
    }

    Write-Host '  Descarregado.'
}
else {
    Write-Host '  Nao estava carregado.'
}

$service = Get-Service -Name $FilterName -ErrorAction SilentlyContinue

if (-not $service) {

    Write-Step 'Instalando o INF (servico ainda nao existe)'

    & rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 (Join-Path $StagingDirectory 'SafeUpload.inf')
    Start-Sleep -Seconds 2

    if (-not (Get-Service -Name $FilterName -ErrorAction SilentlyContinue)) {
        Write-Host '  O servico nao foi criado. Veja as ultimas entradas de:' -ForegroundColor Red
        Write-Host '    C:\Windows\INF\setupapi.dev.log' -ForegroundColor Red
        Stop-WithMessage 'Instalacao do INF falhou.'
    }

    Write-Host '  Servico criado.'
}
else {

    Write-Step 'Substituindo o binario'

    $stagedDriver = Join-Path $StagingDirectory $DriverFileName

    try {
        Copy-Item $stagedDriver $InstalledDriverPath -Force -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {

        # PnpLockdown=1 in the INF leaves files under system32\drivers owned
        # by TrustedInstaller, so an elevated administrator still cannot
        # write them. Taking ownership is acceptable on a disposable test VM;
        # in production a driver binary is replaced through the INF.
        Write-Host '  Acesso negado (PnpLockdown). Tomando posse do arquivo.' -ForegroundColor Yellow

        & takeown.exe /f $InstalledDriverPath | Out-Null
        & icacls.exe $InstalledDriverPath /grant "${AdministratorsSid}:F" | Out-Null

        Copy-Item $stagedDriver $InstalledDriverPath -Force
    }

    $installedHash = (Get-FileHash $InstalledDriverPath -Algorithm SHA256).Hash
    $manifestDriverHash = ($manifest.files | Where-Object { $_.name -eq $DriverFileName }).sha256

    if ($installedHash -ne $manifestDriverHash) {
        Stop-WithMessage 'A copia nao surtiu efeito: o binario instalado nao confere com o pacote.'
    }

    Write-Host '  Binario substituido e conferido.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 4. Load
# ---------------------------------------------------------------------------

Write-Step 'Carregando o filtro'

$loadOutput = & fltmc.exe load $FilterName 2>&1

if (-not (Test-FilterLoaded)) {
    $loadOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Write-Host ''
    Write-Host '  A mensagem do fltmc costuma enganar. O status real esta no log de eventos:' -ForegroundColor Yellow
    Write-Host '    Get-WinEvent -LogName System -MaxEvents 40 | Where-Object { $_.Message -like "*SafeUpload*" } | Format-List' -ForegroundColor Yellow
    Stop-WithMessage 'O filtro nao carregou.'
}

Add-Result -Name 'Filtro carregado' -Passed $true

# Do not try to match the column layout of "fltmc instances": it varies with
# the width of the volume names and gained columns between Windows releases.
# The dashed separator is the reliable landmark - everything after it is a
# row.
$fltmcOutput = @(& fltmc.exe instances -f $FilterName 2>&1 | ForEach-Object { "$_" })
$separatorIndex = -1

for ($i = 0; $i -lt $fltmcOutput.Count; $i += 1) {
    if ($fltmcOutput[$i] -match '^\s*-{4,}') {
        $separatorIndex = $i
        break
    }
}

$instances = @()

if ($separatorIndex -ge 0) {
    $instances = @($fltmcOutput[($separatorIndex + 1)..($fltmcOutput.Count - 1)] |
        Where-Object { $_.Trim().Length -gt 0 } |
        ForEach-Object { $_.Trim() })
}

Write-Host ''
Write-Host "  Instancias anexadas: $($instances.Count)"
$instances | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

if ($instances.Count -eq 0) {
    Add-Result -Name 'Anexou a pelo menos um volume' -Passed $false `
        -Detail 'Nenhuma instancia. Todos os volumes foram recusados na classificacao?'
}
else {
    Add-Result -Name 'Anexou a pelo menos um volume' -Passed $true
}

if ($SkipSmokeTest) {
    Write-Host ''
    Write-Host 'Teste de fumaca pulado a pedido.' -ForegroundColor Yellow
    return
}

# ---------------------------------------------------------------------------
# 5. Smoke test
# ---------------------------------------------------------------------------

Write-Step 'Preparando os arquivos de teste'

# Created while the inspector is stopped, on purpose: with it connected,
# creating a file whose path matches the block rule is itself denied.
if (-not (Test-Path $TestDirectory)) {
    New-Item -ItemType Directory -Path $TestDirectory -Force | Out-Null
}

foreach ($directory in @($SourceDirectory, $OutOfScopeDirectory)) {
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

$allowedFile = Join-Path $TestDirectory 'normal.txt'
$blockedFile = Join-Path $TestDirectory "$BlockToken.txt"

# Under a monitored SOURCE prefix: a file worth reading to find out whether
# it is sensitive, rather than a place a file must not reach.
$sourceFile = Join-Path $SourceDirectory 'documento.txt'

# Under neither list. Monitored extension, ordinary fixed volume, and the
# driver must ignore it entirely.
$outOfScopeFile = Join-Path $OutOfScopeDirectory 'ignorado.txt'

# Sensitive AND under a source prefix: reading it must be allowed and must
# mark the process.
$taintFile = Join-Path $SourceDirectory "$BlockToken.txt"

Set-Content -Path $allowedFile -Value 'conteudo permitido' -Encoding UTF8
Set-Content -Path $blockedFile -Value 'conteudo bloqueado' -Encoding UTF8
Set-Content -Path $sourceFile -Value 'documento de origem' -Encoding UTF8
Set-Content -Path $outOfScopeFile -Value 'fora de escopo' -Encoding UTF8
Set-Content -Path $taintFile -Value 'documento sensivel' -Encoding UTF8

Write-Host "  $allowedFile"
Write-Host "  $blockedFile"
Write-Host "  $sourceFile"
Write-Host "  $outOfScopeFile"

Write-Step 'Subindo o inspetor'

$inspectorLog = Join-Path $StagingDirectory 'inspector.log'

Start-Inspector -LogPath $inspectorLog | Out-Null

Add-Result -Name 'Inspetor conectado na porta' -Passed $true

try {

    Write-Step 'Caso 1 - operacao permitida'

    try {
        $content = Get-Content $allowedFile -Raw -ErrorAction Stop
        Add-Result -Name 'normal.txt abre normalmente' -Passed $true `
            -Detail "$($content.Trim().Length) caracteres lidos"
    }
    catch {
        Add-Result -Name 'normal.txt abre normalmente' -Passed $false `
            -Detail $_.Exception.GetType().Name
    }

    Write-Step 'Caso 2 - operacao bloqueada'

    try {
        Get-Content $blockedFile -Raw -ErrorAction Stop | Out-Null
        Add-Result -Name "$BlockToken.txt e negado pelo kernel" -Passed $false `
            -Detail 'O arquivo abriu, quando deveria ter sido negado.'
    }
    catch [System.UnauthorizedAccessException] {
        Add-Result -Name "$BlockToken.txt e negado pelo kernel" -Passed $true `
            -Detail 'Acesso negado, como esperado.'
    }
    catch {
        Add-Result -Name "$BlockToken.txt e negado pelo kernel" -Passed $false `
            -Detail "Erro inesperado: $($_.Exception.GetType().Name)"
    }
    Write-Step 'Caso 3 - escopo de origem'

    # The other half of scope, and the one that starts the chain: a file
    # here is not a destination, it is something worth reading to find out
    # whether it is sensitive. Without this the driver would never inspect a
    # document being opened, and nothing downstream would have anything to
    # act on.
    try { Get-Content $sourceFile -Raw -ErrorAction Stop | Out-Null } catch { }

    $sourceLine = Wait-InspectorLine -LogPath $inspectorLog `
        -Pattern '^\[\d+\].*safeupload-origem.*documento\.txt'

    if ($sourceLine -lt 0) {

        Add-Result -Name 'Arquivo sob prefixo de origem e inspecionado' -Passed $false `
            -Detail 'O inspetor nao recebeu nada para este caminho.'
    }
    else {

        # The scope is reported on the line right after the request.
        $logLines = @(Get-Content $inspectorLog -ErrorAction SilentlyContinue)
        $scopeLine = if (($sourceLine + 1) -lt $logLines.Count) { $logLines[$sourceLine + 1] } else { '' }

        Add-Result -Name 'Arquivo sob prefixo de origem e inspecionado' -Passed $true

        Add-Result -Name 'O kernel marcou o escopo como origem' -Passed ($scopeLine -match 'escopo:.*origem') `
            -Detail $(if ($scopeLine -match 'escopo:.*origem') { $scopeLine.Trim() } else { "linha seguinte: '$($scopeLine.Trim())'" })
    }

    Write-Step 'Caso 4 - o veredito e reaproveitado do cache'

    # The property the whole design rests on: one round trip per file
    # version, not one per open. Reading the same file again must produce no
    # new request at all - the driver answers from the stream context.
    foreach ($round in 1..3) {
        try { Get-Content $sourceFile -Raw -ErrorAction Stop | Out-Null } catch { }
    }

    Start-Sleep -Seconds 2

    $requestPattern = '^\[\d+\].*safeupload-origem.*documento\.txt'
    $requestCount = @(Get-Content $inspectorLog -ErrorAction SilentlyContinue |
        Where-Object { $_ -match $requestPattern }).Count

    Add-Result -Name 'Quatro aberturas produzem uma unica consulta' -Passed ($requestCount -eq 1) `
        -Detail "$requestCount requisicao(oes) no log para este arquivo."

    Write-Step 'Caso 5 - escrita invalida o cache'

    # A handle opened for write marks the file dirty on cleanup, so the next
    # open has to ask again rather than trust a verdict computed against
    # content that no longer exists.
    Add-Content -Path $sourceFile -Value 'linha nova'
    Start-Sleep -Milliseconds 500

    try { Get-Content $sourceFile -Raw -ErrorAction Stop | Out-Null } catch { }

    Start-Sleep -Seconds 2

    $requestCountAfterWrite = @(Get-Content $inspectorLog -ErrorAction SilentlyContinue |
        Where-Object { $_ -match $requestPattern }).Count

    Add-Result -Name 'Apos escrita, o arquivo e consultado de novo' -Passed ($requestCountAfterWrite -gt $requestCount) `
        -Detail "$requestCountAfterWrite requisicao(oes) apos a escrita, contra $requestCount antes."

    Write-Step 'Caso 6 - fora de escopo nao chega ao modo usuario'

    # Same monitored extension, ordinary fixed volume, but under neither the
    # destination nor the source list. This is what proves the gates reject
    # rather than merely classify: it must never reach user mode at all.
    try { Get-Content $outOfScopeFile -Raw -ErrorAction Stop | Out-Null } catch { }

    Start-Sleep -Seconds 2

    $outOfScopeLine = Wait-InspectorLine -LogPath $inspectorLog `
        -Pattern '^\[\d+\].*safeupload-fora.*ignorado\.txt' -TimeoutSeconds 1

    Add-Result -Name 'Arquivo fora de escopo nao e inspecionado' -Passed ($outOfScopeLine -lt 0) `
        -Detail $(if ($outOfScopeLine -lt 0) { 'Nada foi enviado ao modo usuario, como esperado.' } else { 'O caminho apareceu no log: o escopo nao esta filtrando.' })
    Write-Step 'Caso 7 - ler origem sensivel e permitido, e marca o processo'

    # The behaviour that changed with taint. A sensitive source file is no
    # longer refused: the user has every right to open their own document.
    # What happens instead is that the process is remembered.
    $sourceReadOk = $false

    try {
        Get-Content $taintFile -Raw -ErrorAction Stop | Out-Null
        $sourceReadOk = $true
    }
    catch { }

    Add-Result -Name 'Arquivo sensivel de origem abre normalmente' -Passed $sourceReadOk `
        -Detail $(if ($sourceReadOk) { 'Leitura permitida, como esperado sob contaminacao.' } else { 'A leitura foi negada: a contaminacao nao esta ativa.' })

    Start-Sleep -Seconds 1

    Write-Step 'Caso 8 - o processo marcado nao escreve no destino'

    # The zero-byte refusal, decided in pre-create with no round trip. The
    # file must not even come into existence.
    $destinationWrite = Join-Path $TestDirectory 'saida-marcada.txt'
    Remove-Item $destinationWrite -Force -ErrorAction SilentlyContinue

    $writeRefused = $false

    # Only an access denial counts. Catching every exception would let a
    # write that failed for any other reason - a locked file, a missing
    # directory - be reported as proof that the driver refused it, which is
    # an assertion that can only pass.
    try {
        Set-Content -Path $destinationWrite -Value 'nao deveria existir' -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        $writeRefused = $true
    }
    catch {
        Write-Host "          excecao inesperada: $($_.Exception.GetType().Name)" -ForegroundColor Yellow
    }

    Add-Result -Name 'Escrita no destino e negada apos a marcacao' -Passed $writeRefused `
        -Detail $(if ($writeRefused) { 'Acesso negado antes de qualquer escrita.' } else { 'A escrita passou: a marcacao nao chegou ao pre-create.' })

    # The stronger half of the guarantee: refused in pre-create means the
    # create never happened, so not even an empty file is left behind.
    Add-Result -Name 'Nenhum arquivo vazio ficou no destino' -Passed (-not (Test-Path $destinationWrite)) `
        -Detail $(if (Test-Path $destinationWrite) { 'Sobrou um arquivo: a negacao veio do pos-create.' } else { 'Nada foi criado.' })

    Write-Step 'Caso 9 - fora do destino, o processo marcado continua escrevendo'

    # Taint must not turn into a blanket ban. A tainted process is refused
    # only where the policy says a file must not go.
    $freeWrite = Join-Path $OutOfScopeDirectory 'livre.txt'
    Remove-Item $freeWrite -Force -ErrorAction SilentlyContinue

    $freeWriteOk = $false

    try {
        Set-Content -Path $freeWrite -Value 'permitido' -ErrorAction Stop
        $freeWriteOk = Test-Path $freeWrite
    }
    catch { }

    Add-Result -Name 'Escrita fora de escopo continua permitida' -Passed $freeWriteOk `
        -Detail $(if ($freeWriteOk) { 'A marcacao nao virou proibicao geral.' } else { 'Escrita fora de escopo foi negada: falso positivo grave.' })

    Write-Step 'Caso 10 - renomear para o destino tambem e negado'

    # The bypass this closes: a tainted process cannot create a file inside
    # the monitored folder, but it can write the same content next door and
    # rename it in. Both directories are on the same volume, so Move-Item is
    # a rename, not a copy - which is exactly the operation that would slip
    # past a create-only filter.
    $stagedForRename = Join-Path $OutOfScopeDirectory 'para-mover.txt'
    $renameTarget = Join-Path $TestDirectory 'movido.txt'

    Remove-Item $renameTarget -Force -ErrorAction SilentlyContinue
    Set-Content -Path $stagedForRename -Value 'conteudo a mover' -ErrorAction SilentlyContinue

    $renameRefused = $false

    try {
        Move-Item -Path $stagedForRename -Destination $renameTarget -ErrorAction Stop
    }
    catch [System.UnauthorizedAccessException] {
        $renameRefused = $true
    }
    catch {
        Write-Host "          excecao inesperada: $($_.Exception.GetType().Name)" -ForegroundColor Yellow
    }

    Add-Result -Name 'Rename para o destino e negado apos a marcacao' -Passed $renameRefused `
        -Detail $(if ($renameRefused) { 'Acesso negado, como na abertura para escrita.' } else { 'O rename passou: a porta lateral do create continua aberta.' })

    Add-Result -Name 'Nada chegou ao destino pelo rename' -Passed (-not (Test-Path $renameTarget)) `
        -Detail $(if (Test-Path $renameTarget) { 'O arquivo esta la: o conteudo atravessou.' } else { 'Nada foi movido.' })

    # The case above proves the user-visible behaviour: Move-Item fails and
    # nothing arrives. It does NOT prove the rename hook did it.
    #
    # Move-Item goes through MoveFileEx, which is free to reach the same
    # outcome without ever issuing FileRenameInformation - it can be
    # refused while opening the destination, in which case the pre-create
    # gate blocked it and the SET_INFORMATION callback was never consulted.
    # The first run with these counters showed exactly that: the case
    # passed with RenamesSeen = 0.
    #
    # So issue the rename directly. CreateFile with DELETE, then
    # SetFileInformationByHandle(FileRenameInfo) - the operation the driver
    # claims to intercept, with nothing in between free to substitute it.

    $renameInterop = @'
using System;
using System.Runtime.InteropServices;

public static class SafeUploadRename
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetFileInformationByHandle(IntPtr file, int infoClass,
        IntPtr info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    const uint DELETE = 0x00010000;
    const uint SYNCHRONIZE = 0x00100000;
    const uint SHARE_ALL = 0x00000007;
    const uint OPEN_EXISTING = 3;
    const int FileRenameInfo = 3;

    // Returns 0 when the rename went through, otherwise the Win32 error.
    // A driver refusal shows up as 5, ERROR_ACCESS_DENIED.
    public static int Rename(string source, string destination)
    {
        IntPtr handle = CreateFileW(source, DELETE | SYNCHRONIZE, SHARE_ALL,
                                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        if (handle == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }

        try
        {
            // FILE_RENAME_INFO on x64: ReplaceIfExists at 0 (4 bytes plus 4
            // of padding), RootDirectory at 8, FileNameLength at 16, and the
            // name from 20. FileNameLength counts bytes, not characters, and
            // excludes the terminator.
            byte[] name = System.Text.Encoding.Unicode.GetBytes(destination);
            int size = 20 + name.Length + 2;
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                for (int i = 0; i < size; i++) { Marshal.WriteByte(buffer, i, 0); }

                Marshal.WriteInt32(buffer, 0, 1);
                Marshal.WriteIntPtr(buffer, 8, IntPtr.Zero);
                Marshal.WriteInt32(buffer, 16, name.Length);
                Marshal.Copy(name, 0, IntPtr.Add(buffer, 20), name.Length);

                if (SetFileInformationByHandle(handle, FileRenameInfo, buffer, (uint) size))
                {
                    return 0;
                }

                return Marshal.GetLastWin32Error();
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(handle); }
    }
}
'@

    if (-not ('SafeUploadRename' -as [type])) {
        Add-Type -TypeDefinition $renameInterop -Language CSharp
    }

    $directSource = Join-Path $OutOfScopeDirectory 'rename-direto.txt'
    $directTarget = Join-Path $TestDirectory 'rename-direto.txt'

    Remove-Item $directTarget -Force -ErrorAction SilentlyContinue
    Set-Content -Path $directSource -Value 'conteudo a renomear' -ErrorAction SilentlyContinue

    $renameError = [SafeUploadRename]::Rename($directSource, $directTarget)

    Add-Result -Name 'FileRenameInfo direto para o destino e negado' -Passed ($renameError -eq 5) `
        -Detail $(switch ($renameError) {
            5       { 'ERROR_ACCESS_DENIED: o gancho de SET_INFORMATION recusou.' }
            0       { 'O rename passou. O desvio por rename esta aberto.' }
            default { "Erro $renameError - nem passou nem foi negado; ver o caso antes de concluir." }
        })

    Add-Result -Name 'Nada chegou ao destino pelo rename direto' -Passed (-not (Test-Path $directTarget)) `
        -Detail $(if (Test-Path $directTarget) { 'O arquivo esta la: o conteudo atravessou.' } else { 'Nada foi renomeado.' })

}
finally {

    Write-Step 'Encerrando o inspetor'
    Stop-Inspector | Out-Null
}

Write-Step 'Caso 11 - RN-013, falha de inspecao permite'

# Without a client on the port the driver allows everything. Give the
# disconnect a moment to land, then confirm the same file opens again.
$allowedAfterDisconnect = $false

foreach ($attempt in 1..20) {
    Start-Sleep -Milliseconds 250

    try {
        Get-Content $blockedFile -Raw -ErrorAction Stop | Out-Null
        $allowedAfterDisconnect = $true
        break
    }
    catch [System.UnauthorizedAccessException] {
        continue
    }
}

Add-Result -Name 'Sem inspetor, o arquivo bloqueado volta a abrir' -Passed $allowedAfterDisconnect `
    -Detail $(if ($allowedAfterDisconnect) { 'Permitido sem inspecao.' } else { 'Continuou negado - fail-open quebrado.' })

# ---------------------------------------------------------------------------
# 6. Observability
# ---------------------------------------------------------------------------

Write-Step 'O que o inspetor viu'

if (Test-Path $inspectorLog) {
    $lines = @(Get-Content $inspectorLog -ErrorAction SilentlyContinue)
    $blockedLines = @($lines | Select-String -SimpleMatch 'BLOQUEADO')

    Write-Host "  Linhas no log      : $($lines.Count)"
    Write-Host "  Operacoes negadas  : $($blockedLines.Count)"
    Write-Host "  Log completo em    : $inspectorLog"

    # With the scope gates in place an idle desktop should produce a trickle,
    # not a flood. A large number here means the gates are not doing their job.
    if ($lines.Count -gt 500) {
        Write-Host ''
        Write-Host "  Atencao: $($lines.Count) linhas e muito para este teste." -ForegroundColor Yellow
        Write-Host '  As portas de escopo podem nao estar filtrando como deveriam.' -ForegroundColor Yellow
    }
}

Write-Step 'Contadores do driver'

# Read after the inspector has stopped: the port takes one client at a time,
# and the counters live in the driver rather than in whoever was connected.
$counterOutput = & (Join-Path $StagingDirectory $InspectorFileName) --counters 2>&1

$counterOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

$cacheHits = 0
$roundTrips = 0
$deniedPreCreate = 0
$deniedRename = 0
$renamesSeen = 0
$renamesFromTainted = 0
$setInformationSeen = 0

foreach ($line in $counterOutput) {
    if ($line -match '^CacheHits\s*:\s*(\d+)') { $cacheHits = [int] $matches[1] }
    if ($line -match '^UserModeRoundTrips\s*:\s*(\d+)') { $roundTrips = [int] $matches[1] }
    if ($line -match '^DeniedPreCreate\s*:\s*(\d+)') { $deniedPreCreate = [int] $matches[1] }
    if ($line -match '^DeniedRename\s*:\s*(\d+)') { $deniedRename = [int] $matches[1] }
    if ($line -match '^SetInformationSeen\s*:\s*(\d+)') { $setInformationSeen = [int] $matches[1] }
    if ($line -match '^RenamesSeen\s*:\s*(\d+)') { $renamesSeen = [int] $matches[1] }
    if ($line -match '^RenamesFromTainted\s*:\s*(\d+)') { $renamesFromTainted = [int] $matches[1] }
}

# The cache is the property the design rests on. If it never served a single
# answer, the stream context is not doing its job and every open is paying
# full price - which no other check in this script would notice.
Add-Result -Name 'O cache serviu ao menos uma resposta' -Passed ($cacheHits -gt 0) `
    -Detail "$cacheHits acertos de cache contra $roundTrips idas ao modo usuario."

# The counters have to agree with the cases that just passed. They are the
# only independent witness to WHY a case passed: a denial case can go green
# because the operation failed for an unrelated reason, and no assertion
# above would tell the difference.
#
# This check exists because it was missing. The pre-create refusal ran
# correctly for weeks while its counter was never incremented at all, and
# the run reported DeniedPreCreate = 0 next to a passing block test. The
# numbers disagreed with the results and nothing was watching.

Add-Result -Name 'A recusa por marca no pre-create foi contada' -Passed ($deniedPreCreate -gt 0) `
    -Detail "DeniedPreCreate = $deniedPreCreate; o caso da escrita marcada passou, entao tem de ser >= 1."

# When this fails, the two counters below say where the callback gave up,
# which is the whole reason they exist:
#
#   RenamesSeen = 0        nenhum rename chegou ao callback. O Move-Item
#                          foi barrado antes, no create - o caso nao esta
#                          testando o gancho de SET_INFORMATION.
#   RenamesSeen > 0,
#   RenamesFromTainted = 0 o rename chegou, mas o processo nao estava
#                          marcado naquele instante.
#   ambos > 0              chegou e estava marcado: o destino nao casou.

Add-Result -Name 'A recusa de rename foi contada' -Passed ($deniedRename -gt 0) `
    -Detail "DeniedRename = $deniedRename (SetInformationSeen = $setInformationSeen, RenamesSeen = $renamesSeen, RenamesFromTainted = $renamesFromTainted)."

Write-Step 'Driver Verifier'

# Pool has to be checked with the filter UNLOADED, not while it is running.
#
# An earlier version asserted "current allocations == 0" with the driver
# still loaded. That was valid only while the driver held nothing long
# lived; since the policy arrived it legitimately keeps one allocation - the
# policy snapshot - for as long as it is loaded, and the assertion started
# reporting a leak that was not there.
#
# Unloading first is also the stronger test: bugcheck 0xC4 subcode 0x62 is
# exactly "pool still allocated at unload", so this checks the same
# condition the Verifier itself would bugcheck on.

if ($KeepLoaded) {

    Write-Host '  Filtro mantido carregado a pedido: verificacao de pool pulada.' -ForegroundColor Yellow
    Write-Host '  Com o driver carregado ha alocacoes de vida longa (a politica),' -ForegroundColor DarkGray
    Write-Host '  entao "alocacoes atuais" nao diz nada sobre vazamento.' -ForegroundColor DarkGray
}
else {

    Write-Host '  Descarregando o filtro para conferir o pool.'

    & fltmc.exe unload $FilterName 2>&1 | ForEach-Object { Write-Host "  $_" }

    if (Test-FilterLoaded) {

        Add-Result -Name 'Filtro descarregado' -Passed $false `
            -Detail 'O unload foi recusado; nao da para avaliar o pool.'
    }
    else {

        Add-Result -Name 'Filtro descarregado' -Passed $true

        $verifierOutput = & verifier.exe /query 2>&1 | Out-String

        if ($verifierOutput -match 'SafeUpload\.sys') {

            $peak = [regex]::Match($verifierOutput, 'Peak Pool Allocations:\s*\(\s*(\d+)')
            $peakBytes = [regex]::Match($verifierOutput, 'Peak Pool Bytes:\s*\(\s*(\d+)')
            $current = [regex]::Match($verifierOutput, 'Current Pool Allocations:\s*\(\s*(\d+)')

            if ($peak.Success) { Write-Host "  Pico de alocacoes  : $($peak.Groups[1].Value)" }
            if ($peakBytes.Success) { Write-Host "  Pico em bytes      : $($peakBytes.Groups[1].Value)" }

            if ($current.Success) {

                $currentValue = [int] $current.Groups[1].Value
                Write-Host "  Alocacoes atuais   : $currentValue"

                Add-Result -Name 'Sem vazamento de pool apos o unload' -Passed ($currentValue -eq 0) `
                    -Detail $(if ($currentValue -eq 0) { 'Tudo que foi alocado foi liberado.' } else { "$currentValue alocacoes pendentes." })
            }
        }
        else {

            Write-Host '  O Driver Verifier nao esta instrumentando este driver.' -ForegroundColor Yellow
            Write-Host '  Para ligar:  verifier /standard /driver SafeUpload.sys   e reiniciar.' -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------

$failed = @($script:Results | Where-Object { -not $_.Passed })

Write-Host ''
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host " Resultado: $($script:Results.Count - $failed.Count)/$($script:Results.Count) verificacoes passaram" -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan

foreach ($result in $script:Results) {
    $mark = if ($result.Passed) { 'ok   ' } else { 'FALHA' }
    $color = if ($result.Passed) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1}" -f $mark, $result.Name) -ForegroundColor $color
}

Write-Host ''

if ($failed.Count -gt 0) {
    exit 1
}

Write-Host 'Tudo passou.' -ForegroundColor Green

if ($KeepLoaded) {
    Write-Host 'O filtro continua carregado.' -ForegroundColor DarkGray
    Write-Host 'Para descarregar:  fltmc unload SafeUpload' -ForegroundColor DarkGray
}
else {
    Write-Host 'O filtro foi descarregado ao final, para a verificacao de pool.' -ForegroundColor DarkGray
    Write-Host 'Para carregar de novo:  fltmc load SafeUpload' -ForegroundColor DarkGray
}
