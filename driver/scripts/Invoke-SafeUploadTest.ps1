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
        param([Parameter(Mandatory)] [string] $Name)

        $destination = Join-Path $StagingDirectory $Name

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
        Get-PackageFile -Name $file.name
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
    $expectedHash = ($manifest.files | Where-Object { $_.name -eq $DriverFileName }).sha256

    if ($installedHash -ne $expectedHash) {
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

Set-Content -Path $allowedFile -Value 'conteudo permitido' -Encoding UTF8
Set-Content -Path $blockedFile -Value 'conteudo bloqueado' -Encoding UTF8
Set-Content -Path $sourceFile -Value 'documento de origem' -Encoding UTF8
Set-Content -Path $outOfScopeFile -Value 'fora de escopo' -Encoding UTF8

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
}
finally {

    Write-Step 'Encerrando o inspetor'
    Stop-Inspector | Out-Null
}

Write-Step 'Caso 7 - RN-013, falha de inspecao permite'

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
