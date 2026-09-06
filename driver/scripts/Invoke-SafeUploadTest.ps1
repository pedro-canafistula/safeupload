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

    [switch] $SkipDownload,

    [switch] $SkipSmokeTest
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
# 2. Fetch and verify
# ---------------------------------------------------------------------------

if (-not (Test-Path $StagingDirectory)) {
    New-Item -ItemType Directory -Path $StagingDirectory -Force | Out-Null
}

if (-not $SkipDownload) {

    if (-not $SourceUrl) {
        Stop-WithMessage 'Informe -SourceUrl, ou use -SkipDownload para reaproveitar o que ja esta em disco.'
    }

    Write-Step "Baixando de $SourceUrl"

    $fileNames = @('manifest.json', $DriverFileName, 'SafeUpload.inf', 'safeupload.cat', $InspectorFileName, 'SafeUploadTest.cer')

    foreach ($fileName in $fileNames) {
        $destination = Join-Path $StagingDirectory $fileName

        try {
            Invoke-WebRequest -Uri "$SourceUrl/$fileName" -OutFile $destination -UseBasicParsing -TimeoutSec 30
            Write-Host "  $fileName"
        }
        catch {
            Stop-WithMessage "Falha ao baixar $fileName : $($_.Exception.Message)"
        }
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

Stop-Inspector

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

$instances = @(& fltmc.exe instances -f $FilterName 2>&1 |
    Select-String -Pattern '^\s*\S+\s+\S+\s+\d+' |
    ForEach-Object { $_.Line.Trim() })

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

$allowedFile = Join-Path $TestDirectory 'normal.txt'
$blockedFile = Join-Path $TestDirectory "$BlockToken.txt"

Set-Content -Path $allowedFile -Value 'conteudo permitido' -Encoding UTF8
Set-Content -Path $blockedFile -Value 'conteudo bloqueado' -Encoding UTF8

Write-Host "  $allowedFile"
Write-Host "  $blockedFile"

Write-Step 'Subindo o inspetor'

$inspectorPath = Join-Path $StagingDirectory $InspectorFileName
$inspectorLog = Join-Path $StagingDirectory 'inspector.log'

Remove-Item $inspectorLog -Force -ErrorAction SilentlyContinue

$inspector = Start-Process -FilePath $inspectorPath -NoNewWindow -PassThru `
    -RedirectStandardOutput $inspectorLog

$connected = $false

foreach ($attempt in 1..40) {
    Start-Sleep -Milliseconds 250

    if (Test-Path $inspectorLog) {
        $log = Get-Content $inspectorLog -Raw -ErrorAction SilentlyContinue
        if ($log -and $log -match 'Conectado') {
            $connected = $true
            break
        }
    }

    if ($inspector.HasExited) {
        break
    }
}

if (-not $connected) {
    if ($inspector.HasExited) {
        Write-Host "  O inspetor terminou sozinho (codigo $($inspector.ExitCode))." -ForegroundColor Red
        Write-Host '  Codigo -1073741515 e STATUS_DLL_NOT_FOUND: binario com CRT dinamico.' -ForegroundColor Red
    }
    Stop-WithMessage 'O inspetor nao conectou na porta.'
}

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
}
finally {

    Write-Step 'Encerrando o inspetor'
    Stop-Inspector
}

Write-Step 'Caso 3 - RN-013, falha de inspecao permite'

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

        Add-Result -Name 'Sem vazamento de pool' -Passed ($currentValue -eq 0) `
            -Detail $(if ($currentValue -eq 0) { 'Tudo que foi alocado foi liberado.' } else { "$currentValue alocacoes pendentes." })
    }
}
else {
    Write-Host '  O Driver Verifier nao esta instrumentando este driver.' -ForegroundColor Yellow
    Write-Host '  Para ligar:  verifier /standard /driver SafeUpload.sys   e reiniciar.' -ForegroundColor Yellow
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

Write-Host 'Tudo passou. O filtro continua carregado.' -ForegroundColor Green
Write-Host 'Para descarregar:  fltmc unload SafeUpload' -ForegroundColor DarkGray
