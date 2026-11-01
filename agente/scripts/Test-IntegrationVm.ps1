#requires -Version 7.0
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'),
    [string]$ResultsDirectory
)

$ErrorActionPreference = 'Stop'
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if (-not $ResultsDirectory) {
    $ResultsDirectory = Join-Path $env:TEMP ('safeupload-integration-' + [guid]::NewGuid().ToString('N'))
}
$ResultsDirectory = [IO.Path]::GetFullPath($ResultsDirectory)
if ((Test-Path -LiteralPath $ResultsDirectory) -and (Get-ChildItem -LiteralPath $ResultsDirectory -Force | Select-Object -First 1)) {
    throw 'Escolha uma pasta de resultados vazia para esta execucao.'
}
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
$results = [ordered]@{ startedAtUtc = [DateTime]::UtcNow.ToString('o'); repository = $RepositoryRoot; status = 'running'; steps = @() }
$server = $null
$previousPassword = $env:SAFEUPLOAD_DB_PASSWORD
$previousMachineTests = $env:SAFEUPLOAD_MACHINE_TESTS

function Invoke-ValidationStep {
    param([string]$Name, [string]$Command, [string[]]$Arguments)
    $log = Join-Path $ResultsDirectory ($Name + '.log')
    Write-Host "Executando $Name..."
    & $Command @Arguments *> $log
    $stepExitCode = $LASTEXITCODE
    $script:results.steps += [ordered]@{ name = $Name; exitCode = $stepExitCode; log = $log }
    if ($stepExitCode -ne 0) {
        throw "Etapa $Name falhou (codigo $stepExitCode). Consulte $log"
    }
}

Push-Location $RepositoryRoot
try {
    foreach ($requiredCommand in @('git', 'dotnet', 'java', 'mvn.cmd')) {
        Get-Command $requiredCommand -ErrorAction Stop | Out-Null
    }
    $results.commit = (& git rev-parse HEAD | Out-String).Trim()
    $results.branch = (& git branch --show-current | Out-String).Trim()
    $results.workingTree = @(& git status --short)
    & dotnet --info *> (Join-Path $ResultsDirectory 'dotnet-info.log')
    if ($LASTEXITCODE -ne 0) { throw 'SDK .NET indisponivel.' }
    & java -version *> (Join-Path $ResultsDirectory 'java-version.log')
    if ($LASTEXITCODE -ne 0) { throw 'Java indisponivel.' }
    & mvn.cmd -version *> (Join-Path $ResultsDirectory 'maven-version.log')
    if ($LASTEXITCODE -ne 0) { throw 'Maven indisponivel.' }
    if (Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction SilentlyContinue) {
        throw 'Porta 18080 ocupada. Encerre o servidor de teste anterior antes de continuar.'
    }
    $env:SAFEUPLOAD_DB_PASSWORD = 'isolated-integration-test'
    $env:SAFEUPLOAD_MACHINE_TESTS = '0'
    Invoke-ValidationStep -Name 'backend-tests' -Command 'mvn.cmd' -Arguments @('-B', '-f', 'web/back/pom.xml', 'package')
    Invoke-ValidationStep -Name 'agent-tests' -Command 'dotnet' -Arguments @('test', 'agente/SafeUpload.Agent.Tests/SafeUpload.Agent.Tests.csproj', '--verbosity', 'minimal', '--logger', 'trx', '--results-directory', $ResultsDirectory)
    $server = Start-Process java -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $ResultsDirectory 'backend.log') -RedirectStandardError (Join-Path $ResultsDirectory 'backend-errors.log') -ArgumentList @(
        '-jar', 'web/back/target/backend-0.1.0.jar', '--server.port=18080',
        '--server.address=127.0.0.1', '--spring.datasource.url=jdbc:h2:mem:contract',
        '--spring.datasource.username=sa', '--spring.datasource.password=',
        '--spring.jpa.hibernate.ddl-auto=create-drop', '--spring.jpa.show-sql=false'
    )
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($server.HasExited) { throw 'Backend encerrou antes de iniciar. Consulte backend.log.' }
        try {
            Invoke-RestMethod 'http://127.0.0.1:18080/agent/policy' -TimeoutSec 1 | Out-Null
            $ready = $true
            break
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $ready) { throw 'Backend nao ficou pronto no prazo.' }
    Invoke-ValidationStep -Name 'agent-java-contract' -Command 'dotnet' -Arguments @('run', '--project', 'agente/SafeUpload.Agent.ContractSmoke/SafeUpload.Agent.ContractSmoke.csproj')
    $results.status = 'passed'
} catch {
    $results.status = 'failed'
    $results.error = $_.Exception.Message
    throw
} finally {
    if ($null -ne $server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
    }
    $env:SAFEUPLOAD_DB_PASSWORD = $previousPassword
    $env:SAFEUPLOAD_MACHINE_TESTS = $previousMachineTests
    $results.finishedAtUtc = [DateTime]::UtcNow.ToString('o')
    $results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'result.json') -Encoding utf8
    Pop-Location
    Write-Host "Resultados: $ResultsDirectory"
}
