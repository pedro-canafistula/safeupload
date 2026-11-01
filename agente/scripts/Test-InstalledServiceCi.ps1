#requires -Version 7.0
[CmdletBinding()]
param([string]$ResultsDirectory = (Join-Path $PSScriptRoot '../../artifacts/installed-service'))

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Este teste instala um serviço e só é permitido em runner Windows temporário hospedado pelo GitHub.'
}
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$ResultsDirectory = [IO.Path]::GetFullPath($ResultsDirectory)
$agentRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SafeUpload'
$workRoot = Join-Path ([IO.Path]::GetPathRoot([Environment]::GetFolderPath('Windows'))) 'SafeUpload'
$cache = Join-Path $agentRoot 'server-policy-cache.json'
$queue = Join-Path $agentRoot 'queue.jsonl'
$serviceName = 'SafeUploadAgent'
$serviceExe = Join-Path $root 'artifacts/service/SafeUpload.Agent.Service.exe'
$jar = Join-Path $root 'web/back/target/backend-0.1.0.jar'
$api = 'http://127.0.0.1:18080/'
if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $agentRoot) -or (Test-Path -LiteralPath $workRoot)) {
    throw 'Estado SafeUpload preexistente: teste interrompido para não alterar outra instalação.'
}
if (Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction SilentlyContinue) {
    throw 'Porta de teste ocupada.'
}
if (-not (Test-Path -LiteralPath $serviceExe) -or -not (Test-Path -LiteralPath $jar)) {
    throw 'Publique o serviço em artifacts/service e compile o backend antes de executar.'
}
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
$createdService = $false
$server = $null
$started = Get-Date
$result = [ordered]@{ status = 'running'; runner = $env:RUNNER_NAME; steps = @() }

function Wait-Value {
    param([scriptblock]$Condition, [string]$Description, [int]$Seconds = 45)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $value = & $Condition
        if ($value) { return $value }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Prazo excedido: $Description"
}

function Start-TestBackend {
    param([string]$Label)
    $process = Start-Process java -WindowStyle Hidden -PassThru -ArgumentList @(
        '-jar', ('"' + $jar + '"'), '--server.port=18080', '--server.address=127.0.0.1',
        '--spring.datasource.url=jdbc:h2:mem:installedservice', '--spring.datasource.username=sa',
        '--spring.datasource.password=', '--spring.jpa.hibernate.ddl-auto=create-drop',
        '--spring.jpa.show-sql=false'
    ) -RedirectStandardOutput (Join-Path $ResultsDirectory "$Label-backend.log") `
      -RedirectStandardError (Join-Path $ResultsDirectory "$Label-backend-errors.log")
    try {
        Wait-Value -Description 'backend de teste' -Condition {
            if ($process.HasExited) { throw 'Backend encerrou antes de iniciar.' }
            try { Invoke-RestMethod ($api + 'agent/policy') -TimeoutSec 1 | Out-Null; return $true }
            catch { return $false }
        } | Out-Null
        return $process
    } catch { if (-not $process.HasExited) { Stop-Process -Id $process.Id }; throw }
}

function Read-Queue {
    if (-not (Test-Path -LiteralPath $queue)) { return }
    $stream = [IO.FileStream]::new($queue, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader = [IO.StreamReader]::new($stream)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            try { $line | ConvertFrom-Json -ErrorAction Stop } catch { }
        }
    } finally { $reader.Dispose(); $stream.Dispose() }
}

function Get-AgentLogs {
    param([datetime]$Since)
    @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -eq 'SafeUpload.Agent.Service' })
}

Push-Location $root
try {
    $server = Start-TestBackend 'online'
    $remotePolicy = Invoke-RestMethod ($api + 'agent/policy')
    New-Item -ItemType Directory -Path $agentRoot | Out-Null
    $policyPath = Join-Path $agentRoot 'policy.json'
    $remotePolicy | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $policyPath -Encoding utf8NoBOM
    & (Join-Path $PSScriptRoot 'Protect-SafeUploadPolicy.ps1') -PolicyPath $policyPath
    $binaryPath = '"' + $serviceExe + '" --Interception:Mode=FileSystemWatcher' +
        ' --CentroAdministracao:BaseUrl=http://127.0.0.1:18080/agent/' +
        ' --CentroAdministracao:TimeoutSeconds=2 --CentroAdministracao:DispatchIntervalSeconds=1' +
        ' --InspecaoTls:Habilitada=false --Logging:EventLog:LogLevel:Default=Information'
    New-Service -Name $serviceName -BinaryPathName $binaryPath -StartupType Manual | Out-Null
    $createdService = $true
    Start-Service $serviceName
    Wait-Value -Description 'cache remoto persistido pelo serviço' -Condition { Test-Path -LiteralPath $cache } | Out-Null
    $account = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").StartName
    if ($account -ne 'LocalSystem') { throw "Conta de serviço inesperada: $account" }
    $cacheAcl = Get-Acl -LiteralPath $cache
    $ownerSid = $cacheAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -ne 'S-1-5-18' -or -not $cacheAcl.AreAccessRulesProtected) {
        throw 'O cache persistido não possui proprietário SYSTEM e DACL protegida.'
    }
    & dotnet run --project agente/SafeUpload.Agent.ContractSmoke/SafeUpload.Agent.ContractSmoke.csproj `
        -- --protected-cache-probe $cache $remotePolicy.version
    if ($LASTEXITCODE -ne 0) { throw 'A verificação completa da ACL do cache falhou.' }
    $cacheHash = (Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash
    $result.steps += 'serviço LocalSystem e cache remoto com ACL de produção verificados'

    Stop-Process -Id $server.Id
    $server.WaitForExit()
    $server = $null
    Stop-Service $serviceName
    (Get-Service $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
    $offlineStarted = Get-Date
    Start-Service $serviceName
    $offlineLog = Wait-Value -Description 'recuperação offline pelo serviço a partir de disco' -Condition {
        Get-AgentLogs $offlineStarted | Where-Object { $_.Message -like '*Origem=disk*' } | Select-Object -First 1
    }
    if ((Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash -ne $cacheHash) {
        throw 'O cache foi alterado durante o reinício offline.'
    }
    Wait-Value -Description 'gatilho de arquivos ativo' -Condition {
        Get-AgentLogs $offlineStarted | Where-Object { $_.Message -like '*Vigiando*' } | Select-Object -First 1
    } | Out-Null
    $fileName = 'service-offline-' + [guid]::NewGuid().ToString('N') + '.txt'
    $target = Join-Path $remotePolicy.monitoredScopes.destinationPaths[0] $fileName
    [IO.File]::WriteAllText($target, 'CPF sintético: 529.982.247-25', [Text.UTF8Encoding]::new($false))
    $event = Wait-Value -Description 'auditoria offline do arquivo sintético' -Condition {
        Read-Queue | Where-Object { $_.fileName -eq $fileName } | Select-Object -First 1
    }
    if ($event.dispatched -or $event.verdict -ne 'Blocked' -or $event.policyVersion -ne $remotePolicy.version) {
        throw 'Evento offline divergente ou confirmado sem conexão.'
    }
    if ((Get-Content -LiteralPath $queue -Raw) -match '529[.]982[.]247-25|52998224725') {
        throw 'A fila contém o CPF sem mascaramento.'
    }
    $result.steps += 'novo processo de serviço recuperou política do disco e registrou evento offline mascarado'

    $server = Start-TestBackend 'reconnected'
    Wait-Value -Description 'confirmação de envio após reconexão' -Condition {
        Read-Queue | Where-Object { $_.eventId -eq $event.eventId -and $_.dispatched } | Select-Object -First 1
    } | Out-Null
    $registration = @{nomeCompleto='Teste Serviço';username='service-smoke';email='service-smoke@example.com';
        cpf='52998224725';senha='isolated-service-test-123';confirmarSenha='isolated-service-test-123'} | ConvertTo-Json
    Invoke-RestMethod ($api + 'api/auth/cadastro') -Method Post -ContentType 'application/json' `
        -Body ([Text.Encoding]::UTF8.GetBytes($registration)) | Out-Null
    $login = @{email='service-smoke@example.com';senha='isolated-service-test-123'} | ConvertTo-Json
    Invoke-RestMethod ($api + 'api/auth/login') -Method Post -ContentType 'application/json' `
        -Body $login -SessionVariable adminSession | Out-Null
    $audit = Invoke-RestMethod ($api + 'api/auditoria') -WebSession $adminSession
    $persisted = @($audit.eventos | Where-Object { $_.eventId -eq $event.eventId })
    if ($persisted.Count -ne 1) { throw 'O backend não preservou exatamente o evento do serviço.' }
    if (@(Read-Queue | Where-Object { $_.eventId -eq $event.eventId }).Count -ne 1) {
        throw 'A confirmação alterou a quantidade de registros na trilha local.'
    }
    $result.steps += 'reconexão confirmou o mesmo UUID no Java e preservou a trilha local'
    $result.status = 'passed'
    $result.serviceAccount = $account
    $result.cacheOwnerSid = $ownerSid
    $result.policyVersion = $remotePolicy.version
    $result.eventId = $event.eventId
    $result.offlinePolicyLog = $offlineLog.Message
    Write-Host 'InstalledServiceVerified=True;Account=LocalSystem;OfflineCache=disk;AuditDispatch=True'
} catch {
    $result.status = 'failed'
    $result.error = $_.Exception.Message
    throw
} finally {
    if ($createdService) {
        Stop-Service $serviceName -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
    }
    if ($null -ne $server -and -not $server.HasExited) { Stop-Process -Id $server.Id -ErrorAction SilentlyContinue }
    foreach ($file in @($cache, $queue)) {
        if (Test-Path -LiteralPath $file) { Copy-Item -LiteralPath $file -Destination $ResultsDirectory }
    }
    Get-AgentLogs $started | Select-Object TimeCreated,ProviderName,Message |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ResultsDirectory 'service-events.json') -Encoding utf8
    $result | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ResultsDirectory 'result.json') -Encoding utf8
    Pop-Location
    Write-Host "Resultados: $ResultsDirectory"
}
