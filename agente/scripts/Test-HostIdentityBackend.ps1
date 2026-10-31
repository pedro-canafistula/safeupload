#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$MySqlBase,
    [string]$ResultsDirectory = (Join-Path $PSScriptRoot '../../artifacts/host-identity-backend'),
    [switch]$ContractOnly
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This service test is restricted to a disposable GitHub-hosted Windows runner.'
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$results = [IO.Path]::GetFullPath($ResultsDirectory)
if (-not $results.StartsWith((Join-Path $repo 'artifacts') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Results must stay inside this checkout artifacts directory.'
}
$serviceName = 'SafeUploadAgent'
$agentRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SafeUpload'
$workRoot = Join-Path ([IO.Path]::GetPathRoot([Environment]::GetFolderPath('Windows'))) 'SafeUpload'
$identityFile = Join-Path $agentRoot 'identity/host-registration.json'
$serviceExe = Join-Path $repo 'artifacts/host-identity-service/SafeUpload.Agent.Service.exe'
$contractDll = Join-Path $repo 'agente/SafeUpload.Agent.ContractSmoke/bin/Release/net10.0-windows/SafeUpload.Agent.ContractSmoke.dll'
$jar = Join-Path $repo 'web/back/target/backend-0.1.0.jar'
$mysql = Join-Path $MySqlBase 'bin/mysql.exe'
$mysqlAdmin = Join-Path $MySqlBase 'bin/mysqladmin.exe'
$mysqld = Join-Path $MySqlBase 'bin/mysqld.exe'
$api = 'http://127.0.0.1:18080'
if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $agentRoot) -or (Test-Path -LiteralPath $workRoot)) {
    throw 'Existing SafeUpload state: refusing to touch another installation.'
}
foreach ($port in @(18080,13316)) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { throw 'Test port occupied.' }
}
$testedBinary = if ($ContractOnly) { $contractDll } else { $serviceExe }
foreach ($file in @($testedBinary,$jar,$mysql,$mysqld,$mysqlAdmin)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Required test binary missing.' }
}
New-Item -ItemType Directory -Path $results -Force | Out-Null
$runtime = Join-Path $env:RUNNER_TEMP ('safeupload-host-backend-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runtime | Out-Null
$dbArgs = @('--no-defaults','--protocol=TCP','--host=127.0.0.1','--port=13316','--user=root','--skip-password',
    '--default-character-set=utf8mb4','--batch','--skip-column-names','--raw')
$script:javaProcess = $null
$mysqlProcess = $null
$createdService = $false
$started = Get-Date
$evidence = [ordered]@{
    status='running'; agentCommit=(& git -C $repo rev-parse HEAD); backendSource='same checkout as agent'
    mode=$(if ($ContractOnly) { 'Current C# API contract and real MySQL; remote policy application remains pending' } else { 'Installed LocalSystem service, FileSystemWatcher; no driver, UI or real file inspection qualified' })
    mysqlVersion=$null; checks=@(); snapshots=[ordered]@{}; cleanup=[ordered]@{}
}
function Check([string]$Name, [bool]$Passed) {
    $evidence.checks += [ordered]@{name=$Name;passed=$Passed}
    if (-not $Passed) { throw "Acceptance failed: $Name" }
}
function Read-AuditIntegrity([string]$Phase) {
    $queueFile = Join-Path $agentRoot 'queue.jsonl'
    $beforeExists = Test-Path -LiteralPath $queueFile -PathType Leaf
    $beforeHash = if ($beforeExists) { (Get-FileHash -LiteralPath $queueFile -Algorithm SHA256).Hash } else { $null }
    $scan = & (Join-Path $PSScriptRoot 'Get-SafeUploadDiagnostics.ps1') -Query audit-integrity
    Check "${Phase}: installed service serves complete audit integrity" ($null -ne $scan -and
        ($scan.PSObject.Properties.Name -contains 'linesScanned') -and
        $scan.linesScanned -eq ($scan.validEvents + $scan.validOverrides + $scan.invalidLines + $scan.unknownRecords + $scan.blankLines) -and
        $scan.validEvents -eq ($scan.pendingEvents + $scan.dispatchedEvents) -and
        $scan.validOverrides -eq ($scan.pendingOverrides + $scan.dispatchedOverrides) -and @($scan.issues).Count -le 20)
    $afterExists = Test-Path -LiteralPath $queueFile -PathType Leaf
    $afterHash = if ($afterExists) { (Get-FileHash -LiteralPath $queueFile -Algorithm SHA256).Hash } else { $null }
    Check "${Phase}: diagnostic preserves queue existence and bytes" ($beforeExists -eq $afterExists -and $beforeHash -eq $afterHash)
    return $scan
}
function Read-AuditHealth([string]$Phase) {
    $health = Wait-Value {
        $candidate = & (Join-Path $PSScriptRoot 'Get-SafeUploadDiagnostics.ps1') -Query audit-health
        if (@($candidate.operations | Where-Object { $_.operation -eq 'ReadPending' -and $_.successes -gt 0 }).Count -eq 1) {
            return $candidate
        }
        return $null
    } 'a real dispatcher read observed by audit-health' 20
    $expected = @('WriteEvent','WriteOverride','ReadRecent','ReadPending','ReadPendingOverrides','ConfirmEvents','ConfirmOverrides')
    Check "${Phase}: installed service exposes all monitored queue operations" (
        $null -ne $health.sinceUtc -and @($health.operations).Count -eq 7 -and
        (($health.operations.operation | Sort-Object) -join '|') -eq (($expected | Sort-Object) -join '|'))
    $writeFailures = ($health.operations | Where-Object operation -eq 'WriteEvent').failures +
        ($health.operations | Where-Object operation -eq 'WriteOverride').failures
    Check "${Phase}: health aggregates remain consistent" ($health.failedWriteAttempts -eq $writeFailures -and
        $health.degraded -eq (@($health.operations | Where-Object degraded).Count -gt 0))
    return $health
}
function Read-SessionHistory([string]$Phase) {
    $queueFile = Join-Path $agentRoot 'queue.jsonl'
    $beforeExists = Test-Path -LiteralPath $queueFile -PathType Leaf
    $beforeHash = if ($beforeExists) { (Get-FileHash -LiteralPath $queueFile -Algorithm SHA256).Hash } else { $null }
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SafeUpload.Agent', [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    $reader = $null
    $timeout = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(15))
    try {
        $pipe.ConnectAsync($timeout.Token).GetAwaiter().GetResult()
        $reader = [IO.StreamReader]::new($pipe, [Text.UTF8Encoding]::new($false), $true, 4096, $true)
        $line = $reader.ReadLineAsync($timeout.Token).AsTask().GetAwaiter().GetResult()
        $status = $line | ConvertFrom-Json
        Check "${Phase}: installed service sends status first" ($status.type -eq 'status')
        $line = $reader.ReadLineAsync($timeout.Token).AsTask().GetAwaiter().GetResult()
        $history = $line | ConvertFrom-Json
        Check "${Phase}: authenticated history is available and bounded" ($history.type -eq 'history' -and $history.available -eq $true -and
            @($history.events).Count -eq 0 -and [Text.Encoding]::UTF8.GetByteCount($line) -le 524288)
        $afterExists = Test-Path -LiteralPath $queueFile -PathType Leaf
        $afterHash = if ($afterExists) { (Get-FileHash -LiteralPath $queueFile -Algorithm SHA256).Hash } else { $null }
        Check "${Phase}: history preserves queue existence and bytes" ($beforeExists -eq $afterExists -and $beforeHash -eq $afterHash)
        return [ordered]@{available=$history.available;events=@($history.events).Count;bytes=[Text.Encoding]::UTF8.GetByteCount($line)}
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        $pipe.Dispose()
        $timeout.Dispose()
    }
}
function Wait-Value([scriptblock]$Condition, [string]$Description, [int]$Seconds=60) {
    $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $value=& $Condition
        if ($value) { return $value }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timeout: $Description"
}
function Query([string]$Sql) {
    $errorFile=Join-Path $runtime 'mysql-client.private.log'
    $lines = & $mysql @dbArgs '--execute' $Sql 2> $errorFile
    if ($LASTEXITCODE -ne 0) {
        $evidence.lastSqlError=Get-Content -LiteralPath $errorFile -Raw
        throw 'Isolated SQL query failed.'
    }
    return ($lines -join "`n").Trim()
}
function Stop-Owned([Diagnostics.Process]$Process) {
    if ($null -ne $Process -and -not $Process.HasExited) {
        $Process.Kill($true)
        if (-not $Process.WaitForExit(10000)) { throw 'Owned process did not exit.' }
    }
}
function Start-Backend([string]$Label) {
    $arguments=@('-Duser.timezone=America/Sao_Paulo','-jar', ('"' + $jar + '"'), '--server.port=18080','--server.address=127.0.0.1',
        '--app.datasource.url=jdbc:mysql://127.0.0.1:13316/app?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false',
        '--app.datasource.username=root','--app.datasource.password=',
        '--acesso.datasource.url=jdbc:mysql://127.0.0.1:13316/acesso?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false',
        '--acesso.datasource.username=root','--acesso.datasource.password=','--spring.jpa.show-sql=false')
    $script:javaProcess=Start-Process -FilePath (Get-Command java).Source -ArgumentList $arguments -WindowStyle Hidden -PassThru         -RedirectStandardOutput (Join-Path $runtime "$Label-java.private.log") -RedirectStandardError (Join-Path $runtime "$Label-java-errors.private.log")
    Wait-Value {
        if ($script:javaProcess.HasExited) { throw 'Isolated Java backend exited.' }
        try { Invoke-RestMethod "$api/auth/decision" -TimeoutSec 2 | Out-Null; return $true } catch { return $false }
    } 'Java startup' | Out-Null
}
function Register-Host([string]$Name) {
    $body=@{
        host=@{ip=$null;mascara=24;hostname=$Name;sistema_operacional='Windows';versao_so='test'}
        usuarioSo=@{sid=('S-TEST-' + $Name);usuario_so=$Name;dominio='SYNTHETIC';admin=0}
    } | ConvertTo-Json -Depth 5
    $response=Invoke-RestMethod "$api/agent/synchronize" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 10
    if ([int]$response.id_host -le 0) { throw 'Explicit test registration did not return id_host.' }
    return $response
}
function Host-Snapshot([int]$Id) {
    return Query "SELECT CONCAT(id_host,'|',COALESCE(ativo,-1),'|',COALESCE(DATE_FORMAT(visto_por_ultimo,'%Y-%m-%d %H:%i:%s.%f'),'null')) FROM app.hosts WHERE id_host=$Id;"
}
function Counts { return Query 'SELECT CONCAT((SELECT COUNT(*) FROM app.hosts),CHAR(124),(SELECT COUNT(*) FROM app.usuarios_so));' }
function Wait-Heartbeat([int]$Id) {
    Wait-Value {
        $running=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($running.State -ne 'Running') { throw 'Agent service stopped before heartbeat.' }
        return (Query "SELECT COUNT(*) FROM app.hosts WHERE id_host=$Id AND ativo=1 AND visto_por_ultimo>'2001-01-01';") -eq '1'
    } 'heartbeat persisted for registered host' | Out-Null
}
function Service-Info {
    $service=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $process=Get-Process -Id $service.ProcessId
    return [ordered]@{pid=$service.ProcessId;startedUtc=$process.StartTime.ToUniversalTime().ToString('o');account=$service.StartName;state=$service.State}
}
try {
    $initArgs=@('--no-defaults','--initialize-insecure',('--basedir=' + $MySqlBase),('--datadir=' + (Join-Path $runtime 'data')))
    & $mysqld @initArgs *> (Join-Path $runtime 'mysql-initialize.private.log')
    if ($LASTEXITCODE -ne 0) { throw 'Isolated MySQL initialization failed.' }
    $mysqlArgs=@('--no-defaults',('--basedir="' + $MySqlBase + '"'),('--datadir="' + (Join-Path $runtime 'data') + '"'),
        '--bind-address=127.0.0.1','--port=13316','--mysqlx=0','--default-time-zone=-03:00','--event-scheduler=OFF','--console')
    $mysqlProcess=Start-Process -FilePath $mysqld -ArgumentList $mysqlArgs -WindowStyle Hidden -PassThru         -RedirectStandardOutput (Join-Path $runtime 'mysql.private.log') -RedirectStandardError (Join-Path $runtime 'mysql-errors.private.log')
    Wait-Value {
        if ($mysqlProcess.HasExited) { throw 'Isolated MySQL exited.' }
        try {
            $probe=Query 'SELECT 1;'
            $evidence.mysqlProbe=$probe
            if ($probe -eq '1') { $evidence.Remove('mysqlProbeError'); $evidence.Remove('lastSqlError') }
            return $probe -eq '1'
        } catch { $evidence.mysqlProbeError=$_.Exception.Message; return $false }
    } 'MySQL startup' | Out-Null
    $evidence.mysqlVersion=Query 'SELECT VERSION();'
    $evidence.databaseClock=Query "SELECT CONCAT(@@global.time_zone,'|',@@session.time_zone,'|',DATE_FORMAT(NOW(),'%Y-%m-%d %H:%i:%s'),'|',DATE_FORMAT(UTC_TIMESTAMP(),'%Y-%m-%d %H:%i:%s'));"
    foreach ($file in @('01_schema_acesso.sql','02_schema_app.sql','03_job_usuarios_inativos.sql','05_agent_audit_ingest.sql')) {
        Query (Get-Content -LiteralPath (Join-Path $repo "db/initdb/$file") -Raw) | Out-Null
    }
    Start-Backend 'initial'
    if ($ContractOnly) {
        & dotnet $contractDll --current-api *> (Join-Path $results 'current-api-contract.log')
        $contractExit = $LASTEXITCODE
        Get-Content -LiteralPath (Join-Path $results 'current-api-contract.log') -Tail 40
        Check 'current C# API acceptance completed successfully' ($contractExit -eq 0)
        $contractText = Get-Content -LiteralPath (Join-Path $results 'current-api-contract.log') -Raw
        Check 'current API result retains policy and driver qualification limits' ($contractText.Contains('CurrentApiContract=True;ConsolePolicyRead=True;ConsolePolicyAppliedByAgent=Pending;RemotePolicyCacheQualification=Pending;DriverQualified=False'))
        $evidence.status='passed'
    } else {
    $control=Register-Host 'CONTROLE-IDENTIDADE'
    $target=Register-Host 'ALVO-IDENTIDADE'
    $controlId=[int]$control.id_host
    $targetId=[int]$target.id_host
    Check 'distinct explicit target and control hosts' ($controlId -ne $targetId)
    Query "UPDATE app.hosts SET ativo=0,visto_por_ultimo='2000-01-01 00:00:00' WHERE id_host IN ($controlId,$targetId);" | Out-Null
    $countsBefore=Counts
    $controlBefore=Host-Snapshot $controlId
    $evidence.snapshots.before=[ordered]@{counts=$countsBefore;control=$controlBefore;target=(Host-Snapshot $targetId)}
    $image='"' + $serviceExe + '" --Interception:Mode=FileSystemWatcher --InspecaoTls:Habilitada=false' +
        " --CentroAdministracao:BaseUrl=$api/agent/ --CentroAdministracao:HeartbeatProtocol=AgentApi" +
        ' --CentroAdministracao:DispatchIntervalSeconds=2 --CentroAdministracao:TimeoutSeconds=2' +
        ' --Logging:EventLog:LogLevel:Default=Information'
    New-Service -Name $serviceName -BinaryPathName ($image + " --CentroAdministracao:RegisteredHostId=$targetId") -StartupType Manual | Out-Null
    $createdService=$true
    Start-Service $serviceName
    Wait-Heartbeat $targetId
    $first=Service-Info
    Check 'first startup runs as LocalSystem' ($first.account -eq 'LocalSystem')
    Check 'first heartbeat preserves control host and registration counts' ((Host-Snapshot $controlId) -eq $controlBefore -and (Counts) -eq $countsBefore)
    $identityHash=(Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash
    $identity=Get-Content -LiteralPath $identityFile -Raw | ConvertFrom-Json
    Check 'service persisted target identity bound to test backend' ($identity.registeredHostId -eq $targetId -and $identity.serverBaseUrl -eq "$api/agent/")
    $owner=(Get-Acl -LiteralPath $identityFile).GetOwner([Security.Principal.SecurityIdentifier]).Value
    Check 'identity file owned by SYSTEM with protected DACL' ($owner -eq 'S-1-5-18' -and (Get-Acl -LiteralPath $identityFile).AreAccessRulesProtected)
    $firstAge=[int](Query "SELECT TIMESTAMPDIFF(SECOND,visto_por_ultimo,NOW()) FROM app.hosts WHERE id_host=$targetId;")
    $evidence.snapshots.first=[ordered]@{service=$first;identityHash=$identityHash;target=(Host-Snapshot $targetId);heartbeatAgeSeconds=$firstAge}
    $evidence.snapshots.auditIntegrityFirst = Read-AuditIntegrity 'first startup'
    $evidence.snapshots.auditHealthFirst = Read-AuditHealth 'first startup'
    $evidence.snapshots.historyFirst = Read-SessionHistory 'first startup'
    Stop-Service $serviceName
    Stop-Owned $script:javaProcess
    Query "UPDATE app.hosts SET ativo=0,visto_por_ultimo='2000-01-01 00:00:00' WHERE id_host=$targetId;" | Out-Null
    & sc.exe config $serviceName binPath= $image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to remove configured host ID for restart.' }
    Check 'restart command line omits RegisteredHostId' (-not (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").PathName.Contains('RegisteredHostId'))
    Start-Service $serviceName
    Start-Sleep -Seconds 4
    $second=Service-Info
    Check 'service restarts as LocalSystem in a new process while backend is offline'         ($second.account -eq 'LocalSystem' -and $second.state -eq 'Running' -and $second.startedUtc -ne $first.startedUtc)
    Check 'offline restart preserves identity and does not update database'         ((Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash -eq $identityHash -and
        (Query "SELECT ativo FROM app.hosts WHERE id_host=$targetId;") -eq '0' -and (Counts) -eq $countsBefore)
    $evidence.snapshots.auditIntegrityOffline = Read-AuditIntegrity 'offline restart'
    $evidence.snapshots.auditHealthOffline = Read-AuditHealth 'offline restart'
    $evidence.snapshots.historyOffline = Read-SessionHistory 'offline restart'
    Check 'audit monitoring starts a new observation period after service restart' (
        $evidence.snapshots.auditHealthFirst.sinceUtc -ne $evidence.snapshots.auditHealthOffline.sinceUtc)
    Start-Backend 'recovered'
    Wait-Heartbeat $targetId
    Check 'recovered host heartbeats without another registration' ((Counts) -eq $countsBefore)
    Check 'control host remains unchanged after recovery' ((Host-Snapshot $controlId) -eq $controlBefore)
    Check 'identity bytes remain unchanged after recovery' ((Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash -eq $identityHash)
    $secondAge=[int](Query "SELECT TIMESTAMPDIFF(SECOND,visto_por_ultimo,NOW()) FROM app.hosts WHERE id_host=$targetId;")
    Check 'heartbeat timestamps remain fresh against database clock' ($firstAge -ge -5 -and $firstAge -le 120 -and $secondAge -ge -5 -and $secondAge -le 120)
    $evidence.snapshots.recovered=[ordered]@{service=$second;target=(Host-Snapshot $targetId);control=(Host-Snapshot $controlId);counts=(Counts);identityHash=(Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash;heartbeatAgeSeconds=$secondAge}
    $evidence.status='passed'
    }
} catch {
    $evidence.status='failed'
    $evidence.error=$_.Exception.Message
    throw
} finally {
    if ($createdService) {
        Stop-Service $serviceName -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
        $evidence.cleanup.serviceDeleteExit=$LASTEXITCODE
    }
    if ($null -ne $mysqlProcess) {
        try {
            & $mysqlAdmin --no-defaults --protocol=TCP --host=127.0.0.1 --port=13316 --user=root --skip-password shutdown *> (Join-Path $runtime 'mysql-shutdown.private.log')
            $mysqlProcess.WaitForExit(10000) | Out-Null
        } catch { $evidence.cleanup.mysqlShutdownAttemptFailed=$true }
    }
    foreach ($process in @($script:javaProcess,$mysqlProcess)) {
        try { Stop-Owned $process } catch { $evidence.cleanup.processCleanupError=$true }
    }
    $evidence.cleanup.javaExited=($null -eq $script:javaProcess -or $script:javaProcess.HasExited)
    $evidence.cleanup.mysqlExited=($null -eq $mysqlProcess -or $mysqlProcess.HasExited)
    $evidence.cleanup.mysqlPortClosed=(-not (Get-NetTCPConnection -LocalPort 13316 -State Listen -ErrorAction SilentlyContinue))
    $evidence.cleanup.javaPortClosed=(-not (Get-NetTCPConnection -LocalPort 18080 -State Listen -ErrorAction SilentlyContinue))
    if (($createdService -and $evidence.cleanup.serviceDeleteExit -ne 0) -or
        $evidence.cleanup.processCleanupError -or -not $evidence.cleanup.javaExited -or -not $evidence.cleanup.mysqlExited -or
        -not $evidence.cleanup.mysqlPortClosed -or -not $evidence.cleanup.javaPortClosed) {
        $evidence.status='failed'
    }
    Get-ChildItem -LiteralPath $runtime -Filter '*.log' -File | ForEach-Object {
        $safeName=$_.Name.Replace('.private.log','.sanitized.log')
        Get-Content -LiteralPath $_.FullName | ForEach-Object { $_ -replace '(Using generated security password:).*','$1 [REDACTED]' } |
            Set-Content -LiteralPath (Join-Path $results $safeName) -Encoding utf8
    }
    @(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$started} -ErrorAction SilentlyContinue |
        Where-Object {$_.ProviderName -eq 'SafeUpload.Agent.Service'} |
        Select-Object TimeCreated,ProviderName,Message) | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $results 'service-events.json') -Encoding utf8
    $evidence | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $results 'result.json') -Encoding utf8
}
if ($evidence.status -ne 'passed') { throw 'Acceptance or cleanup failed; inspect result.json.' }
