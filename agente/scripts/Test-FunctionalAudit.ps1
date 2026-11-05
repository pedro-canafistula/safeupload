param(
    [Parameter(Mandatory=$true)][string]$MySqlBasePath,
    [string]$DotNetPath = 'dotnet',
    [string]$BackendJarPath,
    [string]$OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('safeupload-functional-' + [guid]::NewGuid().ToString('N')))
)
# PowerShell 7. Uses only new disposable MySQL data and owned Java/MySQL processes.
# Requires a built ContractSmoke and the unchanged backend JAR from this composition.
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$mysqlBase = [IO.Path]::GetFullPath($MySqlBasePath)
$mysql = Join-Path $mysqlBase 'bin/mysql.exe'
if (-not $BackendJarPath) { $BackendJarPath = Join-Path $repo 'web/back/target/backend-0.1.0.jar' }
$jar = [IO.Path]::GetFullPath($BackendJarPath)
$dll = Join-Path $repo 'agente/SafeUpload.Agent.ContractSmoke/bin/Release/net10.0-windows/SafeUpload.Agent.ContractSmoke.dll'
$runtime = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $runtime) { throw 'OutputDirectory must be new; existing queues and databases are never replaced.' }
foreach ($required in @($mysql,(Join-Path $mysqlBase 'bin/mysqld.exe'),$jar,$dll)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Missing prerequisite: $required" }
}
$dbArgs = @('--no-defaults','--protocol=TCP','--host=127.0.0.1','--port=13326','--user=root','--skip-password','--batch','--raw','--skip-column-names','--default-character-set=utf8mb4')
$database = $null
$backend = $null
$result = [ordered]@{ passed=$false; nativeDriveQualified=$false; installedServiceQualified=$false; wpfInteractiveQualified=$false }
function Wait-Ready([scriptblock]$condition) {
    for ($attempt=0; $attempt -lt 90; $attempt++) {
        if (& $condition) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'Readiness timed out.'
}
function Query([string]$sql) {
    $answer = & $mysql @dbArgs --execute $sql 2> (Join-Path $runtime 'mysql-client.log')
    if ($LASTEXITCODE -ne 0) { throw 'Isolated SQL failed.' }
    return ($answer -join "`n")
}
function Start-Backend([string]$phase) {
    $process = Start-Process java -WindowStyle Hidden -PassThru -ArgumentList @('-Duser.timezone=America/Sao_Paulo','-jar',$jar,'--server.port=18080','--server.address=127.0.0.1','--app.datasource.url=jdbc:mysql://127.0.0.1:13326/app?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false','--app.datasource.username=root','--app.datasource.password=','--acesso.datasource.url=jdbc:mysql://127.0.0.1:13326/acesso?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false','--acesso.datasource.username=root','--acesso.datasource.password=','--spring.jpa.show-sql=false') -RedirectStandardOutput (Join-Path $runtime "java-$phase.log") -RedirectStandardError (Join-Path $runtime "java-$phase-errors.log")
    return $process
}
function Run-Contract([string]$phase, [string[]]$arguments) {
    & $DotNetPath $dll @arguments *> (Join-Path $runtime "$phase.log")
    if ($LASTEXITCODE -ne 0) { throw "Contract failed: $phase. See $runtime/$phase.log" }
}
try {
    foreach ($port in @(13326,18080)) {
        $probe = [Net.Sockets.TcpClient]::new()
        try { if ($probe.ConnectAsync('127.0.0.1',$port).Wait(300) -and $probe.Connected) { throw "Port occupied: $port" } }
        catch [AggregateException] { }
        finally { $probe.Dispose() }
    }
    [void][IO.Directory]::CreateDirectory($runtime)
    $result.agentCommit = (& git -C $repo rev-parse HEAD)
    $result.backendSha256 = (Get-FileHash -LiteralPath $jar).Hash
    $result.contractSha256 = (Get-FileHash -LiteralPath $dll).Hash
    $data = Join-Path $runtime 'data'
    & (Join-Path $mysqlBase 'bin/mysqld.exe') --no-defaults --initialize-insecure "--basedir=$mysqlBase" "--datadir=$data" --console *> (Join-Path $runtime 'mysql-init.log')
    if ($LASTEXITCODE -ne 0) { throw 'MySQL initialization failed.' }
    $database = Start-Process (Join-Path $mysqlBase 'bin/mysqld.exe') -WindowStyle Hidden -PassThru -ArgumentList @('--no-defaults',"--basedir=$mysqlBase","--datadir=$data",'--port=13326','--bind-address=127.0.0.1','--mysqlx=OFF','--event-scheduler=OFF','--default-time-zone=-03:00','--console') -RedirectStandardOutput (Join-Path $runtime 'mysql.log') -RedirectStandardError (Join-Path $runtime 'mysql-errors.log')
    Wait-Ready { try { (Query 'SELECT 1;').Trim() -eq '1' } catch { $false } }
    foreach ($ddl in @('01_schema_acesso.sql','02_schema_app.sql','03_job_usuarios_inativos.sql','05_agent_audit_ingest.sql')) {
        Get-Content -LiteralPath (Join-Path $repo "db/initdb/$ddl") -Raw | & $mysql @dbArgs 2> (Join-Path $runtime 'ddl-errors.log')
        if ($LASTEXITCODE -ne 0) { throw "DDL failed: $ddl" }
    }
    $backend = Start-Backend 'online'
    Wait-Ready { try { Invoke-RestMethod 'http://127.0.0.1:18080/auth/decision' -TimeoutSec 1 | Out-Null; $true } catch { $false } }
    Run-Contract 'online' @('--current-api-functional')
    $rootLine = @(Get-Content (Join-Path $runtime 'online.log') | Where-Object { $_ -like 'FUNCTIONAL_AUDIT_ROOT=*' })
    if ($rootLine.Count -ne 1) { throw 'Missing functional workspace.' }
    $root = $rootLine[0].Substring('FUNCTIONAL_AUDIT_ROOT='.Length)
    $result.functionalWorkspace = $root
    $backend.Kill($true)
    if (-not $backend.WaitForExit(10000)) { throw 'Owned Java process did not stop.' }
    Run-Contract 'offline-new-process' @('--functional-audit','offline',$root)
    $result.offlineSqlCount = [int](Query "SELECT COUNT(*) FROM app.agent_audit_ingest WHERE kind='audit';")
    if ($result.offlineSqlCount -ne 12) { throw 'Offline events unexpectedly reached SQL or online events are missing.' }
    $backend = Start-Backend 'resume'
    Wait-Ready { try { Invoke-RestMethod 'http://127.0.0.1:18080/auth/decision' -TimeoutSec 1 | Out-Null; $true } catch { $false } }
    Run-Contract 'resume-new-process' @('--functional-audit','resume',$root)
    $result.mysqlVersion = Query 'SELECT VERSION();'
    $result.hosts = Query 'SELECT id_host,hostname,ip,ativo,visto_por_ultimo FROM app.hosts ORDER BY id_host;'
    $result.policies = Query 'SELECT id_politica,fk_id_host,acao,versao FROM app.politicas ORDER BY id_politica;'
    $result.auditCount = [int](Query "SELECT COUNT(*) FROM app.agent_audit_ingest WHERE kind='audit';")
    $result.distinctEventCount = [int](Query "SELECT COUNT(DISTINCT event_id) FROM app.agent_audit_ingest WHERE kind='audit';")
    $result.hostCount = [int](Query 'SELECT COUNT(*) FROM app.hosts;')
    $result.policyCount = [int](Query 'SELECT COUNT(*) FROM app.politicas;')
    $result.functionalSql = Query "SELECT event_id,endpoint_id,JSON_UNQUOTE(JSON_EXTRACT(payload,'$.fileName')),JSON_EXTRACT(payload,'$.policyVersion'),JSON_UNQUOTE(JSON_EXTRACT(payload,'$.verdict')) FROM app.agent_audit_ingest WHERE kind='audit' AND JSON_UNQUOTE(JSON_EXTRACT(payload,'$.fileName')) REGEXP '^(online|offline)-' ORDER BY occurred_at_utc,event_id;"
    if ($result.hostCount -ne 2 -or $result.policyCount -ne 5 -or $result.auditCount -ne 14 -or $result.distinctEventCount -ne 14) { throw 'Independent SQL count mismatch.' }
    $result.checks = @(Get-ChildItem -LiteralPath $runtime -Filter '*process.log'; Get-Item (Join-Path $runtime 'online.log')) | ForEach-Object { Get-Content -LiteralPath $_.FullName } | Where-Object { $_ -match '^(CURRENT_API|FUNCTIONAL_AUDIT)_PASS=' } | Measure-Object | Select-Object -ExpandProperty Count
    $result.passed = $true
}
catch { $result.error = $_.Exception.Message; throw }
finally {
    foreach ($owned in @($backend,$database)) {
        if ($null -ne $owned -and -not $owned.HasExited) { $owned.Kill($true); [void]$owned.WaitForExit(10000) }
    }
    $result.ownedProcessesStopped = ($null -eq $backend -or $backend.HasExited) -and ($null -eq $database -or $database.HasExited)
    if (Test-Path -LiteralPath $runtime) { $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $runtime 'result.json') -Encoding utf8 }
}
