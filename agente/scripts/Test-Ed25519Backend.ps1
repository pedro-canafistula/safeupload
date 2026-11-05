param(
    [Parameter(Mandatory=$true)][string]$MySqlBasePath,
    [Parameter(Mandatory=$true)][string]$BackendReferencePath,
    [Parameter(Mandatory=$true)][string]$JavaPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$DotNetPath = 'dotnet',
    [int]$MySqlPort = 13357,
    [int]$ApiPort = 18095
)
# PowerShell 7. New loopback MySQL only; no DDL/source changes or installed service/VM access.
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$reference = [IO.Path]::GetFullPath($BackendReferencePath)
$runtime = [IO.Path]::GetFullPath($OutputDirectory)
$mysqlBase = [IO.Path]::GetFullPath($MySqlBasePath)
$mysql = Join-Path $mysqlBase 'bin/mysql.exe'
$mysqld = Join-Path $mysqlBase 'bin/mysqld.exe'
$jar = Join-Path $reference 'web/back/target/backend-0.1.0.jar'
$dll = Join-Path $repo 'agente/SafeUpload.Agent.ContractSmoke/bin/Release/net10.0-windows/SafeUpload.Agent.ContractSmoke.dll'
if (Test-Path -LiteralPath $runtime) { throw 'OutputDirectory deve ser novo; nenhuma fila ou banco existente será alterado.' }
foreach ($required in @($mysql,$mysqld,$jar,$dll,$JavaPath)) { if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'Pré-requisito ausente.' } }
foreach ($port in @($MySqlPort,$ApiPort)) {
    $probe = [Net.Sockets.TcpClient]::new()
    try { if ($probe.ConnectAsync('127.0.0.1',$port).Wait(300) -and $probe.Connected) { throw "Porta ocupada: $port" } }
    catch [AggregateException] { }
    finally { $probe.Dispose() }
}
[void][IO.Directory]::CreateDirectory($runtime)
$dbArgs = @('--no-defaults','--protocol=TCP','--host=127.0.0.1',"--port=$MySqlPort",'--user=root','--skip-password','--batch','--raw','--skip-column-names','--default-character-set=utf8mb4')
$database = $null
$backend = $null
$result = [ordered]@{ passed=$false; productionAclQualified=$false; installedServiceQualified=$false; nativeGateQualified=$false }
function Query([string]$sql) {
    $answer = & $mysql @dbArgs --execute $sql 2> (Join-Path $runtime 'mysql-client.log')
    if ($LASTEXITCODE -ne 0) { throw 'Consulta ao banco descartável falhou.' }
    return ($answer -join "`n")
}
function Wait-Ready([scriptblock]$condition) {
    for ($attempt=0;$attempt -lt 120;$attempt++) {
        if (& $condition) { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'Dependência descartável não ficou pronta no prazo.'
}
function Start-Backend([string]$phase) {
    return Start-Process $JavaPath -WindowStyle Hidden -PassThru -ArgumentList @('-Duser.timezone=America/Sao_Paulo','-jar',$jar,"--server.port=$ApiPort",'--server.address=127.0.0.1',"--app.datasource.url=jdbc:mysql://127.0.0.1:$MySqlPort/app?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false",'--app.datasource.username=root','--app.datasource.password=',"--acesso.datasource.url=jdbc:mysql://127.0.0.1:$MySqlPort/acesso?serverTimezone=America/Sao_Paulo&allowPublicKeyRetrieval=true&useSSL=false",'--acesso.datasource.username=root','--acesso.datasource.password=','--spring.jpa.show-sql=false','--logging.level.org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration=ERROR') -RedirectStandardOutput (Join-Path $runtime "java-$phase.log") -RedirectStandardError (Join-Path $runtime "java-$phase-errors.log")
}
function Run-Contract([string]$phase,[string]$workspace,[string]$inputToken = '') {
    $start = [Diagnostics.ProcessStartInfo]::new($DotNetPath)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($item in @($dll,'--ed25519-api',$(if ($phase -like 'reject-*') { 'reject' } else { $phase }),"http://127.0.0.1:$ApiPort/agent/",$workspace)) { [void]$start.ArgumentList.Add($item) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($inputToken) { $process.StandardInput.WriteLine($inputToken) }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(60000)) { $process.Kill($true); throw 'Processo C# do ensaio excedeu o prazo.' }
        $stdout.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $runtime "$phase.log") -Encoding utf8
        $stderr.GetAwaiter().GetResult() | Set-Content -LiteralPath (Join-Path $runtime "$phase-errors.log") -Encoding utf8
        if ($process.ExitCode -ne 0) { throw "Ensaio C# falhou na fase $phase; consultar seu log sanitizado." }
    } finally { if (-not $process.HasExited) { $process.Kill($true) }; $process.Dispose() }
}
try {
    $result.backendSha256 = (Get-FileHash -LiteralPath $jar).Hash
    $result.contractSha256 = (Get-FileHash -LiteralPath $dll).Hash
    $data = Join-Path $runtime 'data'
    & $mysqld --no-defaults --initialize-insecure "--basedir=$mysqlBase" "--datadir=$data" --console *> (Join-Path $runtime 'mysql-init.log')
    if ($LASTEXITCODE -ne 0) { throw 'Inicialização do MySQL novo falhou.' }
    $database = Start-Process $mysqld -WindowStyle Hidden -PassThru -ArgumentList @('--no-defaults',"--basedir=$mysqlBase","--datadir=$data","--port=$MySqlPort",'--bind-address=127.0.0.1','--mysqlx=OFF','--event-scheduler=ON','--default-time-zone=-03:00','--console') -RedirectStandardOutput (Join-Path $runtime 'mysql.log') -RedirectStandardError (Join-Path $runtime 'mysql-errors.log')
    Wait-Ready { try { (Query 'SELECT 1;').Trim() -eq '1' } catch { $false } }
    foreach ($ddl in @('01_schema_acesso.sql','02_schema_app.sql','03_jobs.sql','05_agent_audit_ingest.sql')) {
        Get-Content -LiteralPath (Join-Path $reference "db/initdb/$ddl") -Raw | & $mysql @dbArgs 2> (Join-Path $runtime 'ddl-errors.log')
        if ($LASTEXITCODE -ne 0) { throw "DDL original falhou: $ddl" }
    }
    # Synthetic data only. The unchanged original event must expire this token.
    Query "INSERT INTO app.tokens(token,criadoEm,ativo) VALUES ('EXPIR951',NOW()-INTERVAL 16 MINUTE,1);" | Out-Null
    $backend = Start-Backend 'online'
    Wait-Ready { try { Invoke-RestMethod "http://127.0.0.1:$ApiPort/auth/decision" -TimeoutSec 1 | Out-Null; $true } catch { $false } }
    $workspace = Join-Path $runtime 'agent'
    Run-Contract 'enroll' $workspace
    if ((Query 'SELECT COUNT(*) FROM app.hosts;').Trim() -ne '1') { throw 'Cadastro inicial duplicado.' }
    Run-Contract 'reject-invalid' (Join-Path $runtime 'invalid') 'INVALID0'
    Wait-Ready { (Query "SELECT ativo FROM app.tokens WHERE token='EXPIR951';").Trim() -eq '0' }
    $result.expiredByOriginalMySqlEvent = $true
    Run-Contract 'reject-expired' (Join-Path $runtime 'expired') 'EXPIR951'
    $backend.Kill($true)
    [void]$backend.WaitForExit(10000)
    Run-Contract 'offline' $workspace
    if ((Query "SELECT COUNT(*) FROM app.agent_audit_ingest WHERE kind='audit';").Trim() -ne '1') { throw 'Evento offline enviado indevidamente.' }
    $backend = Start-Backend 'resume'
    Wait-Ready { try { Invoke-RestMethod "http://127.0.0.1:$ApiPort/auth/decision" -TimeoutSec 1 | Out-Null; $true } catch { $false } }
    Run-Contract 'resume' $workspace
    $state = Get-Content (Join-Path $workspace 'state.json') -Raw | ConvertFrom-Json
    $result.hostId = $state.HostId
    $result.onlineEvent = $state.OnlineEvent
    $result.offlineEvent = $state.OfflineEvent
    $result.hostCount = [int](Query 'SELECT COUNT(*) FROM app.hosts;')
    $result.auditCount = [int](Query "SELECT COUNT(*) FROM app.agent_audit_ingest WHERE kind='audit';")
    $result.distinctEvents = [int](Query "SELECT COUNT(DISTINCT event_id) FROM app.agent_audit_ingest WHERE kind='audit';")
    if ($result.hostCount -ne 1 -or $result.auditCount -ne 2 -or $result.distinctEvents -ne 2) { throw 'Contagem SQL não confirma identidade/eventos sem duplicação.' }
    $result.hosts = Query 'SELECT id_host,hostname,ip,ativo,visto_por_ultimo,SHA2(chave_publica,256) FROM app.hosts;'
    $result.events = Query 'SELECT event_id,occurred_at_utc,JSON_EXTRACT(payload,"$.policyVersion"),JSON_EXTRACT(payload,"$.categories") FROM app.agent_audit_ingest ORDER BY occurred_at_utc;'
    $result.checks = @(Get-ChildItem -LiteralPath $runtime -Filter '*.log' | ForEach-Object { Get-Content -LiteralPath $_.FullName } | Where-Object { $_ -like 'AUTH_PASS=*' }).Count
    $result.passed = $true
} catch { $result.error = $_.Exception.Message; throw }
finally {
    foreach ($owned in @($backend,$database)) { if ($null -ne $owned -and -not $owned.HasExited) { $owned.Kill($true); [void]$owned.WaitForExit(10000) } }
    $result.ownedProcessesStopped = ($null -eq $backend -or $backend.HasExited) -and ($null -eq $database -or $database.HasExited)
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runtime 'result.json') -Encoding utf8
    $result | ConvertTo-Json -Depth 6
}
