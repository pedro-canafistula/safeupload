#Requires -Version 7.5
# Dot-sourced only by Test-HostIdentityBackend.ps1, after its disposable-runner,
# fresh-state, binary, port and isolated-database guards. Parent owns cleanup.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or -not $ConsolePolicyAcceptance -or $createdService) {
    throw 'Console policy service case requires the guarded fresh Windows harness.'
}
function Assert-ConsoleCacheAcl([string]$Path) {
    foreach ($item in @($Path, (Split-Path -Parent $Path))) {
        $acl = Get-Acl -LiteralPath $item
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $inheritance = if ($item -eq $Path) { [Security.AccessControl.InheritanceFlags]::None } else {
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        }
        Check 'console cache has SYSTEM owner and protected DACL' (
            $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-18' -and
            $acl.AreAccessRulesProtected -and $rules.Count -eq 2 -and
            @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-18' }).Count -eq 1 -and
            @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-32-544' }).Count -eq 1 -and
            @($rules | Where-Object {
                $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or $_.IsInherited -or
                $_.AccessControlType -ne 'Allow' -or
                $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                $_.InheritanceFlags -ne $inheritance -or
                $_.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None
            }).Count -eq 0)
    }
}
function Read-ConsoleAudit {
    $path = Join-Path $agentRoot 'queue.jsonl'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    $file = [IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader = [IO.StreamReader]::new($file)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            try { $item = $line | ConvertFrom-Json -DateKind String -ErrorAction Stop } catch { continue }
            if ($item.eventId -and -not $item.type) { $item }
        }
    } finally { $reader.Dispose() }
}
function Observe-ConsoleFile([string]$Phase, [int]$Revision, [string]$Verdict) {
    $name = "console-$Phase-$([guid]::NewGuid().ToString('N')).txt"
    $path = Join-Path (Join-Path $workRoot 'Escopo Monitorado') $name
    [IO.File]::WriteAllText($path, 'CPF sintetico: 529.982.247-25', [Text.UTF8Encoding]::new($false))
    $audit = Wait-Value {
        Read-ConsoleAudit | Where-Object fileName -eq $name | Select-Object -First 1
    } "service inspection of $Phase file" 30
    Check "${Phase}: production watcher uses the expected console rule and revision" (
        $audit.verdict -eq $Verdict -and [int]$audit.policyVersion -eq $Revision)
    $id = [guid]::Parse([string]$audit.eventId).ToString()
    if ($Verdict -eq 'Approved') { Check "${Phase}: approved file remains intact" ((Get-Content -LiteralPath $path -Raw) -eq 'CPF sintetico: 529.982.247-25') }
    else {
        Wait-Value { -not (Test-Path -LiteralPath $path) } 'post-write movement of the synthetic restricted file' 10 | Out-Null
        $moved = @(Get-ChildItem -LiteralPath (Join-Path $workRoot '_bloqueados') -File |
            Where-Object { $_.Name.StartsWith([IO.Path]::GetFileNameWithoutExtension($name) + '-', [StringComparison]::Ordinal) })
        Check 'recovered restricted file was moved intact by the watcher' ($moved.Count -eq 1 -and
            (Get-Content -LiteralPath $moved[0].FullName -Raw) -eq 'CPF sintetico: 529.982.247-25')
    }
    return [ordered]@{eventId=$id;revision=$Revision;verdict=$Verdict}
}
function Wait-ConsoleCache([int]$Revision, [int]$HostId, [string]$Ip) {
    $file = Join-Path $agentRoot 'console-policy-cache.json'
    Wait-Value {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $false }
        try { $cache = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json } catch { return $false }
        return $cache.format -eq 1 -and $cache.hostId -eq $HostId -and $cache.ip -eq $Ip -and
            $cache.server -eq "$api/agent/" -and $cache.policy.version -eq $Revision
    } 'protected console cache with the expected revision/context' 75 | Out-Null
    Assert-ConsoleCacheAcl $file
    return $file
}
function Wait-ConsoleServiceReady([int]$Revision) {
    Wait-Value {
        $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SafeUpload.Agent', [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
        $reader = $null
        $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(2))
        try {
            $pipe.ConnectAsync($deadline.Token).GetAwaiter().GetResult()
            $reader = [IO.StreamReader]::new($pipe)
            $status = $reader.ReadLineAsync($deadline.Token).AsTask().GetAwaiter().GetResult() | ConvertFrom-Json
            return $status.type -eq 'status' -and $status.policyVersion -eq $Revision -and
                $status.protectionActive -eq $true -and $status.auditOnly -eq $true
        } catch { return $false }
        finally { if ($null -ne $reader) { $reader.Dispose() }; $pipe.Dispose(); $deadline.Dispose() }
    } 'watcher and notification pipe ready under expected policy' 45 | Out-Null
}

# Provision the operational policy explicitly, as deployment requires. This is fresh fixture state,
# not a repair of an existing directory; the parent already refused any preexisting agent state.
New-Item -ItemType Directory -Path $agentRoot | Out-Null
$operationalFile = Join-Path $agentRoot 'policy.json'
$operational = @{
    version=1; activeCategories=@('Cpf'); failOpen=$true; auditOnly=$false; overrideAllowed=$false
    maxFileSizeMb=20; inspectionTimeoutSeconds=5; excludedProcesses=@('System','SafeUpload.Agent.App')
    monitoredScopes=@{extensions=@('.txt');destinationPaths=@((Join-Path $workRoot 'Escopo Monitorado'));removableDrives=$false;networkPaths=$false}
} | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($operationalFile, $operational, [Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot '../Protect-SafeUploadPolicy.ps1') -PolicyPath $operationalFile | Out-Null
Assert-ConsoleCacheAcl $operationalFile
Check 'central cache does not exist before the service starts' (-not (Test-Path -LiteralPath (Join-Path $agentRoot 'console-policy-cache.json')))
$operationalHash = (Get-FileHash -LiteralPath $operationalFile -Algorithm SHA256).Hash

$fixtureFile = Join-Path $results 'console-system-fixture.json'
& dotnet $contractDll --legacy-console-service-fixture setup $fixtureFile *> (Join-Path $results 'console-fixture-setup.log')
Check 'fresh console API fixture was prepared' ($LASTEXITCODE -eq 0)
$fixture = Get-Content -LiteralPath $fixtureFile -Raw | ConvertFrom-Json
$targetId = [int]$fixture.hostId
$controlId = [int]$fixture.controlId
$revision = [int]$fixture.revision
Query "UPDATE app.hosts SET ativo=0,visto_por_ultimo='2000-01-01 00:00:00' WHERE id_host IN ($targetId,$controlId);" | Out-Null
$countsBefore = Counts
$controlBefore = Host-Snapshot $controlId
$image = '"' + $serviceExe + '" --Interception:Mode=FileSystemWatcher --InspecaoTls:Habilitada=false' +
    " --CentroAdministracao:BaseUrl=$api/agent/ --CentroAdministracao:HeartbeatProtocol=AgentApi" +
    " --CentroAdministracao:PolicyProtocol=ConsoleByIp --CentroAdministracao:PolicyHostIp=$($fixture.hostIp)" +
    ' --CentroAdministracao:DispatchIntervalSeconds=2 --CentroAdministracao:TimeoutSeconds=2'
New-Service -Name $serviceName -BinaryPathName ($image + " --CentroAdministracao:RegisteredHostId=$targetId") -StartupType Manual | Out-Null
$createdService = $true
Start-Service $serviceName
Wait-Heartbeat $targetId
$first = Service-Info
Check 'console service runs as SYSTEM' ($first.account -eq 'LocalSystem' -and $first.state -eq 'Running')
$cacheFile = Wait-ConsoleCache $revision $targetId $fixture.hostIp
Wait-ConsoleServiceReady $revision
$cacheHash = (Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash
$identityHash = (Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash
$online = Observe-ConsoleFile 'online' $revision 'Approved'
Wait-Value { (Query "SELECT COUNT(*) FROM app.agent_audit_ingest WHERE event_id='$($online.eventId)' AND kind='audit';") -eq '1' } 'first service event persisted centrally' 30 | Out-Null
$evidence.snapshots.consoleOnline = [ordered]@{service=$first;cacheHash=$cacheHash;audit=$online}
Stop-Service $serviceName
Stop-Owned $script:javaProcess
$centralBeforeOffline = Query 'SELECT COUNT(*) FROM app.agent_audit_ingest;'
& sc.exe config $serviceName binPath= $image | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not remove bootstrap ID from the console service command.' }
Check 'console restart omits bootstrap host ID' (-not (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").PathName.Contains('RegisteredHostId'))
Start-Service $serviceName
$cacheFile = Wait-ConsoleCache $revision $targetId $fixture.hostIp
Wait-ConsoleServiceReady $revision
$offline = Observe-ConsoleFile 'offline' $revision 'Approved'
$second = Service-Info
Check 'offline console restart is a new SYSTEM process' ($second.account -eq 'LocalSystem' -and $second.state -eq 'Running' -and $second.startedUtc -ne $first.startedUtc)
Check 'offline console event remains pending' (@(Read-ConsoleAudit | Where-Object { $_.eventId -eq $offline.eventId -and $_.dispatched -eq $false }).Count -ge 1)
Check 'offline restart preserves cache, identity and central audit' ((Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash -eq $cacheHash -and
    (Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash -eq $identityHash -and (Query 'SELECT COUNT(*) FROM app.agent_audit_ingest;') -eq $centralBeforeOffline)
$evidence.snapshots.consoleOffline = [ordered]@{service=$second;cacheHash=$cacheHash;audit=$offline}
Start-Backend 'console-recovered'
& dotnet $contractDll --legacy-console-service-fixture recover $fixtureFile *> (Join-Path $results 'console-fixture-recover.log')
Check 'recovered console published CPF policy' ($LASTEXITCODE -eq 0)
$recovered = Get-Content -LiteralPath $fixtureFile -Raw | ConvertFrom-Json
Check 'recovery keeps target context and advances revision' ($recovered.hostId -eq $targetId -and $recovered.revision -gt $revision)
$cacheFile = Wait-ConsoleCache ([int]$recovered.revision) $targetId $fixture.hostIp
$blocked = Observe-ConsoleFile 'recovered' ([int]$recovered.revision) 'Blocked'
foreach ($observed in @($online,$offline,$blocked)) {
    Wait-Value { (Query "SELECT COUNT(*) FROM app.agent_audit_ingest WHERE event_id='$($observed.eventId)' AND kind='audit';") -eq '1' } 'service event persisted exactly once after recovery' 30 | Out-Null
    Wait-Value { @(Read-ConsoleAudit | Where-Object { $_.eventId -eq $observed.eventId -and $_.dispatched -eq $true }).Count -ge 1 } 'complete service receipt confirmed locally' 30 | Out-Null
}
Check 'console recovery preserves control host and registration counts' ((Host-Snapshot $controlId) -eq $controlBefore -and (Counts) -eq $countsBefore)
Check 'console recovery preserves identity and changes policy cache' ((Get-FileHash -LiteralPath $identityFile -Algorithm SHA256).Hash -eq $identityHash -and
    (Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash -ne $cacheHash)
$evidence.snapshots.consoleRecovered = [ordered]@{service=(Service-Info);revision=$recovered.revision;audit=$blocked;cacheHash=(Get-FileHash -LiteralPath $cacheFile -Algorithm SHA256).Hash}

Check 'central loading and recovery preserve the provisioned local policy' ((Get-FileHash -LiteralPath $operationalFile -Algorithm SHA256).Hash -eq $operationalHash)
$evidence.snapshots.consoleLimits = [ordered]@{
    installedConsolePolicy=$true; protectedCache=$true; offlineNewServiceProcess=$true
    interceptor='FileSystemWatcher'; preventiveBlockingQualified=$false; driveGateQualified=$false
    remoteStatusRefreshQualified=$false
}
