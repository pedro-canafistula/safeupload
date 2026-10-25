#Requires -Version 7.5
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallerPath,
      [string]$ResultsDirectory = (Join-Path $PSScriptRoot '../../../artifacts/installer-smoke'))
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This test may install services only on a disposable GitHub-hosted Windows runner.'
}
$InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).Path
$ResultsDirectory = [IO.Path]::GetFullPath($ResultsDirectory)
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SafeUpload\Agent'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SafeUpload'
$workRoot = Join-Path ([IO.Path]::GetPathRoot([Environment]::GetFolderPath('Windows'))) 'SafeUpload'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$startupKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
if ((Test-Path -LiteralPath $serviceKey) -or (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload') -or
    (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $dataRoot) -or (Test-Path -LiteralPath $workRoot) -or
    (Get-ItemProperty $startupKey -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) {
    throw 'Existing SafeUpload state detected. No changes were made.'
}
New-Item -ItemType Directory -Path $ResultsDirectory -Force | Out-Null
$result = [ordered]@{status='running';steps=@()}
$startedAt = Get-Date
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Read-AuditEvents([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader = [IO.StreamReader]::new($stream)
    try {
        while ($null -ne ($line = $reader.ReadLine())) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $item = $line | ConvertFrom-Json -DateKind String -ErrorAction Stop }
            catch { continue } # A concurrent append may leave the last line incomplete.
            if ($item.eventId -and -not $item.type) { $item }
        }
    } finally { $reader.Dispose() }
}
function Read-AuditHealth([string]$Query = 'audit-health', [string]$OccurredBeforeUtc, [switch]$VerifyServiceIdentity) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SafeUpload.Agent.Diagnostics', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect(5000)
        if ($VerifyServiceIdentity) {
            [uint32]$diagnosticServerPid = 0
            Require ([SafeUploadInstallerPipeIdentity]::GetNamedPipeServerProcessId($pipe.SafePipeHandle, [ref]$diagnosticServerPid)) 'Cannot identify diagnostics server process.'
            $diagnosticService = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
            Require ($diagnosticServerPid -gt 0 -and $diagnosticService.ProcessId -eq $diagnosticServerPid -and
                $diagnosticService.State -eq 'Running' -and $diagnosticService.StartName -eq 'LocalSystem') 'Diagnostics peer is not the installed LocalSystem service.'
            $owner = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Process -Filter "ProcessId=$diagnosticServerPid") -MethodName GetOwnerSid
            Require ($owner.ReturnValue -eq 0 -and $owner.Sid -eq 'S-1-5-18') 'Diagnostics peer owner is not SYSTEM.'
            $script:classificationServerIdentity = [ordered]@{serverPid=$diagnosticServerPid;scmPid=$diagnosticService.ProcessId;
                serviceAccount=$diagnosticService.StartName;processOwnerSid=$owner.Sid}
        }
        $request = @{query=$Query}
        if ($OccurredBeforeUtc) { $request.occurredBeforeUtc = $OccurredBeforeUtc }
        $payload = [Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Compress) + "`n")
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()
        $reader = [IO.StreamReader]::new($pipe, [Text.Encoding]::UTF8, $false, 1024, $true)
        try {
            $read = $reader.ReadLineAsync()
            Require ($read.Wait(5000)) 'Audit health query timed out.'
            $reply = $read.Result | ConvertFrom-Json
            Require ($reply.ok -eq $true) 'Audit health query failed.'
            return $reply.data
        } finally { $reader.Dispose() }
    } finally { $pipe.Dispose() }
}
function Read-TestCandidatePermissions([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [ordered]@{sid=$_.IdentityReference.Value;rights=[int]$_.FileSystemRights;type=[int]$_.AccessControlType;
            inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags} | ConvertTo-Json -Compress
    })
    [ordered]@{owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
        group=$acl.GetGroup([Security.Principal.SecurityIdentifier]).Value;protected=$acl.AreAccessRulesProtected;
        canonical=$acl.AreAccessRulesCanonical;rules=$rules} | ConvertTo-Json -Depth 5 -Compress
}
function Run-Installer([string]$Label, [string[]]$Additional) {
    $process = Start-Process $InstallerPath -WindowStyle Hidden -PassThru -Wait -ArgumentList (@(
        '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/LOG="' + (Join-Path $ResultsDirectory "$Label.log") + '"')) + $Additional)
    return $process.ExitCode
}
try {
    if (-not ('SafeUploadInstallerPipeIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadInstallerPipeIdentity {
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
'@
    }
    Require ((Run-Installer 'rejected-http' @('/MODE=FileSystemWatcher', '/ADMINURL=http://remote.example.test/agent/')) -ne 0) 'Remote HTTP must be rejected.'
    Require (-not (Test-Path -LiteralPath $serviceKey)) 'Rejected setup registered a service.'
    Require ((Run-Installer 'rejected-driver' @('/MODE=Minifilter')) -ne 0) 'Missing minifilter must be rejected.'
    Require (-not (Test-Path -LiteralPath $serviceKey)) 'Driver preflight failure registered a service.'
    $result.steps += 'unsafe URL and missing driver rejected before service creation'
    Require ((Run-Installer 'install' @('/MODE=FileSystemWatcher')) -eq 0) 'Initial installation failed.'
    $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Require ($service.StartName -eq 'LocalSystem' -and $service.State -eq 'Running') 'Expected running LocalSystem service.'
    Require ($service.PathName.StartsWith(('"' + (Join-Path $installRoot 'service\SafeUpload.Agent.Service.exe') + '" '))) 'Unquoted or unexpected service path.'
    Require ($service.PathName.Contains('--Interception:Mode=FileSystemWatcher') -and
        $service.PathName.Contains('--CentroAdministracao:BaseUrl= --InspecaoTls:Habilitada=false')) 'Unexpected service configuration.'
    Require ((Get-ItemProperty -LiteralPath $serviceKey).ServiceSidType -eq 1) 'Expected unrestricted service SID.'
    Require (Test-Path -LiteralPath (Join-Path $installRoot 'service\coreclr.dll')) 'Self-contained service runtime missing.'
    Require (Test-Path -LiteralPath (Join-Path $installRoot 'ui\coreclr.dll')) 'Self-contained UI runtime missing.'
    $run = Get-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole
    Require ($run.SafeUploadAgentConsole -eq ('"' + (Join-Path $installRoot 'ui\SafeUpload.Agent.App.exe') + '"')) 'Unexpected UI startup entry.'
    $state = Get-Content -LiteralPath (Join-Path $installRoot 'setup\installation.json') -Raw | ConvertFrom-Json
    Require ($state.mode -eq 'FileSystemWatcher' -and -not $state.restartRequired) 'Wrong recorded installation mode.'
    $policy = Join-Path $dataRoot 'policy.json'
    for ($attempt=0; $attempt -lt 30 -and -not (Test-Path -LiteralPath $policy); $attempt++) { Start-Sleep -Seconds 1 }
    Require (Test-Path -LiteralPath $policy) 'The service did not create its protected local policy.'
    $policyHash=(Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash
    $communication = Read-AuditHealth 'communication-health' -VerifyServiceIdentity
    Require (-not $communication.configured -and $communication.operations.Count -eq 3 -and
        @($communication.operations | Where-Object { $_.state -ne 'not_configured' -or $_.attempts -ne 0 }).Count -eq 0 -and
        -not $communication.protectionQualified -and -not $communication.apiPersistenceQualified -and
        -not $communication.policyAppliedToDriverQualified) 'Unconfigured communication diagnostics claimed remote success or protection.'
    $result.communicationHealth = [ordered]@{before=$communication;identityBefore=$script:classificationServerIdentity}
    $result.steps += 'self-contained service and UI installed; SCM identity, arguments, SID and startup verified'
    $monitored = Join-Path $workRoot 'Escopo Monitorado'
    for ($attempt=0; $attempt -lt 30 -and -not (Test-Path -LiteralPath $monitored); $attempt++) { Start-Sleep -Seconds 1 }
    Require (Test-Path -LiteralPath $monitored) 'The installed watcher did not initialize its scope.'
    $fileName = 'installer-synthetic-' + [Guid]::NewGuid().ToString('N') + '.txt'
    $fixture = Join-Path $monitored $fileName
    $queue = Join-Path $dataRoot 'queue.jsonl'
    # Public test fixture already used by the scanner suite; never a user document.
    [IO.File]::WriteAllText($fixture, 'Synthetic CPF: 529.982.247-25', [Text.UTF8Encoding]::new($false))
    $audit = $null
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        $audit = @(Read-AuditEvents $queue | Where-Object fileName -eq $fileName | Where-Object verdict -eq 'Blocked') | Select-Object -First 1
        if ($audit) { break }
        Start-Sleep -Milliseconds 500
    }
    Require ($null -ne $audit) 'The installed service did not audit the synthetic CPF fixture as blocked.'
    Require ($audit.endpointId -eq $env:COMPUTERNAME -and $audit.policyVersion -eq 1 -and
        $audit.channel -eq 'File' -and -not $audit.dispatched) 'Unexpected installed-service audit metadata.'
    Require (-not [string]::IsNullOrWhiteSpace($audit.userName)) 'Audit identity is absent.'
    Require ([Guid]::Parse($audit.eventId) -ne [Guid]::Empty) 'Audit ID is absent.'
    Require ([DateTimeOffset]::Parse($audit.occurredAtUtc) -ge $startedAt.ToUniversalTime()) 'Audit timestamp predates this test.'
    $result.audit = [ordered]@{eventId=$audit.eventId;fileName=$fileName;occurredAtUtc=$audit.occurredAtUtc;
        endpointId=$audit.endpointId;userName=$audit.userName;policyVersion=$audit.policyVersion;verdict=$audit.verdict}
    $result.steps += 'installed LocalSystem service classified a synthetic file and persisted a pending audit event'
    $initialHealth = Read-AuditHealth
    Require (-not $initialHealth.degraded -and $initialHealth.failedWriteAttempts -eq 0) 'Unexpected initial audit health.'
    $failureName = 'audit-health-failure-' + [Guid]::NewGuid().ToString('N') + '.txt'
    $queueLock = [IO.FileStream]::new($queue, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        [IO.File]::WriteAllText((Join-Path $monitored $failureName), 'Synthetic CPF: 529.982.247-25', [Text.UTF8Encoding]::new($false))
        $degradedHealth = $null
        for ($attempt=0; $attempt -lt 40; $attempt++) {
            $degradedHealth = Read-AuditHealth
            if (@($degradedHealth.operations | Where-Object { $_.operation -eq 'WriteEvent' -and $_.degraded }).Count -eq 1) { break }
            Start-Sleep -Milliseconds 250
        }
        Require ($degradedHealth.degraded -and $degradedHealth.failedWriteAttempts -ge 1) 'Installed service did not expose write degradation.'
    } finally { $queueLock.Dispose() }
    $recoveryName = 'audit-health-recovery-' + [Guid]::NewGuid().ToString('N') + '.txt'
    [IO.File]::WriteAllText((Join-Path $monitored $recoveryName), 'Synthetic clean text for recovery.', [Text.UTF8Encoding]::new($false))
    $resumedHealth = $null
    for ($attempt=0; $attempt -lt 40; $attempt++) {
        $resumedHealth = Read-AuditHealth
        if (-not $resumedHealth.degraded) { break }
        Start-Sleep -Milliseconds 250
    }
    Require (-not $resumedHealth.degraded -and $resumedHealth.failedWriteAttempts -ge $degradedHealth.failedWriteAttempts) 'Installed service did not retain failure counters after recovery.'
    $recoveryAudit = @(Read-AuditEvents $queue | Where-Object fileName -eq $recoveryName)
    Require ($recoveryAudit.Count -ge 1) 'Recovery write was not persisted.'
    $healthLogs = @(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$startedAt;Id=3101,3102} -ErrorAction SilentlyContinue |
        Where-Object ProviderName -eq 'SafeUpload.Agent.Service')
    Require (@($healthLogs | Where-Object Id -eq 3101).Count -ge 1) 'Audit failure was not visible in the Windows Application log.'
    Require (@($healthLogs | Where-Object Id -eq 3102).Count -ge 1) 'Audit resumption was not visible in the Windows Application log.'
    foreach ($entry in $healthLogs) {
        Require (-not $entry.Message.Contains($dataRoot) -and -not $entry.Message.Contains($failureName) -and
            -not $entry.Message.Contains('529.982.247-25')) 'Audit health log disclosed sensitive details.'
    }
    $result.auditHealth = [ordered]@{initial=$initialHealth;degraded=$degradedHealth;resumed=$resumedHealth;
        logEvents=@($healthLogs | Select-Object Id,Message)}
    $result.steps += 'audit-health diagnosed a real write refusal without driver, resumed with counters retained and emitted sanitized Windows logs'
    $cleanIntegrity = Read-AuditHealth 'audit-integrity'
    Require ($cleanIntegrity.fileExists -and -not $cleanIntegrity.requiresAttention -and
        $cleanIntegrity.validEvents -ge 2) 'Installed service failed the clean integrity scan.'
    Require ($cleanIntegrity.queueBytes -eq (Get-Item -LiteralPath $queue).Length -and
        $cleanIntegrity.pendingEvents -eq $cleanIntegrity.validEvents -and $cleanIntegrity.dispatchedEvents -eq 0 -and
        $cleanIntegrity.pendingOverrides -eq 0 -and $cleanIntegrity.dispatchedOverrides -eq 0 -and
        $null -ne $cleanIntegrity.oldestPendingUtc -and $cleanIntegrity.pendingWithoutTimestamp -eq 0) 'Installed service did not expose the synthetic offline backlog.'
    $previewCutoff = '2030-01-01T00:00:00Z'
    $cleanPreviewHash = (Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash
    $cleanPreview = & (Join-Path $PSScriptRoot '../../scripts/Get-SafeUploadDiagnostics.ps1') -Query audit-retention-preview -OccurredBeforeUtc $previewCutoff
    Require ($cleanPreview.previewOnly -and -not $cleanPreview.deletionSupported -and
        $cleanPreview.timestampBasis -eq 'record-occurrence-time' -and
        $cleanPreview.confirmedEventsBeforeCutoff -eq 0 -and $cleanPreview.confirmedOverridesBeforeCutoff -eq 0 -and
        $cleanPreview.confirmedWithoutTimestamp -eq 0 -and
        $cleanPreview.integrity.pendingEvents -eq $cleanIntegrity.pendingEvents) 'Installed preview classified offline pending data as confirmed.'
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $cleanPreviewHash) 'Preview modified the queue.'
    # Only synthetic runner data: preserve both malformed and forward-version records.
    [IO.File]::AppendAllText($queue, '{SYNTHETIC_PRIVATE_CONTENT' + "`n" +
        '{"type":"future-runner-record","payload":"SYNTHETIC_PRIVATE_CONTENT"}' + "`n", [Text.UTF8Encoding]::new($false))
    $integrityHash = (Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash
    $damagedIntegrity = Read-AuditHealth 'audit-integrity'
    Require ($damagedIntegrity.requiresAttention -and $damagedIntegrity.invalidLines -eq 1 -and
        $damagedIntegrity.unknownRecords -eq 1 -and $damagedIntegrity.validEvents -eq $cleanIntegrity.validEvents -and
        @($damagedIntegrity.issues).Count -eq 2) 'Installed integrity scan missed malformed or unknown records.'
    $integrityJson = $damagedIntegrity | ConvertTo-Json -Depth 8
    Require (-not $integrityJson.Contains('SYNTHETIC_PRIVATE_CONTENT') -and
        -not $integrityJson.Contains($dataRoot)) 'Integrity diagnostics disclosed queue contents or path.'
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $integrityHash) 'Integrity scan modified queue bytes.'
    Require ($damagedIntegrity.queueBytes -eq (Get-Item -LiteralPath $queue).Length -and
        $damagedIntegrity.queueBytes -gt $cleanIntegrity.queueBytes -and
        $damagedIntegrity.pendingEvents -eq $cleanIntegrity.pendingEvents -and
        $damagedIntegrity.oldestPendingUtc -eq $cleanIntegrity.oldestPendingUtc) 'Unknown or malformed lines distorted the pending inventory.'
    $result.auditIntegrity = [ordered]@{clean=$cleanIntegrity;damaged=$damagedIntegrity;queueHash=$integrityHash}
    $damagedPreview = Read-AuditHealth 'audit-retention-preview' $previewCutoff
    Require ($damagedPreview.integrity.invalidLines -eq 1 -and $damagedPreview.integrity.unknownRecords -eq 1 -and
        $damagedPreview.confirmedEventsBeforeCutoff -eq 0 -and $damagedPreview.integrity.pendingEvents -eq $cleanIntegrity.pendingEvents -and
        $damagedPreview.previewOnly -and -not $damagedPreview.deletionSupported) 'Preview hid incompatible lines or implied removal.'
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $integrityHash) 'Damaged preview modified the queue.'
    $result.auditRetentionPreview = [ordered]@{clean=$cleanPreview;damaged=$damagedPreview;queueHash=$integrityHash}
    $result.steps += 'audit-integrity distinguished malformed and unknown lines without changing queue bytes or disclosing contents'
    $emptyTemporaries = Read-AuditHealth 'audit-temporaries'
    Require ($emptyTemporaries.complete -and $emptyTemporaries.candidateFiles -eq 0) 'Unexpected initial temporary candidates.'
    $temporary = $queue + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, 'SYNTHETIC_PRIVATE_CONTENT', [Text.UTF8Encoding]::new($false))
    $temporaryHash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
    $temporaryBytes = (Get-Item -LiteralPath $temporary).Length
    # A junction with a matching name must be counted as skipped, never traversed.
    $linkTarget = Join-Path $dataRoot ('runner-link-target-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $linkTarget | Out-Null
    $temporaryLink = $queue + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    New-Item -ItemType Junction -Path $temporaryLink -Target $linkTarget | Out-Null
    $temporaries = Read-AuditHealth 'audit-temporaries'
    Require ($temporaries.requiresAttention -and -not $temporaries.complete -and
        $temporaries.candidateFiles -eq 1 -and $temporaries.totalBytes -eq $temporaryBytes -and
        $temporaries.skippedReparsePoints -eq 1 -and $temporaries.unreadableCandidates -eq 0 -and
        -not $temporaries.scanLimitReached) 'Installed temporary inventory failed or traversed a junction.'
    $temporaryJson = $temporaries | ConvertTo-Json -Depth 5
    Require (-not $temporaryJson.Contains('SYNTHETIC_PRIVATE_CONTENT') -and
        -not $temporaryJson.Contains($dataRoot) -and -not $temporaryJson.Contains([IO.Path]::GetFileName($temporary))) 'Temporary inventory disclosed private details.'
    Require ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -eq $temporaryHash -and
        (Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $integrityHash) 'Temporary inventory changed file bytes.'
    $result.auditTemporaries = [ordered]@{initial=$emptyTemporaries;inventory=$temporaries;temporaryHash=$temporaryHash;temporaryBytes=$temporaryBytes}
    $result.steps += 'audit-temporaries counted metadata without reading contents, skipped a junction and preserved queue and candidate bytes'
    # New cases share this existing disposable installation/restart/removal cycle.
    $classificationBaseline = @(Read-AuditEvents $queue | Sort-Object eventId | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 12 })
    $completeRecord = $audit | ConvertTo-Json -Depth 12 | ConvertFrom-Json -DateKind String
    $completeRecord.dispatched = $true # Conflicting copy must not supersede published pending event.
    $completeLine = ($completeRecord | ConvertTo-Json -Compress -Depth 12) + [Environment]::NewLine
    $classificationPaths = @{}
    foreach ($kind in @('complete','suspicious','busy','denied')) {
        $candidatePath = $queue + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
        $content = if ($kind -eq 'suspicious') { '{"type":"future","content":"SYNTHETIC_PRIVATE_CONTENT"}' + [Environment]::NewLine } else { $completeLine }
        [IO.File]::WriteAllText($candidatePath, $content, [Text.UTF8Encoding]::new($false))
        $classificationPaths[$kind] = $candidatePath
    }
    $classificationHashes = @{}
    foreach ($path in $classificationPaths.Values) { $classificationHashes[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    $deniedPath = $classificationPaths.denied
    $originalDacl = (Get-Acl -LiteralPath $deniedPath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $originalPermissions = Read-TestCandidatePermissions $deniedPath
    $deniedAcl = [Security.AccessControl.FileSecurity]::new()
    $deniedAcl.SetSecurityDescriptorSddlForm($originalDacl, [Security.AccessControl.AccessControlSections]::Access)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $deniedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($systemSid,
        [Security.AccessControl.FileSystemRights]::ReadData, [Security.AccessControl.AccessControlType]::Deny))
    $result.temporaryClassification = [ordered]@{queueSha256=$integrityHash;originalDacl=$originalDacl;
        originalPermissions=$originalPermissions;deniedSid='S-1-5-18';daclRestored=$false}
    $busyHandle = $null
    try {
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($deniedPath), $deniedAcl)
        $deniedDacl = (Get-Acl -LiteralPath $deniedPath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        $busyHandle = [IO.FileStream]::new($classificationPaths.busy, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $restrictedClassification = Read-AuditHealth 'audit-temporary-classification' -VerifyServiceIdentity
        $restrictedPeer = $script:classificationServerIdentity
        $result.temporaryClassification.restricted = $restrictedClassification
        $result.temporaryClassification.restrictedPeer = $restrictedPeer
        $result.temporaryClassification.deniedDacl = $deniedDacl
        Require ($restrictedClassification.candidateEntries -eq 6 -and $restrictedClassification.inUseCandidates -eq 1 -and
            $restrictedClassification.unavailableCandidates -eq 1 -and $restrictedClassification.structurallyCompleteCandidates -eq 1 -and
            $restrictedClassification.suspiciousCandidates -eq 1 -and $restrictedClassification.unterminatedCandidates -eq 1 -and
            $restrictedClassification.unsafeCandidates -eq 1 -and -not $restrictedClassification.complete) 'SYSTEM classification did not distinguish denial, sharing or unsafe candidates.'
        Require ((Get-Acl -LiteralPath $deniedPath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -eq $deniedDacl) 'Query changed candidate DACL.'
    } finally {
        if ($busyHandle) { $busyHandle.Dispose() }
        $restoreAcl = [Security.AccessControl.FileSecurity]::new()
        $restoreAcl.SetSecurityDescriptorSddlForm($originalDacl, [Security.AccessControl.AccessControlSections]::Access)
        [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($deniedPath), $restoreAcl)
    }
    $restoredDacl = (Get-Acl -LiteralPath $deniedPath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $restoredPermissions = Read-TestCandidatePermissions $deniedPath
    Require ($restoredPermissions -ceq $originalPermissions) 'Test did not restore original candidate permissions.'
    $result.temporaryClassification.daclRestored = $true
    $result.temporaryClassification.restoredDacl = $restoredDacl
    $restoredClassification = Read-AuditHealth 'audit-temporary-classification' -VerifyServiceIdentity
    $result.temporaryClassification.restored = $restoredClassification
    $result.temporaryClassification.restoredPeer = $script:classificationServerIdentity
    Require ($restoredClassification.candidateEntries -eq 6 -and $restoredClassification.structurallyCompleteCandidates -eq 3 -and
        $restoredClassification.inUseCandidates -eq 0 -and $restoredClassification.unavailableCandidates -eq 0 -and
        $restoredClassification.unsafeCandidates -eq 1 -and $restoredClassification.suspiciousCandidates -eq 1 -and
        $restoredClassification.unterminatedCandidates -eq 1 -and $restoredClassification.requiresAttention -and -not $restoredClassification.complete) 'Classification did not recover after access restoration.'
    foreach ($scan in @($restrictedClassification,$restoredClassification)) {
        foreach ($flag in @('ownershipVerified','recoveryEligible','promotionSupported','deletionSupported')) {
            Require (($scan.$flag -is [bool]) -and $scan.$flag -eq $false) 'Classification implied ownership or recovery capability.'
        }
        $scanJson = $scan | ConvertTo-Json -Depth 6
        Require (-not $scanJson.Contains($dataRoot) -and -not $scanJson.Contains($audit.eventId) -and
            -not $scanJson.Contains('SYNTHETIC_PRIVATE_CONTENT')) 'Classification disclosed private details.'
        foreach ($path in $classificationPaths.Values) { Require (-not $scanJson.Contains([IO.Path]::GetFileName($path))) 'Classification disclosed candidate filename.' }
    }
    foreach ($path in $classificationPaths.Values) { Require ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $classificationHashes[$path]) 'Classification changed candidate bytes.' }
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $integrityHash) 'Classification changed published queue bytes.'
    Require ((@(Read-AuditEvents $queue | Sort-Object eventId | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 12 }) -join "`n") -ceq
        ($classificationBaseline -join "`n")) 'Classification changed published event IDs or metadata.'
    $fixtureInventory = Read-AuditHealth 'audit-temporaries'
    $result.temporaryClassification = [ordered]@{restricted=$restrictedClassification;restored=$restoredClassification;
        restrictedPeer=$restrictedPeer;restoredPeer=$script:classificationServerIdentity;
        deniedSid='S-1-5-18';originalDacl=$originalDacl;deniedDacl=$deniedDacl;daclRestored=$true;
        restoredDacl=$restoredDacl;originalPermissions=$originalPermissions;restoredPermissions=$restoredPermissions;
        queueSha256=$integrityHash;candidateHashes=@($classificationPaths.Values | ForEach-Object {
            [ordered]@{name=[IO.Path]::GetFileName($_);sha256=$classificationHashes[$_]}})}
    $result.steps += 'SYSTEM pipe identity verified; classification separated sharing/ACL denial, recovered after restoration and preserved bytes, IDs, metadata and DACL'
    Restart-Service -Name SafeUploadAgent -ErrorAction Stop
    Start-Sleep -Seconds 3
    Require ((Get-Service SafeUploadAgent).Status -eq 'Running') 'The installed service did not survive restart.'
    $communicationAfterRestart = Read-AuditHealth 'communication-health' -VerifyServiceIdentity
    Require (-not $communicationAfterRestart.configured -and $communicationAfterRestart.operations.Count -eq 3 -and
        @($communicationAfterRestart.operations | Where-Object { $_.state -ne 'not_configured' -or $_.attempts -ne 0 }).Count -eq 0 -and
        $communicationAfterRestart.sinceUtc -ne $communication.sinceUtc) 'Communication diagnostics did not restart cleanly.'
    $result.communicationHealth.afterRestart=$communicationAfterRestart
    $result.communicationHealth.identityAfterRestart=$script:classificationServerIdentity
    $result.steps += 'communication-health read from installed SYSTEM service without driver or API; unconfigured state and reset after restart verified'
    $integrityAfterRestart = Read-AuditHealth 'audit-integrity'
    Require ($integrityAfterRestart.invalidLines -eq 1 -and $integrityAfterRestart.unknownRecords -eq 1) 'Restart lost integrity diagnostics.'
    Require ($integrityAfterRestart.queueBytes -eq $damagedIntegrity.queueBytes -and
        $integrityAfterRestart.pendingEvents -eq $damagedIntegrity.pendingEvents -and
        $integrityAfterRestart.oldestPendingUtc -eq $damagedIntegrity.oldestPendingUtc) 'Restart changed the read-only backlog inventory.'
    $result.auditIntegrity.afterRestart = $integrityAfterRestart
    $previewAfterRestart = Read-AuditHealth 'audit-retention-preview' $previewCutoff
    Require ($previewAfterRestart.integrity.queueBytes -eq $damagedPreview.integrity.queueBytes -and
        $previewAfterRestart.integrity.pendingEvents -eq $damagedPreview.integrity.pendingEvents -and
        $previewAfterRestart.confirmedEventsBeforeCutoff -eq 0 -and -not $previewAfterRestart.deletionSupported) 'Restart changed the read-only preview.'
    $result.auditRetentionPreview.afterRestart = $previewAfterRestart
    $temporariesAfterRestart = Read-AuditHealth 'audit-temporaries'
    Require ($temporariesAfterRestart.candidateFiles -eq $fixtureInventory.candidateFiles -and $temporariesAfterRestart.totalBytes -eq $fixtureInventory.totalBytes -and
        $temporariesAfterRestart.skippedReparsePoints -eq 1) 'Restart lost temporary inventory.'
    $result.auditTemporaries.afterRestart = $temporariesAfterRestart
    $classificationAfterRestart = Read-AuditHealth 'audit-temporary-classification' -VerifyServiceIdentity
    foreach ($field in @('candidateEntries','structurallyCompleteCandidates','inUseCandidates','unavailableCandidates',
        'unsafeCandidates','suspiciousCandidates','unterminatedCandidates','indeterminateCandidates','bytesRead',
        'scanLimitReached','directoryTraversalBlocked','complete','requiresAttention',
        'ownershipVerified','recoveryEligible','promotionSupported','deletionSupported')) {
        Require ($classificationAfterRestart.$field -ceq $restoredClassification.$field) 'Restart changed candidate classification.'
    }
    foreach ($path in $classificationPaths.Values) { Require ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $classificationHashes[$path]) 'Restart changed candidate bytes.' }
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $integrityHash) 'Restart changed published queue bytes.'
    Require ((@(Read-AuditEvents $queue | Sort-Object eventId | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 12 }) -join "`n") -ceq
        ($classificationBaseline -join "`n")) 'Restart changed published IDs or metadata.'
    $result.temporaryClassification.afterRestart = $classificationAfterRestart
    $result.temporaryClassification.peerAfterRestart = $script:classificationServerIdentity
    $retained = @(Read-AuditEvents $queue | Where-Object eventId -eq $audit.eventId)
    Require ($retained.Count -eq 1 -and $retained[0].occurredAtUtc -eq $audit.occurredAtUtc -and
        -not $retained[0].dispatched) 'Restart lost, changed or duplicated the pending event.'
    Require ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $policyHash) 'Restart changed the local policy.'
    $result.steps += 'service restart preserved the pending event ID, timestamp and policy'
    Require ((Run-Installer 'rejected-upgrade' @('/MODE=FileSystemWatcher')) -ne 0) 'Initial installer unexpectedly overwrote an existing service.'
    $after = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Require ($after.State -eq 'Running' -and $after.PathName -eq $service.PathName) 'Refused upgrade changed the service.'
    Require ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $policyHash) 'Refused upgrade changed the policy.'
    $result.steps += 'existing installation refused without changing service or policy'
    $sentinel = Join-Path $dataRoot 'installer-preservation-test.txt'
    [IO.File]::WriteAllText($sentinel, 'synthetic data to preserve')
    $queueHash = (Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash
    $uiExecutable = Join-Path $installRoot 'ui\SafeUpload.Agent.App.exe'
    $installedUi = Start-Process $uiExecutable -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 3
    Require (-not $installedUi.HasExited -and $installedUi.MainModule.FileName -eq $uiExecutable) 'Installed UI did not stay running before removal.'
    $result.uninstallUi = [ordered]@{processId=$installedUi.Id;runningBefore=$true;exitedAfter=$false}
    $uninstaller = Join-Path $installRoot 'unins000.exe'
    $process = Start-Process $uninstaller -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
        '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="' + (Join-Path $ResultsDirectory 'uninstall.log') + '"'))
    Require ($process.ExitCode -eq 0) 'Uninstall failed.'
    Require ($installedUi.WaitForExit(10000)) 'Uninstall left the installed UI running.'
    $result.uninstallUi.exitedAfter = $true
    Require (-not (Test-Path -LiteralPath $uiExecutable) -and
        -not (Test-Path -LiteralPath (Join-Path $installRoot 'service\SafeUpload.Agent.Service.exe'))) 'Installed executables remain after removal.'
    $installedUi.Dispose()
    Require (-not (Test-Path -LiteralPath $serviceKey)) 'Agent service remains registered.'
    Require (-not (Get-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'UI startup entry remains.'
    Require ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $policyHash) 'Uninstall changed the policy.'
    Require ([IO.File]::ReadAllText($sentinel) -eq 'synthetic data to preserve') 'Uninstall removed retained endpoint data.'
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $queueHash) 'Uninstall removed or changed the audit queue.'
    Require ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -eq $temporaryHash) 'Uninstall removed or changed a temporary candidate.'
    foreach ($path in $classificationPaths.Values) { Require ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $classificationHashes[$path]) 'Uninstall removed or changed classification candidate.' }
    Require ((Read-TestCandidatePermissions $deniedPath) -ceq $originalPermissions) 'Uninstall changed candidate permissions.'
    Require ((Get-Acl -LiteralPath $deniedPath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -ceq $restoredDacl) 'Uninstall changed restored candidate DACL.'
    $result.temporaryClassification.preservedAfterUninstall = $true
    Require ((Get-Item -LiteralPath $temporaryLink).Attributes -band [IO.FileAttributes]::ReparsePoint) 'Uninstall removed a preserved junction.'
    $result.steps += 'service and startup removed; endpoint policy and data preserved'
    $result.status='passed'
} catch {
    $result.status='failed'; $result.error=$_.Exception.Message
    throw
} finally {
    if ($result.status -eq 'failed') {
        Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction SilentlyContinue |
            Select-Object Name,State,StartName,PathName | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'service-failure.json') -Encoding utf8NoBOM
        Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$startedAt;Level=2} -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -in @('SafeUpload.Agent.Service','.NET Runtime','Application Error') } |
            Select-Object -First 20 TimeCreated,ProviderName,Id,Message | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $ResultsDirectory 'application-errors.json') -Encoding utf8NoBOM
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ResultsDirectory 'result.json') -Encoding utf8NoBOM
}
