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
function Run-Installer([string]$Label, [string[]]$Additional) {
    $process = Start-Process $InstallerPath -WindowStyle Hidden -PassThru -Wait -ArgumentList (@(
        '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',('/LOG="' + (Join-Path $ResultsDirectory "$Label.log") + '"')) + $Additional)
    return $process.ExitCode
}
try {
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
    Restart-Service -Name SafeUploadAgent -ErrorAction Stop
    Start-Sleep -Seconds 3
    Require ((Get-Service SafeUploadAgent).Status -eq 'Running') 'The installed service did not survive restart.'
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
    $uninstaller = Join-Path $installRoot 'unins000.exe'
    $process = Start-Process $uninstaller -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
        '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="' + (Join-Path $ResultsDirectory 'uninstall.log') + '"'))
    Require ($process.ExitCode -eq 0) 'Uninstall failed.'
    Require (-not (Test-Path -LiteralPath $serviceKey)) 'Agent service remains registered.'
    Require (-not (Get-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue)) 'UI startup entry remains.'
    Require ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $policyHash) 'Uninstall changed the policy.'
    Require ([IO.File]::ReadAllText($sentinel) -eq 'synthetic data to preserve') 'Uninstall removed retained endpoint data.'
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $queueHash) 'Uninstall removed or changed the audit queue.'
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
