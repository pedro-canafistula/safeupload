#Requires -Version 7.5
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallerPath,
      [Parameter(Mandatory)][string]$UpdatePackagePath,
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
    Require ((Run-Installer 'rejected-drive' @('/MODE=Drive')) -ne 0) 'Drive mode without WinFsp (not installed, not bundled) must be rejected.'
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
    $installedDiagnostics = Join-Path $installRoot 'setup\Get-SafeUploadDiagnostics.ps1'
    Require (Test-Path -LiteralPath $installedDiagnostics -PathType Leaf) 'Installed diagnostics client is missing.'
    $diagnosticQueueHash = (Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash
    $temporaryInventory = & $installedDiagnostics -Query audit-temporaries
    $temporaryClassification = & $installedDiagnostics -Query audit-temporary-classification
    $retentionPreview = & $installedDiagnostics -Query audit-retention-preview -OccurredBeforeUtc '2020-01-01T00:00:00Z'
    Require ($temporaryInventory.complete -eq $true -and $temporaryInventory.candidateFiles -eq 0) 'Installed temporary inventory failed.'
    Require ($temporaryClassification.complete -eq $true -and $temporaryClassification.promotionSupported -eq $false -and $temporaryClassification.deletionSupported -eq $false) 'Installed temporary classification failed.'
    Require ($retentionPreview.previewOnly -eq $true -and $retentionPreview.deletionSupported -eq $false -and $retentionPreview.integrity.pendingEvents -ge 1) 'Installed retention preview failed.'
    $diagnosticsLiteral = $installedDiagnostics.Replace("'", "''")
    $legacyCommand = "& '$diagnosticsLiteral' -Query audit-retention-preview -OccurredBeforeUtc '2020-01-01T00:00:00Z' | ConvertTo-Json -Compress -Depth 10"
    $legacyJson = & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $legacyCommand
    Require ($LASTEXITCODE -eq 0) 'Windows PowerShell installed diagnostics failed.'
    $legacyPreview = ($legacyJson -join "`n") | ConvertFrom-Json
    Require ($legacyPreview.previewOnly -eq $true -and $legacyPreview.deletionSupported -eq $false -and $legacyPreview.integrity.pendingEvents -ge 1) 'Windows PowerShell returned an invalid preview.'
    Require ((Get-FileHash -LiteralPath $queue -Algorithm SHA256).Hash -eq $diagnosticQueueHash) 'Installed maintenance changed the queue.'
    $result.maintenance = [ordered]@{inventory=$temporaryInventory;classification=$temporaryClassification;preview=$retentionPreview;windowsPowerShellPreview=$legacyPreview}
    $result.steps += 'installed diagnostics queried read-only maintenance in PowerShell 7 and Windows PowerShell 5.1 without changing queue bytes'
    $peerProbe = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))) 'agente/SafeUpload.Agent.ContractSmoke/bin/Release/net10.0-windows/SafeUpload.Agent.ContractSmoke.dll'
    & dotnet $peerProbe --verify-service-peer (Join-Path $installRoot 'service\SafeUpload.Agent.Service.exe') *> (Join-Path $ResultsDirectory 'service-peer.log')
    Require ($LASTEXITCODE -eq 0) 'Restricted non-administrator could not verify the installed service peer.'
    $result.steps += 'restricted non-administrator verified the installed SCM service peer and rejected a different image'
    Require ((Run-Installer 'rejected-upgrade' @('/MODE=FileSystemWatcher')) -ne 0) 'Initial installer unexpectedly overwrote an existing service.'
    $after = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Require ($after.State -eq 'Running' -and $after.PathName -eq $service.PathName) 'Refused upgrade changed the service.'
    Require ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $policyHash) 'Refused upgrade changed the policy.'
    $result.steps += 'existing installation refused without changing service or policy'
    # Exercise real Windows service maintenance, including a package that passes
    # integrity validation but cannot start. All fixtures remain on this disposable runner.
    $candidate = Join-Path $ResultsDirectory 'maintenance-candidate'
    Copy-Item -LiteralPath (Resolve-Path -LiteralPath $UpdatePackagePath).Path -Destination $candidate -Recurse
    $newAsset = 'service/maintenance-new-file.txt'
    [IO.File]::WriteAllText((Join-Path $candidate $newAsset),'synthetic dependency introduced by a later release')
    function Refresh-Manifest([string]$Root) {
        $path=Join-Path $Root 'payload-manifest.json'
        $manifest=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $manifest.files=@(Get-ChildItem -LiteralPath $Root -File -Recurse | Where-Object Name -ne 'payload-manifest.json' | ForEach-Object {
            @{path=[IO.Path]::GetRelativePath($Root,$_.FullName).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash}
        })
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
    }
    Refresh-Manifest $candidate
    $candidateManifest=Get-Content (Join-Path $candidate 'payload-manifest.json') -Raw | ConvertFrom-Json
    $maintenanceScript=Join-Path $candidate 'setup/Update-SafeUploadAgent.ps1'
    $legacyPowerShell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    function Run-Maintenance([string]$Label,[string[]]$Arguments,[bool]$ExpectSuccess=$true) {
        $stdout=Join-Path $ResultsDirectory ($Label+'.json');$stderr=Join-Path $ResultsDirectory ($Label+'.stderr.log')
        $process=Start-Process $legacyPowerShell -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList (
            @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$maintenanceScript+'"'))+$Arguments)
        if (($process.ExitCode -eq 0) -ne $ExpectSuccess) { Get-Content -LiteralPath $stderr | Write-Host }
        Require (($process.ExitCode -eq 0) -eq $ExpectSuccess) ('Unexpected maintenance result: '+$Label+'; see '+$stderr)
        if($ExpectSuccess){return Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json}
    }
    function Check-Preserved([string]$Version) {
        $active=Get-Content (Join-Path $installRoot 'setup/installation.json') -Raw | ConvertFrom-Json
        Require ($active.version -eq $Version) 'Maintenance recorded the wrong version.'
        $running=Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
        Require ($running.State -eq 'Running' -and $running.PathName -eq $service.PathName -and $running.StartName -eq 'LocalSystem') 'Maintenance changed the service configuration.'
        Require ((Get-ItemProperty -LiteralPath $startupKey).SafeUploadAgentConsole -eq $run.SafeUploadAgentConsole) 'Maintenance changed UI startup.'
        Require ((Get-FileHash -LiteralPath $policy).Hash -eq $policyHash) 'Maintenance changed the local policy.'
        $pending=@(Read-AuditEvents $queue | Where-Object eventId -eq $audit.eventId)
        Require ($pending.Count -eq 1 -and -not $pending[0].dispatched -and $pending[0].occurredAtUtc -eq $audit.occurredAtUtc) 'Maintenance lost or duplicated the pending event.'
    }
    $upgrade=Run-Maintenance 'update' @('-PackagePath',('"'+$candidate+'"'))
    Require ($upgrade.status -eq 'committed' -and -not $upgrade.driverReplaced -and -not $upgrade.endpointDataRestored) 'Update did not commit safely.'
    Check-Preserved $candidateManifest.version
    Require (Test-Path -LiteralPath (Join-Path $installRoot $newAsset)) 'Update did not install the new dependency.'
    $rollback=Run-Maintenance 'rollback' @('-Action','Rollback','-TransactionId',$upgrade.transactionId)
    Require ($rollback.status -eq 'rolled-back') 'Explicit rollback failed.'
    Check-Preserved $state.version
    Require (-not(Test-Path -LiteralPath (Join-Path $installRoot $newAsset))) 'Rollback left the new dependency active.'
    $broken=Join-Path $ResultsDirectory 'maintenance-broken';Copy-Item -LiteralPath $candidate -Destination $broken -Recurse
    [IO.File]::WriteAllText((Join-Path $broken 'service/appsettings.json'),'{ invalid configuration')
    Refresh-Manifest $broken
    Run-Maintenance 'update-startup-failure' @('-PackagePath',('"'+$broken+'"')) $false
    Check-Preserved $state.version
    $transactions=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SafeUpload/Maintenance'
    $receipts=@(Get-ChildItem -LiteralPath $transactions -Filter transaction.json -Recurse | ForEach-Object {Get-Content $_.FullName -Raw | ConvertFrom-Json})
    Require (@($receipts | Where-Object state -eq 'rolled-back').Count -eq 2) 'Failed startup did not record automatic rollback.'
    $finalUpgrade=Run-Maintenance 'update-after-recovery' @('-PackagePath',('"'+$candidate+'"'))
    Check-Preserved $candidateManifest.version
    $result.applicationMaintenance=@{update=$upgrade;rollback=$rollback;startupFailureRecovered=$true;finalUpdate=$finalUpgrade}
    $result.steps += 'real service updated, explicitly rolled back, recovered automatically after invalid startup, then updated again; pending event and policy preserved'
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
    Require (-not(Test-Path -LiteralPath (Join-Path $installRoot $newAsset))) 'Original uninstaller left a dependency introduced by the update.'
    $installedUi.Dispose()
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
