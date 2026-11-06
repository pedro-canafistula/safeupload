#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Updates only a managed SafeUpload application payload, or restores its previous payload.
.DESCRIPTION
Run as administrator. The driver, WinFsp, SCM arguments/startup and ProgramData are not replaced.
Rollback restores binaries, never an older copy of the identity, policy, queue or stage.
Only installations made by the packaged installer at Program Files\SafeUpload\Agent are accepted.
#>
[CmdletBinding()]
param(
    [ValidateSet('Update','Rollback')][string]$Action = 'Update',
    [string]$PackagePath,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$TransactionId
)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = $PSHOME + '\Modules'
Import-Module (Join-Path $PSScriptRoot 'SafeUpload.Setup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'SafeUpload.Maintenance.psm1') -Force
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadMaintenancePeer {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
'@
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SafeUpload\Agent'
$maintenance = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SafeUpload\Maintenance'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$startupKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$journal = $null; $transaction = $null; $lock = $null; $changed = $false

function Assert-TrustedDirectory([string]$Path) {
    $null = Assert-SafeUploadDirectory $Path $Path
    $boundary = [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\')
    $current = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    while ($current.StartsWith($boundary + '\', [StringComparison]::OrdinalIgnoreCase) -or $current -eq $boundary) {
        if (Test-Path -LiteralPath $current) { Assert-SafeUploadInstallAcl (Get-Acl -LiteralPath $current) }
        if ($current -eq $boundary) { break }
        $current = Split-Path -Parent $current
    }
}

function New-PrivateDirectory([string]$Path) {
    $null = Assert-SafeUploadDirectory $Path $Path
    if (Test-Path -LiteralPath $Path) { throw 'Private maintenance directory already exists.' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $null = [IO.DirectoryInfo]::new($Path).Create($acl)
    Assert-TrustedDirectory $Path
}

function Configuration-Fingerprint {
    $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    $prefix = '"' + (Join-Path $install 'service\SafeUpload.Agent.Service.exe') + '"'
    if (-not $service -or $service.StartName -ne 'LocalSystem' -or
        -not ($service.PathName -eq $prefix -or $service.PathName.StartsWith($prefix + ' ', [StringComparison]::OrdinalIgnoreCase))) {
        throw 'The service is not owned by this managed installation.'
    }
    $startup = (Get-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole).SafeUploadAgentConsole
    if ($startup -ne ('"' + (Join-Path $install 'ui\SafeUpload.Agent.App.exe') + '"')) { throw 'Unexpected UI startup registration.' }
    $registered = Get-ItemProperty -LiteralPath $serviceKey
    $bytes = [Text.Encoding]::UTF8.GetBytes($service.PathName + "`n" + $service.StartName + "`n" +
        $service.StartMode + "`n" + $registered.ServiceSidType + "`n" + $startup)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','') }
    finally { $hash.Dispose() }
}

function Data-Fingerprint {
    $result = [ordered]@{}
    $data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SafeUpload'
    foreach ($name in @('policy.json','queue.jsonl','console-policy-cache.json','authentication\ed25519-identity.dat','identity\host-registration.json')) {
        $path = Join-Path $data $name
        $result[$name] = if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path).Hash } else { 'absent' }
    }
    return ($result | ConvertTo-Json -Compress)
}

function Driver-Fingerprint {
    $path = Join-Path $env:SystemRoot 'System32\drivers\SafeUpload.sys'
    if (Test-Path -LiteralPath $path) { return (Get-FileHash -LiteralPath $path).Hash }
    return 'absent'
}

function Assert-BinaryVersions([string]$Root, $Manifest) {
    foreach ($relative in @('service\SafeUpload.Agent.Service.dll','ui\SafeUpload.Agent.App.dll')) {
        $actual = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $Root $relative)).ProductVersion
        if (-not $actual -or ($actual -ne $Manifest.version -and -not $actual.StartsWith($Manifest.version + '+',[StringComparison]::Ordinal)) -or
            $actual.IndexOf($Manifest.commit,[StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw 'Executable version and package manifest disagree.'
        }
    }
}

function Save-Journal {
    $path = Join-Path $transaction 'transaction.json'
    $temporary = Join-Path $transaction ([Guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($journal | ConvertTo-Json -Depth 8)); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $path) { [IO.File]::Replace($temporary,$path,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$path) }
}

function Stop-Application {
    if ((Configuration-Fingerprint) -ne $journal.configuration) { throw 'Service configuration changed; maintenance refused.' }
    $null = Stop-SafeUploadInstalledUi (Join-Path $install 'ui\SafeUpload.Agent.App.exe')
    $service = Get-Service SafeUploadAgent
    try {
        if ($service.Status -ne 'Stopped') { Stop-Service -InputObject $service; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
    } finally { $service.Dispose() }
}

function Wait-Healthy {
    Start-Service SafeUploadAgent
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $pipe = $null; $reader = $null
        try {
            $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
            if ($service.State -ne 'Running') { throw 'Service is not running.' }
            $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SafeUpload.Agent', [IO.Pipes.PipeDirection]::In,
                [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Identification)
            $pipe.Connect(1500)
            [uint32]$peer = 0
            if (-not [SafeUploadMaintenancePeer]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$peer) -or
                $peer -ne $service.ProcessId -or $peer -eq 0) { throw 'The status pipe does not belong to the installed service.' }
            $reader = [IO.StreamReader]::new($pipe)
            $task = $reader.ReadLineAsync()
            if (-not $task.Wait(1500)) { throw 'Status not available.' }
            $line = $task.GetAwaiter().GetResult()
            if (-not $line -or $line.Length -gt 1048576) { throw 'Invalid status.' }
            $status = $line | ConvertFrom-Json
            if ($status.type -ne 'status') { throw 'Invalid status.' }
            $watcher = $service.PathName -match '(?:^|\s)--Interception:Mode=FileSystemWatcher(?:\s|$)'
            if (-not $status.protectionActive) { throw 'Inspection is not active.' }
            if (-not $watcher -and (-not $status.driveProtection.gatePolicyApplied -or
                $status.driveProtection.requiredDrives -le 0 -or $status.driveProtection.mountedDrives -ne $status.driveProtection.requiredDrives -or
                $status.driveProtection.issue -ne 'None')) { throw 'Preventive protection is not ready.' }
            if ((Configuration-Fingerprint) -ne $journal.configuration -or (Driver-Fingerprint) -ne $journal.driver) { throw 'Configuration or driver changed.' }
            return
        } catch { Start-Sleep -Milliseconds 400 }
        finally { if ($reader) { $reader.Dispose() }; if ($pipe) { $pipe.Dispose() } }
    } while ($timer.Elapsed.TotalSeconds -lt 60)
    throw 'The updated service did not report ready status; reverting the application payload.'
}

function Set-InstalledState($Manifest, [string]$BaselinePath) {
    $state = Get-Content -LiteralPath $BaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $state.version = $Manifest.version; $state.commit = $Manifest.commit
    $state | Add-Member NoteProperty updatedAtUtc ([DateTime]::UtcNow.ToString('o')) -Force
    $state | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $install 'setup\installation.json') -Encoding UTF8
}

function Restore-Previous {
    Stop-Application
    $before = Data-Fingerprint
    $previous = Set-SafeUploadMaintenancePayload -Source (Join-Path $transaction 'previous') -InstallRoot $install -WorkRoot $transaction
    Set-InstalledState $previous (Join-Path $transaction 'previous-installation.json')
    if ((Data-Fingerprint) -ne $before -or (Driver-Fingerprint) -ne $journal.driver) { throw 'Endpoint data or driver changed during rollback.' }
    Wait-Healthy
}

try {
    Assert-TrustedDirectory $install
    if (-not (Test-Path -LiteralPath $maintenance)) { New-PrivateDirectory $maintenance }
    Assert-TrustedDirectory $maintenance
    $lockPath = Join-Path $maintenance 'maintenance.lock'
    if ((Test-Path -LiteralPath $lockPath) -and ((Get-Item -LiteralPath $lockPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked maintenance lock refused.' }
    $lock = [IO.FileStream]::new($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $configuration = Configuration-Fingerprint
    if ($Action -eq 'Rollback') {
        if (-not $TransactionId -or $PackagePath) { throw 'Rollback requires only its transaction ID.' }
        $transaction = Join-Path $maintenance $TransactionId
        Assert-TrustedDirectory $transaction
        $journal = Get-Content -LiteralPath (Join-Path $transaction 'transaction.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($journal.schemaVersion -ne 1 -or $journal.id -ne $TransactionId -or $journal.configuration -ne $configuration -or
            $journal.state -notin @('prepared','applying','committed','rollback-failed')) { throw 'Transaction is not eligible for rollback.' }
        $null = Get-SafeUploadMaintenancePayload (Join-Path $transaction 'previous')
        if ($journal.state -eq 'committed') {
            $active = Get-Content -LiteralPath (Join-Path $install 'payload-manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($active.version -ne $journal.newVersion -or $active.commit -ne $journal.newCommit) { throw 'Another release is installed; rollback refused.' }
        }
        Restore-Previous
        $journal.state = 'rolled-back'; Save-Journal
    } else {
        if (-not $PackagePath -or $TransactionId) { throw 'Update requires a package directory, without a transaction ID.' }
        $source = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $PackagePath).Path).TrimEnd('\')
        $null = Assert-SafeUploadDirectory $source $source
        if ($source -eq $install -or $source.StartsWith($install + '\',[StringComparison]::OrdinalIgnoreCase) -or
            $source -eq $maintenance -or $source.StartsWith($maintenance + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'The incoming package must be outside the installed/maintenance roots.' }
        foreach ($entry in Get-ChildItem -LiteralPath $maintenance -Directory -Force) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked transaction directory refused.' }
            if ($entry.Name -notmatch '^[a-f0-9]{32}$') { continue }
            $receipt = Join-Path $entry.FullName 'transaction.json'
            if (Test-Path -LiteralPath $receipt) {
                $previousTransaction = Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($previousTransaction.state -notin @('committed','rolled-back')) { throw 'Resolve the previous maintenance transaction before updating again.' }
            }
        }
        $current = Get-SafeUploadMaintenancePayload $install
        $candidate = Get-SafeUploadMaintenancePayload $source
        Assert-BinaryVersions $install $current
        Assert-BinaryVersions $source $candidate
        Assert-SafeUploadMaintenancePrerequisites $source $install
        if ([Version]$candidate.version -le [Version]$current.version) { throw 'Update requires a newer package version; use rollback for a previous release.' }
        if ((Get-Service SafeUploadAgent).Status -ne 'Running') { throw 'Update requires the existing service to be running.' }
        $installedState = Join-Path $install 'setup\installation.json'
        if ((Get-Item -LiteralPath $installedState -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked installation record refused.' }
        $state = Get-Content -LiteralPath $installedState -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($state.version -ne $current.version -or $state.commit -ne $current.commit) { throw 'Installation record and payload disagree.' }
        $transaction = Join-Path $maintenance ([Guid]::NewGuid().ToString('N'))
        New-PrivateDirectory $transaction
        $previous = Copy-SafeUploadMaintenancePayload $install (Join-Path $transaction 'previous')
        $candidate = Copy-SafeUploadMaintenancePayload $source (Join-Path $transaction 'candidate')
        [IO.File]::Copy($installedState,(Join-Path $transaction 'previous-installation.json'),$false)
        $journal = [pscustomobject]@{schemaVersion=1;id=(Split-Path -Leaf $transaction);state='prepared';
            oldVersion=$previous.version;oldCommit=$previous.commit;newVersion=$candidate.version;newCommit=$candidate.commit;
            configuration=$configuration;driver=(Driver-Fingerprint);createdAtUtc=[DateTime]::UtcNow.ToString('o')}
        Save-Journal
        $changed = $true
        Stop-Application
        $before = Data-Fingerprint
        $journal.state='applying'; Save-Journal
        $deployed = Set-SafeUploadMaintenancePayload -Source (Join-Path $transaction 'candidate') -InstallRoot $install -WorkRoot $transaction
        Set-InstalledState $deployed (Join-Path $transaction 'previous-installation.json')
        if ((Data-Fingerprint) -ne $before -or (Driver-Fingerprint) -ne $journal.driver) { throw 'Endpoint data or driver changed during application update.' }
        Wait-Healthy
        $journal.state='committed'; Save-Journal
    }
    [pscustomobject]@{status=$journal.state;transactionId=$journal.id;oldVersion=$journal.oldVersion;newVersion=$journal.newVersion;
        endpointDataRestored=$false;driverReplaced=$false;ui='Reopen the app in the user session.'} | ConvertTo-Json
} catch {
    if ($changed -and $journal) {
        try { Restore-Previous; $journal.state='rolled-back'; Save-Journal }
        catch { $journal.state='rollback-failed'; Save-Journal; Write-Error 'Automatic recovery did not complete. Keep the driver loaded and use this transaction for explicit rollback.' -ErrorAction Continue }
    }
    elseif ($Action -eq 'Rollback' -and $journal) { $journal.state='rollback-failed'; Save-Journal }
    throw
} finally { if ($lock) { $lock.Dispose() } }
