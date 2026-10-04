#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Prepare', 'AfterBoot', 'Finalize')]
    [string] $Phase,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedFeatureSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedInspectorSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedServicePackageSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedOriginalPolicySha256,

    [ValidatePattern('^SafeUpload-stage-prototype[A-Za-z0-9._-]*\.sys$')]
    [string] $FeatureDriverFileName = 'SafeUpload-stage-prototype.sys',

    [ValidatePattern('^SafeUpload\.Inspector\.[A-Za-z0-9_-]+\.exe$')]
    [string] $InspectorFileName = 'SafeUpload.Inspector.input.exe',

    [ValidatePattern('^StagedTestAgent[A-Za-z0-9._-]*\.ps1$')]
    [string] $TestAgentHelperFileName = 'StagedTestAgent.ps1'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
$stateDirectory = Join-Path $documents 'SafeUpload-boot-start-state'
$statePath = Join-Path $stateDirectory 'state.json'
$bootWriteScript = Join-Path $stateDirectory 'first-boot-write.ps1'
$bootWriteResult = Join-Path $stateDirectory 'first-boot-write.json'
$bootTask = 'SafeUpload-BootStart-X4'
$policyPath = 'C:\ProgramData\SafeUpload\policy.json'
$protectedDirectory = 'C:\SafeUploadBootStart\Protected'
$firstWritePath = Join-Path $protectedDirectory 'first-after-boot.txt'
$installedDriver = 'C:\Windows\System32\drivers\SafeUpload.sys'
$featureDriver = Join-Path $documents $FeatureDriverFileName
$inspectorPath = Join-Path $documents $InspectorFileName
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$serviceDirectory = Join-Path $stateDirectory 'stage-service-publish'
$vhdxPath = Join-Path $stateDirectory 'fresh-after-boot.vhdx'
$originalDriverHash = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$registryService = 'SYSTEM\CurrentControlSet\Services\SafeUpload'
$bootPolicyKey = "HKLM:\$registryService\Parameters\BootPolicy"
$parametersKey = "HKLM:\$registryService\Parameters"

. (Join-Path $documents $TestAgentHelperFileName)

if (-not ('SafeUploadBootSectionNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class SafeUploadBootSectionNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
        EntryPoint = "CreateFileMappingW")]
    private static extern IntPtr CreateFileMapping(SafeFileHandle file, IntPtr attributes,
        uint protection, uint sizeHigh, uint sizeLow, IntPtr name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    public static int TryWritableSection(SafeFileHandle file)
    {
        IntPtr section = CreateFileMapping(file, IntPtr.Zero, 0x04, 0, 4096, IntPtr.Zero);
        if (section == IntPtr.Zero) return Marshal.GetLastWin32Error();
        if (!CloseHandle(section)) throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle(section)");
        return 0;
    }
}
'@
}

function Assert-Debuggee {
    if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
        (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') {
        throw 'Wrong SafeUpload debuggee.'
    }
    $windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if ($windows.CurrentBuildNumber -ne '19045' -or $windows.UBR -ne 2965) {
        throw "MVP target is Windows 10 19045.2965; found $($windows.CurrentBuildNumber).$($windows.UBR)."
    }
}

function ConvertTo-PowerShellLiteral([string] $Value) { $Value.Replace("'", "''") }

function Invoke-RestoreStep([string] $Name, [scriptblock] $Action,
    [System.Collections.Generic.List[string]] $Errors) {
    try { & $Action }
    catch { [void]$Errors.Add($Name + ': ' + $_.Exception.Message) }
}

function Invoke-InspectorAsSystem {
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Stop the agent before querying admission status.'
    }
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-BootInspector-' + $id
    $launcher = Join-Path $stateDirectory ('inspector-' + $id + '.ps1')
    $outPath = $launcher + '.out'
    $errPath = $launcher + '.err'
    $exitPath = $launcher + '.exit'
    $body = @'
$ErrorActionPreference = 'Stop'
$process = Start-Process -FilePath '__EXE__' -ArgumentList '--admission-volume-status' -PassThru -Wait `
    -WindowStyle Hidden -RedirectStandardOutput '__OUT__' -RedirectStandardError '__ERR__'
[IO.File]::WriteAllText('__EXIT__', [string]$process.ExitCode)
'@
    $body = $body.Replace('__EXE__', (ConvertTo-PowerShellLiteral $inspectorPath))
    $body = $body.Replace('__OUT__', (ConvertTo-PowerShellLiteral $outPath))
    $body = $body.Replace('__ERR__', (ConvertTo-PowerShellLiteral $errPath))
    $body = $body.Replace('__EXIT__', (ConvertTo-PowerShellLiteral $exitPath))
    Set-Content -LiteralPath $launcher -Value $body -Encoding UTF8
    $registered = $false
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $exitPath) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if (-not (Test-Path -LiteralPath $exitPath)) { throw 'SYSTEM Inspector timed out.' }
        $exitCode = [int][IO.File]::ReadAllText($exitPath)
        if ($exitCode -ne 0) { throw ('SYSTEM Inspector failed: ' + [IO.File]::ReadAllText($errPath)) }
        return (ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($outPath)).Trim())
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$outPath,$errPath,$exitPath -Force -ErrorAction SilentlyContinue
    }
}

function Wait-AgentPolicyAccepted([string] $LogPrefix) {
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'An agent process is already running.'
    }
    $ready = [Threading.EventWaitHandle]::new($false, [Threading.EventResetMode]::ManualReset,
        'Global\SafeUploadServiceReady')
    $agent = $null
    try {
        [void]$ready.Reset()
        $agent = Start-StagedTestAgent $serviceDirectory $LogPrefix
        if (-not $ready.WaitOne([TimeSpan]::FromSeconds(45))) {
            throw 'The agent did not report accepted policy within 45 seconds.'
        }
        $readback = Get-BootPolicyReadbackAsSystem
        if (-not $readback.AclValid -or $readback.PendingPresent -or $readback.Version -ne 1 -or
            $readback.StructSize -ne 16656 -or $readback.PrefixCount -ne 1 -or $readback.Flags -ne 0 -or
            $readback.Prefix -notmatch '(?i)SafeUploadBootStart\\Protected') {
            throw 'Committed boot policy read-back, scope, or exact registry ACL is invalid.'
        }
        return $agent
    }
    catch {
        if ($null -ne $agent) { Stop-StagedTestAgent $agent }
        throw
    }
    finally { $ready.Dispose() }
}

function Get-BootPolicyReadbackAsSystem {
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-BootPolicyReader-' + $id
    $launcher = Join-Path $stateDirectory ('policy-reader-' + $id + '.ps1')
    $outputPath = $launcher + '.json'
    $body = @'
$ErrorActionPreference = 'Stop'
$path = 'SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy'
$parentPath = 'SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
if ($null -eq $key) { throw 'BootPolicy key missing.' }
$parent = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($parentPath, $false)
if ($null -eq $parent) { $key.Dispose(); throw 'Parameters key missing.' }
function Test-ExactSystemTiAcl($registryKey) {
    $security = $registryKey.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access)
    $owner = $security.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $rulesOk = ($rules.Count -eq 2)
    $sidSet = @()
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            $rule.RegistryRights -ne [Microsoft.Win32.RegistryRights]::FullControl) { $rulesOk = $false }
        $sidSet += $rule.IdentityReference.Value
    }
    $expected = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    return ($owner -eq 'S-1-5-18' -and $security.AreAccessRulesProtected -and $rulesOk -and
        (($sidSet | Sort-Object) -join ';') -eq (($expected | Sort-Object) -join ';'))
}
try {
    $record = $key.GetValue('Scopes', $null)
    $pending = $key.GetValue('PendingScopes', $null)
    if ($record -isnot [byte[]]) { throw 'Scopes is not REG_BINARY.' }
    $aclValid = (Test-ExactSystemTiAcl $key) -and (Test-ExactSystemTiAcl $parent)
    $prefix = ''
    if ($record.Length -ge 18) {
        for ($i = 16; $i -lt ($record.Length - 1); $i += 2) {
            if ([BitConverter]::ToUInt16($record, $i) -eq 0) { break }
            $prefix += [char][BitConverter]::ToUInt16($record, $i)
        }
    }
    $result = [ordered]@{
        AclValid = $aclValid
        Owner = 'S-1-5-18'
        PrefixCount = [BitConverter]::ToUInt32($record, 8)
        Flags = [BitConverter]::ToUInt32($record, 12)
        StructSize = [BitConverter]::ToUInt32($record, 4)
        Version = [BitConverter]::ToUInt32($record, 0)
        PendingPresent = ($null -ne $pending)
        Prefix = $prefix
    }
    $result | ConvertTo-Json -Compress | Set-Content -LiteralPath '__OUT__' -Encoding UTF8
}
finally { $key.Dispose(); $parent.Dispose() }
'@
    Set-Content -LiteralPath $launcher -Value $body.Replace('__OUT__', (ConvertTo-PowerShellLiteral $outputPath)) -Encoding UTF8
    $registered = $false
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $outputPath); ++$attempt) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $outputPath)) { throw 'SYSTEM boot-policy read-back timed out.' }
        return Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$outputPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-VolumeGuid([string] $DriveLetter) {
    $volumes = @(Get-CimInstance Win32_Volume -Filter "DriveLetter='$($DriveLetter):'" -ErrorAction Stop)
    if ($volumes.Count -ne 1 -or $volumes[0].DeviceID -notmatch '(?i)\{[0-9a-f-]{36}\}') {
        throw "Volume identity is not unique for ${DriveLetter}:."
    }
    return $matches[0].ToLowerInvariant()
}

function Find-AdmissionVolume($Status, [string] $Guid) {
    $entries = @($Status.admissionVolumes | Where-Object {
        ($_.volumeFlags -band 1) -eq 0 -and $_.volumeGuidStatus -eq 0 -and
        ([string]$_.volumeGuid).ToLowerInvariant().Contains($Guid)
    })
    if ($entries.Count -gt 1) { throw "Admission instance is ambiguous for volume $Guid." }
    if ($entries.Count -eq 0) { return $null }
    return $entries[0]
}

function Wait-AdmissionVolume([string] $Guid) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $status = Invoke-InspectorAsSystem
        $entry = Find-AdmissionVolume $status $Guid
        if ($null -ne $entry -and $entry.canaryState -ge 2) { return [pscustomobject]@{ Status = $status; Entry = $entry } }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "No terminal canary and admission entry for volume $Guid."
}

function New-BootTestVhdx {
    if (Test-Path -LiteralPath $vhdxPath) { throw 'Boot test VHDX already exists.' }
    if (Test-Path -LiteralPath 'S:\') { throw 'S: is already mounted; preserve and investigate that baseline first.' }
    $diskpartPath = Join-Path $stateDirectory 'fresh-diskpart.txt'
    $lines = @(
        "create vdisk file=`"$vhdxPath`" maximum=128 type=expandable",
        "select vdisk file=`"$vhdxPath`"",
        'attach vdisk',
        'create partition primary',
        'format fs=ntfs quick label=SafeUploadBoot',
        'assign letter=S'
    )
    [IO.File]::WriteAllLines($diskpartPath, $lines, [Text.Encoding]::ASCII)
    $output = (& diskpart.exe /s $diskpartPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $output -match '(?im)\bVirtual Disk Service error\b|\bDiskPart has encountered an error\b') {
        throw ('Fresh VHDX attach failed: ' + ($output -replace '[\r\n]+', ' '))
    }
    $mountDeadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath 'S:\') -and [DateTime]::UtcNow -lt $mountDeadline) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath 'S:\') -or (Get-Volume -DriveLetter S).FileSystem -ne 'NTFS') {
        throw 'The fresh VHDX did not become a mounted NTFS volume at S:.'
    }
    Write-Output 'FreshVhdxMountedAfterBoot=True'
}

function Invoke-SystemRegistryCleanup {
    $taskName = 'SafeUpload-BootRegistryCleanup-' + [guid]::NewGuid().ToString('N')
    $launcher = Join-Path $stateDirectory 'remove-boot-policy.ps1'
    $done = $launcher + '.done'
    $body = @'
$ErrorActionPreference = 'Stop'
$boot = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy'
$parameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters'
if (Test-Path -LiteralPath $boot) { Remove-Item -LiteralPath $boot -Recurse -Force }
if ((Test-Path -LiteralPath $parameters) -and @(Get-ChildItem -LiteralPath $parameters -Force).Count -eq 0) {
    Remove-Item -LiteralPath $parameters -Force
}
[IO.File]::WriteAllText('__DONE__', 'removed')
'@
    Set-Content -LiteralPath $launcher -Value $body.Replace('__DONE__', (ConvertTo-PowerShellLiteral $done)) -Encoding UTF8
    $registered = $false
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $done); ++$attempt) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $done) -or [IO.File]::ReadAllText($done) -ne 'removed') {
            throw 'SYSTEM could not remove the test boot policy registry keys.'
        }
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$done -Force -ErrorAction SilentlyContinue
    }
}

function Set-DemandStartAndRestoreDriver {
    & sc.exe config SafeUpload start= demand | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore SafeUpload to demand start.' }
    $loaded = (& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s'
    if ($loaded) {
        & fltmc.exe unload SafeUpload | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Test filter refused unload; original driver bytes were retained in the state directory.' }
    }
    Copy-StagedOriginalDriver (Join-Path $stateDirectory 'SafeUpload.original.sys') $installedDriver
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $originalDriverHash) {
        throw 'Original driver hash did not restore.'
    }
}

function Restore-PolicyFile {
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if (-not $state.OriginalPolicyBase64) { throw 'Prepare state does not contain the required original policy bytes.' }
    [IO.File]::WriteAllBytes($policyPath, [Convert]::FromBase64String($state.OriginalPolicyBase64))
    if (-not (Test-Path -LiteralPath $policyPath)) { throw 'Original policy file is missing after restoration.' }
    $actual = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedOriginalPolicySha256.ToUpperInvariant()) { throw 'Original policy hash failed restoration.' }
}

if ($Phase -eq 'Prepare') {
    Assert-Debuggee
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $originalDriverHash) {
        throw 'Installed driver is not the recorded original.'
    }
    if ((Get-ItemProperty "HKLM:\$registryService").Start -ne 3) { throw 'Expected original demand-start driver.' }
    if ((& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s') { throw 'Expected the original filter unloaded.' }
    if ((Get-FileHash -LiteralPath $featureDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant() -or
        (Get-FileHash -LiteralPath $inspectorPath -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant() -or
        (Get-FileHash -LiteralPath $servicePackage -Algorithm SHA256).Hash -ne $ExpectedServicePackageSha256.ToUpperInvariant()) {
        throw 'Feature driver, inspector, or service package hash mismatch.'
    }
    if (Test-Path -LiteralPath $parametersKey) { throw 'Parameters exists before the boot-policy experiment; preserve and investigate that baseline first.' }
    if (Test-Path -LiteralPath $protectedDirectory) { throw 'Protected test folder already exists; preserve and investigate that baseline first.' }
    if (Test-Path -LiteralPath 'S:\') { throw 'S: is already mounted; preserve and investigate that baseline first.' }
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Agent must be stopped before checkpointed preparation.' }
    if (Test-Path -LiteralPath $stateDirectory) { throw 'A prior boot-start state directory exists.' }
    if (-not (Test-Path -LiteralPath $policyPath) -or
        (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash -ne $ExpectedOriginalPolicySha256.ToUpperInvariant()) {
        throw 'Original policy is missing or its hash differs from the recorded baseline.'
    }

    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    Backup-StagedTestDriver (Join-Path $stateDirectory 'SafeUpload.original.sys')
    $originalPolicy = if (Test-Path -LiteralPath $policyPath) {
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($policyPath))
    } else { $null }
    $state = [ordered]@{
        PreparedUtc = [DateTime]::UtcNow.ToString('o')
        OriginalStart = 3
        OriginalPolicyBase64 = $originalPolicy
        ExpectedOriginalPolicySha256 = $ExpectedOriginalPolicySha256.ToUpperInvariant()
        FeatureSha256 = $ExpectedFeatureSha256.ToUpperInvariant()
        InspectorSha256 = $ExpectedInspectorSha256.ToUpperInvariant()
        ServicePackageSha256 = $ExpectedServicePackageSha256.ToUpperInvariant()
    }
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
    try {
    New-Item -ItemType Directory -Force -Path $protectedDirectory | Out-Null
    Remove-Item -LiteralPath $firstWritePath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path -LiteralPath $serviceDirectory)) { New-Item -ItemType Directory -Path $serviceDirectory | Out-Null }
    Expand-Archive -LiteralPath $servicePackage -DestinationPath $serviceDirectory -Force
    if (-not (Test-Path -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'))) {
        throw 'Published agent executable is missing.'
    }

    $policyDirectory = Split-Path -Parent $policyPath
    New-Item -ItemType Directory -Force -Path $policyDirectory | Out-Null
    $testPolicy = [ordered]@{
        version = 1
        activeCategories = @('Cpf')
        monitoredScopes = [ordered]@{
            extensions = @('.txt')
            destinationPaths = @($protectedDirectory)
            removableDrives = $false
            networkPaths = $false
        }
        maxFileSizeMb = 20
        inspectionTimeoutSeconds = 5
        failOpen = $true
        excludedProcesses = @('System', 'SafeUpload.Agent.App')
        auditOnly = $false
        overrideAllowed = $false
    }
    $testPolicy | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $policyPath -Encoding UTF8
    Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
        throw 'Feature driver did not install byte-for-byte.'
    }
    & sc.exe config SafeUpload start= boot | Out-Host
    if ($LASTEXITCODE -ne 0 -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 0) {
        throw 'Could not configure boot start before loading the test driver.'
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not demand-load the test driver to write the durable test policy.' }

    $agent = $null
    try {
        $agent = Wait-AgentPolicyAccepted (Join-Path $stateDirectory 'prepare-agent')
        Write-Output 'TestPolicyDurableAndAccepted=True'
    }
    finally {
        if ($null -ne $agent) { Stop-StagedTestAgent $agent }
    }
    & fltmc.exe unload SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not unload the disconnected test driver before boot start.' }
    if ((Get-ItemProperty "HKLM:\$registryService").Start -ne 0) {
        throw 'The test driver no longer has boot start configured.'
    }

    $startupBody = @'
$ErrorActionPreference = 'Continue'
$folder = 'C:\SafeUploadBootStart\Protected'
$target = Join-Path $folder 'first-after-boot.txt'
$resultPath = '__RESULT__'
$bootUtc = [DateTime]::MinValue
try { $bootUtc = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime() } catch { }
$readyQueryStartedUtc = [DateTime]::UtcNow
$instances = (& fltmc.exe instances -f SafeUpload 2>&1 | Out-String)
$ready = ($LASTEXITCODE -eq 0 -and $instances -match '(?m)\bC:\s')
$readyObservedUtc = [DateTime]::UtcNow
$attemptUtc = [DateTime]::UtcNow
$writeResult = 'Denied'
$writeError = ''
try {
    [IO.File]::WriteAllText($target, 'X4-FIRST-USER-MODE-WRITE')
    $writeResult = 'Succeeded'
} catch { $writeError = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message }
$present = Test-Path -LiteralPath $target
$result = [ordered]@{
    BootUtc = $bootUtc.ToString('o')
    FilterReadyQueryStartedUtc = $readyQueryStartedUtc.ToString('o')
    FilterReadyObservedUtc = $readyObservedUtc.ToString('o')
    FilterReadyBeforeAttempt = $ready
    InstanceOutput = ($instances -replace '[\r\n]+', ' ').Trim()
    FirstWriteAttemptUtc = $attemptUtc.ToString('o')
    WriteResult = $writeResult
    WriteError = $writeError
    DestinationVisibleAfterAttempt = $present
}
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
'@
    Set-Content -LiteralPath $bootWriteScript -Value $startupBody.Replace('__RESULT__', (ConvertTo-PowerShellLiteral $bootWriteResult)) -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $bootWriteScript + '"')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2))
    Register-ScheduledTask -TaskName $bootTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

    & verifier.exe /standard /driver SafeUpload.sys | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure standard boot Verifier for SafeUpload.sys.' }
    & verifier.exe /bootmode oneboot | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure one-boot Verifier mode.' }
    $verifier = (& verifier.exe /query 2>&1 | Out-String)
    if ($verifier -notmatch 'SafeUpload\.sys' -or $verifier -notmatch 'Verifier Flags:\s+0x') {
        throw 'Boot Verifier configuration did not report SafeUpload.sys and active flags.'
    }
    Write-Output 'BootVerifierConfigured=True'
    Write-Output 'BOOT_PREPARED=True'
    }
    catch {
        Write-Output ('PrepareRollbackReason=' + $_.Exception.Message)
        $rollbackErrors = [System.Collections.Generic.List[string]]::new()
        Invoke-RestoreStep 'stop agent processes' {
            Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
        } $rollbackErrors
        Invoke-RestoreStep 'set demand start' {
            & sc.exe config SafeUpload start= demand | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Could not set demand start during rollback.' }
        } $rollbackErrors
        $filterUnloaded = $true
        try {
            $loaded = (& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s'
            if ($loaded) {
                & fltmc.exe unload SafeUpload | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Feature driver refused unload; original bytes are retained.' }
            }
        }
        catch {
            $filterUnloaded = $false
            $rollbackErrors.Add('unload feature driver: ' + $_.Exception.Message)
        }
        if ($filterUnloaded -and (Test-Path -LiteralPath (Join-Path $stateDirectory 'SafeUpload.original.sys'))) {
            Invoke-RestoreStep 'restore original driver bytes' {
                Copy-StagedOriginalDriver (Join-Path $stateDirectory 'SafeUpload.original.sys') $installedDriver
            } $rollbackErrors
        }
        if (Test-Path -LiteralPath $statePath) {
            Invoke-RestoreStep 'restore original policy file' { Restore-PolicyFile } $rollbackErrors
        }
        if (Test-Path -LiteralPath $parametersKey) {
            Invoke-RestoreStep 'remove durable test policy' { Invoke-SystemRegistryCleanup } $rollbackErrors
        }
        Invoke-RestoreStep 'reset Driver Verifier' {
            & verifier.exe /reset | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Driver Verifier reset failed during rollback.' }
        } $rollbackErrors
        Invoke-RestoreStep 'remove startup task' {
            if (Get-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $bootTask -Confirm:$false
            }
        } $rollbackErrors
        Invoke-RestoreStep 'remove protected test folder' {
            Remove-Item -LiteralPath $protectedDirectory -Recurse -Force -ErrorAction SilentlyContinue
        } $rollbackErrors
        Invoke-RestoreStep 'remove staged service package' {
            Remove-Item -LiteralPath $serviceDirectory -Recurse -Force -ErrorAction SilentlyContinue
        } $rollbackErrors
        if ($rollbackErrors.Count -gt 0) {
            Write-Output ('PrepareRollbackNeedsAttention=' + ($rollbackErrors -join ' | '))
        }
        throw
    }
}
elseif ($Phase -eq 'AfterBoot') {
    Assert-Debuggee
    if (-not (Test-Path -LiteralPath $statePath)) { throw 'Prepare state is missing; recover the checkpointed guest.' }
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant() -or
        (Get-ItemProperty "HKLM:\$registryService").Start -ne 0) { throw 'Feature boot driver is not installed as boot start.' }
    $agent = $null
    $sectionStream = $null
    $lateWriter = $null
    $vhdAttached = $false
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while (-not (Test-Path -LiteralPath $bootWriteResult) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $bootWriteResult)) { throw 'At-startup X4 writer task did not record its attempt.' }
        $first = Get-Content -LiteralPath $bootWriteResult -Raw | ConvertFrom-Json
        Write-Output ('X4_FirstAttempt=' + ($first | ConvertTo-Json -Compress))
        if (-not $first.FilterReadyBeforeAttempt -or $first.WriteResult -ne 'Denied' -or
            $first.DestinationVisibleAfterAttempt -or (Test-Path -LiteralPath $firstWritePath)) {
            throw 'X4 failed: first scoped write was not refused after filter readiness, or it reached the destination.'
        }
        $readyObserved = [DateTime]::Parse($first.FilterReadyObservedUtc).ToUniversalTime()
        $firstAttempt = [DateTime]::Parse($first.FirstWriteAttemptUtc).ToUniversalTime()
        if ($firstAttempt -lt $readyObserved) { throw 'X4 first write timestamp precedes the completed filter readiness probe.' }
        Write-Output ('X4_ReadinessToAttemptMilliseconds=' + ($firstAttempt - $readyObserved).TotalMilliseconds)
        Write-Output 'X4_FirstWriteRefusedBeforeAgent=True'

        if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'The agent must remain stopped for the first post-boot write.'
        }
        $status = Invoke-InspectorAsSystem
        if ($status.bootPolicyState -ne 1) { throw "Boot policy was not verified as valid by DriverEntry: $($status.bootPolicyState)." }
        $cGuid = Get-VolumeGuid 'C'
        $cAdmission = Wait-AdmissionVolume $cGuid
        $status = $cAdmission.Status
        $cEntry = $cAdmission.Entry
        if ($status.bootPolicyState -ne 1 -or $null -eq $cEntry -or ($cEntry.setupFlags -band 4) -eq 0 -or
            $cEntry.trustState -ne 1 -or $cEntry.canaryState -ne 2) {
            throw 'C: was not reported newly mounted and trusted at boot.'
        }
        Write-Output ('CAtBootTrustState=' + $cEntry.trustState + ';SetupFlags=' + $cEntry.setupFlags +
            ';CanaryState=' + $cEntry.canaryState + ';CanaryStatus=' + $cEntry.canaryStatus)

        $agent = Wait-AgentPolicyAccepted (Join-Path $stateDirectory 'afterboot-agent-1')
        Write-Output 'AgentStartAcceptedDurablePolicy=True'

        $sectionPath = Join-Path $protectedDirectory 'agent-down-section.txt'
        $sectionStream = [IO.File]::Open($sectionPath, [IO.FileMode]::Create,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $sample = [byte[]](65,66,67,68)
        $sectionStream.Write($sample, 0, $sample.Length)
        $sectionStream.Flush($true)
        Stop-StagedTestAgent $agent
        $agent = $null
        $sectionError = [SafeUploadBootSectionNative]::TryWritableSection($sectionStream.SafeFileHandle)
        Write-Output ('AgentDownWritableSectionWin32Error=' + $sectionError)
        if ($sectionError -ne 5) { throw 'A new writable section was not refused after agent disconnect.' }
        $sectionStream.Dispose()
        $sectionStream = $null

        $agentDownPath = Join-Path $protectedDirectory 'agent-down-write.txt'
        $writeDenied = $false
        try { [IO.File]::WriteAllText($agentDownPath, 'MUST-BE-DENIED') }
        catch { $writeDenied = $true; Write-Output ('AgentDownWriteError=' + $_.Exception.GetType().FullName) }
        if (-not $writeDenied -or (Test-Path -LiteralPath $agentDownPath)) {
            throw 'A new protected write open was not refused after agent disconnect.'
        }
        Write-Output 'AgentStopFailClosedForOpenAndSection=True'

        $agent = Wait-AgentPolicyAccepted (Join-Path $stateDirectory 'afterboot-agent-2')
        $restartPath = Join-Path $protectedDirectory 'agent-restart-stage.txt'
        $restartStream = [IO.File]::Open($restartPath, [IO.FileMode]::Create,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        try {
            $restartStream.Write($sample, 0, $sample.Length)
            $restartStream.Flush($true)
            Write-Output 'AgentRestartAcceptedProtectedWrite=True'
        }
        finally { $restartStream.Dispose() }
        Stop-StagedTestAgent $agent
        $agent = $null

        $vhdAttached = $true
        New-BootTestVhdx
        $freshGuid = Get-VolumeGuid 'S'
        $fresh = Wait-AdmissionVolume $freshGuid
        if (($fresh.Entry.setupFlags -band 4) -eq 0 -or $fresh.Entry.trustState -ne 1 -or
            $fresh.Entry.canaryState -ne 2) {
            throw 'A fresh post-boot VHDX was not trusted from NEWLY_MOUNTED setup flags.'
        }
        Write-Output ('FreshVhdxTrustState=' + $fresh.Entry.trustState + ';SetupFlags=' + $fresh.Entry.setupFlags +
            ';CanaryState=' + $fresh.Entry.canaryState + ';CanaryStatus=' + $fresh.Entry.canaryStatus)

        & fltmc.exe detach SafeUpload S: | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Could not detach SafeUpload from the mounted VHDX for E1.' }
        $latePath = 'S:\E1-writer-open-before-late-attach.txt'
        $lateWriter = [IO.File]::Open($latePath, [IO.FileMode]::Create,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $lateWriter.Write($sample, 0, $sample.Length)
        $lateWriter.Flush($true)
        & fltmc.exe attach SafeUpload S: | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Could not attach SafeUpload after the E1 writer was opened.' }
        $late = Wait-AdmissionVolume $freshGuid
        if (($late.Entry.setupFlags -band 4) -ne 0 -or $late.Entry.trustState -ne 0) {
            throw 'E1 failed: late attach upgraded a volume with a pre-attach writer to trusted.'
        }
        Write-Output ('E1_PreAttachWriter=' + $true + ';TrustState=' + $late.Entry.trustState +
            ';SetupFlags=' + $late.Entry.setupFlags + ';CanaryState=' + $late.Entry.canaryState)
        $lateWriter.Dispose()
        $lateWriter = $null

        Write-Output 'BootStartX4AndE1=True'
    }
    finally {
        $restoreErrors = [System.Collections.Generic.List[string]]::new()
        Invoke-RestoreStep 'close E1 writer handle' {
            if ($null -ne $lateWriter) { $lateWriter.Dispose(); $lateWriter = $null }
        } $restoreErrors
        Invoke-RestoreStep 'close section test handle' {
            if ($null -ne $sectionStream) { $sectionStream.Dispose(); $sectionStream = $null }
        } $restoreErrors
        Invoke-RestoreStep 'stop agent' {
            if ($null -ne $agent) { Stop-StagedTestAgent $agent; $agent = $null }
        } $restoreErrors
        if ($vhdAttached -and (Test-Path -LiteralPath $vhdxPath)) {
            Invoke-RestoreStep 'detach filter from test VHDX' {
                & fltmc.exe detach SafeUpload S: | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'fltmc detach failed.' }
            } $restoreErrors
            Invoke-RestoreStep 'detach test VHDX' {
                $detachScript = Join-Path $stateDirectory 'detach-vhd.txt'
                [IO.File]::WriteAllLines($detachScript,
                    @("select vdisk file=`"$vhdxPath`"", 'detach vdisk'), [Text.Encoding]::ASCII)
                $detachOutput = (& diskpart.exe /s $detachScript 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0 -or $detachOutput -match '(?im)\bVirtual Disk Service error\b|\bDiskPart has encountered an error\b') {
                    throw ('DiskPart detach failed: ' + ($detachOutput -replace '[\r\n]+', ' '))
                }
                for ($attempt = 0; $attempt -lt 40 -and (Test-Path -LiteralPath 'S:\'); ++$attempt) {
                    Start-Sleep -Milliseconds 250
                }
                if (Test-Path -LiteralPath 'S:\') { throw 'S: remains mounted after the detach attempt.' }
                Remove-Item -LiteralPath $vhdxPath -Force
            } $restoreErrors
        }
        Invoke-RestoreStep 'remove startup task' {
            if (Get-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue) {
                Stop-ScheduledTask -TaskName $bootTask -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $bootTask -Confirm:$false
            }
        } $restoreErrors
        Invoke-RestoreStep 'restore demand-start driver' { Set-DemandStartAndRestoreDriver } $restoreErrors
        Invoke-RestoreStep 'restore policy file' { Restore-PolicyFile } $restoreErrors
        Invoke-RestoreStep 'remove durable test policy' { Invoke-SystemRegistryCleanup } $restoreErrors
        Invoke-RestoreStep 'reset Driver Verifier' {
            & verifier.exe /reset | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Driver Verifier reset failed.' }
        } $restoreErrors
        Invoke-RestoreStep 'remove protected test folder' {
            Remove-Item -LiteralPath $protectedDirectory -Recurse -Force -ErrorAction SilentlyContinue
        } $restoreErrors
        Invoke-RestoreStep 'remove staged service package' {
            Remove-Item -LiteralPath $serviceDirectory -Recurse -Force -ErrorAction SilentlyContinue
        } $restoreErrors
        if ($restoreErrors.Count -gt 0) {
            throw ('Restoration needs attention: ' + ($restoreErrors -join ' | '))
        }
        Write-Output 'BootStartRestored=True'
        Write-Output 'BOOT_RESTORED=True'
    }
}
else {
    Assert-Debuggee
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $originalDriverHash -or
        (Get-ItemProperty "HKLM:\$registryService").Start -ne 3) {
        throw 'Final boot-start restoration did not return the original demand-start driver.'
    }
    if ((& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload should be unloaded after restoration.' }
    if (-not (Test-Path -LiteralPath $policyPath) -or
        (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash -ne $ExpectedOriginalPolicySha256.ToUpperInvariant()) {
        throw 'Final policy hash differs from the original.'
    }
    if (Test-Path -LiteralPath $parametersKey) { throw 'Test boot policy registry key remained after restoration.' }
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Agent process remained after restoration.' }
    if (@(Get-ScheduledTask | Where-Object {
        $_.TaskName -match '^SafeUpload-(BootStart|BootInspector|BootPolicyReader|BootRegistryCleanup|StagedTest|StagedCleanup)'
    }).Count -ne 0) {
        throw 'A boot-start experiment or agent task remained after restoration.'
    }
    if ((Test-Path -LiteralPath $protectedDirectory) -or (Test-Path -LiteralPath $serviceDirectory) -or
        (Test-Path -LiteralPath $vhdxPath) -or (Test-Path -LiteralPath 'S:\')) {
        throw 'A boot-start test folder, service package, VHDX, or S: mount remained after restoration.'
    }
    $verifier = (& verifier.exe /query 2>&1 | Out-String)
    if ($verifier -match 'Verifier Flags:\s+0x(?!0+)[0-9a-fA-F]+') { throw 'Verifier remains active after the clean restoration boot.' }
    Write-Output 'BOOT_FINAL_STATE=True'
    Write-Output ('FinalOriginalDriverSHA256=' + $originalDriverHash)
    Write-Output ('FinalPolicySHA256=' + (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash)
}
