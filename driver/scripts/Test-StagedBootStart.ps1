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
    [string] $TestAgentHelperFileName = 'StagedTestAgent.ps1',

    # Regression comparison only; qualification defaults to the product seeder.
    [switch] $ManualBootPolicy
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
$stateDirectory = Join-Path $documents 'SafeUpload-boot-start-state'
$statePath = Join-Path $stateDirectory 'state.json'
$bootWriteScript = Join-Path $stateDirectory 'first-boot-write.ps1'
$bootReadyResult = Join-Path $stateDirectory 'first-boot-readiness.json'
$bootWriteResult = Join-Path $stateDirectory 'first-boot-write.json'
$bootTask = 'SafeUpload-BootStart-X4'
$policyPath = 'C:\ProgramData\SafeUpload\policy.json'
$protectedDirectory = 'C:\SafeUploadBootStart\Protected'
$firstWritePath = $null
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(string deviceName, System.Text.StringBuilder target, int maxChars);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
        EntryPoint = "CreateFileMappingW")]
    public static extern IntPtr CreateWritableMapping(SafeFileHandle file, IntPtr attributes,
        uint protection, uint sizeHigh, uint sizeLow, IntPtr name);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint offsetHigh,
        uint offsetLow, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnmapViewOfFile(IntPtr address);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FlushViewOfFile(IntPtr address, UIntPtr size);

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

if (-not ('SafeUploadBootRawNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SafeUploadBootRawNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr attributes,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytes, out uint read, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long position, uint method);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize,
        IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
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

function Get-SecuritySddl([string] $Path, [bool] $Directory) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    return $acl.GetSecurityDescriptorSddlForm($sections)
}

function Set-ProtectedPolicyAcl {
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetAccessRuleProtection($true, $false)
    $directoryAcl.SetOwner($systemSid)
    $childFlags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid, [Security.AccessControl.FileSystemRights]::FullControl, $childFlags,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid, [Security.AccessControl.FileSystemRights]::FullControl, $childFlags,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath (Split-Path -Parent $policyPath) -AclObject $directoryAcl -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $policyPath)) {
        $created = [IO.File]::Open($policyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        $created.Dispose()
    }
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner($systemSid)
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $policyPath -AclObject $fileAcl -ErrorAction Stop

    foreach ($item in @(
        [pscustomobject]@{ Path = (Split-Path -Parent $policyPath); IsDirectory = $true },
        [pscustomobject]@{ Path = $policyPath; IsDirectory = $false }
    )) {
        $actual = Get-Acl -LiteralPath $item.Path -ErrorAction Stop
        $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $ownerSid = $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $expectedFlags = if ($item.IsDirectory) { $childFlags } else { [Security.AccessControl.InheritanceFlags]::None }
        $hasSystem = $false
        $hasAdministrators = $false
        if ($ownerSid -ne $systemSid.Value -or -not $actual.AreAccessRulesProtected -or $rules.Count -ne 2) {
            throw "Protected policy ACL read-back failed: $($item.Path) must be SYSTEM-owned with two explicit ACEs and a protected DACL."
        }
        foreach ($rule in $rules) {
            if ($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                $rule.InheritanceFlags -ne $expectedFlags -or
                $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
                throw "Protected policy ACL read-back found a non-exact ACE: $($item.Path)"
            }
            if ($rule.IdentityReference.Value -eq $systemSid.Value) { $hasSystem = $true }
            elseif ($rule.IdentityReference.Value -eq $administratorsSid.Value) { $hasAdministrators = $true }
            else { throw "Protected policy ACL read-back found an unexpected trustee: $($item.Path)" }
        }
        if (-not $hasSystem -or -not $hasAdministrators) {
            throw "Protected policy ACL read-back is missing SYSTEM or Administrators: $($item.Path)"
        }
    }
    Write-Output 'PolicyAclVerified=True;Trustees=SYSTEM,Administrators;InheritedAces=0'
}

function Get-FirstLcn([string] $Path) {
    $handle = [SafeUploadBootRawNative]::CreateFileW($Path, [uint32]128, [uint32]7,
        [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) {
        throw 'FSCTL_GET_RETRIEVAL_POINTERS open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    $input = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($input, 0)
        [uint32]$returned = 0
        if (-not [SafeUploadBootRawNative]::DeviceIoControl($handle, [uint32]0x00090073,
            $input, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
            throw 'FSCTL_GET_RETRIEVAL_POINTERS failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if ([Runtime.InteropServices.Marshal]::ReadInt32($output, 0) -lt 1) {
            throw 'The raw observer requires a non-resident file with an allocated extent.'
        }
        return [Runtime.InteropServices.Marshal]::ReadInt64($output, 24)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($input)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($output)
        [void][SafeUploadBootRawNative]::CloseHandle($handle)
    }
}

function Read-RawVolumeBytes([string] $DriveLetter, [long] $Lcn, [int] $ClusterSize, [int] $Length) {
    if ($ClusterSize -lt 4096 -or ($ClusterSize % 4096) -ne 0 -or $Length -le 0 -or $Length -gt $ClusterSize) {
        throw 'The raw observer requires one allocated NTFS cluster and a 4 KiB aligned read.'
    }
    $handle = [SafeUploadBootRawNative]::CreateFileW("\\.\${DriveLetter}:", [uint32]2147483648,
        [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) {
        throw 'Unbuffered raw-volume open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    $buffer = [SafeUploadBootRawNative]::VirtualAlloc([IntPtr]::Zero,
        [UIntPtr]::new([uint64]$ClusterSize), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) {
        [void][SafeUploadBootRawNative]::CloseHandle($handle)
        throw 'Unbuffered raw-volume VirtualAlloc failed.'
    }
    try {
        [long]$position = 0
        if (-not [SafeUploadBootRawNative]::SetFilePointerEx($handle, $Lcn * $ClusterSize,
            [ref]$position, 0)) {
            throw 'Unbuffered raw-volume seek failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        [uint32]$read = 0
        if (-not [SafeUploadBootRawNative]::ReadFile($handle, $buffer, [uint32]$ClusterSize,
            [ref]$read, [IntPtr]::Zero) -or $read -lt $Length) {
            throw 'Unbuffered raw-volume read failed or was short: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $bytes = New-Object byte[] $Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
        return ,$bytes
    }
    finally {
        [void][SafeUploadBootRawNative]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadBootRawNative]::CloseHandle($handle)
    }
}

function Compare-Bytes([byte[]] $Expected, [byte[]] $Actual) {
    if ($Expected.Length -ne $Actual.Length) { throw 'Raw byte lengths differ.' }
    $changed = 0
    $firstChanged = -1
    for ($index = 0; $index -lt $Expected.Length; $index++) {
        if ($Expected[$index] -ne $Actual[$index]) {
            $changed++
            if ($firstChanged -lt 0) { $firstChanged = $index }
        }
    }
    return [pscustomobject]@{
        State = if ($changed -eq 0) { 'IDENTICAL_TO_BASELINE' } else { 'BYTES_CHANGED' }
        ByteCount = $Expected.Length
        DifferentBytes = $changed
        FirstDifferentOffset = $firstChanged
        ActualSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($Actual)).Replace('-', '')
    }
}

function Invoke-RestoreStep([string] $Name, [scriptblock] $Action,
    [System.Collections.Generic.List[string]] $Errors) {
    try { & $Action }
    catch { [void]$Errors.Add($Name + ': ' + $_.Exception.Message) }
}

function Set-AgentServiceStart([object] $StartValue) {
    if ($null -eq $StartValue) { return }
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
    if (-not (Test-Path -LiteralPath $serviceKey)) { throw 'SafeUploadAgent service disappeared before its start type was restored.' }
    $startName = switch ([int]$StartValue) {
        2 { 'auto' }
        3 { 'demand' }
        4 { 'disabled' }
        default { throw "Unsupported original SafeUploadAgent start value: $StartValue" }
    }
    & sc.exe config SafeUploadAgent start= $startName | Out-Host
    if ($LASTEXITCODE -ne 0 -or (Get-ItemProperty -LiteralPath $serviceKey).Start -ne [int]$StartValue) {
        throw "Could not set SafeUploadAgent start type to $startName."
    }
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

function Invoke-ProductBootPolicySeedAsSystem {
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-BootPolicySeed-' + $id
    $launcher = Join-Path $stateDirectory ('policy-seed-' + $id + '.ps1')
    $outPath = $launcher + '.out'
    $errPath = $launcher + '.err'
    $exitPath = $launcher + '.exit'
    $errorPath = $launcher + '.error'
    $body = @'
$ErrorActionPreference = 'Stop'
$process = $null
$exitCode = -1
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        if ($identity.User.Value -ne 'S-1-5-18') { throw 'Boot policy seed task is not LocalSystem.' }
    }
    finally { $identity.Dispose() }
    # Seed mode requires exactly this one argument; do not use the normal service launcher.
    $process = Start-Process -FilePath '__EXE__' -ArgumentList '--seed-boot-policy' -PassThru `
        -WorkingDirectory '__DIR__' -WindowStyle Hidden -RedirectStandardOutput '__OUT__' -RedirectStandardError '__ERR__'
    # Retain the process handle so ExitCode remains available in Windows PowerShell 5.1.
    $null = $process.Handle
    if (-not $process.WaitForExit(45000)) { throw 'Product boot policy seed exceeded 45 seconds.' }
    $process.WaitForExit()
    if ($null -eq $process.ExitCode) { throw 'Product boot policy seed returned no exit code.' }
    $exitCode = $process.ExitCode
}
catch {
    [IO.File]::WriteAllText('__ERROR__', (($_ | Out-String) + $_.Exception.ToString() + "`r`n" + $_.ScriptStackTrace))
}
finally {
    try {
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }
    catch {
        $exitCode = -1
        [IO.File]::AppendAllText('__ERROR__', (($_ | Out-String) + $_.Exception.ToString() + "`r`n" + $_.ScriptStackTrace))
    }
    # Completion marker is written last, after the redirected output has closed.
    [IO.File]::WriteAllText('__EXIT__', [string]$exitCode)
}
'@
    $body = $body.Replace('__EXE__', (ConvertTo-PowerShellLiteral (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe')))
    $body = $body.Replace('__DIR__', (ConvertTo-PowerShellLiteral $serviceDirectory))
    $body = $body.Replace('__OUT__', (ConvertTo-PowerShellLiteral $outPath))
    $body = $body.Replace('__ERR__', (ConvertTo-PowerShellLiteral $errPath))
    $body = $body.Replace('__EXIT__', (ConvertTo-PowerShellLiteral $exitPath))
    $body = $body.Replace('__ERROR__', (ConvertTo-PowerShellLiteral $errorPath))
    Set-Content -LiteralPath $launcher -Value $body -Encoding UTF8
    $registered = $false
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while (-not (Test-Path -LiteralPath $exitPath) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if (-not (Test-Path -LiteralPath $exitPath)) {
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            throw ('SYSTEM product boot policy seed timed out; task result ' + $info.LastTaskResult)
        }
        $exitText = [IO.File]::ReadAllText($exitPath)
        if ($exitText -notmatch '^-?[0-9]+$') { throw 'SYSTEM product boot policy seed wrote an invalid exit code.' }
        $exitCode = [int]$exitText
        if ($exitCode -ne 0 -or (Test-Path -LiteralPath $errorPath) -or
            -not (Test-Path -LiteralPath $outPath) -or -not (Test-Path -LiteralPath $errPath)) {
            throw ('SYSTEM product boot policy seed failed; exit code ' + $exitCode)
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            StdOut = [IO.File]::ReadAllText($outPath)
            StdErr = [IO.File]::ReadAllText($errPath)
        }
    }
    catch {
        $failure = $_.Exception.Message
        $captured = foreach ($item in @(
            [pscustomobject]@{ Label = 'stdout'; Path = $outPath },
            [pscustomobject]@{ Label = 'stderr'; Path = $errPath },
            [pscustomobject]@{ Label = 'exit code'; Path = $exitPath },
            [pscustomobject]@{ Label = 'launcher error'; Path = $errorPath }
        )) {
            $value = if (Test-Path -LiteralPath $item.Path) { [IO.File]::ReadAllText($item.Path) } else { '<missing>' }
            $item.Label + ":`r`n" + $value
        }
        throw ($failure + "`r`n" + ($captured -join "`r`n"))
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$outPath,$errPath,$exitPath,$errorPath -Force -ErrorAction SilentlyContinue
    }
}

function Wait-AgentPolicyAccepted([string] $LogPrefix, [int] $ExpectedPrefixCount = 1) {
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
        $hasCscope = @($readback.Prefixes | Where-Object { $_ -match '(?i)SafeUploadBootStart\\Protected' }).Count -gt 0
        $hasSscope = $ExpectedPrefixCount -lt 2 -or
            @($readback.Prefixes | Where-Object { $_ -match '(?i)SafeUploadBootStart\\E1Protected' }).Count -gt 0
        if (-not $readback.AclValid -or $readback.PendingPresent -or $readback.Version -ne 1 -or
            $readback.StructSize -ne 16656 -or $readback.PrefixCount -ne $ExpectedPrefixCount -or
            $readback.Flags -ne 0 -or -not $hasCscope -or -not $hasSscope) {
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
    $errorPath = $launcher + '.error'
    $donePath = $launcher + '.done'
    $body = @'
$ErrorActionPreference = 'Stop'
try {
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
            $rule.RegistryRights -ne [Security.AccessControl.RegistryRights]::FullControl) { $rulesOk = $false }
        $sidSet += $rule.IdentityReference.Value
    }
    $expected = @('S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    return ($owner -eq 'S-1-5-18' -and $security.AreAccessRulesProtected -and $rulesOk -and
        (($sidSet | Sort-Object) -join ';') -eq (($expected | Sort-Object) -join ';'))
}
try {
    $record = $key.GetValue('Scopes', $null)
    $pendingPresent = $key.GetValueNames() -contains 'PendingScopes'
    if ($record -isnot [byte[]]) { throw 'Scopes is not REG_BINARY.' }
    $policyAclValid = Test-ExactSystemTiAcl $key
    $parametersAclValid = Test-ExactSystemTiAcl $parent
    $prefixes = @()
    $prefix = ''
    if ($record.Length -ne 16656) { throw 'Scopes has the wrong record size.' }
    $prefixCount = [BitConverter]::ToUInt32($record, 8)
    if ($prefixCount -gt 32) { throw 'Scopes prefix count exceeds the fixed record capacity.' }
    for ($scopeIndex = 0; $scopeIndex -lt $prefixCount; $scopeIndex++) {
        $scopePrefix = ''
        $slotStart = 16 + ($scopeIndex * 520)
        for ($i = $slotStart; $i -lt ($slotStart + 520); $i += 2) {
            $codeUnit = [BitConverter]::ToUInt16($record, $i)
            if ($codeUnit -eq 0) { break }
            $scopePrefix += [char]$codeUnit
        }
        $prefixes += $scopePrefix
    }
    if ($prefixes.Count -gt 0) { $prefix = $prefixes[0] }
    $result = [ordered]@{
        AclValid = $policyAclValid -and $parametersAclValid
        BootPolicyAclValid = $policyAclValid
        ParametersAclValid = $parametersAclValid
        Owner = $key.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value
        RecordBytes = $record.Length
        RecordBase64 = [Convert]::ToBase64String($record)
        DriverStart = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload' -ErrorAction Stop).Start
        PrefixCount = $prefixCount
        Flags = [BitConverter]::ToUInt32($record, 12)
        StructSize = [BitConverter]::ToUInt32($record, 4)
        Version = [BitConverter]::ToUInt32($record, 0)
        PendingPresent = $pendingPresent
        Prefix = $prefix
        Prefixes = @($prefixes)
    }
    $result | ConvertTo-Json -Compress | Set-Content -LiteralPath '__OUT__' -Encoding UTF8
}
finally { $key.Dispose(); $parent.Dispose() }
}
catch {
    [IO.File]::WriteAllText('__ERROR__', (($_ | Out-String) + $_.Exception.ToString() + "`r`n" + $_.ScriptStackTrace))
}
finally { [IO.File]::WriteAllText('__DONE__', 'done') }
'@
    $body = $body.Replace('__OUT__', (ConvertTo-PowerShellLiteral $outputPath))
    $body = $body.Replace('__ERROR__', (ConvertTo-PowerShellLiteral $errorPath))
    $body = $body.Replace('__DONE__', (ConvertTo-PowerShellLiteral $donePath))
    Set-Content -LiteralPath $launcher -Value $body -Encoding UTF8
    $registered = $false
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $donePath); ++$attempt) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $donePath)) { throw 'SYSTEM boot-policy read-back timed out.' }
        if (Test-Path -LiteralPath $errorPath) { throw ('SYSTEM boot-policy read-back failed: ' + [IO.File]::ReadAllText($errorPath)) }
        if (-not (Test-Path -LiteralPath $outputPath)) { throw 'SYSTEM boot-policy read-back produced no record.' }
        return Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$outputPath,$errorPath,$donePath -Force -ErrorAction SilentlyContinue
    }
}

function Write-BootPolicyAsSystem([string] $Prefix) {
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-BootPolicyWriter-' + $id
    $launcher = Join-Path $stateDirectory ('policy-writer-' + $id + '.ps1')
    $outputPath = $launcher + '.json'
    $body = @'
$ErrorActionPreference = 'Stop'
try {
$servicePath = 'SYSTEM\CurrentControlSet\Services\SafeUpload'
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$installerSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$security = [Security.AccessControl.RegistrySecurity]::new()
$security.SetAccessRuleProtection($true, $false)
$security.SetOwner($systemSid)
$security.SetAccessRule([Security.AccessControl.RegistryAccessRule]::new($systemSid,
    [Security.AccessControl.RegistryRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
$security.SetAccessRule([Security.AccessControl.RegistryAccessRule]::new($installerSid,
    [Security.AccessControl.RegistryRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
function Test-ExactSystemTiAcl($registryKey) {
    $acl = $registryKey.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access)
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($owner -ne 'S-1-5-18' -or -not $acl.AreAccessRulesProtected -or $rules.Count -ne 2) { return $false }
    $seenSystem = $false
    $seenInstaller = $false
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.IsInherited -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
            $rule.RegistryRights -ne [Security.AccessControl.RegistryRights]::FullControl) { return $false }
        if ($rule.IdentityReference.Value -eq 'S-1-5-18') { $seenSystem = $true }
        elseif ($rule.IdentityReference.Value -eq 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') { $seenInstaller = $true }
        else { return $false }
    }
    return ($seenSystem -and $seenInstaller)
}
$service = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($servicePath, $true)
if ($null -eq $service) { throw 'SafeUpload service registry key is missing.' }
$parameters = $null
$policy = $null
try {
    $parameters = $service.CreateSubKey('Parameters', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [Microsoft.Win32.RegistryOptions]::None, $security)
    if ($null -eq $parameters) { throw 'Could not create Parameters.' }
    $parameters.SetAccessControl($security)
    $parameters.Flush()
    $policy = $parameters.CreateSubKey('BootPolicy', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [Microsoft.Win32.RegistryOptions]::None, $security)
    if ($null -eq $policy) { throw 'Could not create BootPolicy.' }
    $policy.SetAccessControl($security)
    $bytes = New-Object byte[] 16656
    [BitConverter]::GetBytes([uint32]1).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint32]16656).CopyTo($bytes, 4)
    [BitConverter]::GetBytes([uint32]1).CopyTo($bytes, 8)
    [BitConverter]::GetBytes([uint32]0).CopyTo($bytes, 12)
    $prefix = '__PREFIX__'
    $prefixBytes = [Text.Encoding]::Unicode.GetBytes($prefix)
    if ($prefixBytes.Length -gt 518) { throw 'Boot scope prefix exceeds its 260 WCHAR slot.' }
    [Array]::Copy($prefixBytes, 0, $bytes, 16, $prefixBytes.Length)
    $policy.SetValue('Scopes', $bytes, [Microsoft.Win32.RegistryValueKind]::Binary)
    $policy.Flush()
    $parameters.Flush()
    $readback = $policy.GetValue('Scopes', $null)
    $result = [ordered]@{
        ParametersAclValid = (Test-ExactSystemTiAcl $parameters)
        BootPolicyAclValid = (Test-ExactSystemTiAcl $policy)
        Version = [BitConverter]::ToUInt32($readback, 0)
        StructSize = [BitConverter]::ToUInt32($readback, 4)
        PrefixCount = [BitConverter]::ToUInt32($readback, 8)
        Prefix = $prefix
        RecordBytes = $readback.Length
        ReadbackMatches = [Convert]::ToBase64String($bytes) -eq [Convert]::ToBase64String($readback)
    }
    [IO.File]::WriteAllText('__OUT__', ($result | ConvertTo-Json -Compress), [Text.Encoding]::UTF8)
}
finally {
    if ($null -ne $policy) { $policy.Dispose() }
    if ($null -ne $parameters) { $parameters.Dispose() }
    $service.Dispose()
}
}
catch {
    # Run 5 timed out silently: report the SYSTEM-side failure instead.
    [IO.File]::WriteAllText('__OUT__', (@{ WriterError = ($_.Exception.GetType().FullName + ': ' + $_.Exception.Message + ' @ ' + $_.ScriptStackTrace) } | ConvertTo-Json -Compress), [Text.Encoding]::UTF8)
}
'@
    $body = $body.Replace('__PREFIX__', (ConvertTo-PowerShellLiteral $Prefix))
    $body = $body.Replace('__OUT__', (ConvertTo-PowerShellLiteral $outputPath))
    Set-Content -LiteralPath $launcher -Value $body -Encoding UTF8
    $registered = $false
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $outputPath); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $outputPath)) { throw 'SYSTEM boot-policy writer timed out.' }
        $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
        if ($result.PSObject.Properties.Name -contains 'WriterError') { throw ('SYSTEM boot-policy writer failed: ' + $result.WriterError) }
        if (-not $result.ParametersAclValid -or -not $result.BootPolicyAclValid -or
            -not $result.ReadbackMatches -or $result.PrefixCount -ne 1 -or $result.Version -ne 1 -or
            $result.StructSize -ne 16656 -or $result.RecordBytes -ne 16656) {
            throw 'SYSTEM boot-policy writer read-back or exact ACL verification failed.'
        }
        return $result
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

function Wait-AdmissionVolume([string] $Guid, [int] $ExpectedTrustState = 3) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $status = Invoke-InspectorAsSystem
        $entry = Find-AdmissionVolume $status $Guid
        $canaryReady = $ExpectedTrustState -ne 3 -or
            ($null -ne $entry -and $entry.canaryState -eq 2)
        if ($null -ne $entry -and $entry.trustState -eq $ExpectedTrustState -and $canaryReady) {
            return [pscustomobject]@{ Status = $status; Entry = $entry }
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Volume $Guid did not reach trust state $ExpectedTrustState."
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
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group -bor
        [Security.AccessControl.AccessControlSections]::Access
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetSecurityDescriptorSddlForm([string]$state.OriginalPolicyFileSddl, $sections)
    Set-Acl -LiteralPath $policyPath -AclObject $fileAcl -ErrorAction Stop
    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetSecurityDescriptorSddlForm([string]$state.OriginalPolicyDirectorySddl, $sections)
    Set-Acl -LiteralPath (Split-Path -Parent $policyPath) -AclObject $directoryAcl -ErrorAction Stop
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
    $agentServiceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
    $originalAgentStart = if (Test-Path -LiteralPath $agentServiceKey) {
        $agentService = Get-Service -Name 'SafeUploadAgent' -ErrorAction Stop
        if ($agentService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw 'SafeUploadAgent must be stopped before the checkpointed boot-path experiment.'
        }
        [int](Get-ItemProperty -LiteralPath $agentServiceKey).Start
    } else { $null }

    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    Backup-StagedTestDriver (Join-Path $stateDirectory 'SafeUpload.original.sys')
    $x4RunId = [guid]::NewGuid().ToString('N')
    $x4Directory = Join-Path $protectedDirectory ('X4-' + $x4RunId)
    $firstWritePath = Join-Path $x4Directory 'marker.bin'
    $x4Baseline = [Text.Encoding]::ASCII.GetBytes(('BASELINE-' + $x4RunId).PadRight(4096, 'B'))
    $x4Attempt = [Text.Encoding]::ASCII.GetBytes(('ATTEMPT-' + $x4RunId).PadRight(4096, 'A'))
    $originalPolicy = if (Test-Path -LiteralPath $policyPath) {
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($policyPath))
    } else { $null }
    $state = [ordered]@{
        PreparedUtc = [DateTime]::UtcNow.ToString('o')
        OriginalStart = 3
        OriginalAgentStart = $originalAgentStart
        OriginalPolicyBase64 = $originalPolicy
        OriginalPolicyDirectorySddl = Get-SecuritySddl (Split-Path -Parent $policyPath) $true
        OriginalPolicyFileSddl = Get-SecuritySddl $policyPath $false
        ExpectedOriginalPolicySha256 = $ExpectedOriginalPolicySha256.ToUpperInvariant()
        FeatureSha256 = $ExpectedFeatureSha256.ToUpperInvariant()
        InspectorSha256 = $ExpectedInspectorSha256.ToUpperInvariant()
        ServicePackageSha256 = $ExpectedServicePackageSha256.ToUpperInvariant()
        X4RunId = $x4RunId
        X4MarkerPath = $firstWritePath
        X4BaselineBase64 = [Convert]::ToBase64String($x4Baseline)
        X4AttemptBase64 = [Convert]::ToBase64String($x4Attempt)
        CVolumeGuid = Get-VolumeGuid 'C'
    }
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
    try {
    if ($null -ne $originalAgentStart) { Set-AgentServiceStart 3 }
    New-Item -ItemType Directory -Force -Path $protectedDirectory | Out-Null
    New-Item -ItemType Directory -Path $x4Directory | Out-Null

    if (-not (Test-Path -LiteralPath $serviceDirectory)) { New-Item -ItemType Directory -Path $serviceDirectory | Out-Null }
    Expand-Archive -LiteralPath $servicePackage -DestinationPath $serviceDirectory -Force
    if (-not (Test-Path -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'))) {
        throw 'Published agent executable is missing.'
    }

    $policyDirectory = Split-Path -Parent $policyPath
    New-Item -ItemType Directory -Force -Path $policyDirectory | Out-Null
    Set-ProtectedPolicyAcl
    $testPolicy = [ordered]@{
        version = 1
        activeCategories = @('Cpf')
        monitoredScopes = [ordered]@{
            extensions = @('.txt')
            # LocalPolicyStore -> PolicyBuilder preserves this suffix (no trailing slash).
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
    $x4Stream = [IO.FileStream]::new($firstWritePath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::WriteThrough)
    try {
        $x4Stream.Write($x4Baseline, 0, $x4Baseline.Length)
        $x4Stream.Flush($true)
    }
    finally { $x4Stream.Dispose() }
    $x4Volume = Get-Volume -DriveLetter C -ErrorAction Stop
    $x4ClusterSize = [int]$x4Volume.AllocationUnitSize
    $x4Lcn = Get-FirstLcn $firstWritePath
    $x4RawBaseline = Read-RawVolumeBytes 'C' $x4Lcn $x4ClusterSize $x4Baseline.Length
    if ((Compare-Bytes $x4Baseline $x4RawBaseline).State -ne 'IDENTICAL_TO_BASELINE') {
        throw 'X4 raw-volume baseline does not match the preboot marker file.'
    }
    $state['X4Lcn'] = $x4Lcn
    $state['X4ClusterSize'] = $x4ClusterSize
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
    Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
        throw 'Feature driver did not install byte-for-byte.'
    }
    $deviceName = [Text.StringBuilder]::new(1024)
    if ([SafeUploadBootSectionNative]::QueryDosDevice('C:', $deviceName, $deviceName.Capacity) -eq 0) {
        throw 'QueryDosDevice could not resolve the C: boot volume for its durable registry scope.'
    }
    $devicePath = $deviceName.ToString().Split([char]0)[0].TrimEnd('\')
    $bootPrefix = $devicePath + '\SafeUploadBootStart\Protected'
    if ((Get-ItemProperty "HKLM:\$registryService").Start -ne 3) {
        throw 'The driver must remain demand-start before boot policy seeding.'
    }
    $seedCapture = ''
    if ($ManualBootPolicy) { $null = Write-BootPolicyAsSystem $bootPrefix }
    else {
        $seed = Invoke-ProductBootPolicySeedAsSystem
        $seedCapture = "Product seed exit code: $($seed.ExitCode)`r`nstdout:`r`n$($seed.StdOut)`r`nstderr:`r`n$($seed.StdErr)"
        Write-Output $seedCapture
    }
    try {
        # Independent oracle: compare ALL bytes, including the first slot's tail and all unused slots.
        $expectedRecord = New-Object byte[] 16656
        [BitConverter]::GetBytes([uint32]1).CopyTo($expectedRecord, 0)
        [BitConverter]::GetBytes([uint32]16656).CopyTo($expectedRecord, 4)
        [BitConverter]::GetBytes([uint32]1).CopyTo($expectedRecord, 8)
        $prefixBytes = [Text.Encoding]::Unicode.GetBytes($bootPrefix)
        if ($prefixBytes.Length -gt 518) { throw 'Boot scope prefix exceeds its 260 WCHAR slot.' }
        [Array]::Copy($prefixBytes, 0, $expectedRecord, 16, $prefixBytes.Length)
        $readback = Get-BootPolicyReadbackAsSystem
        if (-not $readback.ParametersAclValid -or -not $readback.BootPolicyAclValid -or
            $readback.PendingPresent -or $readback.RecordBytes -ne 16656 -or
            $readback.Version -ne 1 -or $readback.StructSize -ne 16656 -or
            $readback.PrefixCount -ne 1 -or $readback.Flags -ne 0 -or
            $readback.Prefix -cne $bootPrefix -or
            $readback.RecordBase64 -cne [Convert]::ToBase64String($expectedRecord)) {
            throw 'Seeded preboot Scopes failed independent exact record or registry ACL read-back.'
        }
        if ($readback.DriverStart -ne 3 -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 3) {
            throw 'Boot policy seeding changed the driver Start value; expected demand-start (3).'
        }
        if ((& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s' -or
            @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'Boot policy seeding left the filter loaded or an agent process running.'
        }
    }
    catch { throw ($_.Exception.Message + "`r`n" + $seedCapture) }
    Write-Output 'BootPolicyPrebootVerified=ParametersAcl:True;BootPolicyAcl:True;RecordBytes:16656;ExactRecord:True;PendingScopes:Absent;Start:3;PASS'
    if ($ManualBootPolicy) { Write-Output 'BootPolicySeed=manual-writer;PASS' }
    else { Write-Output 'BootPolicySeed=product-mode;ExitCode:0;PASS' }
    Write-Output ('TestPolicyStagedWithoutLoading=True;Prefix=' + $bootPrefix +
        ';RegistryRecordBytes=' + $readback.RecordBytes)

    # Only the harness activates boot start, after the seed and independent read-back.
    & sc.exe config SafeUpload start= boot | Out-Host
    if ($LASTEXITCODE -ne 0 -or (Get-ItemProperty "HKLM:\$registryService").Start -ne 0) {
        throw 'Could not stage the test driver as boot start.'
    }
    # Boot review N-03: assert every service setting the boot depends on before requesting the reboot.
    $svc = Get-ItemProperty "HKLM:\$registryService"
    if ($svc.Start -ne 0 -or $svc.ErrorControl -ne 1 -or $svc.Group -ne 'FSFilter Anti-Virus' -or
        @($svc.DependOnService).Count -ne 1 -or @($svc.DependOnService)[0] -ne 'FltMgr' -or $svc.Type -ne 2) {
        throw ('Boot service settings are not as required: Start=' + $svc.Start + ';ErrorControl=' + $svc.ErrorControl +
            ';Group=' + $svc.Group + ';Depend=' + (@($svc.DependOnService) -join ',') + ';Type=' + $svc.Type)
    }
    Write-Output ('BootServiceSettings=Start:0;ErrorControl:1;Group:FSFilter Anti-Virus;Depend:FltMgr;Type:2;PASS')
    if ((Get-ItemProperty "HKLM:\$registryService").Start -ne 0) {
        throw 'The test driver no longer has boot start configured.'
    }

    $startupBody = @'
$ErrorActionPreference = 'Stop'
$target = '__TARGET__'
$readyPath = '__READY__'
$resultPath = '__RESULT__'
$inspectorPath = '__INSPECTOR__'
$volumeGuid = '__VOLUME_GUID__'
$marker = [Convert]::FromBase64String('__MARKER__')
$bootUtc = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
$deadline = [DateTime]::UtcNow.AddSeconds(180)
$ready = $false
$lastStatus = $null
$lastEntry = $null
$lastStatusError = ''
$statusOut = $resultPath + '.status'
$statusErr = $resultPath + '.status.err'
$instances = ''
do {
    $instances = (& fltmc.exe instances -f SafeUpload 2>&1 | Out-String)
    try {
        Remove-Item -LiteralPath $statusOut,$statusErr -Force -ErrorAction SilentlyContinue
        $probe = Start-Process -FilePath $inspectorPath -ArgumentList '--admission-volume-status' -PassThru -Wait `
            -WindowStyle Hidden -RedirectStandardOutput $statusOut -RedirectStandardError $statusErr
        if ($probe.ExitCode -eq 0 -and (Test-Path -LiteralPath $statusOut)) {
            $lastStatus = Get-Content -LiteralPath $statusOut -Raw | ConvertFrom-Json
            $lastEntry = @($lastStatus.admissionVolumes | Where-Object {
                ([string]$_.volumeGuid).ToLowerInvariant().Contains($volumeGuid.ToLowerInvariant())
            } | Select-Object -First 1)
            if ($lastEntry.Count -gt 0) { $lastEntry = $lastEntry[0] } else { $lastEntry = $null }
            $ready = $lastStatus.bootPolicyState -eq 1 -and $null -ne $lastEntry -and
                $lastEntry.trustState -eq 3 -and $lastEntry.canaryState -eq 2 -and
                ($lastEntry.setupFlags -band 4) -ne 0 -and $instances -match '(?m)\bC:\s'
        }
        else { $lastStatusError = 'InspectorExit=' + $probe.ExitCode }
    }
    catch { $lastStatusError = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message }
    if (-not $ready) { Start-Sleep -Milliseconds 500 }
} while (-not $ready -and [DateTime]::UtcNow -lt $deadline)

$readyUtc = [DateTime]::UtcNow
$readiness = [ordered]@{
    BootUtc = $bootUtc.ToString('o')
    RecordedUtc = $readyUtc.ToString('o')
    FilterReady = $ready
    BootPolicyState = if ($null -ne $lastStatus) { $lastStatus.bootPolicyState } else { -1 }
    TrustState = if ($null -ne $lastEntry) { $lastEntry.trustState } else { -1 }
    CanaryState = if ($null -ne $lastEntry) { $lastEntry.canaryState } else { -1 }
    SetupFlags = if ($null -ne $lastEntry) { $lastEntry.setupFlags } else { 0 }
    VolumeGuid = if ($null -ne $lastEntry) { $lastEntry.volumeGuid } else { '' }
    StatusError = $lastStatusError
    InstanceOutput = ($instances -replace '[\r\n]+', ' ').Trim()
}
$readyBytes = [Text.UTF8Encoding]::new($false).GetBytes(($readiness | ConvertTo-Json -Compress -Depth 4))
$readyStream = [IO.FileStream]::new($readyPath, [IO.FileMode]::Create, [IO.FileAccess]::Write,
    [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
try { $readyStream.Write($readyBytes, 0, $readyBytes.Length); $readyStream.Flush($true) }
finally { $readyStream.Dispose() }

$attemptUtc = [DateTime]::UtcNow
$writeResult = 'NotAttemptedBeforeReadiness'
$writeError = ''
$writeErrorType = ''
if ($ready) {
    try {
        $stream = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        try {
            $stream.Position = 0
            $stream.Write($marker, 0, $marker.Length)
            $stream.SetLength($marker.Length)
            $stream.Flush($true)
            $writeResult = 'Succeeded'
        }
        finally { $stream.Dispose() }
    }
    catch {
        $writeResult = 'Denied'
        # PowerShell wraps .NET method failures in MethodInvocationException (run 9: the denial itself was real).
        $ex = $_.Exception
        if ($ex -is [Management.Automation.MethodInvocationException] -and $null -ne $ex.InnerException) { $ex = $ex.InnerException }
        $writeErrorType = $ex.GetType().FullName
        $writeError = $writeErrorType + ': ' + $ex.Message
    }
}
$result = [ordered]@{
    ReadinessRecordDurable = $true
    ReadinessRecordPath = $readyPath
    Readiness = $readiness
    FirstWriteAttemptUtc = $attemptUtc.ToString('o')
    WriteResult = $writeResult
    WriteError = $writeError
    WriteErrorType = $writeErrorType
    AttemptMarkerSha256 = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($marker)).Replace('-', '')
}
$resultBytes = [Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Compress -Depth 4))
$resultStream = [IO.FileStream]::new($resultPath, [IO.FileMode]::Create, [IO.FileAccess]::Write,
    [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
try { $resultStream.Write($resultBytes, 0, $resultBytes.Length); $resultStream.Flush($true) }
finally { $resultStream.Dispose() }
'@
    $startupBody = $startupBody.Replace('__TARGET__', (ConvertTo-PowerShellLiteral $firstWritePath))
    $startupBody = $startupBody.Replace('__READY__', (ConvertTo-PowerShellLiteral $bootReadyResult))
    $startupBody = $startupBody.Replace('__RESULT__', (ConvertTo-PowerShellLiteral $bootWriteResult))
    $startupBody = $startupBody.Replace('__INSPECTOR__', (ConvertTo-PowerShellLiteral $inspectorPath))
    $startupBody = $startupBody.Replace('__VOLUME_GUID__', (ConvertTo-PowerShellLiteral $state.CVolumeGuid))
    $startupBody = $startupBody.Replace('__MARKER__', [Convert]::ToBase64String($x4Attempt))
    Set-Content -LiteralPath $bootWriteScript -Value $startupBody -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $bootWriteScript + '"')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2))
    Register-ScheduledTask -TaskName $bootTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null

    # verifier.exe returns 2 (EXIT_CODE_REBOOT_NEEDED) for a successful boot-time configuration (run 7), 1 for an error.
    & verifier.exe /standard /driver SafeUpload.sys | Out-Host
    if ($LASTEXITCODE -notin @(0, 2)) { throw ('Could not configure standard boot Verifier for SafeUpload.sys (exit ' + $LASTEXITCODE + ').') }
    & verifier.exe /bootmode oneboot | Out-Host
    if ($LASTEXITCODE -notin @(0, 2)) { throw ('Could not configure one-boot Verifier mode (exit ' + $LASTEXITCODE + ').') }
    # /query shows only ACTIVE verification; the settings that apply at the next boot are in /querysettings.
    $verifier = (& verifier.exe /querysettings 2>&1 | Out-String)
    Write-Output ('BootVerifierSettings=' + (($verifier -replace '\s+',' ').Trim()))
    if ($verifier -notmatch 'SafeUpload\.sys' -or $verifier -notmatch 'Verifier Flags:\s+0x(?!0+\b)[0-9a-fA-F]+') {
        throw 'Boot Verifier configuration did not report SafeUpload.sys and nonzero flags for the next boot.'
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
            Invoke-RestoreStep 'restore SafeUploadAgent startup type' { Set-AgentServiceStart $state.OriginalAgentStart } $rollbackErrors
        }
        if (Test-Path -LiteralPath $parametersKey) {
            Invoke-RestoreStep 'remove durable test policy' { Invoke-SystemRegistryCleanup } $rollbackErrors
        }
        Invoke-RestoreStep 'reset Driver Verifier' {
            & verifier.exe /reset | Out-Host
            if ($LASTEXITCODE -notin @(0, 2)) { throw ('Driver Verifier reset failed during rollback (exit ' + $LASTEXITCODE + ').') }
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
        if ($rollbackErrors.Count -eq 0) {
            # A clean rollback leaves no residue that would make the next attempt refuse ("A prior boot-start state directory exists").
            Invoke-RestoreStep 'remove boot-start state and empty test parent' {
                Remove-Item -LiteralPath $stateDirectory -Recurse -Force -ErrorAction Stop
                $parent = Split-Path -Parent $protectedDirectory
                if ((Test-Path -LiteralPath $parent) -and @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
                    Remove-Item -LiteralPath $parent -Force -ErrorAction Stop
                }
            } $rollbackErrors
        }
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
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $firstWritePath = [string]$state.X4MarkerPath
    $agent = $null
    $sectionStream = $null
    $lateWriter = $null
    $lateMapping = [IntPtr]::Zero
    $lateView = [IntPtr]::Zero
    $vhdAttached = $false
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(240)
        while ((-not (Test-Path -LiteralPath $bootReadyResult) -or -not (Test-Path -LiteralPath $bootWriteResult)) -and
            [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $bootReadyResult) -or -not (Test-Path -LiteralPath $bootWriteResult)) {
            throw 'At-startup X4 probe did not durably record readiness and its result.'
        }
        $readiness = Get-Content -LiteralPath $bootReadyResult -Raw | ConvertFrom-Json
        $first = Get-Content -LiteralPath $bootWriteResult -Raw | ConvertFrom-Json
        $baselineBytes = [Convert]::FromBase64String([string]$state.X4BaselineBase64)
        $x4ObservedLcn = Get-FirstLcn $firstWritePath
        $rawBytes = Read-RawVolumeBytes 'C' $x4ObservedLcn ([int]$state.X4ClusterSize) $baselineBytes.Length
        $rawComparison = Compare-Bytes $baselineBytes $rawBytes
        Write-Output ('X4_FirstAttempt=' + ($first | ConvertTo-Json -Compress))
        Write-Output ('X4_ReadinessRecord=' + ($readiness | ConvertTo-Json -Compress))
        Write-Output ('X4_RawVolumeObservation=Method:FSCTL_GET_RETRIEVAL_POINTERS+unbuffered-volume-read;' +
            'State:' + $rawComparison.State + ';DifferentBytes:' + $rawComparison.DifferentBytes +
            ';FirstDifferentOffset:' + $rawComparison.FirstDifferentOffset + ';ActualSha256:' + $rawComparison.ActualSha256 +
            ';BaselineLcn:' + $state.X4Lcn + ';ObservedLcn:' + $x4ObservedLcn +
            ';ActualBytesBase64:' + [Convert]::ToBase64String($rawBytes))
        if (-not $first.ReadinessRecordDurable -or -not $readiness.FilterReady -or
            $readiness.BootPolicyState -ne 1 -or $readiness.TrustState -ne 3 -or
            $readiness.CanaryState -ne 2 -or ($readiness.SetupFlags -band 4) -eq 0 -or
            $first.WriteResult -ne 'Denied' -or $first.WriteErrorType -ne 'System.UnauthorizedAccessException' -or
            $rawComparison.State -ne 'IDENTICAL_TO_BASELINE') {
            throw 'X4 failed: readiness was not durably recorded before a denied write, or the independent raw bytes changed.'
        }
        $readyObserved = [DateTime]::Parse($readiness.RecordedUtc).ToUniversalTime()
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
            $cEntry.trustState -ne 3 -or $cEntry.canaryState -ne 2) {
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
        if (($fresh.Entry.setupFlags -band 4) -eq 0 -or $fresh.Entry.trustState -ne 3 -or
            $fresh.Entry.canaryState -ne 2) {
            throw 'A fresh post-boot VHDX was not trusted from NEWLY_MOUNTED setup flags.'
        }
        Write-Output ('FreshVhdxTrustState=' + $fresh.Entry.trustState + ';SetupFlags=' + $fresh.Entry.setupFlags +
            ';CanaryState=' + $fresh.Entry.canaryState + ';CanaryStatus=' + $fresh.Entry.canaryStatus)

        $e1ProtectedDirectory = 'S:\SafeUploadBootStart\E1Protected'
        $policyDocument = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
        $policyDocument.monitoredScopes.destinationPaths = @($protectedDirectory, $e1ProtectedDirectory)
        Set-ProtectedPolicyAcl
        [IO.File]::WriteAllText($policyPath, ($policyDocument | ConvertTo-Json -Depth 6))
        $agent = Wait-AgentPolicyAccepted (Join-Path $stateDirectory 'afterboot-agent-e1-scope') 2
        Write-Output 'E1ScopeSCommittedAndReadBack=True'
        Stop-StagedTestAgent $agent
        $agent = $null

        & fltmc.exe unload SafeUpload | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Could not unload the complete filter before creating the E1 mapping.' }
        if ((& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s') {
            throw 'SafeUpload remained loaded before the E1 writer and mapping were created.'
        }
        New-Item -ItemType Directory -Path $e1ProtectedDirectory | Out-Null
        $latePath = Join-Path $e1ProtectedDirectory 'E1-mapped-writer.txt'
        $lateBaseline = [Text.Encoding]::ASCII.GetBytes(('E1-BASELINE-' + $state.X4RunId).PadRight(4096, 'B'))
        $lateAttempt = [Text.Encoding]::ASCII.GetBytes(('E1-ATTEMPT-' + $state.X4RunId).PadRight(4096, 'A'))
        $lateWriter = [IO.FileStream]::new($latePath, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite, 4096, [IO.FileOptions]::WriteThrough)
        $lateWriter.Write($lateBaseline, 0, $lateBaseline.Length)
        $lateWriter.Flush($true)
        $lateClusterSize = [int](Get-Volume -DriveLetter S -ErrorAction Stop).AllocationUnitSize
        $lateLcn = Get-FirstLcn $latePath
        $lateRawBaseline = Read-RawVolumeBytes 'S' $lateLcn $lateClusterSize $lateBaseline.Length
        if ((Compare-Bytes $lateBaseline $lateRawBaseline).State -ne 'IDENTICAL_TO_BASELINE') {
            throw 'E1 raw-volume baseline does not match the file before the filter reattaches.'
        }
        $lateMapping = [SafeUploadBootSectionNative]::CreateWritableMapping($lateWriter.SafeFileHandle,
            [IntPtr]::Zero, [uint32]4, [uint32]0, [uint32]4096, [IntPtr]::Zero)
        if ($lateMapping -eq [IntPtr]::Zero) {
            throw 'Could not create the E1 writable mapping before the filter reattaches: ' +
                [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $lateView = [SafeUploadBootSectionNative]::MapViewOfFile($lateMapping, [uint32]2,
            [uint32]0, [uint32]0, [UIntPtr]::new([uint64]4096))
        if ($lateView -eq [IntPtr]::Zero) {
            throw 'Could not map the E1 writable view before the filter reattaches: ' +
                [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        Write-Output 'E1WritableMappingCreatedBeforeFilterReattachment=True'

        & fltmc.exe load SafeUpload | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Could not late-load SafeUpload for the E1 pending-reboot case.' }
        $late = Wait-AdmissionVolume $freshGuid 5
        if (($late.Entry.setupFlags -band 4) -ne 0 -or $late.Entry.trustState -ne 5 -or
            $late.Entry.protectionStatus -ne 'protection pending reboot') {
            throw 'E1 failed: the late-loaded S: instance did not report Untrusted and protection pending reboot.'
        }
        $attemptUtc = [DateTime]::UtcNow.ToString('o')
        [Runtime.InteropServices.Marshal]::Copy($lateAttempt, 0, $lateView, $lateAttempt.Length)
        if (-not [SafeUploadBootSectionNative]::FlushViewOfFile($lateView, [UIntPtr]::new([uint64]4096))) {
            throw 'E1 writable mapped view flush failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $lateWriter.Flush($true)
        $lateObservedLcn = Get-FirstLcn $latePath
        $lateRawBytes = Read-RawVolumeBytes 'S' $lateObservedLcn $lateClusterSize $lateBaseline.Length
        $lateRawComparedToBaseline = Compare-Bytes $lateBaseline $lateRawBytes
        $lateRawComparedToAttempt = Compare-Bytes $lateAttempt $lateRawBytes
        Write-Output ('E1_RawVolumeObservation=Method:FSCTL_GET_RETRIEVAL_POINTERS+unbuffered-volume-read;' +
            'DifferentBytesFromBaseline:' + $lateRawComparedToBaseline.DifferentBytes +
            ';FirstDifferentOffset:' + $lateRawComparedToBaseline.FirstDifferentOffset +
            ';RawBytesMatchAttemptMarker:' + ($lateRawComparedToAttempt.State -eq 'IDENTICAL_TO_BASELINE') +
            ';BaselineLcn:' + $lateLcn + ';ObservedLcn:' + $lateObservedLcn +
            ';ActualSha256:' + $lateRawComparedToBaseline.ActualSha256 +
            ';ActualBytesBase64:' + [Convert]::ToBase64String($lateRawBytes))
        Write-Output ('E1_LateLoad=' + $true + ';ProtectionStatus=' + $late.Entry.protectionStatus +
            ';TrustState=' + $late.Entry.trustState + ';SetupFlags=' + $late.Entry.setupFlags +
            ';CanaryState=' + $late.Entry.canaryState + ';MappedWriteUtc=' + $attemptUtc)
        if ($lateRawBytes.Length -ne $lateBaseline.Length) { throw 'E1 raw observer returned a partial byte record.' }
        Write-Output 'E1_PassConditionMet=True;Volume=Untrusted;Protection=pending reboot;RawBytesRecorded=True'
        [void][SafeUploadBootSectionNative]::UnmapViewOfFile($lateView)
        $lateView = [IntPtr]::Zero
        [void][SafeUploadBootRawNative]::CloseHandle($lateMapping)
        $lateMapping = [IntPtr]::Zero
        $lateWriter.Dispose()
        $lateWriter = $null

        Write-Output 'BootStartX4AndE1=True'
    }
    finally {
        $restoreErrors = [System.Collections.Generic.List[string]]::new()
        Invoke-RestoreStep 'close E1 mapping and writer handles' {
            if ($lateView -ne [IntPtr]::Zero) {
                [void][SafeUploadBootSectionNative]::UnmapViewOfFile($lateView)
                $lateView = [IntPtr]::Zero
            }
            if ($lateMapping -ne [IntPtr]::Zero) {
                [void][SafeUploadBootRawNative]::CloseHandle($lateMapping)
                $lateMapping = [IntPtr]::Zero
            }
            if ($null -ne $lateWriter) { $lateWriter.Dispose(); $lateWriter = $null }
        } $restoreErrors
        Invoke-RestoreStep 'close section test handle' {
            if ($null -ne $sectionStream) { $sectionStream.Dispose(); $sectionStream = $null }
        } $restoreErrors
        Invoke-RestoreStep 'stop agent' {
            if ($null -ne $agent) { Stop-StagedTestAgent $agent; $agent = $null }
        } $restoreErrors
        if ($vhdAttached -and (Test-Path -LiteralPath $vhdxPath)) {
            Invoke-RestoreStep 'unload whole filter before detaching test VHDX' {
                if ((& fltmc.exe filters 2>&1 | Out-String) -match '(?m)^SafeUpload\s') {
                    & fltmc.exe unload SafeUpload | Out-Host
                    if ($LASTEXITCODE -ne 0) { throw 'Could not unload SafeUpload before detaching the E1 VHDX.' }
                }
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
            if ($LASTEXITCODE -notin @(0, 2)) { throw ('Driver Verifier reset failed (exit ' + $LASTEXITCODE + ').') }
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
        $_.TaskName -match '^SafeUpload-(BootStart|BootInspector|BootPolicyReader|BootPolicySeed|BootPolicyWriter|BootRegistryCleanup|StagedTest|StagedCleanup)'
    }).Count -ne 0) {
        throw 'A boot-start experiment or agent task remained after restoration.'
    }
    if ((Test-Path -LiteralPath $protectedDirectory) -or (Test-Path -LiteralPath $serviceDirectory) -or
        (Test-Path -LiteralPath $vhdxPath) -or (Test-Path -LiteralPath 'S:\')) {
        throw 'A boot-start test folder, service package, VHDX, or S: mount remained after restoration.'
    }
    $verifier = (& verifier.exe /query 2>&1 | Out-String)
    if ($verifier -match 'Verifier Flags:\s+0x(?!0+)[0-9a-fA-F]+') { throw 'Verifier remains active after the clean restoration boot.' }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($null -ne $state.OriginalAgentStart) { Set-AgentServiceStart ([int]$state.OriginalAgentStart) }
    $finalAgentStart = if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent') {
        [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent').Start
    } else { $null }
    if ($finalAgentStart -ne $state.OriginalAgentStart) { throw 'SafeUploadAgent start type was not restored.' }
    Write-Output 'BOOT_FINAL_STATE=True'
    Write-Output ('FinalOriginalDriverSHA256=' + $originalDriverHash)
    Write-Output ('FinalPolicySHA256=' + (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash)
}
