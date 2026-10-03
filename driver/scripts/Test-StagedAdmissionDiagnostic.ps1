param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('preattach-immediate', 'preattach-protected-open', 'mmdoes-matrix', 'policy-transition', 'retained-section', 'section-eol', 'writer-count', 'canary-security', 'canary-newvolume', 'section-inflight', 'section-lower', 'writer-fault', 'primitive-cost', 'All')]
    [string] $Variant,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedFeatureSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedInspectorSha256,

    [ValidateRange(1, 600)]
    [int] $InspectorTimeoutSeconds = 60,

    # Run-scoped guest file names keep the long-standing inputs (SafeUpload-stage-prototype.sys and
    # SafeUpload.Inspector.input.exe) untouched when a newer build is staged beside them.
    [ValidatePattern('^SafeUpload-stage-prototype[A-Za-z0-9._-]*\.sys$')]
    [string] $FeatureDriverFileName = 'SafeUpload-stage-prototype.sys',

    [ValidatePattern('^SafeUpload\.Inspector\.[A-Za-z0-9_-]+\.exe$')]
    [string] $InspectorInputFileName = 'SafeUpload.Inspector.input.exe',

    # Runtime Driver Verifier (volatile, flags 0x13B) on SafeUpload.sys for variants that support it.
    [switch] $Verifier,
    [switch] $RequireCanary,
    [switch] $RequireAllVolumeCanaries,
    [ValidatePattern('^StagedTestAgent[A-Za-z0-9._-]*\.ps1$')]
    [string] $TestAgentHelperFileName = 'StagedTestAgent.ps1',
    [ValidatePattern('^SafeUploadSectionFault[A-Za-z0-9._-]*\.sys$')]
    [string] $FaultDriverFileName = 'SafeUploadSectionFault.input.sys',
    [ValidatePattern('^StagedSectionFaultClient[A-Za-z0-9._-]*\.cs$')]
    [string] $FaultClientFileName = 'StagedSectionFaultClient.cs',
    [ValidatePattern('^Invoke-StagedSectionFault[A-Za-z0-9._-]*\.ps1$')]
    [string] $FaultExerciseFileName = 'Invoke-StagedSectionFault.ps1',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string] $ExpectedFaultSha256 = '',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string] $ExpectedFaultClientSha256 = '',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string] $ExpectedFaultExerciseSha256 = '',
    [switch] $FaultCapacity,
    [ValidatePattern('^SafeUpload\.WriterFault[A-Za-z0-9._-]*\.exe$')][string]$WriterFaultFileName='SafeUpload.WriterFault.input.exe',
    [ValidatePattern('^StagedWriterFault[A-Za-z0-9._-]*\.ps1$')][string]$WriterFaultExerciseFileName='StagedWriterFault.ps1',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string]$ExpectedWriterFaultSha256='',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string]$ExpectedWriterFaultExerciseSha256=''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($RequireAllVolumeCanaries) { $RequireCanary = $true }
$documents = Join-Path $env:USERPROFILE 'Documents'
$installedDriver = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginalDriver = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedOriginalPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$expectedServicePackage = 'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997'
$featureDriver = Join-Path $documents $FeatureDriverFileName
$inspectorSource = Join-Path $documents $InspectorInputFileName
$inspectorPath = Join-Path $documents 'SafeUpload-admission-inspector.exe'
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$serviceDirectory = Join-Path $documents 'stage-service-publish'
$policyPath = 'C:\ProgramData\SafeUpload\policy.json'
$mappingLength = 4096

. (Join-Path $documents $TestAgentHelperFileName)

if (-not ('SafeUploadAdmissionNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class SafeUploadAdmissionNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
        EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadFile")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadFile(
        SafeFileHandle file, IntPtr buffer, uint bytesToRead, out uint bytesRead,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetFilePointerEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle file, long distance, out long newPosition, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualAlloc")]
    public static extern IntPtr VirtualAlloc(
        IntPtr address, UIntPtr size, uint allocationType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualFree")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFree(
        IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
        EntryPoint = "GetDiskFreeSpaceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpace(
        string rootPathName, out uint sectorsPerCluster, out uint bytesPerSector,
        out uint numberOfFreeClusters, out uint totalNumberOfClusters);
}
'@
}

if (-not ('SafeUploadCanarySecurityNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class SafeUploadCanarySecurityNative
{
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_IMPERSONATE = 0x0004;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    const uint OPEN_EXISTING = 3;
    const uint FILE_SHARE_ALL = 7;
    const uint TOKEN_ELEVATION_CLASS = 20;
    const uint TOKEN_PRIVILEGES_CLASS = 3;

    [StructLayout(LayoutKind.Sequential)]
    struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct Luid { public uint LowPart; public int HighPart; }

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFileAttributesW")]
    static extern uint GetFileAttributes(string path);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attributes,
        int impersonationLevel, int tokenType, out IntPtr duplicate);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetTokenInformation(IntPtr token, uint infoClass, IntPtr info,
        uint infoLength, out uint returnLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSidToSid(string text, out IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CheckTokenMembership(IntPtr token, IntPtr sid, [MarshalAs(UnmanagedType.Bool)] out bool member);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableSidCount,
        ref SidAndAttributes sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete,
        uint restrictedSidCount, IntPtr sidsToRestrict, out IntPtr restricted);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ImpersonateLoggedOnUser(IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        IntPtr newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);

    static void ThrowLastError(string operation)
    {
        throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    static IntPtr OpenPrimaryToken()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, out token))
            ThrowLastError("OpenProcessToken");
        return token;
    }

    static IntPtr DuplicateForImpersonation(IntPtr token)
    {
        IntPtr duplicate;
        if (!DuplicateTokenEx(token, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                IntPtr.Zero, 2, 2, out duplicate))
            ThrowLastError("DuplicateTokenEx");
        return duplicate;
    }

    static bool PrivilegeEnabled(IntPtr token, string name)
    {
        Luid expected;
        if (!LookupPrivilegeValue(null, name, out expected)) ThrowLastError("LookupPrivilegeValue " + name);
        uint bytes = 0;
        GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, IntPtr.Zero, 0, out bytes);
        int firstError = Marshal.GetLastWin32Error();
        if (bytes < 4 || (firstError != 122 && firstError != 0))
            throw new Win32Exception(firstError, "GetTokenInformation(TokenPrivileges)");
        IntPtr buffer = Marshal.AllocHGlobal((int)bytes);
        try
        {
            if (!GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, buffer, bytes, out bytes))
                ThrowLastError("GetTokenInformation(TokenPrivileges)");
            int count = Marshal.ReadInt32(buffer);
            int offset = 4;
            for (int i = 0; i < count; i++, offset += 12)
            {
                if ((uint)offset > bytes || bytes - (uint)offset < 12)
                    throw new InvalidOperationException("Token privilege list is truncated.");
                uint low = unchecked((uint)Marshal.ReadInt32(buffer, offset));
                int high = Marshal.ReadInt32(buffer, offset + 4);
                uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + 8));
                if (low == expected.LowPart && high == expected.HighPart)
                    return (attributes & SE_PRIVILEGE_ENABLED) != 0;
            }
            return false;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    static IntPtr QueryTokenPrivileges(IntPtr token, out uint count)
    {
        uint bytes = 0;
        GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, IntPtr.Zero, 0, out bytes);
        int firstError = Marshal.GetLastWin32Error();
        if (bytes < 4 || (firstError != 122 && firstError != 0))
            throw new Win32Exception(firstError, "GetTokenInformation(TokenPrivileges)");
        IntPtr buffer = Marshal.AllocHGlobal((int)bytes);
        if (!GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, buffer, bytes, out bytes))
        {
            int error = Marshal.GetLastWin32Error();
            Marshal.FreeHGlobal(buffer);
            throw new Win32Exception(error, "GetTokenInformation(TokenPrivileges)");
        }
        count = unchecked((uint)Marshal.ReadInt32(buffer));
        if (count > (bytes - 4) / 12)
        {
            Marshal.FreeHGlobal(buffer);
            throw new InvalidOperationException("Token privilege list is truncated.");
        }
        return buffer;
    }

    static uint GetPrivilegeCount(IntPtr token)
    {
        uint count;
        IntPtr buffer = QueryTokenPrivileges(token, out count);
        Marshal.FreeHGlobal(buffer);
        return count;
    }

    static bool IsElevated(IntPtr token)
    {
        IntPtr buffer = Marshal.AllocHGlobal(4);
        try
        {
            uint returned;
            if (!GetTokenInformation(token, TOKEN_ELEVATION_CLASS, buffer, 4, out returned))
                ThrowLastError("GetTokenInformation(TokenElevation)");
            return Marshal.ReadInt32(buffer) != 0;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    static IntPtr AdministratorsSid()
    {
        IntPtr sid;
        if (!ConvertStringSidToSid("S-1-5-32-544", out sid)) ThrowLastError("ConvertStringSidToSid(Administrators)");
        return sid;
    }

    public static string RequireElevatedAdministratorAndDisabledPrivileges()
    {
        IntPtr primary = IntPtr.Zero, impersonation = IntPtr.Zero, sid = IntPtr.Zero;
        try
        {
            primary = OpenPrimaryToken();
            impersonation = DuplicateForImpersonation(primary);
            sid = AdministratorsSid();
            if (System.Security.Principal.WindowsIdentity.GetCurrent().User.Value == "S-1-5-18")
                throw new InvalidOperationException("The harness process must be a non-SYSTEM administrator.");
            bool member;
            if (!IsElevated(impersonation) || !CheckTokenMembership(impersonation, sid, out member) || !member)
                throw new InvalidOperationException("The harness token is not an elevated Administrators token.");
            // The launching shell's token may have privileges enabled (OpenSSH sessions do). Record it;
            // the attempts themselves use AdminWithoutPrivileges(), never this token.
            string facts = "elevated=true;administrators=true";
            string[] names = { "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege" };
            foreach (string name in names)
                facts += ";process" + name + "=" + (PrivilegeEnabled(impersonation, name) ? "enabled" : "not-enabled");
            IntPtr attempt = AdminWithoutPrivileges();
            try
            {
                foreach (string name in names)
                    if (PrivilegeEnabled(attempt, name))
                        throw new InvalidOperationException(name + " stayed enabled in the attempt token.");
                bool attemptMember;
                if (!IsElevated(attempt) || !CheckTokenMembership(attempt, sid, out attemptMember) || !attemptMember)
                    throw new InvalidOperationException("The attempt token is not an elevated Administrators token.");
            }
            finally { CloseHandle(attempt); }
            return facts + ";attemptToken=elevatedAdministratorAllPrivilegesDisabled";
        }
        finally
        {
            if (sid != IntPtr.Zero) LocalFree(sid);
            if (impersonation != IntPtr.Zero) CloseHandle(impersonation);
            if (primary != IntPtr.Zero) CloseHandle(primary);
        }
    }

    // Elevated Administrators impersonation token with every privilege disabled (never enabled),
    // matching a default desktop administrator process regardless of how the harness was launched.
    static IntPtr AdminWithoutPrivileges()
    {
        IntPtr primary = IntPtr.Zero, duplicate;
        try
        {
            primary = OpenPrimaryToken();
            if (!DuplicateTokenEx(primary, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | 0x20,
                    IntPtr.Zero, 2, 2, out duplicate))
                ThrowLastError("DuplicateTokenEx");
            if (!AdjustTokenPrivileges(duplicate, true, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero))
            {
                int error = Marshal.GetLastWin32Error();
                CloseHandle(duplicate);
                throw new Win32Exception(error, "AdjustTokenPrivileges(DisableAll)");
            }
            return duplicate;
        }
        finally { if (primary != IntPtr.Zero) CloseHandle(primary); }
    }

    public static int TryOpenCurrent(string path, uint access)
    {
        IntPtr token = AdminWithoutPrivileges();
        bool impersonating = false;
        try
        {
            if (!ImpersonateLoggedOnUser(token)) ThrowLastError("ImpersonateLoggedOnUser");
            impersonating = true;
            IntPtr file = CreateFile(path, access, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0x80, IntPtr.Zero);
            if (file == new IntPtr(-1)) return Marshal.GetLastWin32Error();
            CloseHandle(file);
            return 0;
        }
        finally
        {
            if (impersonating && !RevertToSelf()) ThrowLastError("RevertToSelf");
            CloseHandle(token);
        }
    }

    public static int GetPathAttributesError(string path)
    {
        return GetFileAttributes(path) == 0xFFFFFFFF ? Marshal.GetLastWin32Error() : 0;
    }

    public static int TryOpenRestricted(string path, uint access)
    {
        IntPtr primary = IntPtr.Zero, restrictedPrimary = IntPtr.Zero, restricted = IntPtr.Zero, sid = IntPtr.Zero;
        bool impersonating = false;
        try
        {
            primary = OpenPrimaryToken();
            sid = AdministratorsSid();
            SidAndAttributes disabled = new SidAndAttributes();
            disabled.Sid = sid;
            disabled.Attributes = 0;
            uint privilegeCount;
            IntPtr privileges = QueryTokenPrivileges(primary, out privilegeCount);
            try
            {
                IntPtr privilegesToDelete = privilegeCount == 0 ? IntPtr.Zero : IntPtr.Add(privileges, 4);
                if (!CreateRestrictedToken(primary, 0, 1, ref disabled,
                        privilegeCount, privilegesToDelete, 0, IntPtr.Zero, out restrictedPrimary))
                    ThrowLastError("CreateRestrictedToken");
            }
            finally { Marshal.FreeHGlobal(privileges); }
            restricted = DuplicateForImpersonation(restrictedPrimary);
            bool member;
            if (!CheckTokenMembership(restricted, sid, out member) || member)
                throw new InvalidOperationException("Administrators was not deny-only in the restricted token.");
            if (GetPrivilegeCount(restricted) != 0)
                throw new InvalidOperationException("The restricted token retained a privilege.");
            if (!ImpersonateLoggedOnUser(restricted)) ThrowLastError("ImpersonateLoggedOnUser");
            impersonating = true;
            IntPtr file = CreateFile(path, access, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, 0x80, IntPtr.Zero);
            if (file == new IntPtr(-1)) return Marshal.GetLastWin32Error();
            CloseHandle(file);
            return 0;
        }
        finally
        {
            if (impersonating && !RevertToSelf()) ThrowLastError("RevertToSelf");
            if (sid != IntPtr.Zero) LocalFree(sid);
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            if (restrictedPrimary != IntPtr.Zero) CloseHandle(restrictedPrimary);
            if (primary != IntPtr.Zero) CloseHandle(primary);
        }
    }
}
'@
}

function Get-Sha256Hex([byte[]] $Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
        return [BitConverter]::ToString($digest).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-ErrorText($ErrorRecord) {
    $message = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrEmpty($message)) {
        $message = [string]$ErrorRecord
    }
    return [regex]::Replace($message, '[\r\n\t]', ' ')
}

function Test-HasReparsePoint($Item) {
    return (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-ReparseFreeFixturePath([string] $Path) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -notmatch '^[A-Za-z]:\\') {
        throw "Fixture path is not a local drive path: $fullPath"
    }
    if ($fullPath.Length -gt 2 -and $fullPath.Substring(2).Contains(':')) {
        throw "Fixture path contains an alternate-stream colon: $fullPath"
    }

    $root = $fullPath.Substring(0, 3)
    $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (Test-HasReparsePoint $item) {
        throw "Fixture path component is a reparse point: $root"
    }

    $current = $root
    $parts = @($fullPath.Substring(3).Split([char[]]@('\')) | Where-Object { $_.Length -gt 0 })
    foreach ($part in $parts) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (Test-HasReparsePoint $item) {
            throw "Fixture path component is a reparse point: $current"
        }
    }
}

function Get-StagedAdmissionBaseline {
    $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
    if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
        $uuid -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') {
        throw 'Wrong debuggee host or UUID.'
    }

    $originalHash = (Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash
    if ($originalHash -ne $expectedOriginalDriver) {
        throw "Original driver hash mismatch: $originalHash"
    }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') {
        throw 'SafeUpload must be unloaded at baseline.'
    }

    $verifierQuery = & verifier.exe /query 2>&1 | Out-String
    $verifierSettings = & verifier.exe /querysettings 2>&1 | Out-String
    if ($verifierQuery -notmatch 'No drivers are currently verified' -or
        $verifierSettings -notmatch 'Verifier Flags:\s+0x00000000') {
        throw 'Verifier must be off at baseline.'
    }
    $memory = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    if ($memory.VerifyDriverLevel -or $memory.VerifyDrivers) {
        throw 'Verifier must not be configured at baseline.'
    }

    $service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
    if ($service.StartMode -ne 'Manual' -or $service.State -ne 'Stopped') {
        throw 'Original service baseline mismatch.'
    }

    $policyHash = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash
    if ($policyHash -ne $expectedOriginalPolicy) {
        throw "Original policy hash mismatch: $policyHash"
    }

    $featureHash = (Get-FileHash -LiteralPath $featureDriver -Algorithm SHA256).Hash
    if ($featureHash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
        throw "Feature driver hash mismatch: $featureHash"
    }
    $inspectorSourceHash = (Get-FileHash -LiteralPath $inspectorSource -Algorithm SHA256).Hash
    if ($inspectorSourceHash -ne $ExpectedInspectorSha256.ToUpperInvariant()) {
        throw "Inspector source hash mismatch: $inspectorSourceHash"
    }
    if (Test-Path -LiteralPath $inspectorPath) {
        throw "The fixed Inspector copy path already exists: $inspectorPath"
    }

    $packageHash = (Get-FileHash -LiteralPath $servicePackage -Algorithm SHA256).Hash
    if ($packageHash -ne $expectedServicePackage) {
        throw "Service package hash mismatch: $packageHash"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'))) {
        throw 'Published service executable is missing.'
    }

    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'A SafeUpload agent process is already running.'
    }
    if (@(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'An admission Inspector process is already running.'
    }

    $taskCount = @(Get-ScheduledTask | Where-Object {
        $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)'
    }).Count
    if ($taskCount -ne 0) {
        throw "SafeUpload experiment tasks already exist: $taskCount"
    }

    $fixtureDirectories = @(Get-ChildItem -LiteralPath $documents -Directory -Force |
        Where-Object { $_.Name -match '^SafeUpload-.*[0-9a-f]{32}$' })
    if ($fixtureDirectories.Count -ne 0) {
        throw 'A SafeUpload GUID fixture directory is already present.'
    }
    if (@(Get-ChildItem -LiteralPath $documents -File -Filter 'SafeUpload-admission-driver-*.sys' -Force).Count -ne 0 -or
        @(Get-ChildItem -LiteralPath $documents -File -Filter 'SafeUpload-admission-policy-*.bin' -Force).Count -ne 0) {
        throw 'A SafeUpload admission backup from an earlier run is present.'
    }
    if ((Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx')) -or
        (Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx.txt'))) {
        throw 'An owned-stream VHDX is present.'
    }
    if (Test-Path -LiteralPath 'S:\') {
        throw 'A synthetic SafeUpload volume is present.'
    }

    return [pscustomobject]@{
        UUID = $uuid
        OriginalHash = $originalHash
        PolicyHash = $policyHash
        FeatureHash = $featureHash
        InspectorSourceHash = $inspectorSourceHash
        ServicePackageHash = $packageHash
        TaskCount = $taskCount
    }
}

function ConvertTo-PowerShellLiteral([string] $Value) {
    return $Value.Replace("'", "''")
}

function ConvertTo-WindowsArgument([string] $Value) {
    if ($Value -match '[\s"]') {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Invoke-FeatureFilterLoad {
    $output = (& fltmc.exe load SafeUpload 2>&1 | Out-String).Trim()
    $exitCode = $LASTEXITCODE
    Write-Output ('FeatureFilterLoadOutput=' + [regex]::Replace($output, '[\r\n\t]', ' '))
    if ($exitCode -ne 0) {
        throw 'Feature filter load failed.'
    }
}

function Assert-OutsideBaselineScopes([string] $Path, $PolicyDocument) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    foreach ($configured in @($PolicyDocument.monitoredScopes.destinationPaths)) {
        if ([string]::IsNullOrWhiteSpace([string]$configured)) {
            continue
        }
        $scope = [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables([string]$configured)).TrimEnd('\')
        if ($candidate.Equals($scope, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith($scope + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $scope.StartsWith($candidate + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "The GUID fixture intersects an existing monitored scope: $scope"
        }
    }
}

function Assert-MaptestExtensionOutsideBaselinePolicy($PolicyDocument) {
    $monitoredExtensions = @($PolicyDocument.monitoredScopes.extensions | ForEach-Object {
        $extension = [string]$_
        if (-not $extension.StartsWith('.')) {
            $extension = '.' + $extension
        }
        $extension.ToLowerInvariant()
    })
    if ($monitoredExtensions -contains '.maptest') {
        throw 'The .maptest fixture extension is monitored by the baseline policy.'
    }
}

function Assert-NoAgentProcess {
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Inspector call requires zero SafeUpload.Agent.Service processes.'
    }
}

function Assert-NoInspectorProcess {
    if (@(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'A SafeUpload admission Inspector process is already running.'
    }
}

function Invoke-InspectorAsSystem([string[]] $Arguments, [int] $Timeout) {
    Assert-NoAgentProcess
    Assert-NoInspectorProcess

    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedTest-Inspector-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-inspector-' + $id + '.ps1')
    $pidFile = $launcher + '.pid'
    $exitFile = $launcher + '.exit'
    $stdoutFile = $launcher + '.stdout'
    $stderrFile = $launcher + '.stderr'
    $argumentLine = (@($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) })) -join ' '
    $launcherTemplate = @'
$ErrorActionPreference = 'Stop'
$start = @{ FilePath = '__EXE__'; PassThru = $true; WindowStyle = 'Hidden';
    RedirectStandardOutput = '__STDOUT__'; RedirectStandardError = '__STDERR__' }
$start.ArgumentList = '__ARGUMENTS__'
$process = Start-Process @start
# Windows PowerShell 5.1: without caching the handle, ExitCode stays empty and was recorded as 0.
[void]$process.Handle
[IO.File]::WriteAllText('__PID__', [string]$process.Id)
$process.WaitForExit()
if ($null -eq $process.ExitCode) { throw 'Inspector exit code unavailable.' }
[IO.File]::WriteAllText('__EXIT__', [string]$process.ExitCode)
'@
    $launcherBody = $launcherTemplate.Replace('__EXE__', (ConvertTo-PowerShellLiteral $inspectorPath))
    $launcherBody = $launcherBody.Replace('__STDOUT__', (ConvertTo-PowerShellLiteral $stdoutFile))
    $launcherBody = $launcherBody.Replace('__STDERR__', (ConvertTo-PowerShellLiteral $stderrFile))
    $launcherBody = $launcherBody.Replace('__ARGUMENTS__', (ConvertTo-PowerShellLiteral $argumentLine))
    $launcherBody = $launcherBody.Replace('__PID__', (ConvertTo-PowerShellLiteral $pidFile))
    $launcherBody = $launcherBody.Replace('__EXIT__', (ConvertTo-PowerShellLiteral $exitFile))
    Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding UTF8

    $registered = $false
    $timedOut = $false
    try {
        $taskArgument = '-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgument
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName

        $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
        while (-not (Test-Path -LiteralPath $exitFile) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $exitFile)) {
            $timedOut = $true
            $script:InspectorTimedOut = $true
            $script:InspectorTimeoutCommand = $Arguments -join ' '
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $pidFile) {
                $pidText = [IO.File]::ReadAllText($pidFile)
                $inspectorPid = 0
                if ([int]::TryParse($pidText, [ref]$inspectorPid)) {
                    Stop-Process -Id $inspectorPid -Force -ErrorAction SilentlyContinue
                }
            }
            throw 'Inspector call exceeded its timeout.'
        }

        $taskStopped = $false
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $scheduled = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -eq $scheduled -or $scheduled.State -ne 'Running') {
                $taskStopped = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
        if (-not $taskStopped) {
            $timedOut = $true
            $script:InspectorTimedOut = $true
            $script:InspectorTimeoutCommand = $Arguments -join ' '
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            throw 'Inspector task did not stop after writing its exit code.'
        }

        $capturedPid = [int]([IO.File]::ReadAllText($pidFile))
        $capturedExit = [int]([IO.File]::ReadAllText($exitFile))
        $stdoutBytes = [IO.File]::ReadAllBytes($stdoutFile)
        $stdout = [IO.File]::ReadAllText($stdoutFile)
        $stderr = [IO.File]::ReadAllText($stderrFile)
        return [pscustomobject]@{
            Arguments = $Arguments
            PID = $capturedPid
            ExitCode = $capturedExit
            Stdout = $stdout
            StdoutBytes = $stdoutBytes
            Stderr = $stderr
            StdoutPath = $stdoutFile
            StderrPath = $stderrFile
            TaskName = $taskName
        }
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$pidFile,$exitFile,$stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-InspectorChecked([string[]] $Arguments, [int] $Timeout) {
    if ($script:InspectorTimedOut) {
        throw 'No Inspector call is permitted after an Inspector timeout.'
    }
    $result = Invoke-InspectorAsSystem -Arguments $Arguments -Timeout $Timeout
    if ($result.ExitCode -ne 0) {
        $script:InspectorFailed = $true
        $errorText = [regex]::Replace([string]$result.Stderr, '[\r\n\t]', ' ')
        throw "Inspector command '$($Arguments -join ' ')' returned $($result.ExitCode): $errorText"
    }
    return $result
}

function Start-TestAgentAndWaitForPolicy([string] $LogPrefix) {
    Assert-NoInspectorProcess
    Assert-NoAgentProcess
    $ready = New-Object System.Threading.EventWaitHandle(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        'Global\SafeUploadServiceReady')
    $newAgent = $null
    try {
        [void]$ready.Reset()
        $newAgent = Start-StagedTestAgent $serviceDirectory $LogPrefix
        if (-not $ready.WaitOne([TimeSpan]::FromSeconds(45))) {
            throw 'Agent did not signal policy acceptance within 45 seconds.'
        }
        return $newAgent
    }
    catch {
        if ($null -ne $newAgent) {
            Stop-StagedTestAgent $newAgent
        }
        throw
    }
    finally {
        $ready.Dispose()
    }
}

function New-UncachedObserver([string] $Path) {
    $buffer = [IntPtr]::Zero
    $handle = $null
    try {
        $root = [IO.Path]::GetPathRoot($Path)
        [uint32]$sectorsPerCluster = 0
        [uint32]$bytesPerSector = 0
        [uint32]$freeClusters = 0
        [uint32]$totalClusters = 0
        $ok = [SafeUploadAdmissionNative]::GetDiskFreeSpace(
            $root, [ref]$sectorsPerCluster, [ref]$bytesPerSector,
            [ref]$freeClusters, [ref]$totalClusters)
        if (-not $ok) {
            throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
        if ($bytesPerSector -eq 0 -or ($mappingLength % $bytesPerSector) -ne 0) {
            throw "4096 bytes is not a whole number of $bytesPerSector-byte sectors."
        }

        $buffer = [SafeUploadAdmissionNative]::VirtualAlloc(
            [IntPtr]::Zero, [UIntPtr]([uint32]$mappingLength), [uint32]12288, [uint32]4)
        if ($buffer -eq [IntPtr]::Zero) {
            throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
        if (($buffer.ToInt64() % [long]$bytesPerSector) -ne 0) {
            throw 'VirtualAlloc returned a buffer that is not sector aligned.'
        }

        $genericRead = [uint32]2147483648
        $shareReadWriteDelete = [uint32]7
        $openExisting = [uint32]3
        $noBufferingWriteThrough = [uint32]2684354560
        $handle = [SafeUploadAdmissionNative]::CreateFile(
            $Path, $genericRead, $shareReadWriteDelete, [IntPtr]::Zero,
            $openExisting, $noBufferingWriteThrough, [IntPtr]::Zero)
        if ($null -eq $handle -or $handle.IsInvalid) {
            throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }

        return [pscustomobject]@{
            Handle = $handle
            Buffer = $buffer
            SectorSize = [uint32]$bytesPerSector
            Path = $Path
        }
    }
    catch {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        if ($buffer -ne [IntPtr]::Zero) {
            [void][SafeUploadAdmissionNative]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        }
        throw
    }
}

function New-ObserverPair(
    [string] $Path,
    [System.Collections.ArrayList] $FileHandles,
    [System.Collections.ArrayList] $UncachedReaders
) {
    $buffered = $null
    $bufferedError = ''
    try {
        $buffered = [IO.FileStream]::new(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        [void]$FileHandles.Add($buffered)
    }
    catch {
        $bufferedError = Get-ErrorText $_
    }

    $uncached = $null
    $uncachedError = ''
    try {
        $uncached = New-UncachedObserver $Path
        [void]$UncachedReaders.Add($uncached)
    }
    catch {
        $uncachedError = Get-ErrorText $_
    }

    return [pscustomobject]@{
        R1 = $buffered
        R1Error = $bufferedError
        R2 = $uncached
        R2Error = $uncachedError
    }
}

function New-PaddedFixtureBytes([byte[]] $Prefix) {
    $bytes = New-Object byte[] $mappingLength
    if ($Prefix.Length -gt $bytes.Length) {
        throw 'Fixture prefix is longer than the 4096-byte mapping.'
    }
    [Array]::Copy($Prefix, $bytes, $Prefix.Length)
    return ,$bytes
}

function New-MappedFixture(
    [string] $Path,
    [string] $MappingName,
    [bool] $ReadOnly,
    [bool] $KeepSourceHandle,
    [System.Collections.ArrayList] $FileHandles,
    [System.Collections.ArrayList] $Mappings,
    [System.Collections.ArrayList] $Views
) {
    $fileAccess = [IO.FileAccess]::ReadWrite
    $mappingAccess = [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite
    if ($ReadOnly) {
        $fileAccess = [IO.FileAccess]::Read
        $mappingAccess = [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read
    }

    $file = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, $fileAccess,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    [void]$FileHandles.Add($file)
    if ($file.Length -ne $mappingLength) {
        throw "Fixture EOF $($file.Length) does not equal mapping capacity $mappingLength."
    }

    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
        $file, $MappingName, [long]$mappingLength, $mappingAccess,
        [IO.HandleInheritability]::None, $true)
    [void]$Mappings.Add($mapping)
    $view = $mapping.CreateViewAccessor(
        0, [long]$mappingLength, $mappingAccess)
    [void]$Views.Add($view)
    $initialBytes = New-Object byte[] $mappingLength
    $initialRead = $view.ReadArray(0, $initialBytes, 0, $mappingLength)
    if ($initialRead -ne $mappingLength) {
        throw "Initial mapping read returned $initialRead bytes instead of $mappingLength."
    }

    if (-not $KeepSourceHandle) {
        $file.Dispose()
    }

    return [pscustomobject]@{
        File = $file
        Mapping = $mapping
        View = $view
    }
}

function Get-ExactFileStreamBytes([IO.Stream] $Stream, [int] $Length) {
    $bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($count -le 0) {
            throw "Short read: $offset of $Length bytes."
        }
        $offset += $count
    }
    return ,$bytes
}

function Get-ObservationFromBytes([byte[]] $Bytes, [byte[]] $Original, [byte[]] $Mapped) {
    if ($Bytes.Length -ne $mappingLength) {
        throw "Observer returned $($Bytes.Length) bytes instead of $mappingLength."
    }
    $hash = Get-Sha256Hex $Bytes
    $originalHash = Get-Sha256Hex $Original
    $mappedHash = Get-Sha256Hex $Mapped
    $equalsOriginal = $hash -eq $originalHash
    $equalsMapped = $hash -eq $mappedHash
    $take = [Math]::Min(80, $Bytes.Length)
    $preview = [Text.Encoding]::UTF8.GetString($Bytes, 0, $take)
    $preview = $preview.Replace([string][char]0, '\0')
    $preview = $preview.Replace([string][char]13, '\r').Replace([string][char]10, '\n')
    $class = 'OBSERVED_CHANGED'
    if ($equalsOriginal) {
        $class = 'OBSERVED_UNCHANGED'
    }
    return [pscustomobject]@{
        Text = $preview
        SHA256 = $hash
        Class = $class
        EqualOriginal = $equalsOriginal
        EqualMapped = $equalsMapped
        Error = ''
    }
}

function New-RefusedObservation([string] $ErrorText) {
    return [pscustomobject]@{
        Text = ''
        SHA256 = 'NONE'
        Class = 'OBSERVED_REFUSED'
        EqualOriginal = 'UNKNOWN'
        EqualMapped = 'UNKNOWN'
        Error = [regex]::Replace($ErrorText, '[\r\n\t]', ' ')
    }
}

function Read-BufferedObservation(
    [IO.FileStream] $Stream,
    [byte[]] $Original,
    [byte[]] $Mapped
) {
    $Stream.Position = 0
    $bytes = Get-ExactFileStreamBytes $Stream $mappingLength
    return (Get-ObservationFromBytes $bytes $Original $Mapped)
}

function Read-UncachedObservation(
    $Reader,
    [byte[]] $Original,
    [byte[]] $Mapped
) {
    $newPosition = [long]0
    $ok = [SafeUploadAdmissionNative]::SetFilePointerEx(
        $Reader.Handle, [long]0, [ref]$newPosition, [uint32]0)
    if (-not $ok) {
        throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
    }

    [uint32]$bytesRead = 0
    $ok = [SafeUploadAdmissionNative]::ReadFile(
        $Reader.Handle, $Reader.Buffer, [uint32]$mappingLength, [ref]$bytesRead, [IntPtr]::Zero)
    if (-not $ok) {
        throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
    }
    if ($bytesRead -ne $mappingLength) {
        throw "Uncached read returned $bytesRead bytes instead of $mappingLength."
    }

    $bytes = New-Object byte[] $mappingLength
    [Runtime.InteropServices.Marshal]::Copy($Reader.Buffer, $bytes, 0, $mappingLength)
    return (Get-ObservationFromBytes $bytes $Original $Mapped)
}

function Read-FreshBufferedObservation(
    [string] $Path,
    [byte[]] $Original,
    [byte[]] $Mapped
) {
    $fresh = $null
    try {
        $fresh = [IO.FileStream]::new(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $bytes = Get-ExactFileStreamBytes $fresh $mappingLength
        return (Get-ObservationFromBytes $bytes $Original $Mapped)
    }
    catch {
        return (New-RefusedObservation (Get-ErrorText $_))
    }
    finally {
        if ($null -ne $fresh) {
            $fresh.Dispose()
        }
    }
}

function Get-ObserverReadResult($Observer, [string] $ReaderName, [byte[]] $Original, [byte[]] $Mapped) {
    try {
        if ($ReaderName -eq 'R1') {
            if ($null -eq $Observer.R1) {
                return (New-RefusedObservation $Observer.R1Error)
            }
            return (Read-BufferedObservation $Observer.R1 $Original $Mapped)
        }
        if ($null -eq $Observer.R2) {
            return (New-RefusedObservation $Observer.R2Error)
        }
        return (Read-UncachedObservation $Observer.R2 $Original $Mapped)
    }
    catch {
        return (New-RefusedObservation (Get-ErrorText $_))
    }
}

function Write-ReaderFacts([string] $Prefix, $Observation) {
    Write-Output ($Prefix + '_Text=' + $Observation.Text)
    Write-Output ($Prefix + '_SHA256=' + $Observation.SHA256)
    Write-Output ($Prefix + '_EqualOriginal=' + $Observation.EqualOriginal)
    Write-Output ($Prefix + '_EqualMapped=' + $Observation.EqualMapped)
    Write-Output ($Prefix + '_Class=' + $Observation.Class)
    if (-not [string]::IsNullOrEmpty([string]$Observation.Error)) {
        Write-Output ($Prefix + '_Error=' + $Observation.Error)
    }
}

function Invoke-MappedWrite($View, [string] $Marker) {
    $prefix = [Text.Encoding]::UTF8.GetBytes($Marker)
    $mappedBytes = New-PaddedFixtureBytes $prefix
    try {
        $View.WriteArray(0, $mappedBytes, 0, $mappedBytes.Length)
        $View.Flush()
        return [pscustomobject]@{ Result = 'SUCCESS'; Error = ''; Bytes = $mappedBytes }
    }
    catch {
        return [pscustomobject]@{
            Result = 'OBSERVED_REFUSED'
            Error = Get-ErrorText $_
            Bytes = $mappedBytes
        }
    }
}

function New-ExpandedPolicyForFixture([string] $FixtureDirectory, [string] $PolicyBackup) {
    $policyBytes = [IO.File]::ReadAllBytes($policyPath)
    [IO.File]::WriteAllBytes($PolicyBackup, $policyBytes)
    $policyDocument = [Text.Encoding]::UTF8.GetString($policyBytes) | ConvertFrom-Json
    $policyDocument.monitoredScopes.destinationPaths =
        @($policyDocument.monitoredScopes.destinationPaths) + @($FixtureDirectory)
    $updatedBytes = [Text.Encoding]::UTF8.GetBytes(($policyDocument | ConvertTo-Json -Depth 10))
    return [pscustomobject]@{
        OriginalBytes = $policyBytes
        UpdatedBytes = $updatedBytes
    }
}

function Invoke-AdmissionProbe([string] $Path, [string] $Name, [int] $Timeout) {
    # The reparse-free precondition was verified before the driver loaded. It is not repeated here: with a
    # fence active the file itself may be quarantined and even a stat of it is refused.
    if ($Path.Length -gt 260) {
        throw "Inspector probe path exceeds the 260-character command limit: $Path"
    }
    $result = Invoke-InspectorChecked -Arguments @('--admission-probe', $Path) -Timeout $Timeout
    # Callers discard the return value, so the facts go to the host stream (stdout), not the pipeline.
    Write-Host ('ProbeCommand_' + $Name + '=SUCCESS')
    Write-Host ('ProbeCommand_' + $Name + '_ExitCode=' + $result.ExitCode)
    Write-Host ('ProbeCommand_' + $Name + '_Stdout=' + ([regex]::Replace([string]$result.Stdout, '[\r\n]+', ' ')).Trim())
    Write-Host ('ProbeCommand_' + $Name + '_Stderr=' + ([regex]::Replace([string]$result.Stderr, '[\r\n]+', ' ')).Trim())
    return $result
}

function Get-TraceDump($InspectorResult, [string] $RawPath) {
    [IO.File]::WriteAllBytes($RawPath, $InspectorResult.StdoutBytes)
    $entries = New-Object System.Collections.ArrayList
    $summary = $null
    foreach ($line in ($InspectorResult.Stdout -split "\r?\n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if (-not $line.TrimStart().StartsWith('{')) {
            throw "Inspector trace output contains a non-JSON line: $line"
        }
        $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        if ($record.event) {
            [void]$entries.Add($record)
        }
        elseif ($record.summary -eq $true) {
            $summary = $record
        }
        else {
            throw "Inspector trace JSON line has no event or summary key: $line"
        }
    }
    if ($null -eq $summary) {
        throw 'Inspector trace output did not include its summary JSON object.'
    }
    return [pscustomobject]@{
        Entries = @($entries.ToArray())
        Summary = $summary
        RawFile = $RawPath
    }
}

function Get-PagingWriteEntries($Trace, [UInt64] $AfterSequence = [UInt64]0) {
    $matching = @()
    foreach ($entry in $Trace.Entries) {
        if ([UInt64]$entry.sequence -le $AfterSequence) {
            continue
        }
        $major = [int]$entry.major
        $flagsText = [string]$entry.irpFlags
        $flags = [uint32]0
        if ($flagsText.Length -ge 3) {
            $flags = [Convert]::ToUInt32($flagsText.Substring(2), 16)
        }
        $pagingFlag = (($flags -band [uint32]2) -ne 0)
        if ($major -eq 4 -and
            ($entry.event -eq 'paging_write' -or $pagingFlag) -and
            $entry.ownedStream -eq $false) {
            $matching += $entry
        }
    }
    return $matching
}

function Get-TraceProbeEntries($Trace) {
    $matching = @($Trace.Entries | Where-Object { $_.event -eq 'explicit_probe' })
    return $matching
}

function Get-ProbeProperty($Probe, [string] $PropertyName) {
    if ($null -eq $Probe) {
        return 'AMBIGUOUS'
    }
    $property = $Probe.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return 'AMBIGUOUS'
    }
    return [string]$property.Value
}

function Get-SopEquality([string] $ProbeSop, $PagingEntries, [string] $OtherProbeSop) {
    if ($PagingEntries.Count -eq 0) {
        return 'NoPagingEntry'
    }
    if ([string]::IsNullOrEmpty($ProbeSop) -or $ProbeSop -eq '0x0000000000000000') {
        return 'AMBIGUOUS'
    }
    $sops = @($PagingEntries | ForEach-Object { [string]$_.sectionObjectPointer } | Select-Object -Unique)
    if ($sops.Count -ne 1) {
        return 'AMBIGUOUS'
    }
    if (-not [string]::IsNullOrEmpty($OtherProbeSop) -and $sops[0] -eq $OtherProbeSop) {
        return 'AMBIGUOUS'
    }
    if ($sops[0] -eq $ProbeSop) {
        return 'True'
    }
    return 'False'
}

function Write-TraceFacts($Trace) {
    Write-Output ('Trace_RawFile=' + $Trace.RawFile)
    Write-Output ('Trace_EntryCount=' + $Trace.Entries.Count)
    $pagingWrites = @(Get-PagingWriteEntries $Trace)
    $probeEntries = @(Get-TraceProbeEntries $Trace)
    Write-Output ('Trace_PagingWriteEntries=' + $pagingWrites.Count)
    Write-Output ('Trace_ProbeEntries=' + $probeEntries.Count)
    Write-Output ('Trace_LostEntries=' + $Trace.Summary.lostEntries)

    $counts = @{}
    foreach ($entry in $Trace.Entries) {
        $key = [string]$entry.event + '|' + [string]$entry.irpFlags + '|' +
            [string]$entry.sectionObjectPointer
        if ($counts.ContainsKey($key)) {
            $counts[$key] = [int]$counts[$key] + 1
        }
        else {
            $counts[$key] = 1
        }
    }
    $parts = @()
    foreach ($key in @($counts.Keys | Sort-Object)) {
        $parts += ($key + '=' + $counts[$key])
    }
    if ($parts.Count -eq 0) {
        $parts = @('NONE')
    }
    Write-Output ('Trace_Summary=' + ($parts -join ';'))
}

function Write-ProbeFacts($ProbeEntries, [string[]] $Names) {
    if ($ProbeEntries.Count -ne $Names.Count) {
        Write-Output 'ProbeAttribution=AMBIGUOUS'
        foreach ($name in $Names) {
            Write-Output ('MmDoes_' + $name + '=AMBIGUOUS')
            Write-Output ('ProbeStatus_' + $name + '=AMBIGUOUS')
            Write-Output ('ProbeSOP_' + $name + '=AMBIGUOUS')
        }
        return
    }
    for ($index = 0; $index -lt $Names.Count; $index++) {
        $entry = $ProbeEntries[$index]
        Write-Output ('MmDoes_' + $Names[$index] + '=' + (Get-ProbeProperty $entry 'mmDoes'))
        Write-Output ('ProbeStatus_' + $Names[$index] + '=' + (Get-ProbeProperty $entry 'probeStatus'))
        Write-Output ('ProbeSOP_' + $Names[$index] + '=' + (Get-ProbeProperty $entry 'sectionObjectPointer'))
    }
}

function Dispose-ObserverResources(
    [System.Collections.ArrayList] $Views,
    [System.Collections.ArrayList] $Mappings,
    [System.Collections.ArrayList] $FileHandles,
    [System.Collections.ArrayList] $UncachedReaders,
    [System.Collections.ArrayList] $Errors
) {
    for ($index = $Views.Count - 1; $index -ge 0; $index--) {
        try {
            $Views[$index].Dispose()
        }
        catch {
            $disposeText = Get-ErrorText $_
            if ($disposeText -match 'write protected') {
                # A fenced stream refuses the final flush of its old view: an observation, not a restoration failure.
                Write-Output ('ViewDisposeObserved=' + $disposeText)
            }
            else {
                [void]$Errors.Add('View dispose: ' + $disposeText)
            }
        }
    }
    for ($index = $Mappings.Count - 1; $index -ge 0; $index--) {
        try {
            $Mappings[$index].Dispose()
        }
        catch {
            [void]$Errors.Add('Mapping dispose: ' + (Get-ErrorText $_))
        }
    }
    for ($index = $FileHandles.Count - 1; $index -ge 0; $index--) {
        try {
            $FileHandles[$index].Dispose()
        }
        catch {
            [void]$Errors.Add('File handle dispose: ' + (Get-ErrorText $_))
        }
    }
    for ($index = $UncachedReaders.Count - 1; $index -ge 0; $index--) {
        try {
            $reader = $UncachedReaders[$index]
            $reader.Handle.Dispose()
            [void][SafeUploadAdmissionNative]::VirtualFree(
                $reader.Buffer, [UIntPtr]::Zero, [uint32]32768)
        }
        catch {
            [void]$Errors.Add('Uncached reader dispose: ' + (Get-ErrorText $_))
        }
    }
}

function New-RetainedSection([string] $Path, [string] $MappingName, [System.Collections.ArrayList] $Mappings) {
    # A writable section object with NO view and with the file handle closed again, so the file object
    # stays alive only because the section references it.
    $file = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $mapping = $null
    try {
        if ($file.Length -ne $mappingLength) {
            throw "Fixture EOF $($file.Length) does not equal mapping capacity $mappingLength."
        }
        $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
            $file, $MappingName, [long]$mappingLength,
            [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
            [IO.HandleInheritability]::None, $true)
    }
    finally {
        $file.Dispose()
    }
    [void]$Mappings.Add($mapping)
    return $mapping
}

function Add-RetainedView($Mapping) {
    return $Mapping.CreateViewAccessor(
        0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
}

function ConvertTo-NormalizedHex([string] $Value) {
    return ('0x' + $Value.Substring(2).ToUpperInvariant())
}

$script:LightEntryPattern = [regex]('^\{"sequence":(\d+),"timestamp":(\d+),"event":"(\w+)","pid":(\d+),"irql":(\d+),' +
    '"instance":"[^"]*","targetFileObject":"(0x[0-9A-Fa-f]+)","sectionObjectPointer":"(0x[0-9A-Fa-f]+)",' +
    '"major":(\d+),"minor":(\d+),"irpFlags":"(0x[0-9A-Fa-f]+)","mmDoes":"(\w+)".*"syncType":(\d+),' +
    '"pageProtection":"(0x[0-9A-Fa-f]+)"(?:.*"writeObjects":(\d+),"writersUntracked":(true|false))?(?:,"inFlightSections":(\d+))?')

function Get-LightTrace($InspectorResult, [string] $RawPath) {
    # Cheap parse for dumps of thousands of lines; the raw dump is kept as evidence.
    [IO.File]::WriteAllBytes($RawPath, $InspectorResult.StdoutBytes)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $summary = $null
    foreach ($line in ([string]$InspectorResult.Stdout -split "`n")) {
        $text = $line.TrimEnd("`r")
        if ($text.Length -eq 0) {
            continue
        }
        if ($text.StartsWith('{"summary":true')) {
            $summary = ConvertFrom-Json -InputObject $text
            continue
        }
        $m = $script:LightEntryPattern.Match($text)
        if (-not $m.Success) {
            throw "Unrecognized trace line: $text"
        }
        $g = $m.Groups
        $probe = $null
        $probeValid = $false
        if ($g[3].Value -eq 'explicit_probe') {
            $probe = ConvertFrom-Json -InputObject $text
            $required = @('probeStatus','probeStage','targetFileObject','sectionObjectPointer',
                'writeObjects','writersUntracked','inFlightSections','mmDoes')
            $present = @($probe.PSObject.Properties.Name)
            $missing = @($required | Where-Object { $present -notcontains $_ })
            $probeValid = ($missing.Count -eq 0 -and $probe.probeStatus -eq '0x00000000' -and
                $probe.probeStage -eq 8 -and $probe.targetFileObject -match '^0x[0-9a-fA-F]{16}$' -and
                $probe.targetFileObject -notmatch '^0x0+$' -and
                $probe.sectionObjectPointer -match '^0x[0-9a-fA-F]{16}$' -and
                $probe.sectionObjectPointer -notmatch '^0x0+$' -and
                $probe.mmDoes -in @('yes','no') -and $probe.writersUntracked -is [bool])
        }
        [void]$entries.Add([pscustomobject]@{
            ProbeValid = $probeValid
            ProbeStatus = $(if ($null -ne $probe) { $probe.probeStatus } else { '' })
            ProbeStage = $(if ($null -ne $probe) { $probe.probeStage } else { -1 })
            CanaryOk = ($null -ne $probe -and $probe.canaryState -eq 2 -and
                $probe.canaryStatus -eq '0x00000000' -and $probe.canaryChecks -eq 15 -and
                $probe.canaryCleanupStatus -eq '0x00000000')
            CanaryState = $(if ($null -ne $probe) { $probe.canaryState } else { -1 })
            CanaryStatus = $(if ($null -ne $probe) { $probe.canaryStatus } else { '' })
            CanaryChecks = $(if ($null -ne $probe) { $probe.canaryChecks } else { -1 })
            Seq = [UInt64]$g[1].Value
            Ts = [Int64]$g[2].Value
            Ev = $g[3].Value
            ProcessId = [int]$g[4].Value
            Fo = (ConvertTo-NormalizedHex $g[6].Value)
            Sop = (ConvertTo-NormalizedHex $g[7].Value)
            Major = [int]$g[8].Value
            MmDoes = $g[11].Value
            Sync = [Int64]$g[12].Value   # 4294967295 marks 'sync parameters unavailable'
            Prot = [Convert]::ToUInt32($g[13].Value.Substring(2), 16)
            Writers = $(if ($g[14].Success) { [int]$g[14].Value } else { 0 })
            WritersUntracked = ($g[15].Success -and $g[15].Value -eq 'true')
            InFlightSections = $(if ($g[16].Success) { [Int64]$g[16].Value } else { -1 })
        })
    }
    if ($null -eq $summary) {
        throw 'Trace output did not include its summary object.'
    }
    return [pscustomobject]@{ Entries = $entries; Summary = $summary; RawFile = $RawPath }
}

function Write-DumpQuality([string] $Name, $Trace) {
    $counts = @{}
    foreach ($entry in $Trace.Entries) {
        $counts[$entry.Ev] = 1 + [int]$counts[$entry.Ev]
    }
    $parts = @()
    foreach ($key in @($counts.Keys | Sort-Object)) {
        $parts += ($key + '=' + $counts[$key])
    }
    Write-Output ('Dump_' + $Name + '=entries:' + $Trace.Entries.Count + ';snapshotSequence:' + $Trace.Summary.snapshotSequence +
        ';totalEvents:' + $Trace.Summary.totalEvents + ';lostEntries:' + $Trace.Summary.lostEntries +
        ';ringWrapped:' + ([UInt64]$Trace.Summary.snapshotSequence -gt [UInt64]16384) + ';' + ($parts -join ','))
    Write-Output ('Dump_' + $Name + '_RawFile=' + $Trace.RawFile)
}

function Get-SopEventFacts($Trace, [string] $Sop) {
    $mine = @($Trace.Entries | Where-Object { $_.Sop -eq $Sop })
    return [pscustomobject]@{
        All = $mine
        Acquire = @($mine | Where-Object { $_.Ev -eq 'section_acquire' })
        Release = @($mine | Where-Object { $_.Ev -eq 'section_release' })
        Cleanup = @($mine | Where-Object { $_.Ev -eq 'file_cleanup' })
        Close = @($mine | Where-Object { $_.Ev -eq 'file_close' })
        Paging = @($mine | Where-Object { $_.Ev -eq 'paging_write' })
    }
}

function Format-SopEventFacts($Facts) {
    $acquireText = (@($Facts.Acquire | ForEach-Object { 'sync' + $_.Sync + '/prot0x' + $_.Prot.ToString('X') }) -join ',')
    $pids = (@($Facts.All | ForEach-Object { $_.ProcessId } | Sort-Object -Unique) -join ',')
    return ('acquire=' + $Facts.Acquire.Count + '[' + $acquireText + ']; release=' + $Facts.Release.Count +
        '; cleanup=' + $Facts.Cleanup.Count + '; close=' + $Facts.Close.Count +
        '; pagingWrite=' + $Facts.Paging.Count + '; pids=' + $pids)
}

function Get-ProbeResults($Trace, [string[]] $Labels) {
    $probes = @($Trace.Entries | Where-Object { $_.Ev -eq 'explicit_probe' })
    if ($probes.Count -ne $Labels.Count) {
        Write-Host ('ProbeAttribution=AMBIGUOUS;ProbeEntries=' + $probes.Count + ';Expected=' + $Labels.Count)
        return $null
    }
    $map = @{}
    for ($index = 0; $index -lt $Labels.Count; $index++) {
        $map[$Labels[$index]] = $probes[$index]
    }
    return $map
}

function Write-CompactReader([string] $Name, $Observation) {
    Write-Output ($Name + '=' + $Observation.Class + ';EqualMapped=' + $Observation.EqualMapped +
        ';EqualOriginal=' + $Observation.EqualOriginal + ';Text=' + $Observation.Text)
}

function Initialize-EolNative {
    if (-not ('SafeUploadEolNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SafeUploadEolNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
    }
}

function Initialize-WriterInheritance {
    $script:WriterInheritanceSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class SafeUploadWriterInheritance
{
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
        public uint cb; public string reserved, desktop, title;
        public uint x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags;
        public ushort showWindow, reserved2Size; public IntPtr reserved2, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX { public STARTUPINFO startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr process, thread; public uint processId, threadId; }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetHandleInformation(IntPtr handle, out uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags,
        IntPtr environment, string directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFileAttributesW(string path);
    public static int MissingFileError(string path) {
        uint attributes = GetFileAttributesW(path);
        return attributes == 0xffffffff ? Marshal.GetLastWin32Error() : 0;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(IntPtr file, int informationClass, byte[] information, int size);
    static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static string Identity(IntPtr file) {
        byte[] info = new byte[24]; Check(GetFileInformationByHandleEx(file, 18, info, info.Length));
        return BitConverter.ToString(info).Replace("-", "");
    }
    public static uint ReparseTag(IntPtr directory) {
        byte[] info = new byte[8]; Check(GetFileInformationByHandleEx(directory, 9, info, info.Length));
        if ((BitConverter.ToUInt32(info, 0) & 0x400) == 0) throw new InvalidOperationException("Not a reparse point");
        return BitConverter.ToUInt32(info, 4);
    }
    // The explicit list contains only the fixture file handle. No DuplicateHandle into the child is used.
    public static Process Start(IntPtr file, string application, string command) {
        uint originalFlags; Check(GetHandleInformation(file, out originalFlags));
        IntPtr size = IntPtr.Zero, list = IntPtr.Zero, handles = IntPtr.Zero;
        bool initialized = false, inheritanceChanged = false; Process managed = null;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try {
            Check(SetHandleInformation(file, 1, 1)); inheritanceChanged = true;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            list = Marshal.AllocHGlobal(size); handles = Marshal.AllocHGlobal(IntPtr.Size);
            Check(InitializeProcThreadAttributeList(list, 1, 0, ref size)); initialized = true;
            Marshal.WriteIntPtr(handles, file);
            Check(UpdateProcThreadAttribute(list, 0, new IntPtr(0x20002), handles, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
            STARTUPINFOEX si = new STARTUPINFOEX(); si.startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX)); si.attributes = list;
            Check(CreateProcessW(application, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
                0x08080000, IntPtr.Zero, null, ref si, out pi));
            managed = Process.GetProcessById((int)pi.processId);
            IntPtr managedHandle = managed.Handle; // Acquire managed ownership before releasing the native handle.
            Check(SetHandleInformation(file, 1, originalFlags & 1)); inheritanceChanged = false;
            return managed;
        } catch (Exception error) {
            bool terminated = pi.process == IntPtr.Zero || TerminateProcess(pi.process, 3);
            uint waited = pi.process == IntPtr.Zero ? 0 : WaitForSingleObject(pi.process, 10000);
            if (managed != null) managed.Dispose();
            throw new InvalidOperationException("Inherited child setup failed: " + error.Message +
                "; childPid=" + pi.processId + "; terminated=" + terminated + "; wait=" + waited, error);
        } finally {
            if (inheritanceChanged) SetHandleInformation(file, 1, originalFlags & 1);
            if (pi.thread != IntPtr.Zero) CloseHandle(pi.thread);
            if (pi.process != IntPtr.Zero) CloseHandle(pi.process);
            if (initialized) DeleteProcThreadAttributeList(list);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
        }
    }
}
'@
    if (-not ('SafeUploadWriterInheritance' -as [type])) { Add-Type -TypeDefinition $script:WriterInheritanceSource }
}

function Initialize-WriterStress {
    if (-not ('SafeUploadWriterStress' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;

public static class SafeUploadWriterStress
{
    // Opens and closes the same file for write from several threads; returns the number of failed opens.
    public static int Run(string path, int threads, int iterations)
    {
        int failures = 0;
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++)
        {
            workers[t] = new Thread(delegate ()
            {
                for (int i = 0; i < iterations; i++)
                {
                    try
                    {
                        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite,
                            FileShare.ReadWrite | FileShare.Delete)) { f.WriteByte(0x41); }
                    }
                    catch (IOException) { Interlocked.Increment(ref failures); }
                }
            });
            workers[t].Start();
        }
        foreach (Thread w in workers) { w.Join(); }
        return failures;
    }
}
'@
    }
}

function Initialize-WriterIo {
    # The helper process bounds even a stuck native call. No worker touches a fixture before attachment.
    $script:WriterIoSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class SafeUploadWriterIo
{
    const int Timeout = 10000;
    const uint Read = 0x80000000, Write = 0x40000000;
    static readonly IntPtr Invalid = new IntPtr(-1);
    [StructLayout(LayoutKind.Sequential)]
    struct OplockInput { public ushort Version, Length; public uint Level, Flags; }
    [StructLayout(LayoutKind.Sequential)]
    struct OplockOutput {
        public ushort Version, Length; public uint Original, NewLevel, Flags, Access; public ushort Share;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Overlapped { public IntPtr Internal, InternalHigh; public uint Offset, OffsetHigh; public IntPtr Event; }
    [StructLayout(LayoutKind.Sequential)]
    struct Attributes { public uint AttributesValue, CreationLow, CreationHigh, AccessLow, AccessHigh,
        WriteLow, WriteHigh, SizeHigh, SizeLow; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr file, uint code, IntPtr input, uint inputSize,
        IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetOverlappedResult(IntPtr file, IntPtr overlapped, out uint transferred, bool wait);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CancelIoEx(IntPtr file, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CancelSynchronousIo(IntPtr thread);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DuplicateHandle(IntPtr process, IntPtr source, IntPtr target, out IntPtr handle,
        uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(IntPtr file, byte[] buffer, uint count, out uint done, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadFile(IntPtr file, [Out] byte[] buffer, uint count, out uint done, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFilePointerEx(IntPtr file, long distance, out long position, uint method);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool GetFileAttributesExW(string path, int level, out Attributes info);

    static Exception Error(string operation) { return new Win32Exception(Marshal.GetLastWin32Error(), operation); }
    static IntPtr Open(string path, uint access, uint flags) {
        IntPtr h = CreateFileW(path, access, 7, IntPtr.Zero, 3, flags, IntPtr.Zero);
        if (h == Invalid) throw Error("CreateFile");
        return h;
    }
    static IntPtr ThreadHandle() {
        IntPtr h;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), out h, 0, false, 2))
            throw Error("DuplicateHandle(thread)");
        return h;
    }
    static void Cancel(IntPtr thread, bool allowCompleted) {
        if (thread == IntPtr.Zero) return;
        if (!CancelSynchronousIo(thread)) {
            int error = Marshal.GetLastWin32Error();
            if (!allowCompleted || error != 1168) throw new Win32Exception(error, "CancelSynchronousIo");
        }
    }
    static void Seek(IntPtr h, long offset) {
        long position;
        if (!SetFilePointerEx(h, offset, out position, 0) || position != offset) throw Error("SetFilePointerEx");
    }
    static void Query(string path) {
        Attributes info;
        if (!GetFileAttributesExW(path, 0, out info)) throw Error("GetFileAttributesEx");
    }

    sealed class PendingCreate : IDisposable
    {
        IntPtr holder, input, output, overlapped, victimHandle;
        IntPtr victimFile = Invalid;
        readonly ManualResetEvent broken = new ManualResetEvent(false);
        readonly ManualResetEvent ready = new ManualResetEvent(false);
        Thread victim;
        bool started, requestPending, notificationDone;
        bool succeeded;
        int createError;
        Exception workerError;
        public string Proof;

        public PendingCreate(string path, uint level) {
            try {
                holder = Open(path, Read, 0x40000080); // read-only, overlapped, share all
                input = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OplockInput)));
                output = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OplockOutput)));
                overlapped = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Overlapped)));
                OplockInput request = new OplockInput();
                request.Version = 1; request.Length = (ushort)Marshal.SizeOf(typeof(OplockInput));
                request.Level = level; request.Flags = 1; // REQUEST_OPLOCK_INPUT_FLAG_REQUEST
                Marshal.StructureToPtr(request, input, false);
                Marshal.StructureToPtr(new OplockOutput(), output, false);
                Overlapped ov = new Overlapped(); ov.Event = broken.SafeWaitHandle.DangerousGetHandle();
                Marshal.StructureToPtr(ov, overlapped, false);
                uint returned;
                bool granted = DeviceIoControl(holder, 0x00090240, input, (uint)request.Length,
                    output, (uint)Marshal.SizeOf(typeof(OplockOutput)), out returned, overlapped);
                int error = Marshal.GetLastWin32Error();
                if (granted || error != 997) throw new Win32Exception(error, "Oplock was not granted as ERROR_IO_PENDING");
                requestPending = true;
                if (broken.WaitOne(0)) throw new InvalidOperationException("Oplock broke before victim start");
                victim = new Thread(delegate () {
                    try {
                        victimHandle = ThreadHandle();
                        ready.Set();
                        // OPEN_EXISTING, synchronous CreateFile; no FILE_COMPLETE_IF_OPLOCKED. With a handle-caching
                        // oplock the victim shares nothing, so it conflicts with the holder's open and must wait for the break.
                        victimFile = CreateFileW(path, Write, (level & 2) != 0 ? 0u : 7u, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                        createError = victimFile == Invalid ? Marshal.GetLastWin32Error() : 0;
                        succeeded = victimFile != Invalid;
                        // No later I/O on this thread: a racing cancel must not target CloseHandle.
                        // The owning PendingCreate closes a successful handle in its finally block.
                    } catch (Exception e) { workerError = e; ready.Set(); }
                });
                victim.IsBackground = true;
                victim.Start(); started = true;
                if (!ready.WaitOne(Timeout)) throw new TimeoutException("Victim thread startup");
                if (!broken.WaitOne(Timeout)) throw new TimeoutException("No oplock break: create not proven pending;victim:" +
                    (victim.Join(0) ? Outcome() : "pending"));
                if (!GetOverlappedResult(holder, overlapped, out returned, false)) throw Error("Oplock break completion");
                notificationDone = true;
                OplockOutput result = (OplockOutput)Marshal.PtrToStructure(output, typeof(OplockOutput));
                Proof = "granted:997;original:" + result.Original + ";new:" + result.NewLevel + ";flags:" + result.Flags;
                if (result.Version != 1 || result.Length != Marshal.SizeOf(typeof(OplockOutput)) ||
                    result.Original != level || (result.Flags & 1) == 0)
                    throw new InvalidOperationException("Break cannot establish an acknowledgment barrier: " + Proof);
                if (victim.Join(0)) throw new InvalidOperationException("Victim completed before cancellation: " + Outcome());
            } catch { Dispose(); throw; }
        }
        void CloseHolder() {
            IntPtr h = Interlocked.Exchange(ref holder, IntPtr.Zero);
            if (h != IntPtr.Zero) CloseHandle(h);
        }
        string Outcome() {
            if (workerError != null) throw new InvalidOperationException("Victim error", workerError);
            return "succeeded:" + succeeded + ";win32:" + createError;
        }
        public string CancelOnly() {
            Cancel(victimHandle, false);
            if (!victim.Join(Timeout)) throw new TimeoutException("Cancelled CreateFile did not finish");
            return Outcome(); // holder stays open across the immediate parent probe
        }
        public string Race(int cancelDelay, int closeDelay) {
            Thread closer = null;
            Exception closeError = null;
            using (ManualResetEvent go = new ManualResetEvent(false)) {
                try {
                    closer = new Thread(delegate () {
                        try {
                            if (!go.WaitOne(Timeout)) throw new TimeoutException("Race start");
                            if (closeDelay != 0) Thread.Sleep(closeDelay);
                            CloseHolder();
                        } catch (Exception e) { closeError = e; }
                    });
                    closer.IsBackground = true; closer.Start();
                    go.Set();
                    if (cancelDelay != 0) Thread.Sleep(cancelDelay);
                    Cancel(victimHandle, true); // ERROR_NOT_FOUND is allowed only for the racing cancel call
                    if (!victim.Join(Timeout)) throw new TimeoutException("Race CreateFile did not finish");
                    if (!closer.Join(Timeout)) throw new TimeoutException("Race holder closure did not finish");
                    if (closeError != null) throw closeError;
                    return Outcome();
                } finally {
                    go.Set();
                    if (closer != null && !closer.Join(Timeout)) Environment.Exit(2);
                }
            }
        }
        public void Dispose() {
            try {
                if (holder != IntPtr.Zero && requestPending && !notificationDone) CancelIoEx(holder, overlapped);
                CloseHolder(); // unblock even a victim whose cancellation failed
                if (started) {
                    try { Cancel(victimHandle, true); } catch { /* joining below is mandatory */ }
                    if (!victim.Join(Timeout)) Environment.Exit(2); // parent reaps this isolated process
                }
                if (requestPending && !notificationDone && !broken.WaitOne(Timeout)) Environment.Exit(2);
            } finally {
                if (victimFile != Invalid) { CloseHandle(victimFile); victimFile = Invalid; }
                if (victimHandle != IntPtr.Zero) { CloseHandle(victimHandle); victimHandle = IntPtr.Zero; }
                if (input != IntPtr.Zero) { Marshal.FreeHGlobal(input); input = IntPtr.Zero; }
                if (output != IntPtr.Zero) { Marshal.FreeHGlobal(output); output = IntPtr.Zero; }
                if (overlapped != IntPtr.Zero) { Marshal.FreeHGlobal(overlapped); overlapped = IntPtr.Zero; }
                broken.Dispose(); ready.Dispose();
            }
        }
    }

    static long Concurrent(string path) {
        Thread[] workers = new Thread[8];
        bool[] started = new bool[8];
        IntPtr[] handles = new IntPtr[8];
        long[] iterations = new long[8];
        Exception[] errors = new Exception[8];
        using (ManualResetEvent go = new ManualResetEvent(false))
        using (ManualResetEvent stop = new ManualResetEvent(false))
        using (CountdownEvent ready = new CountdownEvent(8)) {
            try {
                for (int i = 0; i < 8; i++) {
                    int index = i;
                    workers[i] = new Thread(delegate () {
                        IntPtr reader = IntPtr.Zero;
                        bool announced = false;
                        try {
                            handles[index] = ThreadHandle();
                            if (index < 4) reader = Open(path, Read, 0x80);
                            ready.Signal(); announced = true;
                            if (!go.WaitOne(Timeout)) throw new TimeoutException("Concurrent start");
                            byte[] buffer = new byte[512];
                            while (!stop.WaitOne(0)) {
                                if (index < 4) {
                                    Query(path); Seek(reader, 0);
                                    uint done;
                                    if (!ReadFile(reader, buffer, 512, out done, IntPtr.Zero) || done != 512)
                                        throw Error("Concurrent ReadFile");
                                } else {
                                    IntPtr writer = IntPtr.Zero;
                                    try {
                                        writer = Open(path, Write, 0x80);
                                        uint done;
                                        if (!WriteFile(writer, buffer, 512, out done, IntPtr.Zero) || done != 512)
                                            throw Error("Concurrent WriteFile");
                                    } finally { if (writer != IntPtr.Zero) CloseHandle(writer); }
                                }
                                iterations[index]++;
                            }
                        } catch (Exception e) { errors[index] = e; }
                        finally {
                            if (!announced) ready.Signal();
                            if (reader != IntPtr.Zero) CloseHandle(reader);
                        }
                    });
                    workers[i].IsBackground = true; workers[i].Start(); started[i] = true;
                }
                if (!ready.Wait(Timeout)) throw new TimeoutException("Concurrent workers ready");
                go.Set();
                stop.WaitOne(3000); // fixed workload duration; verdict uses joins and counters
            } finally {
                stop.Set(); go.Set();
                // Give ordinary I/O time to finish before cancelling a genuinely stuck call.
                Stopwatch deadline = Stopwatch.StartNew();
                for (int i = 0; i < 8; i++) {
                    if (!started[i]) continue;
                    int remaining = Math.Max(0, Timeout - (int)deadline.ElapsedMilliseconds);
                    if (!workers[i].Join(remaining)) {
                        try { Cancel(handles[i], true); } catch { }
                        if (!workers[i].Join(Timeout)) Environment.Exit(2);
                        if (errors[i] == null) errors[i] = new TimeoutException("Concurrent worker required cancellation");
                    }
                }
                for (int i = 0; i < 8; i++) if (handles[i] != IntPtr.Zero) CloseHandle(handles[i]);
            }
        }
        long total = 0;
        for (int i = 0; i < 8; i++) {
            if (errors[i] != null) throw new InvalidOperationException("Concurrent worker " + i, errors[i]);
            if (iterations[i] == 0) throw new InvalidOperationException("Concurrent worker made no progress: " + i);
            total += iterations[i];
        }
        return total;
    }

    public static void Serve(string path) {
        PendingCreate pending = null;
        IntPtr writer = IntPtr.Zero;
        long offset = 0;
        Console.Out.WriteLine("READY"); Console.Out.Flush();
        try {
            string line;
            while ((line = Console.In.ReadLine()) != null) {
                string[] args = line.Split(' ');
                string result = "OK";
                try {
                    switch (args[0]) {
                        case "BEGIN":
                            if (pending != null) throw new InvalidOperationException("Holder already exists");
                            pending = new PendingCreate(path, UInt32.Parse(args[1]));
                            result += " " + pending.Proof; break;
                        case "CANCEL": result += " " + pending.CancelOnly(); break;
                        case "RELEASE": pending.Dispose(); pending = null; break;
                        case "RACE":
                            using (PendingCreate race = new PendingCreate(path, UInt32.Parse(args[1])))
                                result += " " + race.Race(Int32.Parse(args[2]), Int32.Parse(args[3]));
                            break;
                        case "OPEN":
                            if (writer != IntPtr.Zero) throw new InvalidOperationException("Writer already exists");
                            writer = Open(path, Read | Write, 0x80); offset = 0; break;
                        case "CLOSE":
                            if (writer != IntPtr.Zero) { CloseHandle(writer); writer = IntPtr.Zero; } break;
                        case "WRITES":
                            if (writer == IntPtr.Zero) throw new InvalidOperationException("No cached writer");
                            int count = Int32.Parse(args[1]), size = Int32.Parse(args[2]);
                            byte[] data = new byte[size], readback = new byte[size];
                            for (int i = 0; i < size; i++) data[i] = (byte)(i * 17 + size);
                            for (int i = 0; i < count; i++) {
                                uint done;
                                Seek(writer, offset);
                                if (!WriteFile(writer, data, (uint)size, out done, IntPtr.Zero) || done != size)
                                    throw Error("Cached WriteFile");
                                Seek(writer, offset);
                                if (!ReadFile(writer, readback, (uint)size, out done, IntPtr.Zero) || done != size)
                                    throw Error("Cached ReadFile");
                                for (int j = 0; j < size; j++) if (data[j] != readback[j])
                                    throw new InvalidOperationException("Cached readback mismatch");
                                offset += size;
                            }
                            result += " " + count; break;
                        case "QUERIES":
                            int queries = Int32.Parse(args[1]);
                            for (int i = 0; i < queries; i++) Query(path);
                            result += " " + queries; break;
                        case "CONCURRENT": result += " " + Concurrent(path); break;
                        case "EXIT": return;
                        default: throw new InvalidOperationException("Unknown worker command");
                    }
                } catch (Exception e) {
                    // Failures are data for the parent's WC summary; reclaim all outstanding state first.
                    if (pending != null) { pending.Dispose(); pending = null; }
                    if (writer != IntPtr.Zero) { CloseHandle(writer); writer = IntPtr.Zero; }
                    result = "ERROR " + e.ToString().Replace('\r', ' ').Replace('\n', ' ');
                }
                Console.Out.WriteLine(result); Console.Out.Flush();
            }
        } finally {
            if (pending != null) pending.Dispose();
            if (writer != IntPtr.Zero) CloseHandle(writer);
        }
    }

    public sealed class Session : IDisposable
    {
        Process process;
        bool started, faulted;
        readonly StringBuilder stderr = new StringBuilder();
        public static Session Start(string executable, string source, string fixture) {
            Session session = new Session();
            try {
                string code = "$ErrorActionPreference='Stop'; try { Add-Type -Path '" + source.Replace("'", "''") +
                    "'; [SafeUploadWriterIo]::Serve('" + fixture.Replace("'", "''") +
                    "') } catch { [Console]::Out.WriteLine('ERROR '+$_.Exception.ToString()); exit 2 }";
                ProcessStartInfo start = new ProcessStartInfo(executable,
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " +
                    Convert.ToBase64String(Encoding.Unicode.GetBytes(code)));
                start.UseShellExecute = false; start.CreateNoWindow = true;
                start.RedirectStandardInput = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
                session.process = new Process(); session.process.StartInfo = start;
                session.process.ErrorDataReceived += delegate (object sender, DataReceivedEventArgs e) {
                    if (e.Data != null) lock (session.stderr) { session.stderr.AppendLine(e.Data); }
                };
                if (!session.process.Start()) throw new InvalidOperationException("Worker process did not start");
                session.started = true;
                session.process.BeginErrorReadLine();
                string hello = session.Receive(30000);
                if (hello != "READY") throw new InvalidOperationException("Worker did not report READY: " + hello);
                return session;
            } catch (Exception failure) {
                try { session.Dispose(); }
                catch (Exception cleanup) { throw new AggregateException(failure, cleanup); }
                throw;
            }
        }
        string Receive(int milliseconds) {
            var read = process.StandardOutput.ReadLineAsync();
            if (!read.Wait(milliseconds)) throw new TimeoutException("Writer I/O worker response");
            string line = read.Result;
            if (line == null) {
                lock (stderr) { throw new InvalidOperationException("Writer I/O worker exited: " + stderr); }
            }
            return line;
        }
        public string Request(string command) {
            if (process == null || faulted) throw new InvalidOperationException("Writer I/O session unavailable");
            try {
                process.StandardInput.WriteLine(command); process.StandardInput.Flush();
                string result = Receive(30000);
                if (result != "OK" && !result.StartsWith("OK ")) throw new InvalidOperationException(result);
                return result.Length > 3 ? result.Substring(3) : "";
            } catch { faulted = true; throw; }
        }
        public void Dispose() {
            if (process == null) return;
            try {
                bool killed = false;
                if (started && !process.HasExited) {
                    try { process.StandardInput.WriteLine("EXIT"); process.StandardInput.Flush(); } catch { }
                    if (!process.WaitForExit(5000)) {
                        process.Kill(); killed = true;
                        if (!process.WaitForExit(10000)) throw new TimeoutException("Writer I/O worker termination");
                    }
                }
                if (started && (killed || process.ExitCode != 0))
                    throw new InvalidOperationException("Writer I/O worker exit:" + process.ExitCode + ";forced:" + killed);
            } finally {
                try {
                    if (started) {
                        // StandardError is in asynchronous mode (BeginErrorReadLine); Process.Dispose releases it.
                        try { process.StandardInput.Dispose(); }
                        finally { process.StandardOutput.Dispose(); }
                    }
                } finally { process.Dispose(); process = null; }
            }
        }
    }
}
'@
    if (-not ('SafeUploadWriterIo' -as [type])) { Add-Type -TypeDefinition $script:WriterIoSource }
}

function Initialize-PrimitiveCost {
    # Like WriterIo, compile command-driven child processes before attachment. No fixture opens at READY.
    $script:PrimitiveCostSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class SafeUploadPrimitiveCost
{
    const int Warmup = 2000, Measured = 20000, PhaseMilliseconds = 580000;
    const uint Read = 0x80000000, Write = 0x40000000;
    static readonly IntPtr Invalid = new IntPtr(-1);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr security, uint protection,
        uint sizeHigh, uint sizeLow, IntPtr name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint offsetHigh,
        uint offsetLow, UIntPtr length);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool UnmapViewOfFile(IntPtr view);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteFile(IntPtr file, IntPtr buffer, uint size, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetFilePointerEx(IntPtr file, long distance, out long position, uint method);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool QueryPerformanceCounter(out long value);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool QueryPerformanceFrequency(out long value);

    static long Counter() {
        long value;
        if (!QueryPerformanceCounter(out value)) throw new InvalidOperationException("QPC failed");
        return value;
    }
    static IntPtr Open(string path, uint access) {
        IntPtr handle = CreateFileW(path, access, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (handle == Invalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileW");
        return handle;
    }
    static void Close(IntPtr handle) {
        if (!CloseHandle(handle)) throw new Win32Exception(Marshal.GetLastWin32Error(), "CloseHandle");
    }
    static void Unmap(IntPtr view) {
        if (!UnmapViewOfFile(view)) throw new Win32Exception(Marshal.GetLastWin32Error(), "UnmapViewOfFile");
    }
    static string Summary(long[] ticks, long frequency) {
        Array.Sort(ticks);
        // Nearest-rank percentiles, using the complete measured array, without interpolation.
        return "n:" + ticks.Length.ToString(CultureInfo.InvariantCulture) +
            ";minTicks:" + ticks[0].ToString(CultureInfo.InvariantCulture) +
            ";p50Ticks:" + ticks[(ticks.Length * 50 / 100) - 1].ToString(CultureInfo.InvariantCulture) +
            ";p95Ticks:" + ticks[(ticks.Length * 95 / 100) - 1].ToString(CultureInfo.InvariantCulture) +
            ";p99Ticks:" + ticks[(ticks.Length * 99 / 100) - 1].ToString(CultureInfo.InvariantCulture) +
            ";maxTicks:" + ticks[ticks.Length - 1].ToString(CultureInfo.InvariantCulture) +
            ";frequency:" + frequency.ToString(CultureInfo.InvariantCulture);
    }
    static string Measure(string path, string operation) {
        bool create = operation == "create_write" || operation == "create_read" || operation == "create_attr";
        bool section = operation == "section_write" || operation == "section_read";
        bool write = operation == "write_cached";
        if (!create && !section && !write) throw new ArgumentException("Unknown cost operation");
        long frequency;
        if (!QueryPerformanceFrequency(out frequency) || frequency <= 0)
            throw new InvalidOperationException("QPF failed");
        long[] samples = new long[Measured];
        long[] createOnly = operation == "create_write" ? new long[Measured] : null;
        // Both section controls use an already-open writable handle; only mapping protection changes.
        uint access = (operation == "create_write" || section || write) ? Read | Write :
            (operation == "create_attr" ? 0x100U : Read);
        IntPtr file = Invalid, buffer = IntPtr.Zero;
        try {
            if (!create) file = Open(path, access);
            if (write) {
                buffer = Marshal.AllocHGlobal(4096);
                byte[] data = new byte[4096];
                for (int i = 0; i < data.Length; i++) data[i] = 0x5a;
                Marshal.Copy(data, 0, buffer, data.Length);
            }
            // No managed allocations, sleeping, flushing or sample formatting in the successful loop.
            for (int i = 0; i < Warmup + Measured; i++) {
                long begin, end, opened = 0;
                if (create) {
                    IntPtr current = Invalid;
                    begin = Counter();
                    try {
                        current = Open(path, access);
                        if (createOnly != null) opened = Counter();
                    } finally { if (current != Invalid) Close(current); }
                    end = Counter();
                } else if (section) {
                    IntPtr mapping = IntPtr.Zero, view = IntPtr.Zero;
                    begin = Counter();
                    try {
                        mapping = CreateFileMappingW(file, IntPtr.Zero,
                            operation == "section_write" ? 0x04U : 0x02U, 0, 4096, IntPtr.Zero);
                        if (mapping == IntPtr.Zero)
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateFileMappingW");
                        view = MapViewOfFile(mapping, operation == "section_write" ? 0x02U : 0x04U,
                            0, 0, new UIntPtr(4096U));
                        if (view == IntPtr.Zero)
                            throw new Win32Exception(Marshal.GetLastWin32Error(), "MapViewOfFile");
                    } finally {
                        try { if (view != IntPtr.Zero) Unmap(view); }
                        finally { if (mapping != IntPtr.Zero) Close(mapping); }
                    }
                    end = Counter();
                } else {
                    // Reuse the same 4 KiB extent. Seek is outside the timed WriteFile call.
                    long position;
                    if (!SetFilePointerEx(file, 0, out position, 0))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetFilePointerEx");
                    uint written;
                    begin = Counter();
                    bool ok = WriteFile(file, buffer, 4096, out written, IntPtr.Zero);
                    end = Counter();
                    if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteFile");
                    if (written != 4096) throw new IOException("Short cached WriteFile");
                }
                if (end < begin || (createOnly != null && (opened < begin || end < opened)))
                    throw new InvalidOperationException("QPC moved backwards");
                if (i >= Warmup) {
                    samples[i - Warmup] = end - begin;
                    if (createOnly != null) createOnly[i - Warmup] = opened - begin;
                }
            }
        } finally {
            try { if (file != Invalid) Close(file); }
            finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
        }
        return Summary(samples, frequency) + (createOnly == null ? "" : "|" + Summary(createOnly, frequency));
    }
    public static void Serve(string path) {
        string decision;
        using (Process self = Process.GetCurrentProcess()) {
            ulong allowed = unchecked((ulong)self.ProcessorAffinity.ToInt64());
            if (allowed == 0) throw new InvalidOperationException("Empty allowed CPU affinity");
            ulong single = allowed & unchecked(~allowed + 1UL);
            IntPtr affinity = IntPtr.Size == 8 ? new IntPtr(unchecked((long)single)) :
                new IntPtr(unchecked((int)single));
            self.ProcessorAffinity = affinity;
            self.PriorityClass = ProcessPriorityClass.Normal;
            if (self.ProcessorAffinity != affinity || self.PriorityClass != ProcessPriorityClass.Normal)
                throw new InvalidOperationException("CPU affinity or priority readback mismatch");
            decision = "affinityMask:0x" + single.ToString("X", CultureInfo.InvariantCulture) +
                ";selection:lowestAllowedLogicalProcessorInCurrentGroup;priority:Normal;processorCount:" +
                Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture);
        }
        Console.Out.WriteLine("READY " + decision); Console.Out.Flush();
        string line;
        while ((line = Console.In.ReadLine()) != null && line != "EXIT") {
            // Reply only after every handle/view for this operation has been released: helper is idle.
            Console.Out.WriteLine("OK " + Measure(path, line)); Console.Out.Flush();
        }
    }
    public sealed class Session : IDisposable
    {
        Process process;
        bool started, aborted;
        Stopwatch phase;
        readonly StringBuilder stderr = new StringBuilder();
        public string ReadyInfo { get; private set; }
        public static Session Start(string executable, string source, string fixture) {
            Session session = new Session();
            try {
                string code = "$ErrorActionPreference='Stop'; try { Add-Type -Path '" + source.Replace("'", "''") +
                    "'; [SafeUploadPrimitiveCost]::Serve('" + fixture.Replace("'", "''") +
                    "') } catch { [Console]::Out.WriteLine('ERROR '+$_.Exception.ToString()); exit 2 }";
                ProcessStartInfo start = new ProcessStartInfo(executable,
                    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " +
                    Convert.ToBase64String(Encoding.Unicode.GetBytes(code)));
                start.UseShellExecute = false; start.CreateNoWindow = true;
                start.RedirectStandardInput = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
                session.process = new Process(); session.process.StartInfo = start;
                session.process.ErrorDataReceived += delegate (object sender, DataReceivedEventArgs e) {
                    if (e.Data != null) lock (session.stderr) { session.stderr.AppendLine(e.Data); }
                };
                if (!session.process.Start()) throw new InvalidOperationException("Cost worker did not start");
                session.started = true; session.process.BeginErrorReadLine();
                string hello = session.Receive(30000);
                if (!hello.StartsWith("READY ")) throw new InvalidOperationException("Cost worker not READY: " + hello);
                session.ReadyInfo = hello.Substring(6);
                return session;
            } catch (Exception failure) {
                try { try { session.Kill(); } finally { session.Dispose(); } }
                catch (Exception cleanup) { throw new AggregateException(failure, cleanup); }
                throw;
            }
        }
        string Receive(int milliseconds) {
            var read = process.StandardOutput.ReadLineAsync();
            if (!read.Wait(milliseconds)) throw new TimeoutException("Primitive cost worker response");
            string line = read.Result;
            if (line == null) {
                lock (stderr) { throw new InvalidOperationException("Cost worker exited: " + stderr); }
            }
            return line;
        }
        void Kill() {
            aborted = true;
            if (process != null && started && !process.HasExited) {
                process.Kill();
                if (!process.WaitForExit(10000)) throw new TimeoutException("Cost worker termination");
            }
        }
        public void BeginPhase() { phase = Stopwatch.StartNew(); }
        public string Request(string operation) {
            if (process == null || phase == null) throw new InvalidOperationException("Cost phase unavailable");
            try {
                int remaining = PhaseMilliseconds - (int)Math.Min(phase.ElapsedMilliseconds, PhaseMilliseconds);
                if (remaining <= 0) throw new TimeoutException("Primitive cost phase deadline");
                process.StandardInput.WriteLine(operation); process.StandardInput.Flush();
                string result = Receive(remaining);
                if (!result.StartsWith("OK ")) throw new InvalidOperationException(result);
                if (phase.ElapsedMilliseconds >= PhaseMilliseconds)
                    throw new TimeoutException("Primitive cost phase deadline");
                return result.Substring(3);
            } catch (Exception failure) {
                // Kill immediately on timeout/error, including a native call stuck inside the child.
                try { try { Kill(); } finally { Dispose(); } }
                catch (Exception cleanup) { throw new AggregateException(failure, cleanup); }
                throw;
            }
        }
        public void Dispose() {
            if (process == null) return;
            try {
                if (started && !process.HasExited) {
                    // A failed Kill already consumed its bounded wait; never wait/kill a second time.
                    if (aborted) throw new TimeoutException("Cost worker did not terminate after Kill");
                    try { process.StandardInput.WriteLine("EXIT"); process.StandardInput.Flush(); } catch { }
                    if (!process.WaitForExit(5000)) {
                        Kill();
                        throw new TimeoutException("Cost worker required forced termination");
                    }
                }
                if (started && !aborted && process.ExitCode != 0)
                    throw new InvalidOperationException("Cost worker exit: " + process.ExitCode);
            } finally {
                try {
                    if (started) {
                        try { process.StandardInput.Dispose(); }
                        finally { process.StandardOutput.Dispose(); }
                    }
                } finally { process.Dispose(); process = null; }
            }
        }
    }
}
'@
    if (-not ('SafeUploadPrimitiveCost' -as [type])) { Add-Type -TypeDefinition $script:PrimitiveCostSource }
}

$script:WriterChecks = New-Object System.Collections.ArrayList

function Add-WriterProbe([string] $Path, [string] $Label, [int] $ExpectedWriters, [string] $ExpectedMmDoes = '') {
    # Probes the stream and remembers what the harness knows to be true at this instant.
    [void]$script:WriterChecks.Add(@{ Label = $Label; Expected = $ExpectedWriters; ExpectedMm = $ExpectedMmDoes })
    [void](Invoke-AdmissionProbe $Path ('WC_' + $Label) $InspectorTimeoutSeconds)
}

function Complete-WriterChecks([string] $GroupName, [string] $RawPath) {
    # One dump per group keeps the ring small; entries are matched to checks by order.
    $trace = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds) $RawPath
    $probes = @($trace.Entries | Where-Object { $_.Ev -eq 'explicit_probe' } | Sort-Object Seq)
    Write-Output ('WC_Group_' + $GroupName + '=probes:' + $probes.Count + ';checks:' + $script:WriterChecks.Count +
        ';lostEntries:' + $trace.Summary.lostEntries + ';snapshotSequence:' + $trace.Summary.snapshotSequence)
    if ($probes.Count -ne $script:WriterChecks.Count) {
        Write-Output ('WC_Group_' + $GroupName + '_Attribution=AMBIGUOUS')
        $script:WriterChecksFailed += $script:WriterChecks.Count
    }
    else {
        for ($index = 0; $index -lt $probes.Count; $index++) {
            $check = $script:WriterChecks[$index]
            $entry = $probes[$index]
            $writersOk = ($entry.Writers -eq $check.Expected) -and (-not $entry.WritersUntracked)
            $mmOk = ([string]::IsNullOrEmpty($check.ExpectedMm) -or $entry.MmDoes -eq $check.ExpectedMm)
            $verdict = if ($entry.ProbeValid -and $writersOk -and $mmOk -and
                (-not $RequireCanary -or $entry.CanaryOk)) { 'PASS' } else { 'FAIL' }
            if ($verdict -ne 'PASS') { $script:WriterChecksFailed++ } else { $script:WriterChecksPassed++ }
            Write-Output ('WC_' + $check.Label + '=expected:' + $check.Expected + ';observed:' + $entry.Writers +
                ';untracked:' + $entry.WritersUntracked + ';mmDoes:' + $entry.MmDoes +
                ';probeStatus:' + $entry.ProbeStatus + ';probeStage:' + $entry.ProbeStage +
                $(if ($check.ExpectedMm) { ';expectedMmDoes:' + $check.ExpectedMm } else { '' }) + ';' + $verdict)
        }
    }
    $script:WriterChecks.Clear()
    [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds)
}

function Get-WriterStateStats {
    $r = Invoke-InspectorChecked -Arguments @('--writer-state-status') -Timeout $InspectorTimeoutSeconds
    return (ConvertFrom-Json -InputObject ([string]$r.Stdout).Trim())
}

function Wait-AdmissionCanary([string] $Path, [string] $RawPath) {
    if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($RawPath + '-volumes.json') }
    if (-not $RequireCanary) { return }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        [void](Invoke-AdmissionProbe $Path ('Canary_' + $attempt) $InspectorTimeoutSeconds)
        $trace = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds) ($RawPath + '-canary-' + $attempt + '.jsonl')
        $probes = @($trace.Entries | Where-Object { $_.Ev -eq 'explicit_probe' })
        if ($probes.Count -ne 1 -or -not $probes[0].ProbeValid) { throw 'Canary probe failed or attribution is ambiguous.' }
        if ($probes[0].CanaryOk) {
            Write-Output 'VolumeCanary=PASS;retained:YES;released:NO;removed:YES'
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds)
            return
        }
        if ($probes[0].CanaryState -ge 3) {
            throw ('Volume canary failed: state=' + $probes[0].CanaryState + ';status=' +
                $probes[0].CanaryStatus + ';checks=' + $probes[0].CanaryChecks)
        }
        [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds)
        Start-Sleep -Milliseconds 100
    }
    throw 'Volume canary did not reach its passed state (inspect retained raw canary probes).'
}

function Wait-AllVolumeCanaries([string] $RawPath) {
    $volumes = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop |
        Where-Object FileSystem -eq 'NTFS')
    $expected = @($volumes | ForEach-Object {
        if ($_.DeviceID -notmatch '(?i)\{[0-9a-f-]{36}\}') { throw 'Invalid independent volume GUID.' }
        $matches[0].ToLowerInvariant()
    } | Sort-Object)
    if ($expected.Count -eq 0 -or @($expected | Select-Object -Unique).Count -ne $expected.Count) {
        throw 'Independent fixed NTFS volume set is empty or ambiguous.'
    }
    Write-Output ('IndependentFixedNtfsGuids=' + ($expected -join ';'))
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        $response = Invoke-InspectorChecked -Arguments @('--admission-volume-status') -Timeout $InspectorTimeoutSeconds
        [IO.File]::WriteAllText(($RawPath + '-' + $attempt), [string]$response.Stdout)
        $status = ConvertFrom-Json -InputObject ([string]$response.Stdout).Trim()
        if ($null -eq $status.admissionVolumes -or $null -eq $status.writerGlobalUnknown) {
            throw 'Missing all-volume status fields.'
        }
        if ($status.writerGlobalUnknown -ne 0) { throw 'Global writer tracking is unknown.' }
        foreach ($entry in $status.admissionVolumes) {
            if ($entry.contextStatus -ne 0 -or $entry.fileSystemStatus -ne 0 -or
                $null -eq $entry.volumeInfoStatus -or $entry.volumeInfoStatus -ne 0 -or $null -eq $entry.volumeFlags) {
                throw 'An attached instance has an unresolved context or filesystem.'
            }
        }
        $detached = @($status.admissionVolumes | Where-Object { ($_.volumeFlags -band 1) -ne 0 })
        Write-Output ('DetachedVolumeEntries=' + $detached.Count)
        $eligible = @($status.admissionVolumes | Where-Object {
            $_.volumeKind -eq 1 -and $_.fileSystemType -eq 2 -and ($_.volumeFlags -band 1) -eq 0 })
        $actual = @($eligible | ForEach-Object {
            if ($_.contextStatus -ne 0 -or $_.fileSystemStatus -ne 0 -or $_.volumeGuidStatus -ne 0 -or
                $_.volumeGuid -notmatch '(?i)\{[0-9a-f-]{36}\}') { throw 'Unresolved eligible volume identity.' }
            $matches[0].ToLowerInvariant()
        } | Sort-Object)
        if (($actual -join ';') -ne ($expected -join ';')) { throw 'Attached fixed NTFS set differs from independent volume set.' }
        $pending = $false
        foreach ($entry in $eligible) {
            if ($entry.instanceWritersUntracked -ne 0) { throw 'Instance writer tracking is unknown.' }
            if ($entry.canaryState -lt 2) { $pending = $true; continue }
            if ($entry.canaryState -ne 2 -or $entry.canaryStatus -ne 0 -or $entry.canaryChecks -ne 15 -or
                $entry.canaryCleanupStatus -ne 0) { throw ('All-volume canary failed for ' + $entry.volumeGuid) }
        }
        if (-not $pending) {
            Write-Output ('AllVolumeCanaries=PASS;count:' + $eligible.Count)
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'All-volume canary timeout.'
}

function Initialize-SectionStress {
    if (-not ('SafeUploadSectionStress' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Threading;

public static class SafeUploadSectionStress
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protect, uint maxHigh, uint maxLow, string name);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    // Creates and drops writable sections (and, optionally, read-only ones) from several threads; returns failures.
    public static int Run(string[] paths, int threads, int iterations, bool alsoReadOnly)
    {
        int failures = 0;
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++)
        {
            int seed = t;
            workers[t] = new Thread(delegate ()
            {
                for (int i = 0; i < iterations; i++)
                {
                    string path = paths[(seed * iterations + i) % paths.Length];
                    try
                    {
                        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
                        using (MemoryMappedFile m = MemoryMappedFile.CreateFromFile(f, null, 4096, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true))
                        {
                            using (MemoryMappedViewAccessor v = m.CreateViewAccessor(0, 4096, MemoryMappedFileAccess.ReadWrite)) { v.Write(0, (byte)0x42); }
                        }
                        if (alsoReadOnly)
                        {
                            using (FileStream r = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                            using (MemoryMappedFile m2 = MemoryMappedFile.CreateFromFile(r, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, true))
                            {
                                using (MemoryMappedViewAccessor v2 = m2.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read)) { v2.ReadByte(0); }
                            }
                        }
                    }
                    catch (Exception) { Interlocked.Increment(ref failures); }
                }
            });
            workers[t].Start();
        }
        foreach (Thread w in workers) { w.Join(); }
        return failures;
    }

    // A writable mapping of an empty file with no size fails inside the memory manager. Returns the Win32 error (0 = unexpected success).
    public static int TryEmptyFileMapping(string path)
    {
        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
        {
            IntPtr mapping = CreateFileMappingW(f.SafeFileHandle.DangerousGetHandle(), IntPtr.Zero, 0x04, 0, 0, null);
            if (mapping == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
            CloseHandle(mapping);
            return 0;
        }
    }

    // All threads map the SAME file object. Mixed protections exercise release pairing without
    // the incidental isolation provided by a separate FileStream for every mapping.
    public static int RunSharedFileObject(string path, int threads, int iterations)
    {
        int failures = 0;
        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
        using (ManualResetEvent start = new ManualResetEvent(false))
        {
            IntPtr file = f.SafeFileHandle.DangerousGetHandle();
            Thread[] workers = new Thread[threads];
            for (int t = 0; t < threads; t++)
            {
                workers[t] = new Thread(delegate ()
                {
                    start.WaitOne();
                    for (int i = 0; i < iterations; i++)
                    {
                        foreach (uint protection in new uint[] { 0x04, 0x02 })
                        {
                            IntPtr mapping = CreateFileMappingW(file, IntPtr.Zero, protection, 0, 4096, null);
                            if (mapping == IntPtr.Zero) Interlocked.Increment(ref failures);
                            else if (!CloseHandle(mapping)) Interlocked.Increment(ref failures);
                        }
                    }
                });
                workers[t].Start();
            }
            start.Set();
            foreach (Thread w in workers) w.Join();
        }
        return failures;
    }
}
'@
    }
}

function Invoke-Variant([string] $SelectedVariant) {
    $script:LastRestorationVerified = $false
    $script:LastRunSucceeded = $false
    $script:InspectorTimedOut = $false
    $script:InspectorTimeoutCommand = ''
    $script:InspectorFailed = $false

    $baseline = Get-StagedAdmissionBaseline
    $id = [guid]::NewGuid().ToString('N')
    $fixtureDirectory = Join-Path $documents ('SafeUpload-admission-' + $id)
    $backup = Join-Path $documents ('SafeUpload-admission-driver-' + $id + '.sys')
    $policyBackup = Join-Path $documents ('SafeUpload-admission-policy-' + $id + '.bin')
    $policyBytes = $null
    $fixtureCreated = $false
    $inspectorCopyCreated = $false
    $driverReplaced = $false
    $filterLoaded = $false
    $verifierEnabled = $false
    $traceEnabled = $false
    $agent = $null
    $runSucceeded = $false
    $restorationErrors = New-Object System.Collections.ArrayList
    $fileHandles = New-Object System.Collections.ArrayList
    $mappings = New-Object System.Collections.ArrayList
    $views = New-Object System.Collections.ArrayList
    $uncachedReaders = New-Object System.Collections.ArrayList
    $agentLogs = New-Object System.Collections.ArrayList
    $observers = @{}
    $fixturePaths = @()
    $mappingRecords = @{}
    $probeNames = @()
    $trace = $null
    $preWriteTrace = $null
    $afterATrace = $null
    $rawTrace = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '.jsonl')
    $rawPreWriteTrace = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-prewrite.jsonl')
    $rawAfterATrace = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-after-A.jsonl')
    $rawTraceA = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-A.jsonl')
    $rawTraceP1 = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-P1.jsonl')
    $rawTraceB = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-B.jsonl')
    $rawTraceP2 = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-P2.jsonl')
    $rawTraceCancelledCreates = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-cancelled-creates.jsonl')
    $rawTraceFastIo = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-fast-io.jsonl')
    $writerIoSessions = New-Object System.Collections.ArrayList
    $rawTraceL = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-L.jsonl')
    $originals = @{}
    $mappedExpected = @{}
    $markers = @{}

    Write-Output ('Variant=' + $SelectedVariant)
    Write-Output ('TestTimestampUTC=' + [DateTime]::UtcNow.ToString('o'))
    Write-Output ('Host=' + $env:COMPUTERNAME)
    Write-Output ('UUID=' + $baseline.UUID)
    Write-Output ('OriginalInstalledSHA256=' + $baseline.OriginalHash)
    Write-Output ('FeatureSHA256=' + $baseline.FeatureHash)
    Write-Output ('ExpectedInspectorSHA256=' + $ExpectedInspectorSha256.ToUpperInvariant())
    Write-Output ('OriginalPolicySHA256=' + $baseline.PolicyHash)
    Write-Output ('ServicePackageSHA256=' + $baseline.ServicePackageHash)
    Write-Output 'Baseline=FilterUnloaded;VerifierOffAndUnconfigured;ServiceManualStopped;AgentProcesses0;Tasks0'

    try {
        $baselinePolicyBytes = [IO.File]::ReadAllBytes($policyPath)
        $baselinePolicyDocument = [Text.Encoding]::UTF8.GetString($baselinePolicyBytes) | ConvertFrom-Json
        Assert-OutsideBaselineScopes $fixtureDirectory $baselinePolicyDocument
        Assert-MaptestExtensionOutsideBaselinePolicy $baselinePolicyDocument

        [void][IO.Directory]::CreateDirectory($fixtureDirectory)
        $fixtureCreated = $true
        $inspectorCopyCreated = $true
        Copy-Item -LiteralPath $inspectorSource -Destination $inspectorPath -Force
        $copiedInspectorHash = (Get-FileHash -LiteralPath $inspectorPath -Algorithm SHA256).Hash
        if ($copiedInspectorHash -ne $ExpectedInspectorSha256.ToUpperInvariant()) {
            throw "Copied Inspector hash mismatch: $copiedInspectorHash"
        }
        Write-Output ('InspectorSHA256=' + $copiedInspectorHash)

        if ($SelectedVariant -eq 'canary-security') {
            $script:CanarySecurityChecksPassed = 0
            $script:CanarySecurityChecksFailed = 0
            $script:CanarySecurityFindings = 0
            $holdArmed = $false
            $holdCompleted = $false
            function Add-CSOutcome([string] $Label, [bool] $Ok, [string] $Facts, [bool] $Finding = $false) {
                if ($Finding) { $script:CanarySecurityFindings++ }
                elseif ($Ok) { $script:CanarySecurityChecksPassed++ }
                else { $script:CanarySecurityChecksFailed++ }
                $verdict = if ($Finding) { 'FINDING' } elseif ($Ok) { 'PASS' } else { 'FAIL' }
                Write-Output ('CS_' + $Label + '=' + $Facts + ';' + $verdict)
            }
            try {
                $tokenFacts = [SafeUploadCanarySecurityNative]::RequireElevatedAdministratorAndDisabledPrivileges()
                Write-Output ('CS_CurrentToken=' + $tokenFacts)
                Add-CSOutcome 'CurrentToken' $true $tokenFacts

                Backup-StagedTestDriver $backup
                if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Durable restoration backup mismatch.'
                }
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                    throw 'Feature driver install hash mismatch.'
                }
                if ($Verifier) {
                    & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                    if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
                    $verifierEnabled = $true
                    Write-Output 'VerifierEnabled=volatile flags 0x13B'
                }
                Invoke-FeatureFilterLoad
                $filterLoaded = $true

                Wait-AllVolumeCanaries ($rawTraceA + '-initial-volumes.json')
                Add-CSOutcome 'InitialAllVolumeCanaries' $true 'checks:15'

                $holdTimeout = [Math]::Max($InspectorTimeoutSeconds, 45)
                $holdResult = Invoke-InspectorChecked -Arguments @(
                    '--admission-canary-hold', ($env:SystemDrive + '\'), '10000') -Timeout $holdTimeout
                $held = ConvertFrom-Json -InputObject ([string]$holdResult.Stdout).Trim()
                if ($held.canaryHold -ne 'armed' -or $held.status -ne '0x00000000' -or
                    $held.holdMilliseconds -ne 10000 -or
                    [string]$held.path -notmatch '^\\Device\\HarddiskVolume[^\\]+\\SafeUpload-canary-[0-9A-Fa-f]{32}\.tmp$') {
                    throw 'Canary hold response did not contain the exact held canary path and success status.'
                }
                $holdArmed = $true
                $nativeCanaryPath = [string]$held.path
                $win32CanaryPath = '\\?\GLOBALROOT' + $nativeCanaryPath
                Add-CSOutcome 'HoldAndRerun' $true ('holdMilliseconds:10000;status:' + $held.status + ';path:' + $nativeCanaryPath)

                $accesses = @(
                    @{ Name = 'GENERIC_READ'; Mask = [uint32]2147483648 },
                    @{ Name = 'GENERIC_WRITE'; Mask = [uint32]1073741824 },
                    @{ Name = 'DELETE'; Mask = [uint32]65536 },
                    @{ Name = 'READ_CONTROL'; Mask = [uint32]131072 },
                    @{ Name = 'FILE_READ_ATTRIBUTES'; Mask = [uint32]128 },
                    @{ Name = 'WRITE_DAC'; Mask = [uint32]262144 }
                )
                foreach ($principal in @('Administrator', 'Restricted')) {
                    foreach ($access in $accesses) {
                        if ($principal -eq 'Administrator') {
                            $win32Error = [SafeUploadCanarySecurityNative]::TryOpenCurrent($win32CanaryPath, $access.Mask)
                        }
                        else {
                            $win32Error = [SafeUploadCanarySecurityNative]::TryOpenRestricted($win32CanaryPath, $access.Mask)
                        }
                        $finding = $access.Name -eq 'FILE_READ_ATTRIBUTES' -and $win32Error -eq 0
                        # NTFS attribute access is recorded for the orchestrator to assess.
                        $ok = $win32Error -eq 5
                        $facts = 'win32Error:' + $win32Error
                        if ($finding) { $facts += ';finding:FILE_READ_ATTRIBUTES was granted while the parent directory is listable' }
                        Add-CSOutcome ($principal + '_' + $access.Name) $ok $facts $finding
                    }
                }

                $securityResult = Invoke-InspectorChecked -Arguments @(
                    '--admission-canary-security', $nativeCanaryPath) -Timeout $InspectorTimeoutSeconds
                $security = ConvertFrom-Json -InputObject ([string]$securityResult.Stdout).Trim()
                $expectedSddl = 'O:SYG:SYD:P(A;;FA;;;SY)'
                Write-Output ('CS_SYSTEM_SDDL=' + [string]$security.sddl)
                Add-CSOutcome 'SystemSddl' ($security.canarySecurity -eq 'readback' -and
                    $security.status -eq '0x00000000' -and $security.sddl -ceq $expectedSddl) `
                    ('sddl:' + [string]$security.sddl + ';expected:' + $expectedSddl)

                Wait-AllVolumeCanaries ($rawTraceB + '-held-rerun-volumes.json')
                $holdCompleted = $true
                Add-CSOutcome 'HeldCanaryPassed' $true 'canaryState:2;canaryStatus:0;canaryChecks:15;cleanupStatus:0'
                $pathError = [SafeUploadCanarySecurityNative]::GetPathAttributesError($win32CanaryPath)
                $pathMissing = $pathError -in @(2, 3)
                Add-CSOutcome 'CanaryPathRemoved' $pathMissing ('GetFileAttributesWin32Error:' + $pathError)
            }
            catch {
                $script:CanarySecurityChecksFailed++
                Write-Output ('CS_Unexpected=' + (Get-ErrorText $_) + ';FAIL')
                throw
            }
            finally {
                if ($holdArmed -and -not $holdCompleted -and $filterLoaded -and
                    -not $script:InspectorTimedOut -and -not $script:InspectorFailed) {
                    try {
                        [void](Invoke-InspectorChecked -Arguments @('--admission-canary-hold-cancel') -Timeout 15)
                        Write-Output 'CS_HoldCancellation=sentAfterVariantFailure'
                    }
                    catch { Write-Output ('CS_HoldCancellationError=' + (Get-ErrorText $_)) }
                }
                Write-Output ('CS_Summary=passed:' + $script:CanarySecurityChecksPassed + ';failed:' + $script:CanarySecurityChecksFailed)
                Write-Output ('CS_Findings=' + $script:CanarySecurityFindings)
            }
            $runSucceeded = ($script:CanarySecurityChecksFailed -eq 0)
        }
        elseif ($SelectedVariant -eq 'canary-newvolume') {
            if (-not $Verifier) { throw 'New-volume canary qualification requires runtime Verifier.' }
            $script:CNPassed = 0; $script:CNFailed = 0
            $cnDisks = New-Object System.Collections.ArrayList
            $cnRaw = @{}
            $cnFaultsMayBeEnabled = $false
            $cnHoldMayBeArmed = $false
            $script:CNHelperStopped = $true
            $cnPrefix = Join-Path $documents ('SafeUpload-canary-newvolume-' + $id)
            # Reuse the baseline's exact owned names and S: sequentially. The second image is
            # newly created after the first is disposed; retain both GUIDs in the evidence.
            $cnVhd = Join-Path $documents 'SafeUpload-owned.vhdx'
            $cnDiskpart = $cnVhd + '.txt'
            $cnControl = Join-Path $fixtureDirectory 'canary-section'
            $cnHelper = Join-Path $fixtureDirectory 'cn-system-section.ps1'
            function Add-CNOutcome([string] $Name, [bool] $Ok, [string] $Facts) {
                if ($Ok) { $script:CNPassed++ } else { $script:CNFailed++ }
                Write-Output ('CN_' + $Name + '=' + $Facts + ';' + $(if ($Ok) { 'PASS' } else { 'FAIL' }))
                if (-not $Ok) { throw ('New-volume canary check failed: ' + $Name) }
            }
            function Invoke-CNNative([string] $Exe, [string] $Arguments, [int] $Seconds = 30) {
                $start = [Diagnostics.ProcessStartInfo]::new($Exe, $Arguments)
                $start.UseShellExecute = $false; $start.CreateNoWindow = $true
                $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
                $process = [Diagnostics.Process]::Start($start)
                try {
                    [void]$process.Handle
                    $stdout = $process.StandardOutput.ReadToEndAsync()
                    $stderr = $process.StandardError.ReadToEndAsync()
                    if (-not $process.WaitForExit($Seconds * 1000)) { throw ('Native command timed out: ' + $Exe) }
                    if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw 'Native output did not drain.' }
                    return [pscustomobject]@{ ExitCode = $process.get_ExitCode(); Raw = $stdout.Result + $stderr.Result }
                } finally {
                    if (-not $process.HasExited) {
                        $process.Kill()
                        if (-not $process.WaitForExit(10000)) { throw 'Native command did not terminate.' }
                    }
                    $process.Dispose()
                }
            }
            function Read-CNVerifier([string] $Label, [uint32] $ExpectedFlags) {
                $query = Invoke-CNNative 'verifier.exe' '/query'
                $cnRaw[$Label + '-verifier.txt'] = $query.Raw
                $flags = [regex]::Matches($query.Raw, '(?im)^Verifier Flags:\s+0x([0-9A-F]+)\s*$')
                $counter = [regex]::Matches($query.Raw, '(?im)^\s*Pool Allocations Failed Deliberately:\s+([0-9]+)\s*$')
                $modules = [regex]::Matches($query.Raw, '(?im)^\s*MODULE:\s+(\S+)\s+\(')
                if ($query.ExitCode -ne 0 -or $flags.Count -ne 1 -or $counter.Count -ne 1 -or
                    $modules.Count -ne 1 -or $modules[0].Groups[1].Value -ine 'SafeUpload.sys' -or
                    [Convert]::ToUInt32($flags[0].Groups[1].Value, 16) -ne $ExpectedFlags) {
                    throw 'Canary Verifier flags, inventory or deliberate-failure counter ambiguous.'
                }
                return [pscustomobject]@{ Flags = $ExpectedFlags; Faults = [uint64]$counter[0].Groups[1].Value }
            }
            function Restore-CNVerifier {
                $restore = Invoke-CNNative 'verifier.exe' '/volatile /flags 0x13B'
                $cnRaw['restore-flags.txt'] = $restore.Raw
                if ($restore.ExitCode -ne 0) { throw 'Canary LRS disable failed.' }
                # This exact active query must precede every subsequent operation, including
                # helper termination, path inspection and disk detach. Keep the guard on failure.
                $restored = Read-CNVerifier 'restored' 0x13B
                $script:CNRestoredVerifier = $restored
            }
            function Invoke-CNDiskpart([string[]] $Commands, [string] $Label) {
                Set-Content -LiteralPath $cnDiskpart -Value $Commands -Encoding Ascii
                $diskpart = Invoke-CNNative 'diskpart.exe' ('/s ' + (ConvertTo-WindowsArgument $cnDiskpart)) 60
                $cnRaw[$Label + '-diskpart.txt'] = $diskpart.Raw
                if ($diskpart.ExitCode -ne 0 -or $diskpart.Raw -match 'DiskPart has encountered an error') {
                    throw ('Owned canary disk operation failed: ' + $Label)
                }
            }
            function New-CNVolume([string] $Label) {
                if ((Test-Path -LiteralPath $cnVhd) -or (Test-Path -LiteralPath 'S:\')) { throw 'Owned canary disk/letter already present.' }
                $disk = [pscustomobject]@{ Label = $Label; Guid = ''; Disposed = $false }
                [void]$cnDisks.Add($disk) # Register ownership BEFORE create/attach, including partial setup.
                Invoke-CNDiskpart @("create vdisk file=`"$cnVhd`" maximum=128 type=fixed",
                    "select vdisk file=`"$cnVhd`"", 'attach vdisk', 'create partition primary',
                    'format fs=ntfs quick label=SafeUploadOwned', 'assign letter=S') $Label
                $deadline = [DateTime]::UtcNow.AddSeconds(15)
                do {
                    $volumes = @(Get-CimInstance Win32_Volume -Filter "DriveLetter='S:'" -ErrorAction Stop)
                    if ($volumes.Count -gt 1) { throw 'Owned letter identity ambiguous.' }
                    if ($volumes.Count -eq 1 -and $volumes[0].DriveType -eq 3 -and $volumes[0].FileSystem -eq 'NTFS' -and
                        $volumes[0].DeviceID -match '(?i)\{[0-9a-f-]{36}\}') {
                        $disk.Guid = $matches[0].ToLowerInvariant()
                        return $disk
                    }
                    Start-Sleep -Milliseconds 100
                } while ([DateTime]::UtcNow -lt $deadline)
                throw 'Owned fixed NTFS volume identity did not become ready.'
            }
            function Remove-CNVolume($Disk) {
                if ($Disk.Disposed) { return }
                if (Test-Path -LiteralPath $cnVhd) {
                    $image = Get-DiskImage -ImagePath $cnVhd -ErrorAction Stop
                    if ($image.Attached) {
                        Invoke-CNDiskpart @("select vdisk file=`"$cnVhd`"", 'detach vdisk') ($Disk.Label + '-detach')
                    }
                    $deadline = [DateTime]::UtcNow.AddSeconds(15)
                    do {
                        $image = Get-DiskImage -ImagePath $cnVhd -ErrorAction Stop
                        if (-not $image.Attached -and -not (Test-Path -LiteralPath 'S:\') -and
                            @(Get-CimInstance Win32_Volume -Filter "DriveLetter='S:'" -ErrorAction Stop).Count -eq 0) { break }
                        Start-Sleep -Milliseconds 100
                    } while ([DateTime]::UtcNow -lt $deadline)
                    if ($image.Attached -or (Test-Path -LiteralPath 'S:\') -or
                        @(Get-CimInstance Win32_Volume -Filter "DriveLetter='S:'" -ErrorAction Stop).Count -ne 0) {
                        throw 'Owned canary VHDX detach could not be proven.'
                    }
                    Remove-Item -LiteralPath $cnVhd -Force
                }
                if (Test-Path -LiteralPath $cnDiskpart) { Remove-Item -LiteralPath $cnDiskpart -Force }
                $Disk.Disposed = $true
            }
            function Read-CNVolumes([string] $Label, [int] $Timeout = $InspectorTimeoutSeconds) {
                $response = Invoke-InspectorChecked -Arguments @('--admission-volume-status') -Timeout $Timeout
                $cnRaw[$Label + '-volumes.json'] = [string]$response.Stdout
                $status = ConvertFrom-Json -InputObject ([string]$response.Stdout).Trim()
                if ($null -eq $status.admissionVolumes -or $null -eq $status.writerGlobalUnknown -or $status.writerGlobalUnknown -ne 0) {
                    throw 'Canary volume inventory missing or globally unknown.'
                }
                foreach ($entry in $status.admissionVolumes) {
                    # Detached storage is tolerated exactly as in Wait-AllVolumeCanaries:
                    # context/fs/volume-info resolved, DETACHED flag explicit; no GUID requirement.
                    if ($null -eq $entry.contextStatus -or $entry.contextStatus -ne 0 -or
                        $null -eq $entry.fileSystemStatus -or $entry.fileSystemStatus -ne 0 -or
                        $null -eq $entry.volumeInfoStatus -or $entry.volumeInfoStatus -ne 0 -or $null -eq $entry.volumeFlags) {
                        throw 'Canary inventory has an unresolved attached/detached entry.'
                    }
                }
                return $status
            }
            function Find-CNVolume($Status, [string] $Guid) {
                $entries = @($Status.admissionVolumes | Where-Object {
                    ($_.volumeFlags -band 1) -eq 0 -and $_.volumeKind -eq 1 -and $_.fileSystemType -eq 2 -and
                    $_.volumeGuidStatus -eq 0 -and ([string]$_.volumeGuid).ToLowerInvariant().Contains($Guid) })
                if ($entries.Count -gt 1) { throw 'Canary target instance ambiguous.' }
                if ($entries.Count -eq 1) {
                    $entry = $entries[0]
                    foreach ($field in @('canaryState', 'canaryStatus', 'canaryChecks', 'canaryCleanupStatus', 'setupFlags', 'instanceWritersUntracked')) {
                        if ($null -eq $entry.$field) { throw ('Canary result field missing: ' + $field) }
                    }
                    if ($entry.instanceWritersUntracked -ne 0) { throw 'Canary instance writer tracking unknown.' }
                    return $entry
                }
                return $null
            }
            function Wait-CNVolume([string] $Guid, [string] $Label) {
                $deadline = [DateTime]::UtcNow.AddSeconds(60)
                $attempt = 0
                do {
                    $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - [DateTime]::UtcNow).TotalSeconds))
                    $status = Read-CNVolumes ($Label + '-' + $attempt++) ([Math]::Min($InspectorTimeoutSeconds, $remainingSeconds))
                    $entry = Find-CNVolume $status $Guid
                    if ($null -ne $entry -and $entry.canaryState -ge 2) { return $entry }
                    Start-Sleep -Milliseconds 100
                } while ([DateTime]::UtcNow -lt $deadline)
                throw ('Canary instance/result wait exceeded 60 seconds: ' + $Label)
            }
            function Get-CNCanaryFacts($Entry) {
                return ('instance:' + $Entry.instance + ';guid:' + $Entry.volumeGuid + ';setupFlags:' + $Entry.setupFlags +
                    ';state:' + $Entry.canaryState + ';status:0x' + ([uint32]$Entry.canaryStatus).ToString('X8') +
                    ';checks:' + $Entry.canaryChecks + ';lowChecks:' + ($Entry.canaryChecks -band 15) +
                    ';step:' + (($Entry.canaryChecks -shr 8) -band 255) + ';cleanup:0x' + ([uint32]$Entry.canaryCleanupStatus).ToString('X8'))
            }
            function Test-CNSameCanary($Before, $After) {
                if ($null -eq $After) { return $false }
                foreach ($field in @('instance', 'canaryState', 'canaryStatus', 'canaryChecks', 'canaryCleanupStatus')) {
                    if ($Before.$field -ne $After.$field) { return $false }
                }
                return $true
            }
            function Assert-CNHoldRefused($Before, [string] $Label) {
                # Expected negative control: do NOT poison InspectorFailed through the checked wrapper.
                $refusal = Invoke-InspectorAsSystem -Arguments @('--admission-canary-hold', 'S:\', '1000') -Timeout 45
                $cnRaw[$Label + '-refusal.txt'] = [string]$refusal.Stdout + [string]$refusal.Stderr
                $after = Find-CNVolume (Read-CNVolumes ($Label + '-after-refusal')) $Before.Guid
                Add-CNOutcome ($Label + 'HoldRefused') ($refusal.ExitCode -eq 3 -and
                    # The driver refuses a non-PASSED volume with STATUS_INVALID_DEVICE_STATE (HRESULT 0x80070016).
                    # FilterSendMessage leaves the returned-bytes count unspecified on failure, so it is not checked.
                    $refusal.Stderr -match 'resposta do hold do canary invalida \(hr = 0x80070016, bytes = [0-9]+\)' -and
                    (Test-CNSameCanary $Before.Entry $after) -and $after.canaryState -eq 3) `
                    ('exit:' + $refusal.ExitCode + ';diagnostic:' + ([regex]::Replace([string]$refusal.Stderr, '[\r\n]+', ' ')).Trim() +
                    ';after:' + (Get-CNCanaryFacts $after))
            }
            function Stop-CNHelper {
                if ($null -eq $agent) { return }
                try { [IO.File]::WriteAllText((Join-Path $cnControl 'release'), 'release') }
                catch {
                    # A failed handoff must still reach bounded termination below.
                    $script:CNFailed++; [void]$restorationErrors.Add('Canary helper release: ' + (Get-ErrorText $_))
                    Write-Output ('CN_HelperRelease=' + (Get-ErrorText $_) + ';FAIL')
                }
                if (-not $agent.Process.HasExited -and -not $agent.Process.WaitForExit(10000)) {
                    $agent.Process.Kill()
                    if (-not $agent.Process.WaitForExit(10000)) { throw 'SYSTEM canary section helper did not terminate.' }
                }
                if (-not $agent.Process.HasExited) { throw 'SYSTEM canary section helper still owns its section.' }
                # Process exit closes kernel handles even after a forced termination. Set this
                # before task/log cleanup so their failure cannot prevent safe disk disposal.
                $script:CNHelperStopped = $true
                Stop-StagedTestAgent $agent
                foreach ($suffix in @('-out.log', '-err.log')) {
                    $log = $cnLog + $suffix
                    if (Test-Path -LiteralPath $log) { $cnRaw['helper' + $suffix] = [IO.File]::ReadAllText($log) }
                }
                $cnRaw['system-exit.txt'] = [string]$agent.Process.get_ExitCode()
            }
            try {
                $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                Add-CNOutcome 'Platform' ($os.CurrentBuildNumber -eq '19045' -and $os.UBR -eq 2965) ('build:' + $os.CurrentBuildNumber + '.' + $os.UBR)
                Backup-StagedTestDriver $backup
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256) { throw 'Feature install mismatch.' }
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Canary runtime Verifier enable failed.' }
                $verifierEnabled = $true
                [void](Read-CNVerifier 'initial' 0x13B)
                Invoke-FeatureFilterLoad; $filterLoaded = $true
                Wait-AllVolumeCanaries ($cnPrefix + '-initial-volumes.json')
                $initial = Read-CNVolumes 'initial'
                $cVolumes = @(Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'" -ErrorAction Stop)
                if ($cVolumes.Count -ne 1 -or $cVolumes[0].DeviceID -notmatch '(?i)\{[0-9a-f-]{36}\}') { throw 'C: identity ambiguous.' }
                $cGuid = $matches[0].ToLowerInvariant()
                $cBefore = Find-CNVolume $initial $cGuid
                Add-CNOutcome 'InitialCanaries' ($null -ne $cBefore -and $cBefore.canaryState -eq 2 -and
                    $cBefore.canaryStatus -eq 0 -and $cBefore.canaryChecks -eq 15 -and $cBefore.canaryCleanupStatus -eq 0) (Get-CNCanaryFacts $cBefore)

                # A. New fixed-size, fixed-device NTFS image, while the feature is already loaded.
                $first = $null
                try {
                    $first = New-CNVolume 'fresh'
                    $fresh = Wait-CNVolume $first.Guid 'fresh'
                    $freshFiles = @(Get-ChildItem -LiteralPath 'S:\' -Filter 'SafeUpload-canary-*.tmp' -Force -ErrorAction Stop)
                    Add-CNOutcome 'FreshVolume' ($fresh.canaryState -eq 2 -and $fresh.canaryStatus -eq 0 -and
                        $fresh.canaryChecks -eq 15 -and $fresh.canaryCleanupStatus -eq 0 -and $freshFiles.Count -eq 0 -and
                        ($fresh.setupFlags -band 4) -ne 0 -and $null -eq (Find-CNVolume $initial $first.Guid)) `
                        ((Get-CNCanaryFacts $fresh) + ';rootCanaryFiles:' + $freshFiles.Count)

                    # B. Compile and initialize SYSTEM before arming the timed hold. The held file is
                    # initially empty: mapping maximum 4096 extends it to the driver's intended PAGE_SIZE.
                    [void][IO.Directory]::CreateDirectory($cnControl)
                    $cnSectionSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class SafeUploadCNSection : IDisposable {
    SafeFileHandle file;
    IntPtr section;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileW")]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr sa, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileMappingW")]
    static extern IntPtr CreateFileMapping(SafeFileHandle file, IntPtr sa, uint protect, uint high, uint low, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetFilePointerEx(SafeFileHandle file, long distance, out long position, uint method);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetEndOfFile(SafeFileHandle file);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, ref byte deleteFile, uint size);
    static Win32Exception Failure(string operation) {
        int error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, operation + " win32:" + error);
    }
    public SafeUploadCNSection(string path) {
        try {
            // GENERIC_READ | GENERIC_WRITE | DELETE: with a section held, NTFS refuses the driver's own delete
            // mark (run 2: STATUS_CANNOT_DELETE), so this helper removes the canary after releasing it.
            file = CreateFile(path, 0xC0010000U, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            if (file.IsInvalid) throw Failure("CreateFile share-all");
            // Run 1: mapping the held 0-byte canary with an explicit 4 KiB size failed after the
            // acquire/release pair. Size the file through the handle first, then map the whole file.
            long position;
            if (!SetFilePointerEx(file, 4096, out position, 0)) throw Failure("SetFilePointerEx 4096");
            if (!SetEndOfFile(file)) throw Failure("SetEndOfFile 4096");
            section = CreateFileMapping(file, IntPtr.Zero, 4, 0, 0, null);
            if (section == IntPtr.Zero) throw Failure("CreateFileMapping PAGE_READWRITE");
        } catch { Dispose(); throw; }
    }
    public void ReleaseAndDelete() {
        if (section != IntPtr.Zero) {
            if (!CloseHandle(section)) throw Failure("Close section");
            section = IntPtr.Zero;
        }
        byte deleteFile = 1;
        if (!SetFileInformationByHandle(file, 4, ref deleteFile, 1)) throw Failure("FileDispositionInfo");
        file.Dispose(); file = null;
    }
    public void Dispose() {
        int error = 0;
        if (section != IntPtr.Zero) { if (!CloseHandle(section)) error = Marshal.GetLastWin32Error(); section = IntPtr.Zero; }
        if (file != null) { file.Dispose(); file = null; }
        if (error != 0) throw new Win32Exception(error, "Close section");
    }
}
'@
                    $cnHelperTemplate = @'
param([Parameter(Mandatory=$true)][string]$Control)
$ErrorActionPreference = 'Stop'
$section = $null; $failed = $false
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'SYSTEM required.' }
    Add-Type -TypeDefinition @'
__CS__
__END_CS__
    [IO.File]::WriteAllText((Join-Path $Control 'initialized'), 'SYSTEM;CSharpReady')
    $request = Join-Path $Control 'path.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $request)) {
        if (Test-Path -LiteralPath (Join-Path $Control 'release')) { throw 'Cancelled before section open.' }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Path handoff timed out.' }
        Start-Sleep -Milliseconds 50
    }
    $path = [string](Get-Content -LiteralPath $request -Raw | ConvertFrom-Json).Path
    if ($path -notmatch '^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolume[^\\]+\\SafeUpload-canary-[0-9A-Fa-f]{32}\.tmp$') { throw 'Invalid held canary path.' }
    $section = New-Object SafeUploadCNSection -ArgumentList $path
    $ready = @{ Sid='S-1-5-18'; Path=$path; Protection='PAGE_READWRITE'; Share=7; Maximum=4096; View=$false } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $Control 'ready.tmp'), $ready)
    Move-Item -LiteralPath (Join-Path $Control 'ready.tmp') -Destination (Join-Path $Control 'ready.json')
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    while (-not (Test-Path -LiteralPath (Join-Path $Control 'release'))) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Section retention timed out.' }
        Start-Sleep -Milliseconds 50
    }
} catch { $failed=$true; Write-Error $_ -ErrorAction Continue }
finally {
    try {
        if ($null -ne $section) {
            if (-not $failed) { $section.ReleaseAndDelete() }
            $section.Dispose()
        }
        [IO.File]::WriteAllText((Join-Path $Control 'closed'), $(if ($failed) { 'SectionAndFileClosed' } else { 'SectionClosedFileDeleted' }))
    } catch { $failed=$true; Write-Error $_ -ErrorAction Continue }
}
if ($failed) { exit 1 }
exit 0
'@
                    # Escape the nested here-string terminator in this source template only.
                    $cnHelperBody = $cnHelperTemplate.Replace('__CS__', $cnSectionSource).Replace('__END_CS__', "'@")
                    Set-Content -LiteralPath $cnHelper -Value $cnHelperBody -Encoding UTF8
                    $cnLog = $cnPrefix + '-system'
                    [void]$agentLogs.Add($cnLog + '-out.log'); [void]$agentLogs.Add($cnLog + '-err.log')
                    $cnLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + (ConvertTo-WindowsArgument $cnHelper) +
                        ' -Control ' + (ConvertTo-WindowsArgument $cnControl)
                    $agent = Start-StagedTestAgent $PSHOME $cnLog 'powershell.exe' $cnLine
                    $script:CNHelperStopped = $false; [void]$agent.Process.Handle
                    $deadline = [DateTime]::UtcNow.AddSeconds(15)
                    while (-not (Test-Path -LiteralPath (Join-Path $cnControl 'initialized')) -and [DateTime]::UtcNow -lt $deadline -and -not $agent.Process.HasExited) { Start-Sleep -Milliseconds 50 }
                    if (-not (Test-Path -LiteralPath (Join-Path $cnControl 'initialized'))) { throw 'SYSTEM section helper did not initialize.' }
                    $cnHoldMayBeArmed = $true # Set before sending, including lost/invalid replies.
                    $hold = Invoke-InspectorChecked -Arguments @('--admission-canary-hold', 'S:\', '30000') -Timeout 45
                    $cnRaw['timeout-hold.json'] = [string]$hold.Stdout
                    $held = ConvertFrom-Json -InputObject ([string]$hold.Stdout).Trim()
                    Add-CNOutcome 'HoldAndRerun' ($held.canaryHold -eq 'armed' -and $held.status -eq '0x00000000' -and
                        $held.holdMilliseconds -eq 30000 -and [string]$held.path -match '^\\Device\\HarddiskVolume[^\\]+\\SafeUpload-canary-[0-9A-Fa-f]{32}\.tmp$') `
                        ('holdMilliseconds:' + $held.holdMilliseconds + ';path:' + $held.path)
                    $cnPath = '\\?\GLOBALROOT' + [string]$held.path
                    $leaf = ([string]$held.path -split '\\')[-1]
                    Add-CNOutcome 'HeldPathOnOwnedVolume' (@(Get-ChildItem -LiteralPath 'S:\' -Filter $leaf -Force -ErrorAction Stop).Count -eq 1 -and
                        (Find-CNVolume (Read-CNVolumes 'held') $first.Guid).instance -eq $fresh.instance) ('guid:' + $first.Guid + ';leaf:' + $leaf)
                    [IO.File]::WriteAllText((Join-Path $cnControl 'path.tmp'), (@{Path=$cnPath} | ConvertTo-Json -Compress))
                    Move-Item -LiteralPath (Join-Path $cnControl 'path.tmp') -Destination (Join-Path $cnControl 'path.json')
                    $deadline = [DateTime]::UtcNow.AddSeconds(10)
                    while (-not (Test-Path -LiteralPath (Join-Path $cnControl 'ready.json')) -and [DateTime]::UtcNow -lt $deadline -and -not $agent.Process.HasExited) { Start-Sleep -Milliseconds 50 }
                    if (-not (Test-Path -LiteralPath (Join-Path $cnControl 'ready.json'))) { throw 'SYSTEM section was not ready during hold.' }
                    $cnRaw['system-ready.json'] = [IO.File]::ReadAllText((Join-Path $cnControl 'ready.json'))
                    $ready = ConvertFrom-Json -InputObject $cnRaw['system-ready.json']
                    Add-CNOutcome 'SystemSectionReady' ($ready.Sid -eq 'S-1-5-18' -and $ready.Path -ceq $cnPath -and
                        $ready.Protection -eq 'PAGE_READWRITE' -and $ready.Share -eq 7 -and $ready.Maximum -eq 4096 -and
                        $ready.View -eq $false -and -not $agent.Process.HasExited) ($ready | ConvertTo-Json -Compress)
                    # No cancellation or release here: let the driver's 30-second hold expire naturally.
                    $timedOut = Wait-CNVolume $first.Guid 'timeout'
                    $cnHoldMayBeArmed = $false
                    # Run 2 (Win10 19045): with an external writable section on the held canary, NTFS refuses the
                    # driver's delete mark after the hold (STATUS_CANNOT_DELETE, step 6), so the canary fails closed
                    # before its mapping steps. The STATUS_IO_TIMEOUT branch cannot be reached this way without a race.
                    Add-CNOutcome 'ExternalWriterFailsClosed' ($timedOut.canaryState -eq 3 -and
                        $timedOut.canaryStatus -eq [Convert]::ToUInt32('C0000121',16) -and
                        ($timedOut.canaryChecks -band 2) -eq 0 -and ($timedOut.canaryChecks -band 8) -eq 8 -and
                        (($timedOut.canaryChecks -shr 8) -band 255) -eq 6 -and -not $agent.Process.HasExited) (Get-CNCanaryFacts $timedOut)
                    $attributesError = [SafeUploadCanarySecurityNative]::GetPathAttributesError($cnPath)
                    Add-CNOutcome 'CleanupWhileSectionHeld' (-not $agent.Process.HasExited) `
                        ((Get-CNCanaryFacts $timedOut) + ';GetFileAttributesWin32Error:' + $attributesError + ';sectionStillHeld:true')
                    Assert-CNHoldRefused ([pscustomobject]@{ Guid=$first.Guid; Entry=$timedOut }) 'Timeout'
                    $releaseClock = [Diagnostics.Stopwatch]::StartNew()
                    Stop-CNHelper
                    $helperExit = $agent.Process.get_ExitCode()
                    $script:CNHelperStopped = $true; $agent.Process.Dispose(); $agent = $null
                    Add-CNOutcome 'SystemSectionClosed' ($helperExit -eq 0 -and
                        (Test-Path -LiteralPath (Join-Path $cnControl 'closed')) -and
                        [IO.File]::ReadAllText((Join-Path $cnControl 'closed')) -eq 'SectionClosedFileDeleted') ('exit:' + $helperExit + ';removedBy:SYSTEM helper after release')
                    do {
                        $attributesError = [SafeUploadCanarySecurityNative]::GetPathAttributesError($cnPath)
                        if ($attributesError -in @(2,3)) { break }
                        Start-Sleep -Milliseconds 50
                    } while ($releaseClock.ElapsedMilliseconds -lt 15000)
                    $releaseClock.Stop()
                    $remaining = @(Get-ChildItem -LiteralPath 'S:\' -Filter 'SafeUpload-canary-*.tmp' -Force -ErrorAction Stop)
                    Add-CNOutcome 'PathRemovedAfterRelease' ($attributesError -in @(2,3) -and $remaining.Count -eq 0 -and
                        $releaseClock.ElapsedMilliseconds -le 15000) ('millisecondsFromRelease:' + $releaseClock.ElapsedMilliseconds +
                        ';GetFileAttributesWin32Error:' + $attributesError + ';rootCanaryFiles:' + $remaining.Count)
                    $postRelease = Read-CNVolumes 'timeout-after-release'
                    $failedAfterRelease = Find-CNVolume $postRelease $first.Guid
                    Add-CNOutcome 'TimeoutRemainsFailedAfterRelease' (Test-CNSameCanary $timedOut $failedAfterRelease) (Get-CNCanaryFacts $failedAfterRelease)
                    $cAfter = Find-CNVolume $postRelease $cGuid
                    Add-CNOutcome 'CUnchangedAfterTimeout' (Test-CNSameCanary $cBefore $cAfter) (Get-CNCanaryFacts $cAfter)
                } finally {
                    if ($null -ne $first -and $script:CNHelperStopped) { Remove-CNVolume $first }
                }

                # C. PsCreateSystemThread(..., ProcessHandle=NULL, ...) establishes a system thread,
                # not a matchable .exe. Leave Applications empty (any context), with only unique SUcN.
                # https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/low-resources-simulation
                # Explicit native argument string preserves "" under Windows PowerShell 5.1.
                $beforeFault = Read-CNVerifier 'before-fault' 0x13B
                $allocation = $null; $second = $null
                try {
                    try {
                        $cnFaultsMayBeEnabled = $true
                        $config = Invoke-CNNative 'verifier.exe' '/volatile /faults 10000 SUcN "" 0'
                        $cnRaw['fault-configuration.txt'] = $config.Raw
                        if ($config.ExitCode -ne 0) { throw 'Canary fault configuration failed.' }
                        # Run 4 (Win10 19045): an empty Applications argument is acknowledged as a blank value. Match
                        # within one line only, so a blank value cannot borrow the next line.
                        foreach ($field in @(@('Probability','10000'), @('Pool Tags','SUcN'), @('Applications',''), @('Delay Minutes','0'))) {
                            $fields = [regex]::Matches($config.Raw, ('(?im)^[ \t]*' + [regex]::Escape($field[0]) + ':[ \t]*([^\r\n]*)\r?$'))
                            if ($fields.Count -ne 1 -or $fields[0].Groups[1].Value.Trim() -cne $field[1]) { throw 'Verifier did not confirm exact canary fault filters.' }
                        }
                        # Win10 evidence: /faults replaces active flags with 0x4. Never reassert /flags
                        # inside this window (that resets the filters). Surrounding windows require 0x13B.
                        $armedFault = Read-CNVerifier 'armed-fault' 4
                        $second = New-CNVolume 'allocation'
                        $allocation = Wait-CNVolume $second.Guid 'allocation'
                    } finally {
                        # Close the window as soon as any terminal result is observed, BEFORE assertions,
                        # counter interpretation, root listing, negative hold or disposal. Retry in outer finally.
                        Restore-CNVerifier
                        $cnFaultsMayBeEnabled = $false
                    }
                    $afterFault = $script:CNRestoredVerifier
                    Add-CNOutcome 'VerifierRestored' ($afterFault.Flags -eq 0x13B) 'activeFlags:0x13B;faultWindowFlags:0x4;applications:(null);poolTag:SUcN'
                    Add-CNOutcome 'RealAllocationFailure' ($second.Guid -ne $first.Guid -and $allocation.canaryState -eq 3 -and
                        $allocation.canaryStatus -eq [Convert]::ToUInt32('C000009A',16) -and
                        $allocation.canaryChecks -eq (1 -shl 8) -and $allocation.canaryCleanupStatus -eq 0 -and
                        ($allocation.setupFlags -band 4) -ne 0 -and $null -eq (Find-CNVolume $initial $second.Guid) -and
                        $afterFault.Faults -gt $beforeFault.Faults -and $afterFault.Faults -gt $armedFault.Faults) `
                        ((Get-CNCanaryFacts $allocation) + ';deliberateBefore:' + $beforeFault.Faults +
                        ';deliberateArmed:' + $armedFault.Faults + ';deliberateAfter:' + $afterFault.Faults +
                        ';deliberateDelta:' + ([decimal]$afterFault.Faults - [decimal]$beforeFault.Faults))
                    $allocationFiles = @(Get-ChildItem -LiteralPath 'S:\' -Filter 'SafeUpload-canary-*.tmp' -Force -ErrorAction Stop)
                    Add-CNOutcome 'AllocationRootClean' ($allocationFiles.Count -eq 0) ('rootCanaryFiles:' + $allocationFiles.Count)
                    Assert-CNHoldRefused ([pscustomobject]@{ Guid=$second.Guid; Entry=$allocation }) 'Allocation'
                } finally {
                    if ($null -ne $second -and -not $cnFaultsMayBeEnabled) { Remove-CNVolume $second }
                }
                Wait-AllVolumeCanaries ($cnPrefix + '-disposed-volumes.json')
                $disposed = Read-CNVolumes 'disposed'
                $cFinal = Find-CNVolume $disposed $cGuid
                Add-CNOutcome 'CUnchangedAfterAllocation' (Test-CNSameCanary $cBefore $cFinal) (Get-CNCanaryFacts $cFinal)
                $detached = @($disposed.admissionVolumes | Where-Object { ($_.volumeFlags -band 1) -ne 0 })
                Add-CNOutcome 'DisposedVolumeInventory' ($null -eq (Find-CNVolume $disposed $first.Guid) -and
                    $null -eq (Find-CNVolume $disposed $second.Guid)) ('detachedEntries:' + $detached.Count +
                    ';entries:' + ($detached | ConvertTo-Json -Depth 5 -Compress))
            } catch {
                $script:CNFailed++
                Write-Output ('CN_Unexpected=' + (Get-ErrorText $_) + ';FAIL')
                throw
            } finally {
                if ($cnFaultsMayBeEnabled) {
                    try { Restore-CNVerifier; $cnFaultsMayBeEnabled = $false }
                    catch { $script:CNFailed++; [void]$restorationErrors.Add('Canary LRS restore: ' + (Get-ErrorText $_)); Write-Output ('CN_LRSRestore=' + (Get-ErrorText $_) + ';FAIL') }
                }
                if ($null -ne $agent) {
                    try { Stop-CNHelper; $script:CNHelperStopped = $true; $agent.Process.Dispose(); $agent = $null }
                    catch { $script:CNFailed++; [void]$restorationErrors.Add('Canary SYSTEM helper stop: ' + (Get-ErrorText $_)); Write-Output ('CN_HelperStop=' + (Get-ErrorText $_) + ';FAIL') }
                }
                if ($cnHoldMayBeArmed -and $filterLoaded -and -not $script:InspectorTimedOut -and -not $script:InspectorFailed) {
                    try { [void](Invoke-InspectorChecked -Arguments @('--admission-canary-hold-cancel') -Timeout 15) }
                    catch { $script:CNFailed++; [void]$restorationErrors.Add('Canary hold cancel: ' + (Get-ErrorText $_)); Write-Output ('CN_HoldCancel=' + (Get-ErrorText $_) + ';FAIL') }
                }
                foreach ($disk in $cnDisks) {
                    try {
                        if (-not $script:CNHelperStopped) { throw 'Cannot detach while SYSTEM section ownership remains unresolved.' }
                        Remove-CNVolume $disk
                    } catch { $script:CNFailed++; [void]$restorationErrors.Add('Canary disk disposal: ' + (Get-ErrorText $_)); Write-Output ('CN_DiskDisposal=' + (Get-ErrorText $_) + ';FAIL') }
                }
                $cnDisposed = (-not (Test-Path -LiteralPath $cnVhd)) -and (-not (Test-Path -LiteralPath $cnDiskpart)) -and
                    (-not (Test-Path -LiteralPath 'S:\')) -and @($cnDisks | Where-Object { -not $_.Disposed }).Count -eq 0
                if (-not $cnDisposed) { $script:CNFailed++; [void]$restorationErrors.Add('Owned canary VHDX/letter/script remains.') }
                Write-Output ('CN_OwnedDisksRemoved=vhdxAbsent:' + (-not (Test-Path -LiteralPath $cnVhd)) +
                    ';diskpartAbsent:' + (-not (Test-Path -LiteralPath $cnDiskpart)) + ';SAbsent:' + (-not (Test-Path -LiteralPath 'S:\')) +
                    ';' + $(if ($cnDisposed) { $script:CNPassed++; 'PASS' } else { 'FAIL' }))
                foreach ($leaf in $cnRaw.Keys) {
                    try { [IO.File]::WriteAllText(($cnPrefix + '-' + $leaf), [string]$cnRaw[$leaf]) }
                    catch { $script:CNFailed++; [void]$restorationErrors.Add('Canary evidence write: ' + (Get-ErrorText $_)); Write-Output ('CN_EvidenceWrite=' + (Get-ErrorText $_) + ';FAIL') }
                }
                Write-Output ('CanaryNewVolumeRawPrefix=' + $cnPrefix)
                Write-Output ('CN_Summary=passed:' + $script:CNPassed + ';failed:' + $script:CNFailed)
            }
            $runSucceeded = ($script:CNFailed -eq 0)
        }
        elseif ($SelectedVariant -eq 'mmdoes-matrix') {
            foreach ($name in @('A', 'B', 'C', 'D')) {
                $target = Join-Path $fixtureDirectory ($name + '.maptest')
                $fixturePaths += $target
                $originalText = 'PUBLIC BASELINE ' + $name + ' ' + $id
                $originals[$name] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($originalText))
                [IO.File]::WriteAllBytes($target, $originals[$name])
            }

            $mappingRecords['A'] = New-MappedFixture $fixturePaths[0] ('Local\SafeUpload-Admission-' + $id + '-A') $false $false $fileHandles $mappings $views
            $mappingRecords['B'] = New-MappedFixture $fixturePaths[1] ('Local\SafeUpload-Admission-' + $id + '-B') $true $false $fileHandles $mappings $views
            $mappingRecords['D'] = New-MappedFixture $fixturePaths[3] ('Local\SafeUpload-Admission-' + $id + '-D') $false $true $fileHandles $mappings $views

            $observers['A'] = New-ObserverPair $fixturePaths[0] $fileHandles $uncachedReaders
            $observers['D'] = New-ObserverPair $fixturePaths[3] $fileHandles $uncachedReaders

            foreach ($path in $fixturePaths) {
                Assert-ReparseFreeFixturePath $path
            }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true

            $clear = Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds
            $enable = Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds
            $traceEnabled = $true
            Write-Output 'AdmissionTrace=ClearedAndEnabled'

            $probeNames = @('A', 'B', 'C', 'D')
            foreach ($name in $probeNames) {
                $probePath = Join-Path $fixtureDirectory ($name + '.maptest')
                [void](Invoke-AdmissionProbe $probePath $name $InspectorTimeoutSeconds)
            }

            $preWriteResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
            $preWriteTrace = Get-TraceDump $preWriteResult $rawPreWriteTrace
            Write-Output ('Trace_PreWrite_RawFile=' + $rawPreWriteTrace)
            $preWriteBoundary = [UInt64]$preWriteTrace.Summary.snapshotSequence

            foreach ($name in @('A', 'D')) {
                $markers[$name] = 'MAPPED DIAGNOSTIC ' + $name + ' ' + $id
                $mappedExpected[$name] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers[$name]))
                $write = Invoke-MappedWrite $mappingRecords[$name].View $markers[$name]
                Write-Output ('MappedWrite_' + $name + '_Result=' + $write.Result)
                if (-not [string]::IsNullOrEmpty($write.Error)) {
                    Write-Output ('MappedWrite_' + $name + '_Error=' + $write.Error)
                }
                Write-Output ('WriteMarker_' + $name + '=' + $markers[$name])
                if ($name -eq 'A') {
                    $afterAResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
                    $afterATrace = Get-TraceDump $afterAResult $rawAfterATrace
                    Write-Output ('Trace_AfterA_RawFile=' + $rawAfterATrace)
                    $afterABoundary = [UInt64]$afterATrace.Summary.snapshotSequence
                }
            }

            foreach ($name in @('A', 'D')) {
                $mappedExpected[$name] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers[$name]))
                $r1 = Get-ObserverReadResult $observers[$name] 'R1' $originals[$name] $mappedExpected[$name]
                $r2 = Get-ObserverReadResult $observers[$name] 'R2' $originals[$name] $mappedExpected[$name]
                $pathIndex = 0
                if ($name -eq 'D') {
                    $pathIndex = 3
                }
                $r3 = Read-FreshBufferedObservation $fixturePaths[$pathIndex] $originals[$name] $mappedExpected[$name]
                Write-ReaderFacts ($name + '_R1') $r1
                Write-ReaderFacts ($name + '_R2') $r2
                Write-ReaderFacts ($name + '_R3') $r3
            }

            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $InspectorTimeoutSeconds
            $traceEnabled = $false
            $traceResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
            $trace = Get-TraceDump $traceResult $rawTrace
            Write-TraceFacts $trace
            $fence = Invoke-InspectorChecked -Arguments @('--admission-fence-status') -Timeout $InspectorTimeoutSeconds
            Write-Output ('FenceStatus=' + ([regex]::Replace([string]$fence.Stdout, '[\r\n]+', ' ')).Trim())

            $probes = @(Get-TraceProbeEntries $trace)
            Write-ProbeFacts $probes $probeNames
            if ($probes.Count -eq 4) {
                $probeSopA = Get-ProbeProperty $probes[0] 'sectionObjectPointer'
                $probeSopD = Get-ProbeProperty $probes[3] 'sectionObjectPointer'
                $aWindow = @(Get-PagingWriteEntries $afterATrace $preWriteBoundary)
                $dWindow = @(Get-PagingWriteEntries $trace $afterABoundary)
                if ($probeSopA -eq $probeSopD) {
                    Write-Output 'SOP_Equal_A=AMBIGUOUS'
                    Write-Output 'SOP_Equal_D=AMBIGUOUS'
                }
                else {
                    Write-Output ('SOP_Equal_A=' + (Get-SopEquality $probeSopA $aWindow $probeSopD))
                    Write-Output ('SOP_Equal_D=' + (Get-SopEquality $probeSopD $dWindow $probeSopA))
                }
            }
            else {
                Write-Output 'SOP_Equal_A=AMBIGUOUS'
                Write-Output 'SOP_Equal_D=AMBIGUOUS'
            }
            $runSucceeded = $true
        }
        elseif ($SelectedVariant -eq 'retained-section') {
            # Question under test: can a writable section object that outlives its file handle (and has no view)
            # create a NEW view later without any filter-visible event, and when does the writer's file object
            # finally close? Observe-only: no policy, no agent, fixtures outside every protected scope.
            $copies = 4
            $t = $InspectorTimeoutSeconds
            $labels = @()
            $records = @{}
            foreach ($kind in @('Rpre', 'Rpost', 'S')) {
                for ($i = 0; $i -lt $copies; $i++) {
                    $label = $kind + $i
                    $path = Join-Path $fixtureDirectory ($label + '.maptest')
                    $original = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('PUBLIC BASELINE ' + $label + ' ' + $id))
                    [IO.File]::WriteAllBytes($path, $original)
                    $fixturePaths += $path
                    $labels += $label
                    $records[$label] = [pscustomobject]@{
                        Label = $label; Kind = $kind; Path = $path; Original = $original
                        Mapping = $null; View = $null; Observer = $null; Sop = ''; Expected = $null
                    }
                }
            }
            $lifeLabels = @('Lnv0', 'Lnv1', 'Lv0', 'Lv1', 'Lc0', 'Lc1', 'Lh0', 'Lh1')   # Lc = cached (buffered I/O before mapping)
            $lifePaths = @{}
            foreach ($label in $lifeLabels) {
                $path = Join-Path $fixtureDirectory ($label + '.maptest')
                [IO.File]::WriteAllBytes($path, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('LIFETIME BASELINE ' + $label + ' ' + $id))))
                $fixturePaths += $path
                $lifePaths[$label] = $path
            }
            foreach ($path in $fixturePaths) {
                Assert-ReparseFreeFixturePath $path
            }
            foreach ($label in $labels) {
                $records[$label].Observer = New-ObserverPair $records[$label].Path $fileHandles $uncachedReaders
            }
            foreach ($label in $labels) {
                if ($records[$label].Kind -eq 'Rpre') {
                    $records[$label].Mapping = New-RetainedSection $records[$label].Path ('Local\SafeUpload-Retained-' + $id + '-' + $label) $mappings
                }
            }
            Write-Output ('RetainedSection_Copies=' + $copies)
            Write-Output 'RetainedPreAttachSections=Created;NoViews;FileHandlesClosed'

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)

            # Window A: creation of the post-attach retained sections (section + lifetime events on).
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-sections-lifetime') -Timeout $t)
            $traceEnabled = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                if ($records[$label].Kind -eq 'Rpost') {
                    $records[$label].Mapping = New-RetainedSection $records[$label].Path ('Local\SafeUpload-Retained-' + $id + '-' + $label) $mappings
                }
            }
            $traceA = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceA
            Write-DumpQuality 'A' $traceA

            # Probes before any retained section has a view (lifetime events only, so the ring stays quiet).
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                [void](Invoke-AdmissionProbe $records[$label].Path ('P1_' + $label) $t)
            }
            $traceP1 = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceP1
            Write-DumpQuality 'P1' $traceP1
            $probe1 = Get-ProbeResults $traceP1 $labels
            if ($null -ne $probe1) {
                foreach ($label in $labels) {
                    $records[$label].Sop = ConvertTo-NormalizedHex ([string]$probe1[$label].Sop)
                    Write-Output ('P1_' + $label + '_MmDoes=' + $probe1[$label].MmDoes + ';Sop=' + $records[$label].Sop)
                }
            }

            # Window B: view creation from the retained sections, plus fresh sections as the positive control.
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-sections-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                $record = $records[$label]
                $marker = $record.Kind + ' MARKER ' + $label + ' ' + $id
                if ($record.Kind -eq 'S') {
                    $fixture = New-MappedFixture $record.Path ('Local\SafeUpload-Retained-' + $id + '-' + $label) $false $false $fileHandles $mappings $views
                    $record.Mapping = $fixture.Mapping
                    $record.View = $fixture.View
                }
                else {
                    $record.View = Add-RetainedView $record.Mapping
                    [void]$views.Add($record.View)
                }
                $record.Expected = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($marker))
                $write = Invoke-MappedWrite $record.View $marker
                Write-Output ('B_MappedWrite_' + $label + '=' + $write.Result + $(if ($write.Error) { ';' + $write.Error } else { '' }))
            }
            $traceB = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceB
            Write-DumpQuality 'B' $traceB

            foreach ($label in $labels) {
                $record = $records[$label]
                $r1 = Get-ObserverReadResult $record.Observer 'R1' $record.Original $record.Expected
                $r2 = Get-ObserverReadResult $record.Observer 'R2' $record.Original $record.Expected
                $r3 = Read-FreshBufferedObservation $record.Path $record.Original $record.Expected
                Write-CompactReader ('B_' + $label + '_R1buffered') $r1
                Write-CompactReader ('B_' + $label + '_R2uncached') $r2
                Write-CompactReader ('B_' + $label + '_R3fresh') $r3
            }

            # Probes after every view exists.
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                [void](Invoke-AdmissionProbe $records[$label].Path ('P2_' + $label) $t)
            }
            $traceP2 = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceP2
            Write-DumpQuality 'P2' $traceP2
            $probe2 = Get-ProbeResults $traceP2 $labels
            if ($null -ne $probe2) {
                foreach ($label in $labels) {
                    $sop2 = ConvertTo-NormalizedHex ([string]$probe2[$label].Sop)
                    Write-Output ('P2_' + $label + '_MmDoes=' + $probe2[$label].MmDoes + ';Sop=' + $sop2 + ';SopStable=' + ($sop2 -eq $records[$label].Sop))
                }
            }

            # Per-label event facts for windows A and B.
            foreach ($label in $labels) {
                $sop = $records[$label].Sop
                if ([string]::IsNullOrEmpty($sop)) {
                    Write-Output ('A_' + $label + '=AMBIGUOUS_NO_SOP')
                    Write-Output ('B_' + $label + '=AMBIGUOUS_NO_SOP')
                    continue
                }
                Write-Output ('A_' + $label + '=' + (Format-SopEventFacts (Get-SopEventFacts $traceA $sop)))
                Write-Output ('B_' + $label + '=' + (Format-SopEventFacts (Get-SopEventFacts $traceB $sop)))
            }
            foreach ($kind in @('Rpre', 'Rpost', 'S')) {
                $bWithSection = 0
                $aWithAcquire = 0
                foreach ($label in ($labels | Where-Object { $records[$_].Kind -eq $kind })) {
                    $sop = $records[$label].Sop
                    if ([string]::IsNullOrEmpty($sop)) { continue }
                    $bFacts = Get-SopEventFacts $traceB $sop
                    if (($bFacts.Acquire.Count + $bFacts.Release.Count) -gt 0) { $bWithSection++ }
                    if ((Get-SopEventFacts $traceA $sop).Acquire.Count -gt 0) { $aWithAcquire++ }
                }
                Write-Output ('Summary_' + $kind + '_SectionAcquireInWindowA=' + $aWithAcquire + 'of' + $copies)
                Write-Output ('Summary_' + $kind + '_SectionEventsInWindowB=' + $bWithSection + 'of' + $copies)
            }

            # Lifetime window: no observers and no probes on these files, so no other file object touches their streams.
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            $lifeSteps = @{}
            foreach ($label in $lifeLabels) {
                $step = @{ FileClosed = [Int64]0; Unmapped = [Int64]0; MappingClosed = [Int64]0 }
                $lifeSteps[$label] = $step
                $mapPath = $lifePaths[$label]
                $mapName = 'Local\SafeUpload-Life-' + $id + '-' + $label
                if ($label.StartsWith('Lnv')) {
                    $mapping = New-RetainedSection $mapPath $mapName $mappings
                    $step.FileClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                    Start-Sleep -Seconds 3
                    $mapping.Dispose()
                    $step.MappingClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                }
                else {
                    $fileStream = [IO.FileStream]::new($mapPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    if ($label.StartsWith('Lc')) {
                        # Buffered write first, so the Cache Manager has initialized a cache map for this stream.
                        $cachedBytes = [Text.Encoding]::UTF8.GetBytes('CACHED ' + $label)
                        $fileStream.Write($cachedBytes, 0, $cachedBytes.Length)
                        $fileStream.Flush()
                    }
                    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                        $fileStream, $mapName, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
                        [IO.HandleInheritability]::None, $true)
                    $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
                    [void](Invoke-MappedWrite $view ('LIFETIME ' + $label + ' ' + $id))
                    $fileStream.Dispose()
                    $step.FileClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                    if ($label.StartsWith('Lv') -or $label.StartsWith('Lc')) {
                        $view.Dispose()
                        $step.Unmapped = [DateTime]::UtcNow.ToFileTimeUtc()
                        Start-Sleep -Seconds 3
                        $mapping.Dispose()
                        $step.MappingClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                    }
                    else {
                        $mapping.Dispose()
                        $step.MappingClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                        Start-Sleep -Seconds 3
                        $view.Dispose()
                        $step.Unmapped = [DateTime]::UtcNow.ToFileTimeUtc()
                    }
                }
            }
            $lifeEndFt = [DateTime]::UtcNow.ToFileTimeUtc()
            $lifeDumps = @()
            foreach ($wait in @(5, 15, 30)) {
                Start-Sleep -Seconds $wait
                $dump = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) ($rawTraceL + '-after' + $wait)
                Write-DumpQuality ('L_after_' + $wait + 's') $dump
                $lifeDumps += $dump
            }
            $finalLife = $lifeDumps[$lifeDumps.Count - 1]
            $writableMask = [uint32]0xCC
            $creates = @($finalLife.Entries | Where-Object {
                $_.Ev -eq 'section_acquire' -and $_.Sync -eq 1 -and (($_.Prot -band $writableMask) -ne 0) -and $_.ProcessId -eq $PID
            } | Sort-Object Seq)
            Write-Output ('L_OwnWritableCreateSectionEvents=' + $creates.Count + ';Expected=' + $lifeLabels.Count)
            if ($creates.Count -eq $lifeLabels.Count) {
                for ($index = 0; $index -lt $lifeLabels.Count; $index++) {
                    $label = $lifeLabels[$index]
                    $step = $lifeSteps[$label]
                    $sop = $creates[$index].Sop
                    $unmapText = 'n/a'
                    if ($step.Unmapped -ne 0) { $unmapText = [string][Math]::Round(($step.Unmapped - $step.FileClosed) / 10000.0, 1) }
                    Write-Output ('L_' + $label + '=sop:' + $sop + ';unmapMsFromFileClose:' + $unmapText +
                        ';mappingClosedMsFromFileClose:' + [Math]::Round(($step.MappingClosed - $step.FileClosed) / 10000.0, 1))
                    foreach ($event in @($finalLife.Entries | Where-Object { $_.Sop -eq $sop -and $_.Seq -ge $creates[$index].Seq } | Sort-Object Seq)) {
                        Write-Output ('L_' + $label + '_Event=' + $event.Ev + ';fo=' + $event.Fo + ';pid=' + $event.ProcessId +
                            ';msFromFileClose=' + [Math]::Round(($event.Ts - $step.FileClosed) / 10000.0, 1))
                    }
                }
            }
            else {
                Write-Output 'L_Attribution=AMBIGUOUS'
            }
            Write-Output ('L_ObservedMsAfterLastStep=' + [Math]::Round(([DateTime]::UtcNow.ToFileTimeUtc() - $lifeEndFt) / 10000.0, 0))

            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t
            $traceEnabled = $false
            $fence = Invoke-InspectorChecked -Arguments @('--admission-fence-status') -Timeout $t
            Write-Output ('FenceStatus=' + ([regex]::Replace([string]$fence.Stdout, '[\r\n]+', ' ')).Trim())
            $runSucceeded = $true
        }
        elseif ($SelectedVariant -eq 'section-eol') {
            # Question under test: how does MmDoesFileHaveUserWritableReferences (the explicit probe) behave across the
            # life of a writable section, and does it flip back to "no" promptly once the last writable section/view is
            # gone? Observer-free fixtures, one probe per state change, each probe timestamped by the kernel.
            $t = $InspectorTimeoutSeconds
            $caseNames = @('Env', 'Eview', 'Ecache', 'Ehold')
            $copies = 2
            $eolLabels = @()
            $eolPaths = @{}
            foreach ($case in $caseNames) {
                for ($i = 0; $i -lt $copies; $i++) {
                    $label = $case + $i
                    $path = Join-Path $fixtureDirectory ($label + '.maptest')
                    [IO.File]::WriteAllBytes($path, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('EOL BASELINE ' + $label + ' ' + $id))))
                    $fixturePaths += $path
                    $eolPaths[$label] = $path
                    $eolLabels += $label
                }
            }
            $extraLabels = @('Edup0', 'Ecow0', 'Eread0')
            foreach ($label in $extraLabels) {
                $path = Join-Path $fixtureDirectory ($label + '.maptest')
                [IO.File]::WriteAllBytes($path, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('EOL BASELINE ' + $label + ' ' + $id))))
                $fixturePaths += $path
                $eolPaths[$label] = $path
            }
            foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }
            if (-not ('SafeUploadEolNative' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SafeUploadEolNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
            }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            $traceEnabled = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)

            $eolProbes = New-Object System.Collections.ArrayList
            $releaseFt = @{}
            foreach ($label in $eolLabels) {
                $path = $eolPaths[$label]
                $name = 'Local\SafeUpload-Eol-' + $id + '-' + $label
                $mapping = $null; $view = $null
                if ($label.StartsWith('Env')) {
                    $mapping = New-RetainedSection $path $name $mappings
                    [void]$eolProbes.Add(@{ Label = $label; State = 'sectionOpenNoView' })
                    [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_sectionOpenNoView') $t)
                }
                else {
                    $fileStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    if ($label.StartsWith('Ecache')) {
                        $cachedBytes = [Text.Encoding]::UTF8.GetBytes('CACHED ' + $label)
                        $fileStream.Write($cachedBytes, 0, $cachedBytes.Length)
                        $fileStream.Flush()
                    }
                    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                        $fileStream, $name, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
                        [IO.HandleInheritability]::None, $true)
                    [void]$mappings.Add($mapping)
                    $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
                    [void](Invoke-MappedWrite $view ('EOL ' + $label + ' ' + $id))
                    $fileStream.Dispose()
                    [void]$eolProbes.Add(@{ Label = $label; State = 'viewLiveSectionOpen' })
                    [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_viewLiveSectionOpen') $t)
                    if ($label.StartsWith('Ehold')) {
                        $mapping.Dispose()      # section handle gone, view still mapped
                        [void]$eolProbes.Add(@{ Label = $label; State = 'viewOnlySectionHandleClosed' })
                        [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_viewOnlySectionHandleClosed') $t)
                        $view.Dispose()
                        $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
                    }
                    else {
                        $view.Dispose()         # section handle still open, no views
                        [void]$eolProbes.Add(@{ Label = $label; State = 'sectionOpenNoView' })
                        [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_sectionOpenNoView') $t)
                    }
                }
                if (-not $label.StartsWith('Ehold')) {
                    $mapping.Dispose()
                    $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
                }
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)
                Start-Sleep -Seconds 4
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease2' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease2') $t)
                Start-Sleep -Seconds 10
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease3' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease3') $t)
            }
            # Edup: the only writable section handle lives in ANOTHER process after the creator closes its own.
            $child = $null
            try {
                $label = 'Edup0'; $path = $eolPaths[$label]
                $mapping = New-RetainedSection $path ('Local\SafeUpload-Eol-' + $id + '-' + $label) $mappings
                $child = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 300') -PassThru -WindowStyle Hidden
                $duplicate = [IntPtr]::Zero
                $ok = [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(),
                    $mapping.SafeMemoryMappedFileHandle.DangerousGetHandle(), $child.Handle, [ref]$duplicate, [uint32]0, $false, [uint32]2)
                if (-not $ok) { throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error())) }
                Write-Output ('Edup_DuplicatedIntoChildPid=' + $child.Id)
                $mapping.Dispose()
                [void]$eolProbes.Add(@{ Label = $label; State = 'creatorClosedChildHolds' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_creatorClosedChildHolds') $t)
                $child.Kill()
                $child.WaitForExit()
                $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)
                Start-Sleep -Seconds 4
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease2' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease2') $t)
            }
            finally {
                if ($null -ne $child -and -not $child.HasExited) { $child.Kill() }
            }
            # Ecow: a copy-on-write section can never write back to the file, so it must not read as "writable".
            $label = 'Ecow0'; $path = $eolPaths[$label]
            $fileStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                $fileStream, ('Local\SafeUpload-Eol-' + $id + '-' + $label), [long]$mappingLength,
                [IO.MemoryMappedFiles.MemoryMappedFileAccess]::CopyOnWrite, [IO.HandleInheritability]::None, $true)
            [void]$mappings.Add($mapping)
            $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::CopyOnWrite)
            $view.WriteArray(0, [byte[]](1, 2, 3, 4), 0, 4)
            $fileStream.Dispose()
            [void]$eolProbes.Add(@{ Label = $label; State = 'copyOnWriteViewLive' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_copyOnWriteViewLive') $t)
            $view.Dispose(); $mapping.Dispose()
            $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
            [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)
            # Eread: a read-only section and view.
            $label = 'Eread0'; $path = $eolPaths[$label]
            $fileStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                $fileStream, ('Local\SafeUpload-Eol-' + $id + '-' + $label), [long]$mappingLength,
                [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read, [IO.HandleInheritability]::None, $true)
            [void]$mappings.Add($mapping)
            $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
            $fileStream.Dispose()
            [void]$eolProbes.Add(@{ Label = $label; State = 'readOnlyViewLive' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_readOnlyViewLive') $t)
            $view.Dispose(); $mapping.Dispose()
            $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
            [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)

            $traceE = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceL
            Write-DumpQuality 'EOL' $traceE
            $probeEntries = @($traceE.Entries | Where-Object { $_.Ev -eq 'explicit_probe' } | Sort-Object Seq)
            Write-Output ('EOL_ProbeEntries=' + $probeEntries.Count + ';Expected=' + $eolProbes.Count)
            if ($probeEntries.Count -eq $eolProbes.Count) {
                for ($index = 0; $index -lt $eolProbes.Count; $index++) {
                    $probe = $eolProbes[$index]
                    $entry = $probeEntries[$index]
                    $msText = 'n/a'
                    if ($releaseFt.ContainsKey($probe.Label)) {
                        $msText = [string][Math]::Round(($entry.Ts - $releaseFt[$probe.Label]) / 10000.0, 0)
                    }
                    Write-Output ('EOL_' + $probe.Label + '_' + $probe.State + '=mmDoes:' + $entry.MmDoes + ';msAfterFinalRelease:' + $msText)
                }
            }
            else {
                Write-Output 'EOL_Attribution=AMBIGUOUS'
            }
            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t
            $traceEnabled = $false
            $runSucceeded = $true
        }
        elseif ($SelectedVariant -eq 'writer-count') {
            # X2: H(F), the per-stream count of write file objects, against what the harness knows to be true.
            $t = $InspectorTimeoutSeconds
            Initialize-EolNative
            Initialize-WriterStress
            Initialize-WriterInheritance
            Initialize-WriterIo
            $script:WriterChecksPassed = 0
            $script:WriterChecksFailed = 0
            $access = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            function Open-WC([string] $p, [IO.FileMode] $mode = [IO.FileMode]::Open, [IO.FileAccess] $acc = [IO.FileAccess]::ReadWrite,
                [IO.FileShare] $share = ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)) {
                return [IO.FileStream]::new($p, $mode, $acc, $share)
            }
            function New-WCFile([string] $name) {
                $p = Join-Path $fixtureDirectory $name
                [IO.File]::WriteAllBytes($p, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('WC BASELINE ' + $name + ' ' + $id))))
                $script:fixturePathsLocal += $p
                return $p
            }
            $script:fixturePathsLocal = @()
            $fa = New-WCFile 'wc_single.maptest'
            $fb = New-WCFile 'wc_two.maptest'
            $fc = New-WCFile 'wc_readonly.maptest'
            $fd = New-WCFile 'wc_dupsame.maptest'
            $fe = New-WCFile 'wc_dupchild.maptest'
            $ff = New-WCFile 'wc_failed.maptest'
            $fg = New-WCFile 'wc_truncate.maptest'
            $fh = New-WCFile 'wc_alias_target.maptest'
            $fi = New-WCFile 'wc_a_rather_long_file_name_for_short_names.maptest'
            $fj = New-WCFile 'wc_many.maptest'
            $fk = New-WCFile 'wc_stress.maptest'
            $fl = New-WCFile 'wc_section.maptest'
            $fm = New-WCFile 'wc_ads_base.maptest'
            $fn = New-WCFile 'wc_delete_only.maptest'
            $fo = New-WCFile 'wc_inherited.maptest'
            $fp = New-WCFile 'wc_delete_on_close.maptest'
            $reparseTargetDirectory = Join-Path $fixtureDirectory 'wc-reparse-target'
            [void][IO.Directory]::CreateDirectory($reparseTargetDirectory)
            $fq = New-WCFile 'wc-reparse-target\wc_reparsed.maptest'
            $fr = New-WCFile 'wc_cancelled.maptest'
            $fs = New-WCFile 'wc_fast_io.maptest'
            $writerIoSourcePath = Join-Path $fixtureDirectory 'wc-io-native.cs'
            [IO.File]::WriteAllText($writerIoSourcePath, $script:WriterIoSource)
            # Compile both isolated helpers before loading the driver; their source/temp assembly writes
            # must not contaminate group counter deltas. They wait for commands without opening fixtures.
            $writerIoExecutable = Join-Path $PSHOME 'powershell.exe'
            $cancelledIo = [SafeUploadWriterIo+Session]::Start($writerIoExecutable, $writerIoSourcePath, $fr)
            [void]$writerIoSessions.Add($cancelledIo)
            $fastIo = [SafeUploadWriterIo+Session]::Start($writerIoExecutable, $writerIoSourcePath, $fs)
            [void]$writerIoSessions.Add($fastIo)
            function Add-WCOutcome([string] $Label, [bool] $Ok, [string] $Facts) {
                $verdict = if ($Ok) { 'PASS' } else { 'FAIL' }
                if ($Ok) { $script:WriterChecksPassed++ } else { $script:WriterChecksFailed++ }
                Write-Output ('WC_' + $Label + '=' + $Facts + ';' + $verdict)
            }
            function Add-WCBalance([string] $Label, $Before, $After) {
                $counted = [int64]$After.writeObjectsCounted - [int64]$Before.writeObjectsCounted
                $released = [int64]$After.writeObjectsReleased - [int64]$Before.writeObjectsReleased
                $untracked = [int64]$After.untrackedCreates - [int64]$Before.untrackedCreates
                $unmatched = [int64]$After.cleanupUnmatched - [int64]$Before.cleanupUnmatched
                Add-WCOutcome ($Label + '_balance') ($counted -eq $released) ('counted:' + $counted + ';released:' + $released)
                Add-WCOutcome ($Label + '_untrackedCreates') ($untracked -eq 0) ('delta:' + $untracked)
                Add-WCOutcome ($Label + '_cleanupUnmatched') ($unmatched -eq 0) ('delta:' + $unmatched)
            }
            function Invoke-WCQuietWorkload($Session, [string] $Command) {
                # Preserve earlier explicit probes in the 16384-entry ring through high-volume loops.
                # H(F) accounting and stats remain active; only diagnostic event collection is paused.
                [void](Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t)
                $traceEnabled = $false
                try { return $Session.Request($Command) }
                finally {
                    [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $t)
                    $traceEnabled = $true
                }
            }
            $fixturePaths += $script:fixturePathsLocal
            foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            if ($Verifier) {
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
                $verifierEnabled = $true
                Write-Output 'VerifierEnabled=volatile flags 0x13B'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $t)
            $traceEnabled = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            $statsBefore = Get-WriterStateStats
            Wait-AdmissionCanary $fa $rawTraceA
            Write-Output ('WC_StatsBefore=counted:' + $statsBefore.writeObjectsCounted + ';released:' + $statsBefore.writeObjectsReleased +
                ';untracked:' + $statsBefore.untrackedCreates + ';unmatched:' + $statsBefore.cleanupUnmatched)

            # Group 1: basic counting
            Add-WriterProbe $fa 'single_beforeOpen' 0
            $s1 = Open-WC $fa
            Add-WriterProbe $fa 'single_open' 1
            $s1.Dispose()
            Add-WriterProbe $fa 'single_closed' 0
            $sa = Open-WC $fb; Add-WriterProbe $fb 'two_firstOpen' 1
            $sb = Open-WC $fb; Add-WriterProbe $fb 'two_secondOpen' 2
            $sa.Dispose(); Add-WriterProbe $fb 'two_firstClosed' 1
            $sb.Dispose(); Add-WriterProbe $fb 'two_allClosed' 0
            $r1 = Open-WC $fc ([IO.FileMode]::Open) ([IO.FileAccess]::Read); Add-WriterProbe $fc 'readOnly_open' 0
            $r1.Dispose()
            $attr = [SafeUploadAdmissionNative]::CreateFile($fc, [uint32]0x100, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
            if ($attr.IsInvalid) { throw 'Attributes-only open failed.' }
            Add-WriterProbe $fc 'attributesOnly_open' 0
            $attr.Dispose(); Add-WriterProbe $fc 'attributesOnly_closed' 0
            $deleteOnly = [SafeUploadAdmissionNative]::CreateFile($fn, [uint32]0x10000, [uint32]7,
                [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
            if ($deleteOnly.IsInvalid) { throw 'Delete-only open failed.' }
            Add-WriterProbe $fn 'deleteOnly_open' 1
            $deleteOnly.Dispose(); Add-WriterProbe $fn 'deleteOnly_closed' 0
            # FILE_FLAG_DELETE_ON_CLOSE takes effect after the final handle to the same file object closes.
            $deleteClose = [SafeUploadAdmissionNative]::CreateFile($fp, [uint32]0x40010000, [uint32]7,
                [IntPtr]::Zero, [uint32]3, [uint32]0x04000080, [IntPtr]::Zero)
            if ($deleteClose.IsInvalid) { throw 'Delete-on-close open failed.' }
            [void]$fileHandles.Add($deleteClose)
            $deleteDup = $null
            try {
                Add-WriterProbe $fp 'deleteOnClose_open' 1
                $deleteDupPtr = [IntPtr]::Zero
                if (-not [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(),
                    $deleteClose.DangerousGetHandle(), [SafeUploadEolNative]::GetCurrentProcess(),
                    [ref]$deleteDupPtr, [uint32]0, $false, [uint32]2)) { throw 'Delete-on-close duplicate failed.' }
                $deleteDup = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($deleteDupPtr, $true)
                [void]$fileHandles.Add($deleteDup)
                $deleteClose.Dispose()
                Add-WriterProbe $fp 'deleteOnClose_originalClosedDuplicateHolds' 1
                $deleteDup.Dispose()
                $deleteError = [SafeUploadWriterInheritance]::MissingFileError($fp)
                $deleted = $deleteError -eq 2
                Write-Output ('WC_DeleteOnClose_FinalHandleDeletedFile=' + $deleted + ';NativeError=' + $deleteError)
                if (-not $deleted) { throw 'Delete-on-close did not delete the fixture after final close.' }
            } finally {
                $deleteClose.Dispose()
                if ($null -ne $deleteDup) { $deleteDup.Dispose() }
            }
            Complete-WriterChecks 'basic_and_deleteOnClose' $rawTraceA

            # Group 2: duplicated handles
            $d1 = Open-WC $fd
            $dupPtr = [IntPtr]::Zero
            $okDup = [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(), $d1.SafeFileHandle.DangerousGetHandle(),
                [SafeUploadEolNative]::GetCurrentProcess(), [ref]$dupPtr, [uint32]0, $false, [uint32]2)
            if (-not $okDup) { throw 'In-process DuplicateHandle failed.' }
            $dup = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($dupPtr, $true)
            Add-WriterProbe $fd 'dupSame_afterDuplicate' 1
            $d1.Dispose(); Add-WriterProbe $fd 'dupSame_originalClosed' 1
            $dup.Dispose(); Add-WriterProbe $fd 'dupSame_allClosed' 0
            $e1 = Open-WC $fe
            $child = $null
            try {
                $child = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 300') -PassThru -WindowStyle Hidden
                $dupChild = [IntPtr]::Zero
                $okChild = [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(), $e1.SafeFileHandle.DangerousGetHandle(),
                    $child.Handle, [ref]$dupChild, [uint32]0, $false, [uint32]2)
                if (-not $okChild) { throw 'Cross-process DuplicateHandle failed.' }
                $e1.Dispose()
                Add-WriterProbe $fe 'dupChild_parentClosedChildHolds' 1
                $child.Kill(); $child.WaitForExit()
                Add-WriterProbe $fe 'dupChild_childKilled' 0
            }
            finally { if ($null -ne $child -and -not $child.HasExited) { $child.Kill() } }
            # True CreateProcess inheritance, with child-side FILE_ID_INFO proof of the inherited handle.
            $inheritedFile = Open-WC $fo
            [void]$fileHandles.Add($inheritedFile)
            $nativeSourcePath = Join-Path $fixtureDirectory 'wc-inherit-native.cs'
            $readyPath = Join-Path $fixtureDirectory 'wc-inherit-ready.json'
            [IO.File]::WriteAllText($nativeSourcePath, $script:WriterInheritanceSource)
            $nativeHandle = $inheritedFile.SafeFileHandle.DangerousGetHandle()
            $expectedIdentity = [SafeUploadWriterInheritance]::Identity($nativeHandle)
            $childCode = @"
`$ErrorActionPreference='Stop'
Add-Type -Path '$nativeSourcePath'
`$identity=[SafeUploadWriterInheritance]::Identity([IntPtr]::new($($nativeHandle.ToInt64())))
if (`$identity -ne '$expectedIdentity') { throw 'Inherited file identity mismatch' }
@{ Identity=`$identity; ProcessId=`$PID; Handle=$($nativeHandle.ToInt64()) } | ConvertTo-Json | Set-Content -LiteralPath '$readyPath.next'
Move-Item -LiteralPath '$readyPath.next' -Destination '$readyPath'
Start-Sleep -Seconds 300
"@
            $childScriptPath = Join-Path $fixtureDirectory 'wc-inherit-child.ps1'
            [IO.File]::WriteAllText($childScriptPath, $childCode)
            $application = Join-Path $PSHOME 'powershell.exe'
            $child = $null
            try {
                $child = [SafeUploadWriterInheritance]::Start($nativeHandle, $application,
                    ('"' + $application + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $childScriptPath + '"'))
                $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
                while (-not (Test-Path -LiteralPath $readyPath) -and -not $child.HasExited -and [DateTime]::UtcNow -lt $readyDeadline) {
                    Start-Sleep -Milliseconds 50
                }
                if (-not (Test-Path -LiteralPath $readyPath)) { throw 'Inherited child did not prove its handle.' }
                $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
                if ($ready.Identity -ne $expectedIdentity -or $ready.ProcessId -ne $child.Id -or
                    $ready.Handle -ne $nativeHandle.ToInt64()) { throw 'Inherited child proof mismatch.' }
                Write-Output ('WC_InheritedProof=PID:' + $ready.ProcessId + ';Identity:' + $ready.Identity + ';Handle:' + $ready.Handle)
                Add-WriterProbe $fo 'inherited_parentAndChildHold' 1
                $inheritedFile.Dispose()
                Add-WriterProbe $fo 'inherited_parentClosedChildHolds' 1
                $child.Kill(); $child.WaitForExit()
                Add-WriterProbe $fo 'inherited_childExited' 0
            } finally {
                $inheritedFile.Dispose()
                if ($null -ne $child) {
                    if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
                    $child.Dispose()
                }
            }
            Complete-WriterChecks 'duplicates_and_inheritance' $rawTraceP1

            # Group 3: failed creates, truncation, aliases
            $x1 = Open-WC $ff ([IO.FileMode]::Open) ([IO.FileAccess]::ReadWrite) ([IO.FileShare]::None)
            Add-WriterProbe ($ff) 'failed_exclusiveOpen' 1
            $failedSharing = $false
            try { $x2 = Open-WC $ff; $x2.Dispose() } catch { $failedSharing = $true }
            Write-Output ('WC_Note_SharingViolationRaised=' + $failedSharing)
            if (-not $failedSharing) { throw 'Sharing-violation fixture did not fail its create.' }
            Add-WriterProbe $ff 'failed_afterSharingViolation' 1
            $failedMissing = $false
            try { $x3 = Open-WC (Join-Path $fixtureDirectory 'wc_missing.maptest'); $x3.Dispose() } catch { $failedMissing = $true }
            Write-Output ('WC_Note_MissingOpenRaised=' + $failedMissing)
            if (-not $failedMissing) { throw 'Missing-file fixture did not fail its create.' }
            Add-WriterProbe $ff 'failed_afterMissingOpen' 1
            $x1.Dispose(); Add-WriterProbe $ff 'failed_closed' 0
            $tr = Open-WC $fg ([IO.FileMode]::Create); Add-WriterProbe $fg 'truncate_open' 1
            $tr.Dispose(); Add-WriterProbe $fg 'truncate_closed' 0
            $linkPath = Join-Path $fixtureDirectory 'wc_alias_link.maptest'
            New-Item -ItemType HardLink -Path $linkPath -Target $fh | Out-Null
            $script:fixturePathsLocal += $linkPath; $fixturePaths += $linkPath
            $viaLink = Open-WC $linkPath
            Add-WriterProbe $fh 'hardLink_openedViaLinkProbedViaTarget' 1
            Add-WriterProbe $linkPath 'hardLink_probedViaLink' 1
            $viaLink.Dispose(); Add-WriterProbe $fh 'hardLink_closed' 0
            $shortPath = $null
            try { $shortPath = (New-Object -ComObject Scripting.FileSystemObject).GetFile($fi).ShortPath } catch { }
            if ($shortPath -and $shortPath -ne $fi) {
                $viaShort = Open-WC $shortPath
                Add-WriterProbe $fi 'shortName_openedViaShortProbedViaLong' 1
                $viaShort.Dispose(); Add-WriterProbe $fi 'shortName_closed' 0
                Write-Output ('WC_Note_ShortPath=' + $shortPath)
            }
            else { Write-Output 'WC_Note_ShortPath=NOT_AVAILABLE' }
            $adsPath = $fm + ':side'
            # .NET FileStream rejects stream names; use the Win32 open. GENERIC_WRITE, share all, OPEN_ALWAYS.
            $adsHandle = [SafeUploadAdmissionNative]::CreateFile($adsPath, [uint32]0x40000000, [uint32]7, [IntPtr]::Zero, [uint32]4, [uint32]0x80, [IntPtr]::Zero)
            if ($adsHandle.IsInvalid) { throw 'Alternate stream open failed.' }
            Add-WriterProbe $fm 'ads_sideStreamWriterDoesNotCountForBase' 0
            $adsHandle.Dispose()
            # A same-volume junction causes a real filesystem reparse of the write create.
            $junction = Join-Path $fixtureDirectory 'wc-reparse-junction'
            $reparsedFile = $null
            try {
                New-Item -ItemType Junction -Path $junction -Target $reparseTargetDirectory | Out-Null
                $junctionHandle = [SafeUploadAdmissionNative]::CreateFile($junction, [uint32]0x100, [uint32]7,
                    [IntPtr]::Zero, [uint32]3, [uint32]0x02200000, [IntPtr]::Zero)
                if ($junctionHandle.IsInvalid) { throw 'Junction tag open failed.' }
                try { $tag = [SafeUploadWriterInheritance]::ReparseTag($junctionHandle.DangerousGetHandle()) }
                finally { $junctionHandle.Dispose() }
                if ($tag -ne [uint32]2684354563) { throw 'Fixture is not a mount-point junction.' }
                $direct = [SafeUploadAdmissionNative]::CreateFile($fq, [uint32]0x100, [uint32]7,
                    [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
                if ($direct.IsInvalid) { throw 'Canonical reparse target identity open failed.' }
                try { $canonicalIdentity = [SafeUploadWriterInheritance]::Identity($direct.DangerousGetHandle()) }
                finally { $direct.Dispose() }
                $reparsedFile = [SafeUploadAdmissionNative]::CreateFile((Join-Path $junction 'wc_reparsed.maptest'),
                    [uint32]0x40010000, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
                if ($reparsedFile.IsInvalid) { throw 'Reparsed write-create failed.' }
                [void]$fileHandles.Add($reparsedFile)
                $redirectedIdentity = [SafeUploadWriterInheritance]::Identity($reparsedFile.DangerousGetHandle())
                if ($redirectedIdentity -ne $canonicalIdentity) { throw 'Reparsed write-create resolved to another file.' }
                Write-Output ('WC_ReparseProof=Tag:' + $tag + ';Identity:' + $redirectedIdentity + ';MatchesCanonical=True')
                Add-WriterProbe $fq 'reparsed_writeOpenCountsCanonicalTarget' 1
                $reparsedFile.Dispose()
                Add-WriterProbe $fq 'reparsed_closed' 0
            } finally {
                if ($null -ne $reparsedFile) { $reparsedFile.Dispose() }
                # Remove only the junction itself; never recurse through the target during cleanup.
                if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction, $false) }
            }
            Complete-WriterChecks 'aliases_and_reparse' $rawTraceP2

            # Group 4: many handles, stress, and a writer whose file handle closed but whose section is retained
            $many = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt 120; $i++) { [void]$many.Add((Open-WC $fj)) }
            Add-WriterProbe $fj 'many_120open' 120
            for ($i = 0; $i -lt 60; $i++) { $many[$i].Dispose() }
            Add-WriterProbe $fj 'many_60closed' 60
            for ($i = 60; $i -lt 120; $i++) { $many[$i].Dispose() }
            Add-WriterProbe $fj 'many_allClosed' 0
            $stressFailures = [SafeUploadWriterStress]::Run($fk, 8, 400)
            Write-Output ('WC_Note_StressOpenFailures=' + $stressFailures)
            if ($stressFailures -ne 0) { throw ('Writer stress open failures: ' + $stressFailures) }
            Add-WriterProbe $fk 'stress_8x400_allClosed' 0
            $secFile = Open-WC $fl
            $secMap = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($secFile, ('Local\SafeUpload-Wc-' + $id), [long]$mappingLength,
                [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
            [void]$mappings.Add($secMap)
            Add-WriterProbe $fl 'section_fileOpenSectionRetained' 1 'yes'
            $secFile.Dispose()
            Add-WriterProbe $fl 'section_fileClosedSectionRetained_HzeroSyes' 0 'yes'
            $secMap.Dispose()
            Add-WriterProbe $fl 'section_released_HzeroSno' 0 'no'
            Complete-WriterChecks 'many_and_sections' $rawTraceB

            # Group 5: cancelled creates. A break completion alone is not enough: require ACK_REQUIRED
            # and a still-pending victim before cancelling. A read-only oplock breaks without an acknowledgment barrier,
            # so the read-only holder takes READ|HANDLE caching and the victim opens write with FILE_SHARE_NONE, which
            # conflicts with the holder and pends until it acknowledges. Anything else must fail, never skip.
            $cancelledStatsBefore = Get-WriterStateStats
            $deterministicCancelled = 0
            $raceSucceeded = 0
            $raceCancelled = 0
            $cancelSeed = 1904503
            $cancelRng = [Random]::new($cancelSeed)
            $cancelOplockLevel = 3 # OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE
            Write-Output ('WC_CancelledCreates_Seed=' + $cancelSeed + ';oplockLevel:' + $cancelOplockLevel)
            try {
                for ($iteration = 1; $iteration -le 20; $iteration++) {
                    $holderActive = $false
                    try {
                        $proof = $cancelledIo.Request('BEGIN ' + $cancelOplockLevel)
                        $holderActive = $true
                        Write-Output ('WC_CancelledCreate_' + $iteration + '_Pending=' + $proof)
                        $outcome = $cancelledIo.Request('CANCEL')
                        $cancelOk = ($outcome -eq 'succeeded:False;win32:995')
                        Add-WCOutcome ('cancelled_deterministic_' + $iteration) $cancelOk $outcome
                        if (-not $cancelOk) { throw ('Deterministic create did not return ERROR_OPERATION_ABORTED: ' + $outcome) }
                        $deterministicCancelled++
                        if ($iteration -eq 1) {
                            # Keep the read-only holder open through the immediate zero-writer probe.
                            Add-WriterProbe $fr 'cancelled_immediate_holderStillOpen' 0
                        }
                    } finally {
                        if ($holderActive) { [void]$cancelledIo.Request('RELEASE') }
                    }
                    if ($iteration -eq 1) {
                        [void]$cancelledIo.Request('OPEN')
                        try { Add-WriterProbe $fr 'cancelled_normalWriter_afterCancel' 1 }
                        finally { [void]$cancelledIo.Request('CLOSE') }
                        Add-WriterProbe $fr 'cancelled_normalWriter_closed' 0
                    }
                    if (($iteration % 5) -eq 0) {
                        Add-WriterProbe $fr ('cancelled_batch_' + $iteration + '_allClosed') 0
                    }
                }
                for ($iteration = 1; $iteration -le 200; $iteration++) {
                    $cancelOffset = $cancelRng.Next(0, 6)
                    $closeOffset = $cancelRng.Next(0, 6)
                    $outcome = $cancelledIo.Request(('RACE ' + $cancelOplockLevel + ' ' + $cancelOffset + ' ' + $closeOffset))
                    $raceOk = ($outcome -eq 'succeeded:True;win32:0' -or $outcome -eq 'succeeded:False;win32:995')
                    Add-WCOutcome ('cancelled_race_' + $iteration) $raceOk ($outcome + ';cancelMs:' + $cancelOffset + ';closeMs:' + $closeOffset)
                    if (-not $raceOk) { throw ('Unexpected racing create outcome: ' + $outcome) }
                    if ($outcome -eq 'succeeded:True;win32:0') { $raceSucceeded++ } else { $raceCancelled++ }
                }
            } catch {
                Add-WCOutcome 'cancelled_execution' $false (Get-ErrorText $_)
            } finally {
                # Counters are sampled before the helper exits so its process teardown is attributed separately.
                $cancelledStatsAfter = Get-WriterStateStats
                # Graceful EXIT runs worker finally blocks; the process is killed/reaped if native I/O is stuck.
                try { $cancelledIo.Dispose() }
                catch { Add-WCOutcome 'cancelled_worker_disposal' $false (Get-ErrorText $_) }
            }
            Add-WCOutcome 'cancelled_iterations' ($deterministicCancelled -eq 20 -and ($raceSucceeded + $raceCancelled) -eq 200) ('deterministic:' + $deterministicCancelled + ';race:' + ($raceSucceeded + $raceCancelled))
            Add-WriterProbe $fr 'cancelled_final_allClosed' 0
            $cancelledStatsDisposed = Get-WriterStateStats
            Write-Output ('WC_cancelled_helperExitDelta=counted:' + ([int64]$cancelledStatsDisposed.writeObjectsCounted - [int64]$cancelledStatsAfter.writeObjectsCounted) +
                ';released:' + ([int64]$cancelledStatsDisposed.writeObjectsReleased - [int64]$cancelledStatsAfter.writeObjectsReleased) +
                ';untracked:' + ([int64]$cancelledStatsDisposed.untrackedCreates - [int64]$cancelledStatsAfter.untrackedCreates) +
                ';unmatched:' + ([int64]$cancelledStatsDisposed.cleanupUnmatched - [int64]$cancelledStatsAfter.cleanupUnmatched))
            Add-WCBalance 'cancelled' $cancelledStatsBefore $cancelledStatsAfter
            Write-Output ('WC_CancelledCreates=deterministic:' + $deterministicCancelled + ';race_succeeded:' + $raceSucceeded +
                ';race_cancelled:' + $raceCancelled + ';seed:' + $cancelSeed)
            Write-Output ('WC_Group_cancelled_creates_RawFile=' + $rawTraceCancelledCreates)
            Complete-WriterChecks 'cancelled_creates' $rawTraceCancelledCreates

            # Group 6: cached small I/O and query-open calls. APIs may fall back to IRPs; guest tracing
            # must establish actual FASTIO_* coverage separately. Probes always require known H(F).
            $fastStatsBefore = Get-WriterStateStats
            $fastWrites = 0
            $fastQueries = 0
            $concurrentIterations = [long]0
            try {
                [void]$fastIo.Request('OPEN')
                try {
                    Add-WriterProbe $fs 'fast_cached_before' 1
                    $fastWrites += [int]$fastIo.Request('WRITES 1000 512')
                    Add-WriterProbe $fs 'fast_cached_during_1000' 1
                    $fastWrites += [int]$fastIo.Request('WRITES 1000 4096')
                    Add-WriterProbe $fs 'fast_cached_after_2000' 1
                    Add-WCOutcome 'fast_cached_readback' ($fastWrites -eq 2000) ('writeReadPairs:' + $fastWrites)
                } finally { [void]$fastIo.Request('CLOSE') }
                Add-WriterProbe $fs 'fast_cached_closed' 0

                Add-WriterProbe $fs 'fast_query_noWriter_before' 0
                $fastQueries += [int](Invoke-WCQuietWorkload $fastIo 'QUERIES 5000')
                Add-WriterProbe $fs 'fast_query_noWriter_after' 0
                [void]$fastIo.Request('OPEN')
                try {
                    Add-WriterProbe $fs 'fast_query_writer_before' 1
                    $fastQueries += [int](Invoke-WCQuietWorkload $fastIo 'QUERIES 5000')
                    Add-WriterProbe $fs 'fast_query_writer_after' 1
                } finally { [void]$fastIo.Request('CLOSE') }
                Add-WriterProbe $fs 'fast_query_writer_closed' 0
                Add-WCOutcome 'fast_queries' ($fastQueries -eq 10000) ('GetFileAttributesEx:' + $fastQueries)

                $concurrentIterations = [long](Invoke-WCQuietWorkload $fastIo 'CONCURRENT')
                Add-WCOutcome 'fast_concurrent' ($concurrentIterations -ge 8) ('threads:8;durationMs:3000;iterations:' + $concurrentIterations)
            } catch {
                Add-WCOutcome 'fast_execution' $false (Get-ErrorText $_)
            } finally {
                $fastStatsAfter = Get-WriterStateStats
                try { $fastIo.Dispose() }
                catch { Add-WCOutcome 'fast_worker_disposal' $false (Get-ErrorText $_) }
            }
            Add-WriterProbe $fs 'fast_concurrent_allClosed' 0
            $fastStatsDisposed = Get-WriterStateStats
            Write-Output ('WC_fast_helperExitDelta=counted:' + ([int64]$fastStatsDisposed.writeObjectsCounted - [int64]$fastStatsAfter.writeObjectsCounted) +
                ';released:' + ([int64]$fastStatsDisposed.writeObjectsReleased - [int64]$fastStatsAfter.writeObjectsReleased) +
                ';untracked:' + ([int64]$fastStatsDisposed.untrackedCreates - [int64]$fastStatsAfter.untrackedCreates) +
                ';unmatched:' + ([int64]$fastStatsDisposed.cleanupUnmatched - [int64]$fastStatsAfter.cleanupUnmatched))
            Add-WCBalance 'fast' $fastStatsBefore $fastStatsAfter
            Write-Output ('WC_FastIo=writes:' + $fastWrites + ';queries:' + $fastQueries + ';concurrent_iterations:' + $concurrentIterations)
            Write-Output ('WC_Group_fast_io_RawFile=' + $rawTraceFastIo)
            Complete-WriterChecks 'fast_io' $rawTraceFastIo

            $statsAfter = Get-WriterStateStats
            Write-Output ('WC_StatsAfter=counted:' + $statsAfter.writeObjectsCounted + ';released:' + $statsAfter.writeObjectsReleased +
                ';untracked:' + $statsAfter.untrackedCreates + ';unmatched:' + $statsAfter.cleanupUnmatched +
                ';postCreateRuns:' + $statsAfter.postCreateRuns)
            $dCounted = [int64]$statsAfter.writeObjectsCounted - [int64]$statsBefore.writeObjectsCounted
            $dReleased = [int64]$statsAfter.writeObjectsReleased - [int64]$statsBefore.writeObjectsReleased
            Write-Output ('WC_StatsDelta=counted:' + $dCounted + ';released:' + $dReleased + ';liveDelta:' + ($dCounted - $dReleased))
            Write-Output ('WC_Summary=passed:' + $script:WriterChecksPassed + ';failed:' + $script:WriterChecksFailed)
            if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceB + '-final-volumes.json') }
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t)
            $traceEnabled = $false
            $runSucceeded = ($script:WriterChecksFailed -eq 0)
        }
        elseif ($SelectedVariant -eq 'primitive-cost') {
            # X6: absolute latency budget, with original unloaded-driver B followed by feature-driver F.
            # Helpers use the existing session cleanup list; the common restoration finally is unchanged.
            $passed = 0
            $failed = 0
            try {
                $t = $InspectorTimeoutSeconds
                Initialize-PrimitiveCost
                $costBPath = Join-Path $fixtureDirectory 'cost_baseline.maptest'
                $costFPath = Join-Path $fixtureDirectory 'cost_feature.maptest'
                $costSourcePath = Join-Path $fixtureDirectory 'cost-native.cs'
                $fixturePaths += @($costBPath, $costFPath, $costSourcePath)
                $costBytes = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('COST BASELINE ' + $id))
                foreach ($path in @($costBPath, $costFPath)) { [IO.File]::WriteAllBytes($path, $costBytes) }
                [IO.File]::WriteAllText($costSourcePath, $script:PrimitiveCostSource)
                foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }
                $costDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($costBPath))
                if ($costDrive.DriveType -ne [IO.DriveType]::Fixed -or $costDrive.DriveFormat -ne 'NTFS') {
                    throw 'Primitive cost fixtures require a local fixed NTFS volume.'
                }
                Write-Output ('COST_ProcessorCount=' + [Environment]::ProcessorCount)
                Write-Output ('COST_Fixtures=B:' + $costBPath + ';F:' + $costFPath + ';sizeBytes:' + $costBytes.Length)
                Write-Output 'COST_Counts=warmupDiscarded:2000;measured:20000;totalPerOperation:22000'
                Write-Output 'COST_Method=QPC;percentiles:nearestRank;phaseDeadlineMs:580000;killWaitMs:10000'
                Write-Output 'COST_create_write_createOnly_Method=additionalQPCInsidePair;noTimerOverheadSubtraction'
                Write-Output 'COST_write_cached_Method=4096Bytes;sameExtent;seekOutsideTimedCall;noFlush'
                $costExecutable = Join-Path $PSHOME 'powershell.exe'
                # Both sessions reach READY before B: no Add-Type/compiler/source I/O under the feature driver.
                $costB = [SafeUploadPrimitiveCost+Session]::Start($costExecutable, $costSourcePath, $costBPath)
                [void]$writerIoSessions.Add($costB)
                $costF = [SafeUploadPrimitiveCost+Session]::Start($costExecutable, $costSourcePath, $costFPath)
                [void]$writerIoSessions.Add($costF)
                Write-Output ('COST_Helper_B=' + $costB.ReadyInfo)
                Write-Output ('COST_Helper_F=' + $costF.ReadyInfo)
                $costOperations = @('create_write', 'create_read', 'create_attr', 'section_write', 'section_read', 'write_cached')
                $costReportedOperations = @($costOperations) + @('create_write_createOnly')
                Write-Output ('COST_Order=' + ($costOperations -join ','))
                $costResults = @{ B = @{}; F = @{} }
                $costCulture = [Globalization.CultureInfo]::InvariantCulture
                function Convert-CostSample([string] $Packet) {
                    $values = @{}
                    foreach ($field in $Packet.Split(';')) {
                        $parts = $field.Split(':')
                        if ($parts.Length -ne 2 -or $values.ContainsKey($parts[0])) { throw 'Malformed cost sample.' }
                        $values[$parts[0]] = [long]::Parse($parts[1], $costCulture)
                    }
                    foreach ($key in @('n', 'frequency', 'minTicks', 'p50Ticks', 'p95Ticks', 'p99Ticks', 'maxTicks')) {
                        if (-not $values.ContainsKey($key)) { throw ('Missing cost field: ' + $key) }
                    }
                    if ($values.n -ne 20000 -or $values.frequency -le 0) { throw 'Invalid cost sample counts/frequency.' }
                    $stats = @{ n = $values.n }
                    $previous = [long]-1
                    foreach ($stat in @('min', 'p50', 'p95', 'p99', 'max')) {
                        $ticks = $values[$stat + 'Ticks']
                        if ($ticks -lt 0 -or $ticks -lt $previous) { throw 'Invalid cost sample ordering.' }
                        $previous = $ticks
                        # Keep unrounded decimal values for budgets, deltas and ratios. Format only for output.
                        $stats[$stat + 'Us'] = [decimal]$ticks * [decimal]1000000 / [decimal]$values.frequency
                    }
                    return $stats
                }
                function Format-CostUs([decimal] $Value) { return $Value.ToString('F6', $costCulture) }
                function Invoke-CostPhase($Session, [string] $Phase) {
                    $Session.BeginPhase()
                    foreach ($operation in $costOperations) {
                        $packets = $Session.Request($operation).Split('|')
                        $expectedPackets = if ($operation -eq 'create_write') { 2 } else { 1 }
                        if ($packets.Length -ne $expectedPackets) { throw 'Unexpected cost sample packet count.' }
                        for ($index = 0; $index -lt $packets.Length; $index++) {
                            $label = if ($index -eq 0) { $operation } else { 'create_write_createOnly' }
                            $stats = Convert-CostSample $packets[$index]
                            $costResults[$Phase][$label] = $stats
                            Write-Output ('COST_' + $label + '_' + $Phase + '=n:' + $stats.n +
                                ';minUs:' + (Format-CostUs $stats.minUs) + ';p50Us:' + (Format-CostUs $stats.p50Us) +
                                ';p95Us:' + (Format-CostUs $stats.p95Us) + ';p99Us:' + (Format-CostUs $stats.p99Us) +
                                ';maxUs:' + (Format-CostUs $stats.maxUs))
                        }
                    }
                }
                Invoke-CostPhase $costB 'B'
                $costB.Dispose()

                # Same install/load/Verifier structure as writer-count. Do not change the baseline policy.
                Backup-StagedTestDriver $backup
                if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Durable restoration backup mismatch.'
                }
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                    throw 'Feature driver install hash mismatch.'
                }
                if ($Verifier) {
                    & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                    if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
                    $verifierEnabled = $true
                    Write-Output 'VerifierEnabled=volatile flags 0x13B'
                }
                Invoke-FeatureFilterLoad
                $filterLoaded = $true
                [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
                [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $t)
                $traceEnabled = $true
                [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
                Wait-AdmissionCanary $costFPath $rawTraceA
                [void](Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t)
                $traceEnabled = $false
                Write-Output 'COST_TraceDuringF=DISABLED'
                $costStatsBefore = Get-WriterStateStats
                Invoke-CostPhase $costF 'F'
                # OK arrives after native finally blocks. Keep the helper idle for the stats snapshot.
                $costStatsAfter = Get-WriterStateStats
                foreach ($stats in @($costStatsBefore, $costStatsAfter)) {
                    foreach ($key in @('writeObjectsCounted', 'writeObjectsReleased', 'untrackedCreates')) {
                        if ($null -eq $stats.$key) { throw ('Missing writer-state counter: ' + $key) }
                    }
                }
                $costCounted = [long]$costStatsAfter.writeObjectsCounted - [long]$costStatsBefore.writeObjectsCounted
                $costReleased = [long]$costStatsAfter.writeObjectsReleased - [long]$costStatsBefore.writeObjectsReleased
                $costUntracked = [long]$costStatsAfter.untrackedCreates - [long]$costStatsBefore.untrackedCreates
                $pathOk = $costCounted -ge 22000 -and $costCounted -eq $costReleased -and $costUntracked -eq 0
                Write-Output ('COST_PathEvidence=countedDelta:' + $costCounted + ';releasedDelta:' + $costReleased +
                    ';untrackedCreatesDelta:' + $costUntracked + ';minimumCounted:22000;balanceTolerance:0;' +
                    $(if ($pathOk) { 'PASS' } else { 'FAIL' }))
                if ($pathOk) { $passed++ } else { $failed++ }
                $costF.Dispose()
                if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceB + '-final-volumes.json') }
                foreach ($operation in $costReportedOperations) {
                    $b = $costResults.B[$operation]
                    $f = $costResults.F[$operation]
                    Write-Output ('COST_' + $operation + '_delta=p50Us:' + (Format-CostUs ($f.p50Us - $b.p50Us)) +
                        ';p95Us:' + (Format-CostUs ($f.p95Us - $b.p95Us)) +
                        ';p99Us:' + (Format-CostUs ($f.p99Us - $b.p99Us)) +
                        ';maxUs:' + (Format-CostUs ($f.maxUs - $b.maxUs)))
                    $ratio50 = if ($b.p50Us -eq 0) { 'undefined' } else { Format-CostUs ($f.p50Us / $b.p50Us) }
                    $ratio95 = if ($b.p95Us -eq 0) { 'undefined' } else { Format-CostUs ($f.p95Us / $b.p95Us) }
                    Write-Output ('COST_' + $operation + '_ratio=p50:' + $ratio50 + ';p95:' + $ratio95 + ';informationalOnly:true')
                    if ($operation -ne 'create_write_createOnly') {
                        $budgetOk = $f.p95Us -le 250000 -and $f.maxUs -le 1000000
                        Write-Output ('COST_' + $operation + '_budget=' + $(if ($budgetOk) { 'PASS' } else { 'FAIL' }))
                        if ($budgetOk) { $passed++ } else { $failed++ }
                    }
                }
            } catch {
                $failed++
                Write-Output ('COST_Execution=FAIL;' + (Get-ErrorText $_))
                throw
            } finally {
                Write-Output ('COST_Summary=passed:' + $passed + ';failed:' + $failed)
                $runSucceeded = ($failed -eq 0)
            }
        }
        elseif ($SelectedVariant -eq 'writer-fault') {
            if (-not $Verifier) { throw 'Writer fault qualification requires runtime Verifier.' }
            $writerInput=Join-Path $documents $WriterFaultFileName
            $writerExercise=Join-Path $documents $WriterFaultExerciseFileName
            $writerClient=Join-Path $documents $FaultClientFileName
            foreach ($item in @(@($writerInput,$ExpectedWriterFaultSha256),@($writerExercise,$ExpectedWriterFaultExerciseSha256),@($writerClient,$ExpectedFaultClientSha256))) {
                if ($item[1].Length -ne 64 -or (Get-FileHash $item[0] -Algorithm SHA256).Hash -ne $item[1]) { throw 'Writer qualification input hash mismatch.' }
            }
            if (@(Get-CimInstance Win32_Process -Filter "Name='SUHFail.exe'" -ErrorAction Stop).Count -ne 0) { throw 'Writer fixture process baseline is not empty.' }
            $target=Join-Path $fixtureDirectory 'hf_target.maptest';$healthy=Join-Path $fixtureDirectory 'hf_healthy.maptest'
            $writerExe=Join-Path $fixtureDirectory 'SUHFail.exe'
            foreach ($path in @($target,$healthy)) { [IO.File]::WriteAllBytes($path,(New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('H FAULT '+$id))));$fixturePaths+=$path;Assert-ReparseFreeFixturePath $path }
            Copy-Item -LiteralPath $writerInput -Destination $writerExe
            $fixturePaths+=$writerExe
            if ((Get-FileHash $writerExe -Algorithm SHA256).Hash -ne $ExpectedWriterFaultSha256) { throw 'Writer fixture installed hash mismatch.' }
            Backup-StagedTestDriver $backup
            $driverReplaced=$true;Copy-Item $featureDriver $installedDriver -Force
            if ((Get-FileHash $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256) { throw 'Feature install mismatch.' }
            & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys|Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Runtime Verifier enable failed.' };$verifierEnabled=$true
            Invoke-FeatureFilterLoad;$filterLoaded=$true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds);$traceEnabled=$true
            Wait-AdmissionCanary $target $rawTraceA
            $rawPrefix=Join-Path $documents ('SafeUpload-writer-fault-'+$id)
            $cleanupErrors=New-Object System.Collections.Generic.List[string]
            try {
                $arguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$writerExercise,
                    '-Target',$target,'-Healthy',$healthy,'-Executable',$writerExe,'-Inspector',$inspectorPath,
                    '-ClientSource',$writerClient,'-RawPrefix',$rawPrefix,'-ExpectedClientSha256',$ExpectedFaultClientSha256,
                    '-ExpectedExecutableSha256',$ExpectedWriterFaultSha256,'-ExpectedInspectorSha256',$ExpectedInspectorSha256)
                $line=(@($arguments|ForEach-Object {ConvertTo-WindowsArgument ([string]$_)})) -join ' '
                $agent=Start-StagedTestAgent $PSHOME ($rawPrefix+'-system') 'powershell.exe' $line
                [void]$agent.Process.Handle
                if (-not $agent.Process.WaitForExit(60000)) { throw 'SYSTEM writer fault exercise timed out.' }
                $exit=$agent.Process.get_ExitCode();Write-Output ('WriterFaultProcessExitCode='+$exit)
                $result=Get-Content -LiteralPath ($rawPrefix+'-result.json') -Raw|ConvertFrom-Json
                Write-Output ('WriterFaultResult='+($result|ConvertTo-Json -Depth 10 -Compress))
                Write-Output ('WriterFaultRawPrefix='+$rawPrefix)
                if ($exit -ne 0 -or $result.Passed -ne $true -or $result.Errors.Count -ne 0) { throw 'Writer allocation failure qualification failed.' }
                if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceB+'-final-volumes.json') }
                $runSucceeded=$true;Write-Output 'WriterFaultQualification=PASS'
            } finally {
                # Clear low-resource injection before stopping any remaining private fixture.
                & verifier.exe /volatile /flags 0x13B|Out-Host
                if ($LASTEXITCODE -ne 0) { [void]$cleanupErrors.Add('Parent low-resource clear failed.') }
                $query=& verifier.exe /query 2>&1|Out-String
                $queryExit=$LASTEXITCODE
                $flags=[regex]::Matches($query,'(?im)^Verifier Flags:\s+0x([0-9A-F]+)\s*$')
                if ($queryExit -ne 0 -or $flags.Count -ne 1 -or ([Convert]::ToUInt32($flags[0].Groups[1].Value,16) -band 4) -ne 0) { [void]$cleanupErrors.Add('Parent could not prove injection disabled.') }
                try { Stop-StagedTestAgent $agent;$agent=$null } catch { [void]$cleanupErrors.Add('SYSTEM helper stop: '+$_.Exception.Message) }
                try {
                    $remaining=@(Get-CimInstance Win32_Process -Filter "Name='SUHFail.exe'" -ErrorAction Stop)
                    foreach ($process in $remaining) {
                        $native=$null
                        try {
                            if ($process.ExecutablePath -ne $writerExe) { throw 'Remaining writer fixture ownership unresolved.' }
                            $native=Get-Process -Id $process.ProcessId -ErrorAction Stop
                            # Retain the native handle before validating identity or terminating.
                            [void]$native.Handle
                            if ($native.HasExited) { continue }
                            $livePath=$native.MainModule.FileName
                            $liveStart=$native.StartTime.ToUniversalTime()
                            $snapshotStart=([datetime]$process.CreationDate).ToUniversalTime()
                            if ($livePath -ne $writerExe -or [Math]::Abs(($liveStart-$snapshotStart).TotalMilliseconds) -ge 1) {
                                throw 'Remaining writer fixture live identity mismatch.'
                            }
                            if (-not $native.HasExited) { $native.Kill() }
                            if (-not $native.WaitForExit(10000)) { throw 'Native writer fixture did not terminate.' }
                        } catch {
                            # A vanished snapshot PID is harmless only when a fresh query proves absence.
                            $nativeCleanupMessage=$_.Exception.Message
                            try {
                                if (@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.ProcessId) -ErrorAction Stop).Count -ne 0) {
                                    [void]$cleanupErrors.Add('Native fixture cleanup: '+$nativeCleanupMessage)
                                }
                            } catch { [void]$cleanupErrors.Add('Native fixture absence unresolved: '+$_.Exception.Message) }
                        } finally {
                            if ($native) { try { $native.Dispose() } catch { [void]$cleanupErrors.Add('Native fixture disposal: '+$_.Exception.Message) } }
                        }
                    }
                } catch { [void]$cleanupErrors.Add('Native fixture cleanup: '+$_.Exception.Message) }
                Write-Output ('WriterFaultRestored='+($cleanupErrors.Count -eq 0))
                if ($cleanupErrors.Count -ne 0) { throw ($cleanupErrors -join '; ') }
            }
        }
        elseif ($SelectedVariant -eq 'section-lower') {
            $t = $InspectorTimeoutSeconds
            $faultInput=Join-Path $documents $FaultDriverFileName
            $faultClientSource=Join-Path $documents $FaultClientFileName
            $faultExercise=Join-Path $documents $FaultExerciseFileName
            foreach ($lowerInput in @(@($faultInput,$ExpectedFaultSha256),@($faultClientSource,$ExpectedFaultClientSha256),
                @($faultExercise,$ExpectedFaultExerciseSha256))) {
                if ($lowerInput[1].Length -ne 64 -or (Get-FileHash -LiteralPath $lowerInput[0] -Algorithm SHA256).Hash -ne $lowerInput[1]) {
                    throw 'Lower qualification input hash mismatch.'
                }
            }
            $faultInstalled='C:\Windows\System32\drivers\SafeUploadSectionFault.sys'
            $faultKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadSectionFault'
            $faultInventory=& fltmc.exe filters 2>&1|Out-String
            if ($LASTEXITCODE -ne 0) { throw 'Companion baseline filter enumeration failed.' }
            if ((Test-Path $faultInstalled) -or (Test-Path $faultKey) -or
                @(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUploadSectionFault'" -ErrorAction Stop).Count -ne 0 -or
                ($faultInventory -match '(?m)^SafeUploadSectionFault\s')) { throw 'Companion baseline is not empty.' }
            $sig=Get-AuthenticodeSignature -LiteralPath $faultInput
            if ($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7') {
                throw 'Companion signature mismatch.'
            }
            $target=Join-Path $fixtureDirectory 'sf_lower.maptest'
            [IO.File]::WriteAllBytes($target,(New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('SECTION LOWER '+$id))))
            $fixturePaths += $target
            Assert-ReparseFreeFixturePath $target
            Backup-StagedTestDriver $backup
            if ((Get-FileHash $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) { throw 'Original backup mismatch.' }
            $driverReplaced=$true
            Copy-Item $featureDriver $installedDriver -Force
            if ((Get-FileHash $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256) { throw 'Upper install mismatch.' }
            if ($Verifier) {
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Upper Verifier enable failed.' }
                $verifierEnabled=$true
            }
            Invoke-FeatureFilterLoad
            $filterLoaded=$true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-sections') -Timeout $t)
            $traceEnabled=$true
            Wait-AdmissionCanary $target $rawTraceA
            $faultFileOwned=$false; $faultServiceOwned=$false; $faultLoaded=$false; $faultVerified=$false
            $faultCleanupErrors=New-Object System.Collections.Generic.List[string]
            try {
                $faultFileOwned=$true
                Copy-Item -LiteralPath $faultInput -Destination $faultInstalled
                if ((Get-FileHash $faultInstalled -Algorithm SHA256).Hash -ne $ExpectedFaultSha256) { throw 'Companion installed hash mismatch.' }
                & sc.exe create SafeUploadSectionFault type= filesys start= demand binPath= $faultInstalled group= 'FSFilter Anti-Virus' depend= FltMgr|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Companion service creation failed.' }
                $faultServiceOwned=$true
                $instances=Join-Path $faultKey 'Instances'; $instance=Join-Path $instances 'SectionFault Test'
                New-Item $instance -Force|Out-Null
                New-ItemProperty $instances DefaultInstance -PropertyType String -Value 'SectionFault Test' -Force|Out-Null
                New-ItemProperty $instance Altitude -PropertyType String -Value '321409' -Force|Out-Null
                New-ItemProperty $instance Flags -PropertyType DWord -Value 1 -Force|Out-Null
                if ($Verifier) {
                    & verifier.exe /volatile /flags 0x13B /adddriver SafeUploadSectionFault.sys|Out-Host
                    if ($LASTEXITCODE -ne 0) { throw 'Companion Verifier enable failed.' }
                    $faultVerified=$true
                }
                & fltmc.exe load SafeUploadSectionFault|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Companion load failed.' }
                $faultLoaded=$true
                & fltmc.exe attach SafeUploadSectionFault C:|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Companion manual attachment failed.' }
                Write-Output ('SectionFaultSHA256='+$ExpectedFaultSha256)
                Add-Type -Path $faultClientSource
                if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') { throw 'NonSYSTEM control-denial qualification needs the ordinary harness identity.' }
                $denied=$false; $denialCode=''
                try { $unexpected=[SafeUploadSectionFaultClient]::new(); $unexpected.Dispose() }
                catch {
                    $exception=$_.Exception
                    while ($exception.InnerException) { $exception=$exception.InnerException }
                    $denialCode='0x'+([BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exception.HResult),0)).ToString('X8')
                    $denied=$denialCode -eq '0x80070005'
                }
                Write-Output ('SectionFaultNonSystemDenied='+$denied+';HRESULT='+$denialCode)
                if (-not $denied) { throw 'Companion port did not reject the ordinary identity with access denied.' }
                $resultPath=Join-Path $documents ('SafeUpload-section-lower-'+$id+'-result.json')
                $tracePrefix=Join-Path $documents ('SafeUpload-section-lower-'+$id)
                $exerciseArguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$faultExercise,
                    '-Fixture',$target,'-Inspector',$inspectorPath,'-ClientSource',$faultClientSource,'-ResultPath',$resultPath,
                    '-TracePrefix',$tracePrefix,'-ExpectedInspectorSha256',$ExpectedInspectorSha256,
                    '-ExpectedClientSha256',$ExpectedFaultClientSha256)
                if ($FaultCapacity) { $exerciseArguments += '-Capacity' }
                $argumentLine=(@($exerciseArguments|ForEach-Object { ConvertTo-WindowsArgument ([string]$_) })) -join ' '
                $agent=Start-StagedTestAgent $PSHOME (Join-Path $documents ('SafeUpload-section-lower-'+$id+'-system')) 'powershell.exe' $argumentLine
                # Retain the native process handle before exit; use the CLR getter to avoid
                # Get-Process adapter snapshots of ExitCode. A missing exit code must fail.
                [void]$agent.Process.Handle
                if (-not $agent.Process.WaitForExit(60000)) { throw 'SYSTEM lower exercise timed out.' }
                $lowerExitCode=$agent.Process.get_ExitCode()
                Write-Output ('SectionLowerProcessExitCode='+$lowerExitCode)
                if (-not (Test-Path $resultPath)) { throw 'SYSTEM lower exercise did not write its result.' }
                $lower=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
                Write-Output ('SectionLowerResult='+($lower|ConvertTo-Json -Depth 10 -Compress))
                Write-Output ('SectionLowerResultFile='+$resultPath)
                Write-Output ('SectionLowerTracePrefix='+$tracePrefix)
                if ($lowerExitCode -ne 0 -or $lower.Passed -ne $true -or $lower.Errors.Count -ne 0 -or
                    $lower.Disarmed.Mode -ne 0 -or $lower.Disarmed.ArmedFileObject -ne 0 -or $lower.Disarmed.CurrentHeld -ne 0) {
                    throw 'Live lower-stack section qualification failed.'
                }
                if ($FaultCapacity -and ($lower.Capacity.StickyUnknown -ne $true -or $lower.Capacity.Workers -ne 66)) { throw 'Capacity qualification result missing.' }
                if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceB+'-final-volumes.json') }
                $runSucceeded=$true
                Write-Output 'SectionLowerQualification=PASS'
            } finally {
                try { Stop-StagedTestAgent $agent; $agent=$null }
                finally {
                    if ($faultLoaded) {
                        & fltmc.exe unload SafeUploadSectionFault|Out-Host
                        if ($LASTEXITCODE -ne 0) { [void]$faultCleanupErrors.Add('Companion unload failed.') }
                    }
                    if ($faultVerified) {
                        & verifier.exe /volatile /removedriver SafeUploadSectionFault.sys|Out-Host
                        if ($LASTEXITCODE -ne 0) { [void]$faultCleanupErrors.Add('Companion Verifier removal failed.') }
                    }
                    if ($faultServiceOwned) {
                        & sc.exe delete SafeUploadSectionFault|Out-Host
                        if ($LASTEXITCODE -ne 0) { [void]$faultCleanupErrors.Add('Companion service delete failed.') }
                    }
                    $faultInventory=& fltmc.exe filters 2>&1|Out-String
                    $faultInventoryExit=$LASTEXITCODE
                    if ($faultInventoryExit -ne 0) { [void]$faultCleanupErrors.Add('Companion filter enumeration failed; binary retained.') }
                    if ($faultFileOwned -and $faultInventoryExit -eq 0 -and $faultInventory -notmatch '(?m)^SafeUploadSectionFault\s') {
                        try { Remove-Item -LiteralPath $faultInstalled -Force }
                        catch { [void]$faultCleanupErrors.Add('Companion file delete: '+$_.Exception.Message) }
                    }
                    $faultServices=@(); $faultServicesRead=$false
                    try {
                        $deleteDeadline=[DateTime]::UtcNow.AddSeconds(5)
                        do {
                            $faultServices=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUploadSectionFault'" -ErrorAction Stop)
                            if ($faultServices.Count -ne 0 -or (Test-Path $faultKey)) { Start-Sleep -Milliseconds 100 }
                        } while (($faultServices.Count -ne 0 -or (Test-Path $faultKey)) -and [DateTime]::UtcNow -lt $deleteDeadline)
                        $faultServicesRead=$true
                    } catch { [void]$faultCleanupErrors.Add('Companion service enumeration: '+$_.Exception.Message) }
                    $clean=$faultInventoryExit -eq 0 -and $faultServicesRead -and
                        -not (Test-Path $faultInstalled) -and -not (Test-Path $faultKey) -and $faultServices.Count -eq 0 -and
                        $faultInventory -notmatch '(?m)^SafeUploadSectionFault\s'
                    Write-Output ('SectionFaultRestored='+$clean)
                    if (-not $clean -or $faultCleanupErrors.Count -ne 0) { throw ('Companion restoration failed: '+($faultCleanupErrors -join '; ')) }
                }
            }
        }
        elseif ($SelectedVariant -eq 'section-inflight') {
            # X3: C(F), writable CreateSections in flight. The window is microseconds, so this checks conservation:
            # every entry inserted is removed again (release, or post-operation on a failed acquire), nothing
            # overflows or sticks, and read-only sections are never tracked.
            $t = $InspectorTimeoutSeconds
            Initialize-SectionStress
            $stormFiles = @()
            for ($i = 0; $i -lt 16; $i++) {
                $p = Join-Path $fixtureDirectory ('sf_{0:D2}.maptest' -f $i)
                [IO.File]::WriteAllBytes($p, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('SF ' + $i + ' ' + $id))))
                $fixturePaths += $p
                $stormFiles += $p
            }
            $emptyFile = Join-Path $fixtureDirectory 'sf_empty.maptest'
            [IO.File]::WriteAllBytes($emptyFile, [byte[]]@())
            $fixturePaths += $emptyFile
            foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            if ($Verifier) {
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
                $verifierEnabled = $true
                Write-Output 'VerifierEnabled=volatile flags 0x13B'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $t)
            $traceEnabled = $true

            $s0 = Get-WriterStateStats
            Wait-AdmissionCanary $stormFiles[0] $rawTraceA
            Write-Output ('X3_Stats0=inserted:' + $s0.sectionInFlightInserted + ';released:' + $s0.sectionInFlightReleased +
                ';removedOnFailure:' + $s0.sectionInFlightRemovedOnFailure + ';now:' + $s0.sectionInFlightNow +
                ';overflow:' + $s0.sectionInFlightOverflow + ';stuck:' + $s0.sectionInFlightStuck)

            $single = [SafeUploadSectionStress]::Run($stormFiles, 1, 500, $false)
            $s1 = Get-WriterStateStats
            Write-Output ('X3_Single=failures:' + $single + ';insertedDelta:' + ([int64]$s1.sectionInFlightInserted - [int64]$s0.sectionInFlightInserted) +
                ';releasedDelta:' + ([int64]$s1.sectionInFlightReleased - [int64]$s0.sectionInFlightReleased) +
                ';now:' + $s1.sectionInFlightNow)

            $storm = [SafeUploadSectionStress]::Run($stormFiles, 8, 300, $true)
            $s2 = Get-WriterStateStats
            Write-Output ('X3_Storm=failures:' + $storm + ';writableSections:2400;readOnlySections:2400' +
                ';insertedDelta:' + ([int64]$s2.sectionInFlightInserted - [int64]$s1.sectionInFlightInserted) +
                ';releasedDelta:' + ([int64]$s2.sectionInFlightReleased - [int64]$s1.sectionInFlightReleased) +
                ';removedOnFailureDelta:' + ([int64]$s2.sectionInFlightRemovedOnFailure - [int64]$s1.sectionInFlightRemovedOnFailure) +
                ';maxDepth:' + $s2.sectionInFlightMaxDepth + ';overflowDelta:' + ([int64]$s2.sectionInFlightOverflow - [int64]$s1.sectionInFlightOverflow))

            # Failure injection: a writable mapping of an empty file with no size fails inside Mm.
            $failed = 0
            for ($i = 0; $i -lt 20; $i++) {
                if ([SafeUploadSectionStress]::TryEmptyFileMapping($emptyFile) -eq 1006) { $failed++ }
            }
            $s3 = Get-WriterStateStats
            Write-Output ('X3_InjectedFailures=attempts:20;failedAsExpected:' + $failed +
                ';insertedDelta:' + ([int64]$s3.sectionInFlightInserted - [int64]$s2.sectionInFlightInserted) +
                ';releasedDelta:' + ([int64]$s3.sectionInFlightReleased - [int64]$s2.sectionInFlightReleased) +
                ';removedOnFailureDelta:' + ([int64]$s3.sectionInFlightRemovedOnFailure - [int64]$s2.sectionInFlightRemovedOnFailure))
            # A failed CreateFileMapping can still have a successful acquire followed by release.
            # Count the callback path separately so this does not qualify failed-acquire cleanup.
            Write-Output ('X3_FailedAcquireCoverage=' + $(if ([int64]$s3.sectionInFlightRemovedOnFailure -gt [int64]$s2.sectionInFlightRemovedOnFailure) { 'EXERCISED' } else { 'NOT_EXERCISED' }))

            $shared = [SafeUploadSectionStress]::RunSharedFileObject($stormFiles[0], 8, 300)
            $sharedStats = Get-WriterStateStats
            $sharedTracked = [int64]$sharedStats.sectionInFlightInserted - [int64]$s3.sectionInFlightInserted
            Write-Output ('X3_SharedFileObject=failures:' + $shared + ';writableSections:2400;readOnlySections:2400;insertedDelta:' + $sharedTracked +
                ';releasedDelta:' + ([int64]$sharedStats.sectionInFlightReleased - [int64]$s3.sectionInFlightReleased))

            Start-Sleep -Seconds 3
            $s4 = Get-WriterStateStats
            Write-Output ('X3_AtRest=inserted:' + $s4.sectionInFlightInserted + ';released:' + $s4.sectionInFlightReleased +
                ';removedOnFailure:' + $s4.sectionInFlightRemovedOnFailure + ';now:' + $s4.sectionInFlightNow +
                ';overflow:' + $s4.sectionInFlightOverflow + ';stuck:' + $s4.sectionInFlightStuck + ';maxDepth:' + $s4.sectionInFlightMaxDepth)
            [void](Invoke-AdmissionProbe $stormFiles[0] 'X3_Probe' $t)
            $traceX = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceA
            $probeX = @($traceX.Entries | Where-Object { $_.Ev -eq 'explicit_probe' })
            $probeText = if ($probeX.Count -eq 1) { [string]$probeX[0].InFlightSections } else { 'AMBIGUOUS' }
            Write-Output ('X3_Probe=' + $probeText + ';mmDoes:' + $(if ($probeX.Count -eq 1) { $probeX[0].MmDoes } else { 'n/a' }))
            $probeOk = ($probeX.Count -eq 1 -and $probeX[0].ProbeValid -and
                $probeX[0].InFlightSections -eq 0 -and $probeX[0].MmDoes -eq 'no' -and
                (-not $RequireCanary -or $probeX[0].CanaryOk))

            $conserved = ([int64]$s4.sectionInFlightInserted - [int64]$s4.sectionInFlightReleased - [int64]$s4.sectionInFlightRemovedOnFailure - [int64]$s4.sectionInFlightNow)
            $tracked = ([int64]$s2.sectionInFlightInserted - [int64]$s1.sectionInFlightInserted)
            Write-Output ('X3_Verdict=conservationResidual:' + $conserved + ';stormTrackedSections:' + $tracked +
                ';overflow:' + $s4.sectionInFlightOverflow + ';stuck:' + $s4.sectionInFlightStuck + ';now:' + $s4.sectionInFlightNow)
            if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceA + '-final-volumes.json') }
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t)
            $traceEnabled = $false
            # The storm creates 2400 writable sections; other processes may add a few. Read-only sections must not be tracked.
            $ok = ($conserved -eq 0) -and ([int64]$s4.sectionInFlightOverflow -eq 0) -and ([int64]$s4.sectionInFlightStuck -eq 0) -and
                ([int64]$s4.sectionInFlightNow -eq 0) -and ($tracked -ge 2400) -and ($tracked -lt 3000) -and ($storm -eq 0) -and
                ($single -eq 0) -and ($failed -eq 20) -and ($shared -eq 0) -and ($sharedTracked -ge 2400) -and ($sharedTracked -lt 3000) -and $probeOk
            Write-Output ('X3_Result=' + $(if ($ok) { 'PASS' } else { 'FAIL' }))
            $runSucceeded = $ok
        }
        else {
            $target = Join-Path $fixtureDirectory ('synthetic-' + $id + '.maptest')
            $fixturePaths = @($target)
            $originalText = 'PUBLIC BASELINE ' + $SelectedVariant + ' ' + $id
            $originals['Fixture'] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($originalText))
            [IO.File]::WriteAllBytes($target, $originals['Fixture'])

            if ($SelectedVariant -eq 'preattach-immediate' -or
                $SelectedVariant -eq 'preattach-protected-open') {
                $mappingRecords['Fixture'] = New-MappedFixture $target ('Local\SafeUpload-Admission-' + $id) $false $false $fileHandles $mappings $views
                $observers['Fixture'] = New-ObserverPair $target $fileHandles $uncachedReaders
                Assert-ReparseFreeFixturePath $target

                Backup-StagedTestDriver $backup
                if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Durable restoration backup mismatch.'
                }
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                    throw 'Feature driver install hash mismatch.'
                }
                Invoke-FeatureFilterLoad
                $filterLoaded = $true

                $clear = Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds
                $enable = Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds
                $traceEnabled = $true
                Write-Output 'AdmissionTrace=ClearedAndEnabled'

                if ($SelectedVariant -eq 'preattach-protected-open') {
                    $expandedPolicy = New-ExpandedPolicyForFixture $fixtureDirectory $policyBackup
                    $policyBytes = $expandedPolicy.OriginalBytes
                    [IO.File]::WriteAllBytes($policyPath, $expandedPolicy.UpdatedBytes)
                    Write-Output ('ExpandedPolicySHA256=' + (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash)
                    Write-Output 'ExpandedPolicyIncludesFixture=True'

                    $baseLog = Join-Path $documents ('admission-agent-protected-' + $id)
                    [void]$agentLogs.Add($baseLog + '-out.log')
                    [void]$agentLogs.Add($baseLog + '-err.log')
                    $agent = Start-TestAgentAndWaitForPolicy $baseLog
                    Write-Output 'ExpandedPolicyAcceptedByRealAgentAndDriver=True'

                    $protected = $null
                    try {
                        $protected = [IO.FileStream]::new(
                            $target, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                        $protected.Dispose()
                        $protected = $null
                        Write-Output 'ProtectedOpen_Result=SUCCESS'
                    }
                    catch {
                        if ($null -ne $protected) {
                            $protected.Dispose()
                        }
                        Write-Output 'ProtectedOpen_Result=EXCEPTION'
                        Write-Output 'ProtectedOpen_Class=OBSERVED_REFUSED'
                        Write-Output ('ProtectedOpen_Exception=' + (Get-ErrorText $_))
                    }
                    finally {
                        if ($null -ne $agent) {
                            Stop-StagedTestAgent $agent
                            $agent = $null
                        }
                    }
                }

                if ($SelectedVariant -eq 'preattach-immediate') {
                    $markers['Fixture'] = 'MAPPED IMMEDIATE ' + $id
                }
                else {
                    $markers['Fixture'] = 'MAPPED AFTER PROTECTED OPEN ' + $id
                }
                $mappedExpected['Fixture'] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers['Fixture']))
                $write = Invoke-MappedWrite $mappingRecords['Fixture'].View $markers['Fixture']
                Write-Output ('MappedWrite_Result=' + $write.Result)
                if (-not [string]::IsNullOrEmpty($write.Error)) {
                    Write-Output ('MappedWrite_Error=' + $write.Error)
                }
                $r1 = Get-ObserverReadResult $observers['Fixture'] 'R1' $originals['Fixture'] $mappedExpected['Fixture']
                $r2 = Get-ObserverReadResult $observers['Fixture'] 'R2' $originals['Fixture'] $mappedExpected['Fixture']
                $r3 = Read-FreshBufferedObservation $target $originals['Fixture'] $mappedExpected['Fixture']
                Write-ReaderFacts 'R1' $r1
                Write-ReaderFacts 'R2' $r2
                Write-ReaderFacts 'R3' $r3
                [void](Invoke-AdmissionProbe $target 'Fixture' $InspectorTimeoutSeconds)
            }
            else {
                # V4 creates its file and pre-load readers before attachment.
                $observers['Fixture'] = New-ObserverPair $target $fileHandles $uncachedReaders
                Assert-ReparseFreeFixturePath $target

                Backup-StagedTestDriver $backup
                if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Durable restoration backup mismatch.'
                }
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                    throw 'Feature driver install hash mismatch.'
                }
                Invoke-FeatureFilterLoad
                $filterLoaded = $true

                $mappingRecords['Fixture'] = New-MappedFixture $target ('Local\SafeUpload-Admission-' + $id) $false $false $fileHandles $mappings $views
                Write-Output 'FilterAttachedBeforeMapping=True;NoAgentOrPolicyPushedAtMapping=True'

                $clear = Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds
                $enable = Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds
                $traceEnabled = $true
                Write-Output 'AdmissionTrace=ClearedAndEnabled'

                $baseLog = Join-Path $documents ('admission-agent-baseline-' + $id)
                [void]$agentLogs.Add($baseLog + '-out.log')
                [void]$agentLogs.Add($baseLog + '-err.log')
                $agent = Start-TestAgentAndWaitForPolicy $baseLog
                Write-Output 'BaselinePolicyAcceptedByRealAgentAndDriver=True'
                Stop-StagedTestAgent $agent
                $agent = $null

                $expandedPolicy = New-ExpandedPolicyForFixture $fixtureDirectory $policyBackup
                $policyBytes = $expandedPolicy.OriginalBytes
                [IO.File]::WriteAllBytes($policyPath, $expandedPolicy.UpdatedBytes)
                Write-Output ('ExpandedPolicySHA256=' + (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash)
                Write-Output 'ExpandedPolicyIncludesFixture=True'

                $expandedLog = Join-Path $documents ('admission-agent-expanded-' + $id)
                [void]$agentLogs.Add($expandedLog + '-out.log')
                [void]$agentLogs.Add($expandedLog + '-err.log')
                $agent = Start-TestAgentAndWaitForPolicy $expandedLog
                Write-Output 'ExpandedPolicyAcceptedByRealAgentAndDriver=True'

                $markers['Fixture'] = 'MAPPED AFTER POLICY CHANGE ' + $id
                $mappedExpected['Fixture'] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers['Fixture']))
                $write = Invoke-MappedWrite $mappingRecords['Fixture'].View $markers['Fixture']
                Write-Output ('MappedWrite_Result=' + $write.Result)
                if (-not [string]::IsNullOrEmpty($write.Error)) {
                    Write-Output ('MappedWrite_Error=' + $write.Error)
                }

                Stop-StagedTestAgent $agent
                $agent = $null

                $r1 = Get-ObserverReadResult $observers['Fixture'] 'R1' $originals['Fixture'] $mappedExpected['Fixture']
                $r2 = Get-ObserverReadResult $observers['Fixture'] 'R2' $originals['Fixture'] $mappedExpected['Fixture']
                $r3 = Read-FreshBufferedObservation $target $originals['Fixture'] $mappedExpected['Fixture']
                Write-ReaderFacts 'R1' $r1
                Write-ReaderFacts 'R2' $r2
                Write-ReaderFacts 'R3' $r3
                [void](Invoke-AdmissionProbe $target 'Fixture' $InspectorTimeoutSeconds)
            }

            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $InspectorTimeoutSeconds
            $traceEnabled = $false
            $traceResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
            $trace = Get-TraceDump $traceResult $rawTrace
            Write-TraceFacts $trace
            $fence = Invoke-InspectorChecked -Arguments @('--admission-fence-status') -Timeout $InspectorTimeoutSeconds
            Write-Output ('FenceStatus=' + ([regex]::Replace([string]$fence.Stdout, '[\r\n]+', ' ')).Trim())
            $probes = @(Get-TraceProbeEntries $trace)
            Write-ProbeFacts $probes @('Fixture')
            $runSucceeded = $true
        }
    }
    catch {
        $runSucceeded = $false
        Write-Output ('RunError=' + (Get-ErrorText $_))
        if ($filterLoaded) {
            foreach ($command in @('--writer-state-status','--admission-fence-status','--admission-volume-status')) {
                try {
                    $diagnostic = Invoke-InspectorChecked -Arguments @($command) -Timeout $InspectorTimeoutSeconds
                    Write-Output ('RunErrorDiagnostic_' + $command + '=' + ([string]$diagnostic.Stdout).Trim())
                } catch { Write-Output ('RunErrorDiagnosticFailed_' + $command + '=' + (Get-ErrorText $_)) }
            }
        }
    }
    finally {
        foreach ($writerIoSession in $writerIoSessions) {
            try { $writerIoSession.Dispose() }
            catch { [void]$restorationErrors.Add('Writer I/O worker stop: ' + (Get-ErrorText $_)) }
        }
        if ($null -ne $agent) {
            try {
                Stop-StagedTestAgent $agent
                $agent = $null
            }
            catch {
                [void]$restorationErrors.Add('Agent stop: ' + (Get-ErrorText $_))
            }
        }

        Dispose-ObserverResources $views $mappings $fileHandles $uncachedReaders $restorationErrors

        if ($traceEnabled -and -not $script:InspectorTimedOut -and
            -not $script:InspectorFailed -and
            (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -eq 0)) {
            try {
                $disableResult = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $InspectorTimeoutSeconds
                $traceEnabled = $false
            }
            catch {
                [void]$restorationErrors.Add('Admission trace disable: ' + (Get-ErrorText $_))
            }
        }

        if ($null -ne $policyBytes) {
            try {
                $restoreBytes = $policyBytes
                if (Test-Path -LiteralPath $policyBackup) {
                    $restoreBytes = [IO.File]::ReadAllBytes($policyBackup)
                }
                [IO.File]::WriteAllBytes($policyPath, $restoreBytes)
            }
            catch {
                [void]$restorationErrors.Add('Policy restore: ' + (Get-ErrorText $_))
            }
        }

        if ($driverReplaced) {
            try {
                Restore-StagedTestDriver $backup $filterLoaded $verifierEnabled
                $filterLoaded = $false
            }
            catch {
                [void]$restorationErrors.Add('Driver restore: ' + (Get-ErrorText $_))
                foreach ($command in @('--writer-state-status','--admission-fence-status')) {
                    try {
                        $diagnostic = Invoke-InspectorChecked -Arguments @($command) -Timeout 15
                        Write-Output ('UnloadRefusalDiagnostic_' + $command + '=' + ([string]$diagnostic.Stdout).Trim())
                    } catch { Write-Output ('UnloadRefusalDiagnosticFailed_' + $command + '=' + (Get-ErrorText $_)) }
                }
            }
        }

        $driverRestored = $false
        $policyRestored = $false
        $filterUnloaded = $false
        $verifierOff = $false
        $serviceRestored = $false
        $agentProcessesZero = $false
        $inspectorProcessesZero = $false
        $tasksZero = $false
        try {
            $driverRestored = (Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -eq $expectedOriginalDriver
        }
        catch {
            [void]$restorationErrors.Add('Original driver verification: ' + (Get-ErrorText $_))
        }
        try {
            $policyRestored = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash -eq $expectedOriginalPolicy
        }
        catch {
            [void]$restorationErrors.Add('Original policy verification: ' + (Get-ErrorText $_))
        }
        try {
            $filterUnloaded = -not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s')
        }
        catch {
            [void]$restorationErrors.Add('Filter verification: ' + (Get-ErrorText $_))
        }
        try {
            $query = & verifier.exe /query 2>&1 | Out-String
            $settings = & verifier.exe /querysettings 2>&1 | Out-String
            $memory = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            $verifierOff = ($query -match 'No drivers are currently verified' -and
                $settings -match 'Verifier Flags:\s+0x00000000' -and
                -not $memory.VerifyDriverLevel -and -not $memory.VerifyDrivers)
        }
        catch {
            [void]$restorationErrors.Add('Verifier verification: ' + (Get-ErrorText $_))
        }
        try {
            $service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
            $serviceRestored = ($service.StartMode -eq 'Manual' -and $service.State -eq 'Stopped')
        }
        catch {
            [void]$restorationErrors.Add('Service verification: ' + (Get-ErrorText $_))
        }

        $agentProcessCount = @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count
        $inspectorProcessCount = @(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count
        $taskCount = @(Get-ScheduledTask | Where-Object {
            $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)'
        }).Count
        $agentProcessesZero = $agentProcessCount -eq 0
        $inspectorProcessesZero = $inspectorProcessCount -eq 0
        $tasksZero = $taskCount -eq 0

        $coreRestored = ($driverRestored -and $policyRestored -and $filterUnloaded -and
            $verifierOff -and $serviceRestored -and $agentProcessesZero -and
            $inspectorProcessesZero -and $tasksZero)

        if ($coreRestored) {
            if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) {
                try {
                    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
                }
                catch {
                    [void]$restorationErrors.Add('Fixture cleanup: ' + (Get-ErrorText $_))
                }
            }
            if (Test-Path -LiteralPath $backup) {
                try {
                    Remove-Item -LiteralPath $backup -Force
                }
                catch {
                    [void]$restorationErrors.Add('Driver backup cleanup: ' + (Get-ErrorText $_))
                }
            }
            if (Test-Path -LiteralPath $policyBackup) {
                try {
                    Remove-Item -LiteralPath $policyBackup -Force
                }
                catch {
                    [void]$restorationErrors.Add('Policy backup cleanup: ' + (Get-ErrorText $_))
                }
            }
            foreach ($logPath in $agentLogs) {
                if (Test-Path -LiteralPath $logPath) {
                    try {
                        Remove-Item -LiteralPath $logPath -Force
                    }
                    catch {
                        [void]$restorationErrors.Add('Agent log cleanup: ' + (Get-ErrorText $_))
                    }
                }
            }
            if ($inspectorCopyCreated -and (Test-Path -LiteralPath $inspectorPath) -and
                @(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count -eq 0) {
                try {
                    Remove-Item -LiteralPath $inspectorPath -Force
                }
                catch {
                    [void]$restorationErrors.Add('Inspector copy cleanup: ' + (Get-ErrorText $_))
                }
            }
        }

        $fixtureRemoved = -not (Test-Path -LiteralPath $fixtureDirectory)
        $backupRemoved = (-not (Test-Path -LiteralPath $backup)) -and
            (-not (Test-Path -LiteralPath $policyBackup))
        $agentLogsRemoved = $true
        foreach ($logPath in $agentLogs) {
            if (Test-Path -LiteralPath $logPath) {
                $agentLogsRemoved = $false
            }
        }
        $inspectorCopyRemoved = (-not $inspectorCopyCreated) -or
            (-not (Test-Path -LiteralPath $inspectorPath))
        $restorationVerified = ($coreRestored -and $fixtureRemoved -and $backupRemoved -and
            $agentLogsRemoved -and $inspectorCopyRemoved -and $restorationErrors.Count -eq 0)

        Write-Output ('Restoration_OriginalDriver=' + $driverRestored)
        Write-Output ('Restoration_OriginalPolicy=' + $policyRestored)
        Write-Output ('Restoration_FilterUnloaded=' + $filterUnloaded)
        Write-Output ('Restoration_VerifierOff=' + $verifierOff)
        Write-Output ('Restoration_ServiceManualStopped=' + $serviceRestored)
        Write-Output ('Restoration_AgentProcesses=' + $agentProcessCount)
        Write-Output ('Restoration_InspectorProcesses=' + $inspectorProcessCount)
        Write-Output ('Restoration_Tasks=' + $taskCount)
        Write-Output ('Restoration_FixtureRemoved=' + $fixtureRemoved)
        Write-Output ('Restoration_BackupsRemoved=' + $backupRemoved)
        Write-Output ('Restoration_AgentLogsRemoved=' + $agentLogsRemoved)
        Write-Output ('Restoration_InspectorCopyRemoved=' + $inspectorCopyRemoved)
        if ($script:InspectorTimedOut) {
            Write-Output ('InspectorTimeout=' + $script:InspectorTimeoutCommand)
        }
        foreach ($errorText in $restorationErrors) {
            Write-Output ('RestorationError=' + $errorText)
        }
        Write-Output ('RestorationSucceeded=' + $restorationVerified)
        if ($restorationVerified -and $runSucceeded) {
            Write-Output ('VariantComplete=' + $SelectedVariant)
        }

        $script:LastRestorationVerified = $restorationVerified
        $script:LastRunSucceeded = $runSucceeded
    }
}

$variantsToRun = @()
if ($Variant -eq 'All') {
    $variantsToRun = @('preattach-immediate', 'preattach-protected-open', 'mmdoes-matrix', 'policy-transition')
}
else {
    $variantsToRun = @($Variant)
}

$overallSucceeded = $true
try {
    foreach ($selected in $variantsToRun) {
        Invoke-Variant $selected
        if (-not $script:LastRestorationVerified) {
            $overallSucceeded = $false
            break
        }
        if (-not $script:LastRunSucceeded) {
            $overallSucceeded = $false
            if ($script:InspectorTimedOut) {
                break
            }
        }
    }
}
catch {
    Write-Output ('HarnessError=' + (Get-ErrorText $_))
    $overallSucceeded = $false
}

if ($overallSucceeded) {
    exit 0
}
exit 1
