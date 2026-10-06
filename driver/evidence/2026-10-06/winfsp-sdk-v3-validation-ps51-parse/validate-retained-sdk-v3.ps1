[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{8}:[0-9A-Fa-f]{16}$')]
    [string]$ExpectedRetainedLogIdentity
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Read-only completion check for the already executed v3 administrative image.
# This script never invokes Windows Installer, writes the target/log, deletes
# anything, stops a process/service, changes service configuration, or executes
# an extracted file. If any MSI/build actor remains, it emits a failed readout
# and exits without traversing the output tree.
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$msiPath = 'C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006\winfsp-2.2.26215.msi'
$targetPath = 'C:\Users\vika\Documents\SafeUploadWinFspSdk-20261006-ef9bea72fc3545d985354fa5a939179b'
$logPath = $targetPath + '.msi.log'
$expectedMsiBytes = [Int64]2207744
$expectedMsiSha256 = '2ECB5C89405488A95BBD8A01875E02C48534FD37BBDFD84488F7590464D65944'
$expectedMsiIdentity = 'D6632F7F:00030000000DEDF1'
$expectedSignerThumbprint = '75C6C88B0B6C4556F13FCE3B081FC9051EAE457E'
$expectedSignerSubject = 'CN=NAVIMATICS LLC, O=NAVIMATICS LLC, L=KIRKLAND, S=Washington, C=US, SERIALNUMBER=604 419 559, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US'
$expectedTargetIdentity = 'D6632F7F:00060000000DEE49'
$expectedLogBytes = [Int64]338400
$expectedLogSha256 = '46E05B92C953B1D9062E608607CB130DC68EACB327663A8842D4BCA3DDF22159'
$historicalExtractionSourceSha256 = '0e0b17a56c528834c91745fbf0e54661561ae7e62c0acde113982f16e5df41cf'
$historicalExtractionStdoutSha256 = '661c152bf5dfe8d605da06fbd2ae22b599d5e685b88a680cf5de18f1a2397c75'
$historicalExtractionExitSha256 = '7f1ba10d97031722ae486d06bc4299438addcb5b6f3a9779cfd6d6d942ab048b'
$historicalActorDiagnosticStdoutSha256 = '6dddc59ed5787569fded34930fdb6c398f156659f6827b015174951d15ba8451'
$historicalUnresolvedActor = 'msiexec|2272'
$historicalAdminExecuteSequence = @(
    'CostInitialize||800',
    'FileCost||900',
    'CostFinalize||1000',
    'InstallValidate||1400',
    'InstallInitialize||1500',
    'InstallAdminPackage||3900',
    'InstallFiles||4000',
    'InstallFinalize||6600'
)

$expectedDirectoryPins = @(
    [pscustomobject]@{ Path = 'C:\'; Identity = 'D6632F7F:0005000000000005' },
    [pscustomobject]@{ Path = 'C:\Users'; Identity = 'D6632F7F:00010000000005FD' },
    [pscustomobject]@{ Path = 'C:\Users\vika'; Identity = 'D6632F7F:0002000000019D5D' },
    [pscustomobject]@{ Path = 'C:\Users\vika\Documents'; Identity = 'D6632F7F:0001000000019D67' },
    [pscustomobject]@{ Path = 'C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006'; Identity = 'D6632F7F:00030000000DEDF0' }
)
$expectedWindowsInstallerStartMode = 'Manual'
$expectedWindowsInstallerPath = 'C:\Windows\system32\msiexec.exe /V'
$actorNames = @('msiexec', 'MSBuild', 'dotnet', 'csc', 'VBCSCompiler')

$nativeSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class SafeUploadSdkValidationFileInfo
{
    public UInt32 Attributes;
    public UInt32 VolumeSerial;
    public UInt64 FileId;
    public UInt64 Length;
}

public static class SafeUploadSdkValidationNative
{
    private const UInt32 GenericRead = 0x80000000;
    private const UInt32 FileReadAttributes = 0x00000080;
    private const UInt32 ShareRead = 0x00000001;
    private const UInt32 ShareWrite = 0x00000002;
    private const UInt32 OpenExisting = 3;
    private const UInt32 FileFlagOpenReparsePoint = 0x00200000;
    private const UInt32 FileFlagBackupSemantics = 0x02000000;
    private const UInt32 DirectoryAttribute = 0x00000010;
    private const UInt32 ReparseAttribute = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public UInt32 FileAttributes;
        public UInt32 CreationTimeLow;
        public UInt32 CreationTimeHigh;
        public UInt32 LastAccessTimeLow;
        public UInt32 LastAccessTimeHigh;
        public UInt32 LastWriteTimeLow;
        public UInt32 LastWriteTimeHigh;
        public UInt32 VolumeSerialNumber;
        public UInt32 FileSizeHigh;
        public UInt32 FileSizeLow;
        public UInt32 NumberOfLinks;
        public UInt32 FileIndexHigh;
        public UInt32 FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    private static extern SafeFileHandle CreateFile(
        String fileName, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes,
        UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern Boolean GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);

    public static SafeFileHandle OpenDirectory(String path)
    {
        SafeFileHandle handle = CreateFile(path, FileReadAttributes, ShareRead | ShareWrite,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open guarded directory failed: " + path);
        SafeUploadSdkValidationFileInfo info = GetInfo(handle);
        if ((info.Attributes & DirectoryAttribute) == 0 || (info.Attributes & ReparseAttribute) != 0)
        {
            handle.Dispose();
            throw new IOException("Directory is missing, not a directory, or is a reparse point: " + path);
        }
        return handle;
    }

    public static SafeFileHandle OpenObjectMetadata(String path)
    {
        SafeFileHandle handle = CreateFile(path, FileReadAttributes, ShareRead | ShareWrite,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open no-follow object failed: " + path);
        return handle;
    }

    public static SafeFileHandle OpenReadFile(String path)
    {
        // Share-read only denies a concurrent write or delete while this check hashes the member.
        SafeFileHandle handle = CreateFile(path, GenericRead, ShareRead,
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open pinned read-only file failed: " + path);
        return handle;
    }

    public static SafeUploadSdkValidationFileInfo GetInfo(SafeFileHandle handle)
    {
        ByHandleFileInformation native;
        if (handle == null || handle.IsInvalid || !GetFileInformationByHandle(handle, out native))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed");
        SafeUploadSdkValidationFileInfo info = new SafeUploadSdkValidationFileInfo();
        info.Attributes = native.FileAttributes;
        info.VolumeSerial = native.VolumeSerialNumber;
        info.FileId = ((UInt64)native.FileIndexHigh << 32) | native.FileIndexLow;
        info.Length = ((UInt64)native.FileSizeHigh << 32) | native.FileSizeLow;
        return info;
    }

    public static String Identity(SafeFileHandle handle)
    {
        SafeUploadSdkValidationFileInfo info = GetInfo(handle);
        return info.VolumeSerial.ToString("X8") + ":" + info.FileId.ToString("X16");
    }

    public static String SnapshotNames(String[] names)
    {
        Array.Sort(names, StringComparer.OrdinalIgnoreCase);
        System.Text.StringBuilder value = new System.Text.StringBuilder();
        foreach (String name in names) value.Append(name.Length).Append(':').Append(name);
        return value.ToString();
    }
}
'@

$heldHandles = New-Object System.Collections.ArrayList
$heldStreams = New-Object System.Collections.ArrayList
$directorySnapshots = @{}
$failure = $null
$computerSystem = $null
$identity = $null
$principal = $null
$sourceHashBefore = $null
$sourceHashAfter = $null
$sourceSignatureBefore = $null
$sourceSignatureAfter = $null
$sourceIdentity = $null
$targetIdentity = $null
$logIdentity = $null
$logBytes = $null
$logHash = $null
$treeInventory = @()
$sdkRoot = $null
$winFspBefore = $null
$winFspAfter = $null
$actorsBefore = @()
$actorsAfter = @()
$installerServiceBefore = $null
$installerServiceAfter = $null
$sourceStream = $null
$logStream = $null
$resultStatus = 'WINFSP_SDK_RETAINED_OUTPUT_VALIDATION_FAILED'

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '')
    } finally {
        $Stream.Position = 0
        $sha.Dispose()
    }
}

function Get-BuildActors {
    $all = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    return @($all | Where-Object { $actorNames -contains [IO.Path]::GetFileNameWithoutExtension([string]$_.Name) } |
        ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name
                ProcessId = [UInt32]$_.ProcessId
                ParentProcessId = [UInt32]$_.ParentProcessId
                ExecutablePath = [string]$_.ExecutablePath
                CommandLine = [string]$_.CommandLine
                CreationDate = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
            }
        } | Sort-Object Name, ProcessId)
}

function Get-WindowsInstallerService {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='msiserver'" -ErrorAction Stop
    if ($null -eq $service) { throw 'Windows Installer service inventory is unavailable.' }
    return [pscustomobject]@{
        Name = [string]$service.Name
        State = [string]$service.State
        StartMode = [string]$service.StartMode
        ProcessId = [UInt32]$service.ProcessId
        PathName = [string]$service.PathName
    }
}

function Get-WinfspInstalledInventory {
    $packages = @(
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*WinFsp*' } |
            ForEach-Object { '{0}|{1}|{2}' -f $_.PSChildName, $_.DisplayName, $_.DisplayVersion } |
            Sort-Object
    )
    $drivers = @(
        Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
            Where-Object { $_.Name -like '*WinFsp*' } |
            ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.State, $_.PathName } |
            Sort-Object
    )
    $services = @(
        Get-Service -ErrorAction Stop |
            Where-Object { $_.Name -like '*WinFsp*' } |
            ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.Status, $_.ServiceType } |
            Sort-Object
    )
    return [ordered]@{ Packages = $packages; Drivers = $drivers; Services = $services }
}

function Assert-ExpectedDirectoryPins {
    foreach ($pin in $expectedDirectoryPins) {
        $handle = [SafeUploadSdkValidationNative]::OpenDirectory([string]$pin.Path)
        try {
            if ([SafeUploadSdkValidationNative]::Identity($handle) -cne [string]$pin.Identity) {
                throw ('Pinned directory identity changed: ' + $pin.Path)
            }
            [void]$heldHandles.Add($handle)
            $handle = $null
        } finally { if ($null -ne $handle) { $handle.Dispose() } }
    }
}

function Get-DirectoryNameSnapshot {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    $paths = [IO.Directory]::GetFileSystemEntries($DirectoryPath)
    $names = @($paths | ForEach-Object { [IO.Path]::GetFileName($_) })
    return [SafeUploadSdkValidationNative]::SnapshotNames([string[]]$names)
}

function Get-QuarantinedTreeInventory {
    param([Parameter(Mandatory = $true)][string]$RootPath)
    $items = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{ FullName = $RootPath; RelativePath = ''; ExpectedIdentity = $expectedTargetIdentity })
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        $directoryHandle = [SafeUploadSdkValidationNative]::OpenDirectory([string]$directory.FullName)
        [void]$heldHandles.Add($directoryHandle)
        $directoryIdentity = [SafeUploadSdkValidationNative]::Identity($directoryHandle)
        if ($directoryIdentity -cne [string]$directory.ExpectedIdentity) {
            throw ('Retained output directory identity changed: ' + $directory.FullName)
        }
        $snapshot = Get-DirectoryNameSnapshot -DirectoryPath ([string]$directory.FullName)
        $script:directorySnapshots[[string]$directory.FullName] = [string]$snapshot
        [void]$items.Add([ordered]@{
            Kind = 'Directory'
            RelativePath = [string]$directory.RelativePath
            Identity = $directoryIdentity
        })
        foreach ($entry in [IO.Directory]::GetFileSystemEntries([string]$directory.FullName)) {
            $metadataHandle = [SafeUploadSdkValidationNative]::OpenObjectMetadata([string]$entry)
            [void]$heldHandles.Add($metadataHandle)
            $metadata = [SafeUploadSdkValidationNative]::GetInfo($metadataHandle)
            if (($metadata.Attributes -band 0x00000400) -ne 0) {
                throw ('Reparse point found in retained administrative image: ' + $entry)
            }
            $relative = if ([String]::IsNullOrEmpty([string]$directory.RelativePath)) {
                [IO.Path]::GetFileName($entry)
            } else {
                [string]$directory.RelativePath + '\' + [IO.Path]::GetFileName($entry)
            }
            if (($metadata.Attributes -band 0x00000010) -ne 0) {
                $stack.Push([pscustomobject]@{
                    FullName = [string]$entry
                    RelativePath = $relative
                    ExpectedIdentity = [SafeUploadSdkValidationNative]::Identity($metadataHandle)
                })
            } else {
                $readHandle = [SafeUploadSdkValidationNative]::OpenReadFile([string]$entry)
                if ([SafeUploadSdkValidationNative]::Identity($readHandle) -cne [SafeUploadSdkValidationNative]::Identity($metadataHandle)) {
                    $readHandle.Dispose()
                    throw ('Inventory member identity changed during read-only open: ' + $entry)
                }
                try { $stream = [IO.FileStream]::new($readHandle, [IO.FileAccess]::Read) }
                catch { $readHandle.Dispose(); throw }
                [void]$heldStreams.Add($stream)
                $fileHash = Get-StreamSha256 -Stream $stream
                $alternateStreams = @(
                    Get-Item -LiteralPath ([string]$entry) -Stream * -ErrorAction Stop |
                        Where-Object { $_.Stream -notin @('::$DATA', ':$DATA') }
                )
                if ($alternateStreams.Count -ne 0) {
                    throw ('Alternate data stream found in retained administrative image: ' + $entry)
                }
                [void]$items.Add([ordered]@{
                    Kind = 'File'
                    RelativePath = $relative
                    Identity = [SafeUploadSdkValidationNative]::Identity($readHandle)
                    Bytes = [Int64]$stream.Length
                    SHA256 = $fileHash
                    AlternateDataStreams = @()
                })
            }
        }
    }
    foreach ($path in @($script:directorySnapshots.Keys)) {
        $actual = Get-DirectoryNameSnapshot -DirectoryPath ([string]$path)
        if ($actual -cne [string]$script:directorySnapshots[[string]$path]) {
            throw ('Retained administrative image changed during inventory: ' + $path)
        }
    }
    return ,$items
}

function Find-WinfspSdkRoot {
    param([Parameter(Mandatory = $true)][System.Collections.IEnumerable]$Items)
    $files = @($Items | Where-Object { $_.Kind -ceq 'File' })
    $roots = New-Object System.Collections.ArrayList
    foreach ($file in $files) {
        $parts = ([string]$file.RelativePath).Split('\')
        if ($parts.Length -lt 3 -or $parts[$parts.Length - 3] -ine 'inc' -or
            $parts[$parts.Length - 2] -ine 'winfsp' -or $parts[$parts.Length - 1] -ine 'winfsp.h') { continue }
        $prefixParts = @()
        if ($parts.Length -gt 3) { $prefixParts = $parts[0..($parts.Length - 4)] }
        $prefix = [String]::Join('\', [string[]]$prefixParts)
        $expectedLib = if ($prefix.Length -eq 0) { 'lib\winfsp-x64.lib' } else { $prefix + '\lib\winfsp-x64.lib' }
        $lib = @($files | Where-Object { [StringComparer]::OrdinalIgnoreCase.Equals([string]$_.RelativePath, $expectedLib) })
        if ($lib.Count -eq 1) { [void]$roots.Add($prefix) }
    }
    $unique = @($roots | Sort-Object -Unique)
    if ($unique.Count -ne 1) { throw 'Could not derive exactly one root containing inc\winfsp\winfsp.h and lib\winfsp-x64.lib.' }
    if ([string]::IsNullOrEmpty([string]$unique[0])) { return $targetPath }
    return Join-Path $targetPath ([string]$unique[0])
}

function Get-AuthenticodePin {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction Stop
    $thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { $null }
    $subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
    return [pscustomobject]@{ Status = [string]$signature.Status; Thumbprint = $thumbprint; Subject = $subject }
}

try {
    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
        throw 'This validation script requires Windows PowerShell 5.1.'
    }
    if ($env:COMPUTERNAME -cne $expectedComputer) { throw 'Wrong builder computer name.' }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
    if ([string]$computerSystem.UUID -ine $expectedUuid) { throw 'Wrong builder UUID.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ([string]$identity.User.Value -cne $expectedSid) { throw 'Wrong builder user SID.' }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated local administrator token required.' }
    if ([IO.Path]::GetFullPath($msiPath) -cne 'C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006\winfsp-2.2.26215.msi' -or
        [IO.Path]::GetFullPath($targetPath) -cne 'C:\Users\vika\Documents\SafeUploadWinFspSdk-20261006-ef9bea72fc3545d985354fa5a939179b') {
        throw 'Source or retained target path differs from the exact completed extraction.'
    }
    if ($ExpectedRetainedLogIdentity.ToUpperInvariant() -notmatch '^[0-9A-F]{8}:[0-9A-F]{16}$') { throw 'Log identity pin is malformed.' }

    $actorsBefore = @(Get-BuildActors)
    $installerServiceBefore = Get-WindowsInstallerService
    if ($actorsBefore.Count -ne 0 -or $installerServiceBefore.State -cne 'Stopped' -or
        $installerServiceBefore.ProcessId -ne 0 -or $installerServiceBefore.StartMode -cne $expectedWindowsInstallerStartMode -or
        $installerServiceBefore.PathName -cne $expectedWindowsInstallerPath) {
        throw 'Installer/build actors or running Windows Installer service remain; waiting for natural drain is required.'
    }
    $winFspBefore = Get-WinfspInstalledInventory
    if ($winFspBefore.Packages.Count -or $winFspBefore.Drivers.Count -or $winFspBefore.Services.Count) {
        throw 'WinFsp package, driver, or service is installed; retained extraction cannot qualify as SDK-only.'
    }

    Assert-ExpectedDirectoryPins
    $sourceMetadata = [SafeUploadSdkValidationNative]::OpenObjectMetadata($msiPath)
    try {
        $sourceInfo = [SafeUploadSdkValidationNative]::GetInfo($sourceMetadata)
        if (($sourceInfo.Attributes -band 0x00000010) -ne 0 -or ($sourceInfo.Attributes -band 0x00000400) -ne 0) {
            throw 'Pinned MSI is a directory or reparse point.'
        }
        $sourceIdentity = [SafeUploadSdkValidationNative]::Identity($sourceMetadata)
    } finally { $sourceMetadata.Dispose() }
    if ($sourceIdentity -cne $expectedMsiIdentity) { throw 'MSI file identity differs from the extraction receipt.' }
    $sourceHandle = [SafeUploadSdkValidationNative]::OpenReadFile($msiPath)
    if ([SafeUploadSdkValidationNative]::Identity($sourceHandle) -cne $sourceIdentity) {
        $sourceHandle.Dispose()
        throw 'MSI identity changed between metadata and read-only open.'
    }
    $sourceStream = [IO.FileStream]::new($sourceHandle, [IO.FileAccess]::Read)
    [void]$heldStreams.Add($sourceStream)
    if ($sourceStream.Length -ne $expectedMsiBytes) { throw 'MSI byte length differs from the signed inspection receipt.' }
    $sourceHashBefore = Get-StreamSha256 -Stream $sourceStream
    if ($sourceHashBefore -cne $expectedMsiSha256) { throw 'MSI SHA-256 differs from the signed inspection receipt.' }
    $sourceSignatureBefore = Get-AuthenticodePin -LiteralPath $msiPath
    if ($sourceSignatureBefore.Status -cne 'Valid' -or $sourceSignatureBefore.Thumbprint -cne $expectedSignerThumbprint -or
        $sourceSignatureBefore.Subject -cne $expectedSignerSubject) { throw 'MSI Authenticode identity differs from the reviewed signer receipt.' }

    $targetHandle = [SafeUploadSdkValidationNative]::OpenDirectory($targetPath)
    [void]$heldHandles.Add($targetHandle)
    $targetIdentity = [SafeUploadSdkValidationNative]::Identity($targetHandle)
    if ($targetIdentity -cne $expectedTargetIdentity) { throw 'Retained target directory identity differs from the extraction receipt.' }
    $logMetadata = [SafeUploadSdkValidationNative]::OpenObjectMetadata($logPath)
    try {
        $logInfo = [SafeUploadSdkValidationNative]::GetInfo($logMetadata)
        if (($logInfo.Attributes -band 0x00000010) -ne 0 -or ($logInfo.Attributes -band 0x00000400) -ne 0) {
            throw 'Retained installer log is a directory or reparse point.'
        }
        $logIdentity = [SafeUploadSdkValidationNative]::Identity($logMetadata)
    } finally { $logMetadata.Dispose() }
    if ($logIdentity -cne $ExpectedRetainedLogIdentity.ToUpperInvariant()) { throw 'Retained log identity differs from the separately captured pin.' }
    $logHandle = [SafeUploadSdkValidationNative]::OpenReadFile($logPath)
    if ([SafeUploadSdkValidationNative]::Identity($logHandle) -cne $logIdentity) {
        $logHandle.Dispose()
        throw 'Retained log identity changed between metadata and read-only open.'
    }
    $logStream = [IO.FileStream]::new($logHandle, [IO.FileAccess]::Read)
    [void]$heldStreams.Add($logStream)
    $logBytes = [Int64]$logStream.Length
    $logHash = Get-StreamSha256 -Stream $logStream
    if ($logBytes -ne $expectedLogBytes -or $logHash -cne $expectedLogSha256) {
        throw 'Retained installer log bytes or SHA-256 differ from the completed extraction receipt.'
    }

    $treeInventory = Get-QuarantinedTreeInventory -RootPath $targetPath
    if ($treeInventory.Count -eq 0) { throw 'Retained administrative image inventory is empty.' }
    $sdkRoot = Find-WinfspSdkRoot -Items $treeInventory
    if ([IO.Path]::GetFullPath($sdkRoot).StartsWith([IO.Path]::GetFullPath($targetPath + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        # This is valid for nested SDK layouts; the exact root remains emitted in the inventory.
    } elseif ([IO.Path]::GetFullPath($sdkRoot) -ine [IO.Path]::GetFullPath($targetPath)) {
        throw 'Derived SDK root is outside the retained target directory.'
    }

    $sourceHashAfter = Get-StreamSha256 -Stream $sourceStream
    $sourceSignatureAfter = Get-AuthenticodePin -LiteralPath $msiPath
    if ($sourceHashAfter -cne $expectedMsiSha256 -or
        $sourceSignatureAfter.Status -cne 'Valid' -or $sourceSignatureAfter.Thumbprint -cne $expectedSignerThumbprint -or
        $sourceSignatureAfter.Subject -cne $expectedSignerSubject) { throw 'MSI changed during retained-output validation.' }
    $sourcePathHandle = [SafeUploadSdkValidationNative]::OpenObjectMetadata($msiPath)
    try {
        if ([SafeUploadSdkValidationNative]::Identity($sourcePathHandle) -cne $sourceIdentity) {
            throw 'MSI path no longer resolves to the exact retained source file.'
        }
    } finally { $sourcePathHandle.Dispose() }
    if ((Get-StreamSha256 -Stream $logStream) -cne $expectedLogSha256 -or
        [Int64]$logStream.Length -ne $expectedLogBytes) { throw 'Retained installer log changed during validation.' }
    $winFspAfter = Get-WinfspInstalledInventory
    $actorsAfter = @(Get-BuildActors)
    $installerServiceAfter = Get-WindowsInstallerService
    if ($winFspAfter.Packages.Count -or $winFspAfter.Drivers.Count -or $winFspAfter.Services.Count) {
        throw 'WinFsp installed inventory changed during validation.'
    }
    if ($actorsAfter.Count -ne 0 -or $installerServiceAfter.State -cne 'Stopped' -or $installerServiceAfter.ProcessId -ne 0) {
        throw 'Installer/build actor or Windows Installer service appeared during validation.'
    }
    if ($installerServiceAfter.StartMode -cne $installerServiceBefore.StartMode -or
        $installerServiceAfter.PathName -cne $installerServiceBefore.PathName) {
        throw 'Windows Installer service configuration changed during validation.'
    }
    Assert-ExpectedDirectoryPins
    $resultStatus = 'WINFSP_SDK_RETAINED_OUTPUT_VALIDATED'
} catch {
    $failure = $_.Exception.Message
}

$result = [ordered]@{
    Status = $resultStatus
    Failure = $failure
    ValidationOnly = $true
    MSIExtractionRepeated = $false
    OutputDeleted = $false
    ProcessOrServiceStopped = $false
    ServiceConfigurationChanged = $false
    ExtractedProgramsExecuted = $false
    RuntimeInstalled = $false
    RuntimeQualified = $false
    MappingPrivacyQualified = $false
    Computer = $env:COMPUTERNAME
    UUID = if ($computerSystem) { [string]$computerSystem.UUID } else { $null }
    UserSid = if ($identity) { [string]$identity.User.Value } else { $null }
    EffectiveAdministrator = if ($principal) { [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } else { $false }
    RunGuid = 'ef9bea72fc3545d985354fa5a939179b'
    ExtractionSourceSHA256 = $historicalExtractionSourceSha256
    HistoricalExtractionStdoutSHA256 = $historicalExtractionStdoutSha256
    HistoricalExtractionExitSHA256 = $historicalExtractionExitSha256
    HistoricalExtractionNativeExitCode = 0
    HistoricalVerifierExitCode = 1
    HistoricalVerifierFailure = 'Installer/build actors remain after extraction process exit'
    HistoricalAdminExecuteSequence = @($historicalAdminExecuteSequence)
    HistoricalActorDiagnosticStdoutSHA256 = $historicalActorDiagnosticStdoutSha256
    HistoricalUnresolvedActor = $historicalUnresolvedActor
    MsiPath = $msiPath
    MsiIdentity = $sourceIdentity
    MsiBytes = if ($null -ne $sourceStream) { [Int64]$sourceStream.Length } else { $null }
    MsiSHA256Before = $sourceHashBefore
    MsiSHA256After = $sourceHashAfter
    MsiSignatureBefore = $sourceSignatureBefore
    MsiSignatureAfter = $sourceSignatureAfter
    TargetDirectory = $targetPath
    TargetDirectoryIdentity = $targetIdentity
    RetainedLogPath = $logPath
    ExpectedRetainedLogIdentity = $ExpectedRetainedLogIdentity.ToUpperInvariant()
    RetainedLogIdentity = $logIdentity
    RetainedLogBytes = $logBytes
    RetainedLogSHA256 = $logHash
    WindowsInstallerServiceBefore = $installerServiceBefore
    WindowsInstallerServiceAfter = $installerServiceAfter
    ExpectedDirectoryPins = @($expectedDirectoryPins)
    BuildActorsBefore = @($actorsBefore)
    BuildActorsAfter = @($actorsAfter)
    WinFspBefore = $winFspBefore
    WinFspAfter = $winFspAfter
    OutputInventory = @($treeInventory)
    OutputFileCount = @($treeInventory | Where-Object { $_.Kind -ceq 'File' }).Count
    OutputDirectoryCount = @($treeInventory | Where-Object { $_.Kind -ceq 'Directory' }).Count
    WinFspSdkRoot = $sdkRoot
}
Write-Output (ConvertTo-Json -InputObject $result -Depth 12 -Compress)
foreach ($stream in $heldStreams) { try { $stream.Dispose() } catch {} }
foreach ($handle in $heldHandles) { try { $handle.Dispose() } catch {} }
if ($null -ne $failure) { exit 1 }
exit 0
