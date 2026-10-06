[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RunGuid
)

$ErrorActionPreference = 'Stop'

# This package extracts the complete, signed WinFsp administrative image into
# a fresh quarantine directory. It does not install the runtime or execute any
# extracted program. The source MSI and its directory ancestry are held open
# against write/delete/rename for the entire transaction.
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$msiPath = 'C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006\winfsp-2.2.26215.msi'
$msiParent = Split-Path -LiteralPath $msiPath -Parent
$documents = 'C:\Users\vika\Documents'
$targetPrefix = 'C:\Users\vika\Documents\SafeUploadWinFspSdk-20261006-'
$targetPath = $targetPrefix + $RunGuid
$logPath = $targetPath + '.msi.log'
$expectedMsiBytes = [Int64]2207744
$expectedMsiSha256 = '2ECB5C89405488A95BBD8A01875E02C48534FD37BBDFD84488F7590464D65944'
$expectedSignerThumbprint = '75C6C88B0B6C4556F13FCE3B081FC9051EAE457E'
$expectedSignerSubject = 'CN=NAVIMATICS LLC, O=NAVIMATICS LLC, L=KIRKLAND, S=Washington, C=US, SERIALNUMBER=604 419 559, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Washington, OID.1.3.6.1.4.1.311.60.2.1.3=US'
$expectedAdminActions = @(
    'CostInitialize||800',
    'FileCost||900',
    'CostFinalize||1000',
    'InstallValidate||1400',
    'InstallInitialize||1500',
    'InstallAdminPackage||3900',
    'InstallFiles||4000',
    'InstallFinalize||6600'
)

$nativeSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class SafeUploadSdkFileInfo
{
    public UInt32 Attributes;
    public UInt32 VolumeSerial;
    public UInt64 FileId;
    public UInt64 Length;
}

public static class SafeUploadSdkNative
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
    private struct NativeFileTime
    {
        public UInt32 Low;
        public UInt32 High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public UInt32 FileAttributes;
        public NativeFileTime CreationTime;
        public NativeFileTime LastAccessTime;
        public NativeFileTime LastWriteTime;
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
    private static extern Boolean GetFileInformationByHandle(
        SafeFileHandle file, out ByHandleFileInformation information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateDirectoryW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern Boolean CreateDirectory(String path, IntPtr securityAttributes);

    public static SafeFileHandle OpenDirectory(String path)
    {
        SafeFileHandle handle = CreateFile(path, FileReadAttributes, ShareRead | ShareWrite,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open guarded directory failed: " + path);
        SafeUploadSdkFileInfo info = GetInfo(handle);
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
        SafeFileHandle handle = CreateFile(path, GenericRead, ShareRead,
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open read-only pinned file failed: " + path);
        return handle;
    }

    public static SafeFileHandle OpenReadShareReadWrite(String path)
    {
        SafeFileHandle handle = CreateFile(path, GenericRead, ShareRead | ShareWrite,
            IntPtr.Zero, OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle == null || handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Open pinned read-only shared file failed: " + path);
        return handle;
    }

    public static void CreateFreshDirectory(String path)
    {
        if (!CreateDirectory(path, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Fresh output directory creation failed: " + path);
    }

    public static SafeUploadSdkFileInfo GetInfo(SafeFileHandle handle)
    {
        ByHandleFileInformation native;
        if (handle == null || handle.IsInvalid || !GetFileInformationByHandle(handle, out native))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandle failed");
        SafeUploadSdkFileInfo info = new SafeUploadSdkFileInfo();
        info.Attributes = native.FileAttributes;
        info.VolumeSerial = native.VolumeSerialNumber;
        info.FileId = ((UInt64)native.FileIndexHigh << 32) | native.FileIndexLow;
        info.Length = ((UInt64)native.FileSizeHigh << 32) | native.FileSizeLow;
        return info;
    }

    public static String Identity(SafeFileHandle handle)
    {
        SafeUploadSdkFileInfo info = GetInfo(handle);
        return info.VolumeSerial.ToString("X8") + ":" + info.FileId.ToString("X16");
    }

    public static String SnapshotNames(String[] names)
    {
        Array.Sort(names, StringComparer.OrdinalIgnoreCase);
        System.Text.StringBuilder value = new System.Text.StringBuilder();
        foreach (String name in names)
            value.Append(name.Length).Append(':').Append(name);
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
$nativeExitCode = $null
$installerStarted = $false
$targetIdentity = $null
$sourceIdentity = $null
$sourceStream = $null
$logStream = $null
$logCreateStream = $null
$sourceHashBefore = $null
$sourceHashAfter = $null
$sourceSignatureBefore = $null
$sourceSignatureAfter = $null
$logHash = $null
$logBytes = $null
$targetInventory = @()
$sdkRoot = $null
$beforeInstall = $null
$afterInstall = $null
$actorSnapshotBefore = @()
$actorSnapshotAfter = @()
$adminRows = @()
$resultStatus = 'WINFSP_SDK_ADMIN_IMAGE_ABORTED'

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

function Open-PinnedDirectoryChain {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    $full = [IO.Path]::GetFullPath($DirectoryPath)
    $root = [IO.Path]::GetPathRoot($full)
    if ([String]::IsNullOrEmpty($root)) { throw 'Directory path is not rooted' }
    $paths = New-Object System.Collections.ArrayList
    [void]$paths.Add($root)
    $tail = $full.Substring($root.Length).Trim('\')
    if ($tail.Length -gt 0) {
        $prefix = $root.TrimEnd('\')
        foreach ($part in $tail.Split('\')) {
            if ($part.Length -eq 0) { continue }
            $prefix = $prefix + '\' + $part
            [void]$paths.Add($prefix)
        }
    }
    $pins = New-Object System.Collections.ArrayList
    foreach ($path in $paths) {
        $handle = [SafeUploadSdkNative]::OpenDirectory([string]$path)
        [void]$heldHandles.Add($handle)
        [void]$pins.Add([ordered]@{Path = [string]$path; Identity = [SafeUploadSdkNative]::Identity($handle)})
    }
    return ,$pins
}

function Assert-PinnedDirectoryChain {
    param([Parameter(Mandatory = $true)][System.Collections.IEnumerable]$Pins)
    foreach ($pin in $Pins) {
        $handle = [SafeUploadSdkNative]::OpenDirectory([string]$pin.Path)
        try {
            if ([SafeUploadSdkNative]::Identity($handle) -cne [string]$pin.Identity) {
                throw ('Pinned directory identity changed: ' + $pin.Path)
            }
        } finally { $handle.Dispose() }
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
        Get-Service -Name '*WinFsp*' -ErrorAction SilentlyContinue |
            ForEach-Object { '{0}|{1}|{2}' -f $_.Name, $_.Status, $_.ServiceType } |
            Sort-Object
    )
    return [ordered]@{Packages = $packages; Drivers = $drivers; Services = $services}
}

function Get-BuildActors {
    return @(
        Get-Process -Name 'msiexec', 'MSBuild', 'dotnet', 'csc', 'VBCSCompiler' -ErrorAction SilentlyContinue |
            ForEach-Object { '{0}|{1}' -f $_.ProcessName, $_.Id } |
            Sort-Object
    )
}

function Get-DirectoryNameSnapshot {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    $paths = [IO.Directory]::GetFileSystemEntries($DirectoryPath)
    $names = @($paths | ForEach-Object { [IO.Path]::GetFileName($_) })
    return [SafeUploadSdkNative]::SnapshotNames([string[]]$names)
}

function Get-QuarantinedTreeInventory {
    param([Parameter(Mandatory = $true)][string]$RootPath)
    $items = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{FullName = $RootPath; RelativePath = ''})
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        $snapshot = Get-DirectoryNameSnapshot -DirectoryPath $directory.FullName
        $directorySnapshots[[string]$directory.FullName] = [string]$snapshot
        $directoryHandle = [SafeUploadSdkNative]::OpenDirectory([string]$directory.FullName)
        [void]$heldHandles.Add($directoryHandle)
        $directoryId = [SafeUploadSdkNative]::Identity($directoryHandle)
        [void]$items.Add([ordered]@{Kind = 'Directory'; RelativePath = [string]$directory.RelativePath; Identity = $directoryId})
        foreach ($entry in [IO.Directory]::GetFileSystemEntries([string]$directory.FullName)) {
            $metadataHandle = [SafeUploadSdkNative]::OpenObjectMetadata([string]$entry)
            $metadata = [SafeUploadSdkNative]::GetInfo($metadataHandle)
            if (($metadata.Attributes -band 0x00000400) -ne 0) {
                $metadataHandle.Dispose()
                throw ('Reparse point found in administrative image: ' + $entry)
            }
            $relative = if ([String]::IsNullOrEmpty([string]$directory.RelativePath)) {
                [IO.Path]::GetFileName($entry)
            } else {
                [string]$directory.RelativePath + '\' + [IO.Path]::GetFileName($entry)
            }
            if (($metadata.Attributes -band 0x00000010) -ne 0) {
                [void]$heldHandles.Add($metadataHandle)
                $stack.Push([pscustomobject]@{FullName = [string]$entry; RelativePath = $relative})
            } else {
                $readHandle = [SafeUploadSdkNative]::OpenReadFile([string]$entry)
                if ([SafeUploadSdkNative]::Identity($readHandle) -cne [SafeUploadSdkNative]::Identity($metadataHandle)) {
                    $readHandle.Dispose()
                    $metadataHandle.Dispose()
                    throw ('File identity changed while opening inventory member: ' + $entry)
                }
                $stream = [IO.FileStream]::new($readHandle, [IO.FileAccess]::Read)
                [void]$heldHandles.Add($metadataHandle)
                [void]$heldStreams.Add($stream)
                [void]$items.Add([ordered]@{
                    Kind = 'File'; RelativePath = $relative; Identity = [SafeUploadSdkNative]::Identity($readHandle)
                    Bytes = [Int64]$stream.Length; SHA256 = (Get-StreamSha256 -Stream $stream)
                })
            }
        }
    }
    foreach ($path in @($directorySnapshots.Keys)) {
        $actual = Get-DirectoryNameSnapshot -DirectoryPath ([string]$path)
        if ($actual -cne [string]$directorySnapshots[[string]$path]) {
            throw ('Administrative image directory changed during inventory: ' + $path)
        }
    }
    return ,$items
}

function Find-WinfspSdkRoot {
    param([Parameter(Mandatory = $true)][string]$RootPath,
          [Parameter(Mandatory = $true)][System.Collections.IEnumerable]$Items)
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
        if ($lib.Count -eq 1) {
            $candidate = if ($prefix.Length -eq 0) { $RootPath } else { Join-Path $RootPath $prefix }
            [void]$roots.Add($candidate)
        }
    }
    $unique = @($roots | Sort-Object -Unique)
    if ($unique.Count -ne 1) { throw 'Could not derive one unique SDK root containing inc\winfsp\winfsp.h and lib\winfsp-x64.lib' }
    return [string]$unique[0]
}

try {
    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
    if ($env:COMPUTERNAME -cne $expectedComputer) { throw 'Wrong builder computer name' }
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop
    if ([string]$computerSystem.UUID -ine $expectedUuid) { throw 'Wrong builder UUID' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ([string]$identity.User.Value -cne $expectedSid) { throw 'Wrong builder user SID' }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated local administrator token required' }
    if ([IO.Path]::GetFullPath($msiPath) -cne 'C:\Users\vika\Documents\SafeUploadDependencyReview-WinFsp-v2.2B4-20261006\winfsp-2.2.26215.msi') { throw 'Unexpected MSI path' }
    if ($RunGuid -cnotmatch '^[0-9a-f]{32}$') { throw 'RunGuid must be 32 lowercase hexadecimal characters' }

    $sourceDirectoryPins = Open-PinnedDirectoryChain -DirectoryPath $msiParent
    $outputDirectoryPins = Open-PinnedDirectoryChain -DirectoryPath $documents

    $sourceMetadataHandle = [SafeUploadSdkNative]::OpenObjectMetadata($msiPath)
    $sourceMetadata = [SafeUploadSdkNative]::GetInfo($sourceMetadataHandle)
    if (($sourceMetadata.Attributes -band 0x00000010) -ne 0 -or ($sourceMetadata.Attributes -band 0x00000400) -ne 0) {
        $sourceMetadataHandle.Dispose()
        throw 'MSI source is a directory or reparse point'
    }
    [void]$heldHandles.Add($sourceMetadataHandle)
    $sourceIdentity = [SafeUploadSdkNative]::Identity($sourceMetadataHandle)
    $sourceReadHandle = [SafeUploadSdkNative]::OpenReadFile($msiPath)
    if ([SafeUploadSdkNative]::Identity($sourceReadHandle) -cne $sourceIdentity) {
        $sourceReadHandle.Dispose()
        throw 'MSI identity changed while opening source read handle'
    }
    $sourceStream = [IO.FileStream]::new($sourceReadHandle, [IO.FileAccess]::Read)
    [void]$heldStreams.Add($sourceStream)
    if ($sourceStream.Length -ne $expectedMsiBytes) { throw 'MSI byte length does not match signed inspection' }
    $sourceHashBefore = Get-StreamSha256 -Stream $sourceStream
    if ($sourceHashBefore -cne $expectedMsiSha256) { throw 'MSI SHA-256 does not match signed inspection' }
    $sourceSignatureBefore = Get-AuthenticodeSignature -LiteralPath $msiPath -ErrorAction Stop
    if ($sourceSignatureBefore.Status.ToString() -cne 'Valid' -or
        $sourceSignatureBefore.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $expectedSignerThumbprint -or
        $sourceSignatureBefore.SignerCertificate.Subject -cne $expectedSignerSubject) {
        throw 'MSI Authenticode identity does not match the reviewed receipt'
    }

    if ((Test-Path -LiteralPath $targetPath) -or (Test-Path -LiteralPath $logPath)) { throw 'Fresh target or log already exists' }
    $actorSnapshotBefore = @(Get-BuildActors)
    if ($actorSnapshotBefore.Count -ne 0) { throw 'Unexpected installer/build actors are already running' }
    $beforeInstall = Get-WinfspInstalledInventory
    if ($beforeInstall.Packages.Count -or $beforeInstall.Drivers.Count -or $beforeInstall.Services.Count) {
        throw 'WinFsp package, driver, or service already exists on the builder'
    }

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    $view = $null
    try {
        $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($msiPath, 0))
        $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database,
            @('SELECT `Action`,`Condition`,`Sequence` FROM `AdminExecuteSequence` ORDER BY `Sequence`'))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $rowList = New-Object System.Collections.ArrayList
        for (;;) {
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($null -eq $record) { break }
            $values = @()
            foreach ($column in 1..3) {
                $values += [string]$record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @($column))
            }
            [void]$rowList.Add(($values -join '|'))
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($record)
        }
        $adminRows = @($rowList.ToArray())
    } finally {
        if ($view) {
            $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
        }
        if ($database) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database) }
        if ($installer) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
    }
    if (($adminRows -join ';') -cne ($expectedAdminActions -join ';')) { throw 'AdminExecuteSequence differs from the exact reviewed sequence' }

    [SafeUploadSdkNative]::CreateFreshDirectory($targetPath)
    $targetHandle = [SafeUploadSdkNative]::OpenDirectory($targetPath)
    [void]$heldHandles.Add($targetHandle)
    $targetIdentity = [SafeUploadSdkNative]::Identity($targetHandle)
    $logCreateStream = [IO.FileStream]::new($logPath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    [void]$heldStreams.Add($logCreateStream)
    $logCreateIdentity = [SafeUploadSdkNative]::Identity($logCreateStream.SafeFileHandle)
    $logReadHandle = [SafeUploadSdkNative]::OpenReadShareReadWrite($logPath)
    if ([SafeUploadSdkNative]::Identity($logReadHandle) -cne $logCreateIdentity) {
        $logReadHandle.Dispose()
        throw 'MSI log identity changed between exclusive creation and guarded reopen'
    }
    $logStream = [IO.FileStream]::new($logReadHandle, [IO.FileAccess]::Read)
    [void]$heldStreams.Add($logStream)
    $logCreateStream.Dispose()
    $logCreateStream = $null

    $processInfo = [Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $processInfo.Arguments = '/a "' + $msiPath + '" /qn /norestart TARGETDIR="' + $targetPath + '" /l*v "' + $logPath + '"'
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($processInfo)
    if ($null -eq $process) { throw 'Could not start the pinned administrative extraction process' }
    $installerStarted = $true
    $process.WaitForExit()
    $nativeExitCode = [Int32]$process.ExitCode
    $process.Dispose()

    $afterInstall = Get-WinfspInstalledInventory
    if ($afterInstall.Packages.Count -or $afterInstall.Drivers.Count -or $afterInstall.Services.Count) {
        throw 'Administrative image extraction changed installed WinFsp package/driver/service inventory'
    }
    $actorSnapshotAfter = @(Get-BuildActors)
    if ($actorSnapshotAfter.Count -ne 0) { throw 'Installer/build actors remain after extraction process exit' }

    $sourceHashAfter = Get-StreamSha256 -Stream $sourceStream
    if ($sourceHashAfter -cne $expectedMsiSha256) { throw 'MSI bytes changed while extraction was running' }
    $sourceSignatureAfter = Get-AuthenticodeSignature -LiteralPath $msiPath -ErrorAction Stop
    if ($sourceSignatureAfter.Status.ToString() -cne 'Valid' -or
        $sourceSignatureAfter.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $expectedSignerThumbprint -or
        $sourceSignatureAfter.SignerCertificate.Subject -cne $expectedSignerSubject) {
        throw 'MSI signature or signer changed after extraction'
    }
    $sourcePathHandle = [SafeUploadSdkNative]::OpenObjectMetadata($msiPath)
    try {
        if ([SafeUploadSdkNative]::Identity($sourcePathHandle) -cne $sourceIdentity) { throw 'MSI path no longer resolves to held source file' }
    } finally { $sourcePathHandle.Dispose() }
    Assert-PinnedDirectoryChain -Pins $sourceDirectoryPins
    Assert-PinnedDirectoryChain -Pins $outputDirectoryPins
    $targetPathHandle = [SafeUploadSdkNative]::OpenDirectory($targetPath)
    try {
        if ([SafeUploadSdkNative]::Identity($targetPathHandle) -cne $targetIdentity) { throw 'Output directory path no longer resolves to held directory' }
    } finally { $targetPathHandle.Dispose() }

    $logStream.Flush($true)
    $logBytes = [Int64]$logStream.Length
    $logHash = Get-StreamSha256 -Stream $logStream
    if ($logBytes -le 0) { throw 'Windows Installer log is empty; refusing an unverified result' }
    $targetInventory = Get-QuarantinedTreeInventory -RootPath $targetPath
    if ($targetInventory.Count -eq 0) { throw 'Administrative image contained no inventory records' }
    $sdkRoot = Find-WinfspSdkRoot -RootPath $targetPath -Items $targetInventory
    if ($nativeExitCode -ne 0) { throw ('Administrative extraction process returned ' + $nativeExitCode) }
    $resultStatus = 'WINFSP_BUILDER_ADMIN_IMAGE_EXTRACTED_AND_HASHED'
} catch {
    $failure = $_.Exception.Message
}

if ($null -ne $sourceStream) {
    try {
        $sourceHashAfter = Get-StreamSha256 -Stream $sourceStream
    } catch { if ($null -eq $failure) { $failure = 'Final MSI hash read failed: ' + $_.Exception.Message } }
}
if ($null -ne $logStream) {
    try {
        $logStream.Flush($true)
        $logBytes = [Int64]$logStream.Length
        $logHash = Get-StreamSha256 -Stream $logStream
    } catch { if ($null -eq $failure) { $failure = 'Retained MSI log hash failed: ' + $_.Exception.Message } }
}
if ($installerStarted -and $nativeExitCode -ne 0 -and $null -eq $failure) {
    $failure = 'Administrative extraction returned a nonzero native exit code'
}
if ($null -ne $failure) { $resultStatus = 'WINFSP_BUILDER_ADMIN_IMAGE_FAILED_RETAIN_OUTPUT' }

$result = [ordered]@{
    Status = $resultStatus
    Failure = $failure
    Computer = $env:COMPUTERNAME
    UUID = if ($computerSystem) { [string]$computerSystem.UUID } else { $null }
    UserSid = if ($identity) { [string]$identity.User.Value } else { $null }
    EffectiveAdministrator = if ($principal) { [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } else { $false }
    MsiPath = $msiPath
    MsiBytes = if ($sourceStream) { [Int64]$sourceStream.Length } else { $null }
    MsiIdentity = $sourceIdentity
    MsiSHA256Before = $sourceHashBefore
    MsiSHA256After = $sourceHashAfter
    MsiSignatureBefore = if ($sourceSignatureBefore) { $sourceSignatureBefore.Status.ToString() } else { $null }
    MsiSignerThumbprintBefore = if ($sourceSignatureBefore -and $sourceSignatureBefore.SignerCertificate) { $sourceSignatureBefore.SignerCertificate.Thumbprint } else { $null }
    MsiSignatureAfter = if ($sourceSignatureAfter) { $sourceSignatureAfter.Status.ToString() } else { $null }
    MsiSignerThumbprintAfter = if ($sourceSignatureAfter -and $sourceSignatureAfter.SignerCertificate) { $sourceSignatureAfter.SignerCertificate.Thumbprint } else { $null }
    SourceDirectoryPins = $sourceDirectoryPins
    OutputParentDirectoryPins = $outputDirectoryPins
    AdminExecuteSequence = $adminRows
    InstallerStarted = $installerStarted
    NativeExitCode = $nativeExitCode
    TargetDirectory = $targetPath
    TargetDirectoryIdentity = $targetIdentity
    RetainedLogPath = $logPath
    RetainedLogBytes = $logBytes
    RetainedLogSHA256 = $logHash
    WinFspBefore = $beforeInstall
    WinFspAfter = $afterInstall
    BuildActorsBefore = $actorSnapshotBefore
    BuildActorsAfter = $actorSnapshotAfter
    OutputInventory = @($targetInventory)
    WinFspSdkRoot = $sdkRoot
    ExtractedProgramsExecuted = $false
    RuntimeInstalled = $false
    RuntimeQualified = $false
    MappingPrivacyQualified = $false
}
$json = ConvertTo-Json -InputObject $result -Depth 12 -Compress
Write-Output $json

foreach ($stream in $heldStreams) { try { $stream.Dispose() } catch {} }
foreach ($handle in $heldHandles) { try { $handle.Dispose() } catch {} }
if ($null -ne $failure) { throw $failure }
