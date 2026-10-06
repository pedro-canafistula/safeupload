<#
.SYNOPSIS
    Capture one raw-only admission-evidence sample through the service's existing private pipe.

.DESCRIPTION
    Dot-source this file from the staged mapping harness. It never connects a
    FilterPort and never starts, stops, or reconfigures the service. The caller
    supplies an already-open target FileStream, a stable per-target RunId, and
    the hook ordinal. Only hooks 2 through 7 are eligible in the current
    service sequence. The result is diagnostic evidence only; it has no Ready
    or privacy meaning.
#>

if (-not ('SafeUploadAdmissionEvidence.Client.Native' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace SafeUploadAdmissionEvidence.Client
{
    public sealed class TargetIdentity
    {
        private readonly byte[] _fileId;

        internal TargetIdentity(string volumeGuid, ulong volumeSerial, byte[] fileId)
        {
            NativeVolumeGuid = volumeGuid;
            VolumeSerial = volumeSerial;
            _fileId = (byte[])fileId.Clone();
            FileIdHex = BitConverter.ToString(_fileId).Replace("-", String.Empty);
        }

        public string NativeVolumeGuid { get; private set; }
        public ulong VolumeSerial { get; private set; }
        public byte[] FileId { get { return (byte[])_fileId.Clone(); } }
        public string FileIdHex { get; private set; }

        public bool HasSameTuple(TargetIdentity other)
        {
            if (other == null || VolumeSerial != other.VolumeSerial ||
                !String.Equals(NativeVolumeGuid, other.NativeVolumeGuid, StringComparison.OrdinalIgnoreCase) ||
                _fileId.Length != other._fileId.Length) return false;
            for (int i = 0; i < _fileId.Length; i++)
                if (_fileId[i] != other._fileId[i]) return false;
            return true;
        }
    }

    public sealed class ProcessIdentity
    {
        public int ProcessId { get; private set; }
        public long CreationTimeFileTime { get; private set; }
        public string ImagePath { get; private set; }
        public string ImageSha256 { get; private set; }
        public TargetIdentity ImageFileIdentity { get; private set; }

        internal ProcessIdentity(int processId, long creationTimeFileTime, string imagePath,
            string imageSha256, TargetIdentity imageFileIdentity)
        {
            ProcessId = processId;
            CreationTimeFileTime = creationTimeFileTime;
            ImagePath = imagePath;
            ImageSha256 = imageSha256;
            ImageFileIdentity = imageFileIdentity;
        }

        public bool HasSameIdentity(ProcessIdentity other)
        {
            return other != null && ProcessId == other.ProcessId &&
                CreationTimeFileTime == other.CreationTimeFileTime &&
                String.Equals(ImagePath, other.ImagePath, StringComparison.OrdinalIgnoreCase) &&
                String.Equals(ImageSha256, other.ImageSha256, StringComparison.OrdinalIgnoreCase) &&
                ImageFileIdentity != null && ImageFileIdentity.HasSameTuple(other.ImageFileIdentity);
        }
    }

    public static class Native
    {
        private const int FileIdInfoClass = 18;
        private const uint VolumeNameGuid = 0x00000001;
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint CreateNew = 1;
        private const uint OpenExisting = 3;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint ProcessQueryLimitedInformation = 0x00001000;
        private const string DirectorySddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        private const string FileSddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }

        [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string sddl, uint revision, out IntPtr securityDescriptor, out uint size);

        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string path, uint access, uint share, ref SecurityAttributes attributes,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenExistingFile(
            string path, uint access, uint share, IntPtr securityAttributes,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(SafeProcessHandle process,
            out long creationTime, out long exitTime, out long kernelTime, out long userTime);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageName(SafeProcessHandle process,
            uint flags, StringBuilder imageName, ref uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle handle, int informationClass, [Out] byte[] information, uint size);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(
            SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);

        [DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformation(
            string root, StringBuilder volumeName, uint volumeNameSize,
            out uint volumeSerial, out uint maximumComponentLength, out uint fileSystemFlags,
            StringBuilder fileSystemName, uint fileSystemNameSize);

        [DllImport("kernel32.dll", EntryPoint = "GetNamedPipeServerProcessId", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetNamedPipeServerProcessId(
            SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("kernel32.dll", EntryPoint = "PeekNamedPipe", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekNamedPipe(
            SafePipeHandle pipe, IntPtr buffer, uint bufferSize,
            out uint bytesRead, out uint totalBytesAvailable, out uint bytesLeftThisMessage);

        [DllImport("kernel32.dll", EntryPoint = "LocalFree")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static TargetIdentity GetTargetIdentity(SafeFileHandle handle)
        {
            if (!BitConverter.IsLittleEndian)
                throw new PlatformNotSupportedException("Admission evidence identity requires a little-endian Windows host.");
            if (handle == null || handle.IsClosed || handle.IsInvalid)
                throw new ArgumentException("The caller must provide an already-open target handle.", "handle");

            byte[] information = new byte[24];
            if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, information, (uint)information.Length))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "FILE_ID_INFO query failed.");

            ulong serial = BitConverter.ToUInt64(information, 0);
            byte[] fileId = new byte[16];
            Buffer.BlockCopy(information, 8, fileId, 0, fileId.Length);
            string finalPath = GetFinalVolumeGuidPath(handle);
            const string prefix = @"\\?\Volume{";
            if (!finalPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || finalPath.Length < 49 ||
                finalPath[47] != '}' || finalPath[48] != '\\')
                throw new InvalidDataException("The existing target handle did not resolve to one GUID volume path.");

            Guid volumeGuid;
            if (!Guid.TryParseExact(finalPath.Substring(11, 36), "D", out volumeGuid))
                throw new InvalidDataException("The existing target handle returned an invalid volume GUID.");

            string nativeGuid = @"\??\Volume{" + volumeGuid.ToString("D") + "}";
            return new TargetIdentity(nativeGuid, serial, fileId);
        }

        public static ProcessIdentity GetProcessIdentity(int processId)
        {
            if (processId <= 0) throw new ArgumentOutOfRangeException("processId");
            using (SafeProcessHandle process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)processId))
            {
                if (process == null || process.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Tracked service process could not be opened.");
                long creationTime, exitTime, kernelTime, userTime;
                if (!GetProcessTimes(process, out creationTime, out exitTime, out kernelTime, out userTime))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Tracked service process times could not be read.");
                if (exitTime != 0)
                    throw new InvalidOperationException("Tracked service process has already exited.");

                StringBuilder imageName = new StringBuilder(32768);
                uint imageChars = (uint)imageName.Capacity;
                if (!QueryFullProcessImageName(process, 0, imageName, ref imageChars) || imageChars == 0 || imageChars >= imageName.Capacity)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Tracked service image path could not be read.");
                string imagePath = imageName.ToString();
                if (!Path.IsPathRooted(imagePath))
                    throw new InvalidDataException("Tracked service image path is not absolute.");

                using (SafeFileHandle imageHandle = OpenExistingFile(imagePath, 0x80000000, 0x00000007,
                    IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero))
                {
                    if (imageHandle == null || imageHandle.IsInvalid)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Tracked service image file could not be opened.");
                    TargetIdentity imageIdentity = GetTargetIdentity(imageHandle);
                    using (FileStream imageStream = new FileStream(imageHandle, FileAccess.Read, 65536, false))
                    using (SHA256 sha = SHA256.Create())
                    {
                        string imageHash = BitConverter.ToString(sha.ComputeHash(imageStream)).Replace("-", String.Empty);
                        return new ProcessIdentity(processId, creationTime, imagePath, imageHash, imageIdentity);
                    }
                }
            }
        }

        private static string GetFinalVolumeGuidPath(SafeFileHandle handle)
        {
            StringBuilder path = new StringBuilder(1024);
            uint length = GetFinalPathNameByHandle(handle, path, (uint)path.Capacity, VolumeNameGuid);
            if (length == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GUID volume path query failed.");
            if (length >= path.Capacity)
            {
                if (length > 32767) throw new InvalidDataException("The final target path exceeded the Windows bound.");
                path = new StringBuilder(checked((int)length + 1));
                length = GetFinalPathNameByHandle(handle, path, (uint)path.Capacity, VolumeNameGuid);
                if (length == 0 || length >= path.Capacity)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GUID volume path query failed.");
            }
            return path.ToString();
        }

        public static string GetFileSystemName(string root)
        {
            StringBuilder fileSystem = new StringBuilder(64);
            uint serial, maximumComponentLength, flags;
            if (!GetVolumeInformation(root, null, 0, out serial, out maximumComponentLength,
                out flags, fileSystem, (uint)fileSystem.Capacity))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Evidence volume file-system query failed.");
            return fileSystem.ToString();
        }

        public static uint GetPipeServerProcessId(SafePipeHandle pipe)
        {
            uint processId;
            if (pipe == null || pipe.IsClosed || pipe.IsInvalid ||
                !GetNamedPipeServerProcessId(pipe, out processId) || processId == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Evidence pipe server identity query failed.");
            return processId;
        }

        public static int GetPipeAvailableBytes(SafePipeHandle pipe)
        {
            uint bytesRead, available, left;
            if (pipe == null || pipe.IsClosed || pipe.IsInvalid)
                throw new ArgumentException("The connected admission-evidence pipe is unavailable.", "pipe");
            if (!PeekNamedPipe(pipe, IntPtr.Zero, 0, out bytesRead, out available, out left))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 109 || error == 233) return -1; // Broken or disconnected pipe is terminal EOF.
                throw new Win32Exception(error, "Admission evidence pipe state could not be read.");
            }
            return available > Int32.MaxValue ? Int32.MaxValue : (int)available;
        }

        public static void ObserveTaskFailure(Task task)
        {
            if (task == null) return;
            task.ContinueWith(delegate(Task completed)
            {
                completed.Exception.Handle(delegate(Exception ignored) { return true; });
            }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        public static void CreatePrivateDirectory(string path)
        {
            WithSecurityDescriptor(DirectorySddl, delegate(SecurityAttributes attributes)
            {
                if (!CreateDirectory(path, ref attributes))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Private evidence directory creation failed.");
            });
        }

        public static FileStream CreatePrivateFile(string path)
        {
            SafeFileHandle handle = null;
            WithSecurityDescriptor(FileSddl, delegate(SecurityAttributes attributes)
            {
                handle = CreateFile(path, GenericRead | GenericWrite, 0, ref attributes,
                    CreateNew, FileAttributeNormal, IntPtr.Zero);
                if (handle == null || handle.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Exclusive private evidence file creation failed.");
            });
            try { return new FileStream(handle, FileAccess.Write, 65536, false); }
            catch { if (handle != null) handle.Dispose(); throw; }
        }

        private delegate void SecurityAction(SecurityAttributes attributes);

        private static void WithSecurityDescriptor(string sddl, SecurityAction action)
        {
            IntPtr descriptor = IntPtr.Zero;
            uint descriptorSize;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out descriptorSize))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Private evidence security descriptor creation failed.");
            try
            {
                SecurityAttributes attributes = new SecurityAttributes();
                attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes));
                attributes.SecurityDescriptor = descriptor;
                attributes.InheritHandle = false;
                action(attributes);
            }
            finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
        }
    }
}
'@
}

$script:AdmissionEvidencePipeName = 'SafeUploadAdmissionEvidence.Capture'
$script:AdmissionEvidenceMaxRequestBytes = 4096
$script:AdmissionEvidenceMaxFrameBytes = 65536
$script:AdmissionEvidenceMaxResponseBytes = 167772160
$script:AdmissionEvidenceMaxFrames = 10000
$script:AdmissionEvidenceMaxActivatingBytes = 134217728
$script:AdmissionEvidenceMaxActivatingPagesPerAttempt = 640
$script:AdmissionEvidenceMaxActivatingAttempts = 5
$script:AdmissionEvidenceMaxCaptureMilliseconds = 300000
$script:AdmissionEvidenceUtf8Strict = [Text.UTF8Encoding]::new($false, $true)

function ConvertTo-AdmissionEvidenceHex([byte[]] $Bytes) {
    if ($null -eq $Bytes) { return '' }
    return ([BitConverter]::ToString($Bytes)).Replace('-', '').ToUpperInvariant()
}

function Get-AdmissionEvidenceHash([string] $Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (ConvertTo-AdmissionEvidenceHex ($sha.ComputeHash($stream))) }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Get-AdmissionEvidenceTargetIdentity([IO.FileStream] $TargetStream) {
    if ($null -eq $TargetStream) { throw 'An already-open target FileStream is required.' }
    if ($TargetStream.SafeFileHandle.IsClosed -or $TargetStream.SafeFileHandle.IsInvalid) {
        throw 'The caller-owned target handle is not open.'
    }
    return [SafeUploadAdmissionEvidence.Client.Native]::GetTargetIdentity($TargetStream.SafeFileHandle)
}

function Get-AdmissionEvidenceProcessIdentity([Diagnostics.Process] $TrackedProcess) {
    if ($null -eq $TrackedProcess) { throw 'The harness must supply its tracked expanded-agent process object.' }
    $TrackedProcess.Refresh()
    if ($TrackedProcess.HasExited) { throw 'The tracked expanded-agent process has exited.' }
    return [SafeUploadAdmissionEvidence.Client.Native]::GetProcessIdentity([int]$TrackedProcess.Id)
}

function New-AdmissionEvidenceBindingContinuity {
    return [pscustomobject]@{
        Bound = $false
        BindingGeneration = $null
        AcceptedPolicyVersion = $null
        CanonicalCandidatePolicyFingerprint = $null
    }
}

function Test-AdmissionEvidenceAclModel($OwnerSid, $GroupSid, $Protected, $Rules, [switch] $Directory) {
    $system = 'S-1-5-18'
    $administrators = 'S-1-5-32-544'
    if ($OwnerSid -cne $administrators -or $GroupSid -cne $administrators -or -not $Protected -or $null -eq $Rules) {
        return $false
    }
    $ruleArray = @($Rules)
    if ($ruleArray.Count -ne 2) { return $false }
    $expected = @($system, $administrators)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($rule in $ruleArray) {
        if ($rule.Sid -cnotin $expected -or $rule.Type -cne 'Allow' -or
            [int]$rule.Rights -ne [int][System.Security.AccessControl.FileSystemRights]::FullControl -or
            [bool]$rule.IsInherited) { return $false }
        if ($Directory) {
            $expectedInheritance = [int]([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit)
        } else { $expectedInheritance = [int][Security.AccessControl.InheritanceFlags]::None }
        if ([int]$rule.Inheritance -ne $expectedInheritance -or
            [int]$rule.Propagation -ne [int][Security.AccessControl.PropagationFlags]::None) { return $false }
        if (-not $seen.Add([string]$rule.Sid)) { return $false }
    }
    return $seen.Contains($system) -and $seen.Contains($administrators)
}

function Assert-AdmissionEvidencePrivateAcl([string] $Path, [switch] $Directory) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $groupSid = $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        [pscustomobject]@{
            Sid = $_.IdentityReference.Value
            Type = $_.AccessControlType.ToString()
            Rights = [int]$_.FileSystemRights
            Inheritance = [int]$_.InheritanceFlags
            Propagation = [int]$_.PropagationFlags
            IsInherited = [bool]$_.IsInherited
        }
    })
    if (-not (Test-AdmissionEvidenceAclModel $ownerSid $groupSid $acl.AreAccessRulesProtected $rules -Directory:$Directory)) {
        throw 'Private evidence ACL verification failed.'
    }
}

function Assert-AdmissionEvidenceNoReparseAncestors([string] $Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($current)) {
        if (-not (Test-Path -LiteralPath $current -PathType Container)) { throw 'Evidence path contains a missing ancestor.' }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Evidence path contains a reparse point.'
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) { break }
        $current = $parent.FullName
    }
}

function Test-AdmissionEvidenceAncestorAclModel($OwnerSid, $Rules, [switch] $DirectParent) {
    $trustedOwners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($OwnerSid -cnotin $trustedOwners -or $null -eq $Rules) { return $false }
    $mutationMask = if ($DirectParent) {
        [long]([System.Security.AccessControl.FileSystemRights]::WriteData -bor
            [System.Security.AccessControl.FileSystemRights]::AppendData -bor
            [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
            [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [System.Security.AccessControl.FileSystemRights]::Delete -bor
            [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [System.Security.AccessControl.FileSystemRights]::TakeOwnership) -bor 0x40000000 -bor 0x10000000
    } else {
        [long]([System.Security.AccessControl.FileSystemRights]::Delete -bor
            [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [System.Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
            [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes) -bor
            0x40000000 -bor 0x10000000
    }
    foreach ($rule in @($Rules)) {
        if ($rule.Type -ceq 'Allow' -and [string]$rule.Sid -notin $trustedOwners -and
            -not [bool]$rule.InheritOnly -and (([long]$rule.Rights -band $mutationMask) -ne 0)) {
            return $false
        }
    }
    return $true
}

function Assert-AdmissionEvidenceTrustedParent([string] $Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($current)) {
        if (-not (Test-Path -LiteralPath $current -PathType Container)) { throw 'Evidence path has a missing ACL ancestor.' }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Evidence ACL ancestor is a reparse point.' }
        $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        $isDirectParent = $current.Equals([IO.Path]::GetFullPath($Path), [StringComparison]::OrdinalIgnoreCase)
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
            [pscustomobject]@{
                Sid = $_.IdentityReference.Value
                Type = $_.AccessControlType.ToString()
                Rights = [long]$_.FileSystemRights
                InheritOnly = (($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
            }
        })
        if (-not (Test-AdmissionEvidenceAncestorAclModel $ownerSid $rules -DirectParent:$isDirectParent)) {
            throw 'Evidence path ancestor grants untrusted file replacement or rename rights.'
        }
        if ($current.Equals([IO.Path]::GetPathRoot($current), [StringComparison]::OrdinalIgnoreCase)) { break }
        $parentInfo = [IO.Directory]::GetParent($current)
        if ($null -eq $parentInfo) { throw 'Evidence ACL ancestors could not be resolved.' }
        $current = $parentInfo.FullName
    }
}

function New-AdmissionEvidencePrivateRunDirectory([Guid] $RunGuid) {
    if ($RunGuid -eq [Guid]::Empty) { throw 'A non-empty evidence RunGuid is required.' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The admission-evidence client requires an elevated administrator token.'
    }
    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'The canonical Program Files evidence parent is unavailable.' }
    $parent = [IO.Path]::GetFullPath($parent).TrimEnd('\')
    Assert-AdmissionEvidenceNoReparseAncestors $parent
    Assert-AdmissionEvidenceTrustedParent $parent
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($parent))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed -or
        [SafeUploadAdmissionEvidence.Client.Native]::GetFileSystemName($drive.Name) -cne 'NTFS') {
        throw 'The private evidence parent must be on a local fixed NTFS volume.'
    }
    $leaf = 'SafeUploadAdmissionEvidence-' + $RunGuid.ToString('N')
    $path = [IO.Path]::Combine($parent, $leaf)
    [SafeUploadAdmissionEvidence.Client.Native]::CreatePrivateDirectory($path)
    Assert-AdmissionEvidencePrivateRunDirectory $path $RunGuid
    return $path
}

function Assert-AdmissionEvidencePrivateRunDirectory([string] $Path, [Guid] $RunGuid) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A private evidence directory is required.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetDirectoryName($full).TrimEnd('\')
    $canonicalParent = [IO.Path]::GetFullPath([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)).TrimEnd('\')
    $leaf = [IO.Path]::GetFileName($full)
    $expectedLeaf = 'SafeUploadAdmissionEvidence-' + $RunGuid.ToString('N')
    if ($RunGuid -eq [Guid]::Empty -or $parent -ine $canonicalParent -or
        $leaf -cne $expectedLeaf) {
        throw 'Evidence directory must be a unique direct child of canonical Program Files.'
    }
    Assert-AdmissionEvidenceTrustedParent $parent
    Assert-AdmissionEvidenceNoReparseAncestors $full
    Assert-AdmissionEvidencePrivateAcl $full -Directory
}

function New-AdmissionEvidenceRequestBytes($Identity, [Guid] $RunGuid, [Guid] $RequestGuid, [byte] $HookOrdinal) {
    if ($null -eq $Identity -or $RunGuid -eq [Guid]::Empty -or $RequestGuid -eq [Guid]::Empty) {
        throw 'Request, run, and exact target identity fields are required.'
    }
    if ($HookOrdinal -lt 2 -or $HookOrdinal -gt 7) {
        throw 'Only live mapping hooks 2 through 7 can be sent; prelaunch hook 1 is unavailable.'
    }
    $nativeGuid = [string]$Identity.NativeVolumeGuid
    $nativePrefix = '\??\Volume{'
    $parsedNativeGuid = [Guid]::Empty
    $parsedGuidOk = $false
    if ($nativeGuid.Length -eq 48 -and $nativeGuid.StartsWith($nativePrefix, [StringComparison]::OrdinalIgnoreCase) -and $nativeGuid[47] -eq '}') {
        try { $parsedNativeGuid = [Guid]::ParseExact($nativeGuid.Substring(11, 36), 'D'); $parsedGuidOk = $true } catch { }
    }
    if (-not $parsedGuidOk) {
        throw 'The target handle did not yield the canonical native volume GUID form.'
    }
    $fileId = [byte[]]$Identity.FileId
    if ($fileId.Length -ne 16) { throw 'The target handle did not yield a 16-byte FileId.' }
    $volumeBytes = [Text.Encoding]::ASCII.GetBytes($nativeGuid)
    if ($volumeBytes.Length -gt 63) { throw 'Native volume GUID exceeds the protocol bound.' }
    $bodyLength = 65 + $volumeBytes.Length
    if ($bodyLength -gt $script:AdmissionEvidenceMaxRequestBytes) { throw 'Request exceeds protocol bound.' }
    $body = New-Object byte[] $bodyLength
    $magic = [Text.Encoding]::ASCII.GetBytes('SAER')
    [Array]::Copy($magic, 0, $body, 0, $magic.Length)
    $version = [BitConverter]::GetBytes([uint16]1); [Array]::Copy($version, 0, $body, 4, 2)
    $body[6] = $HookOrdinal
    [Array]::Copy($RunGuid.ToByteArray(), 0, $body, 8, 16)
    [Array]::Copy($RequestGuid.ToByteArray(), 0, $body, 24, 16)
    [Array]::Copy([BitConverter]::GetBytes([uint64]$Identity.VolumeSerial), 0, $body, 40, 8)
    [Array]::Copy($fileId, 0, $body, 48, 16)
    $body[64] = [byte]$volumeBytes.Length
    [Array]::Copy($volumeBytes, 0, $body, 65, $volumeBytes.Length)
    $request = New-Object byte[] (4 + $body.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$body.Length), 0, $request, 0, 4)
    [Array]::Copy($body, 0, $request, 4, $body.Length)
    return ,$request
}

function Get-AdmissionEvidenceRemainingMilliseconds([Diagnostics.Stopwatch] $Clock, [int] $TimeoutMilliseconds) {
    $remaining = $TimeoutMilliseconds - [int]$Clock.ElapsedMilliseconds
    if ($remaining -le 0) { return 0 }
    return [Math]::Min($remaining, [int]::MaxValue)
}

function Write-AdmissionEvidencePipeWithDeadline([IO.Pipes.PipeStream] $Pipe,
    [byte[]] $Bytes, [Diagnostics.Stopwatch] $Clock, [int] $TimeoutMilliseconds,
    $WriteAttemptState) {
    if ($null -eq $WriteAttemptState -or $WriteAttemptState.PSObject.Properties['State'] -eq $null -or
        $WriteAttemptState.PSObject.Properties['AbortedTask'] -eq $null) {
        throw 'An explicit request-write disposition object is required.'
    }
    $remaining = Get-AdmissionEvidenceRemainingMilliseconds $Clock $TimeoutMilliseconds
    if ($remaining -le 0) { throw [TimeoutException]::new('Admission evidence transport deadline exceeded before request write.') }
    $cancellation = [Threading.CancellationTokenSource]::new()
    $writeTask = $null
    try {
        $WriteAttemptState.State = 'REQUEST_DELIVERY_IN_PROGRESS'
        $writeTask = $Pipe.WriteAsync($Bytes, 0, $Bytes.Length, $cancellation.Token)
        try { $completed = $writeTask.Wait($remaining) }
        catch [AggregateException] { throw $_.Exception.GetBaseException() }
        if (-not $completed) {
            $cancellation.Cancel()
            try { $Pipe.Dispose() } catch { }
            # Close aborts the pending overlapped I/O; observe any later fault
            # without extending the whole transport deadline.
            $WriteAttemptState.AbortedTask = $writeTask
            [SafeUploadAdmissionEvidence.Client.Native]::ObserveTaskFailure($writeTask)
            throw [TimeoutException]::new('Admission evidence request write exceeded the whole transport deadline.')
        }
        [void]$writeTask.GetAwaiter().GetResult()
        if ((Get-AdmissionEvidenceRemainingMilliseconds $Clock $TimeoutMilliseconds) -le 0) {
            try { $Pipe.Dispose() } catch { }
            throw [TimeoutException]::new('Admission evidence request write completed at or beyond the whole transport deadline.')
        }
        $WriteAttemptState.State = 'REQUEST_DELIVERY_COMPLETE'
    }
    catch {
        if ($WriteAttemptState.State -eq 'REQUEST_DELIVERY_IN_PROGRESS') {
            $WriteAttemptState.State = 'REQUEST_DELIVERY_INDETERMINATE'
        }
        throw
    }
    finally { $cancellation.Dispose() }
}

function New-AdmissionEvidenceFrameState {
    return [pscustomobject]@{
        FrameCount = 0; FrameKinds = New-Object 'System.Collections.Generic.List[int]'
        BindingReceiptSeen = $false; RawCallCount = 0; Terminal = $false
        TerminalKind = $null; ErrorCode = $null; Summary = $null
        FrameBinding = $null; StopwatchFrequency = $null
        BindingGeneration = $null; AcceptedPolicyVersion = $null
        CanonicalCandidatePolicyFingerprint = $null; ServiceProcessId = $null
        ProtocolPhase = 0; ActivatingAttempt = 0; ActivatingLastStart = $null
        ActivatingPagesInAttempt = 0; ActivatingAttemptCount = 0
        RawActivatingBytes = [long]0
    }
}

function Read-AdmissionEvidenceExact([IO.Stream] $Pipe,
    [IO.Stream] $ResponseFile, [Security.Cryptography.SHA256] $Sha,
    $ResponseCounter, [int] $Count, [Diagnostics.Stopwatch] $Clock,
    [int] $TimeoutMilliseconds) {
    if ($Count -lt 0 -or $Count -gt $script:AdmissionEvidenceMaxFrameBytes) {
        throw [IO.InvalidDataException]::new('Admission evidence read length is outside its bound.')
    }
    $memory = New-Object IO.MemoryStream
    try {
        $buffer = New-Object byte[] ([Math]::Min(8192, [Math]::Max(1, $Count)))
        $remaining = $Count
        while ($remaining -gt 0) {
            $timeLeft = Get-AdmissionEvidenceRemainingMilliseconds $Clock $TimeoutMilliseconds
            if ($timeLeft -le 0) { throw [TimeoutException]::new('Admission evidence response deadline exceeded.') }
            $available = $null
            if ($Pipe -is [IO.Pipes.PipeStream]) {
                $available = [SafeUploadAdmissionEvidence.Client.Native]::GetPipeAvailableBytes($Pipe.SafePipeHandle)
                if ($available -lt 0) { throw [IO.EndOfStreamException]::new('Admission evidence pipe closed mid-frame.') }
                if ($available -eq 0) {
                    [Threading.Thread]::Sleep([Math]::Min(10, $timeLeft))
                    continue
                }
            }
            $responseRoom = $script:AdmissionEvidenceMaxResponseBytes - [long]$ResponseCounter.Value
            if ($responseRoom -le 0) { throw [IO.InvalidDataException]::new('Admission evidence response byte bound exceeded.') }
            $requestCount = [int][Math]::Min([Math]::Min([long]$buffer.Length, [long]$remaining), $responseRoom)
            if ($null -ne $available) { $requestCount = [int][Math]::Min([long]$requestCount, [long]$available) }
            try { $read = $Pipe.Read($buffer, 0, $requestCount) }
            catch [IO.IOException] {
                if ((Get-AdmissionEvidenceRemainingMilliseconds $Clock $TimeoutMilliseconds) -le 0) {
                    throw [TimeoutException]::new('Admission evidence response deadline exceeded.')
                }
                if ($Pipe -is [IO.Pipes.PipeStream] -and
                    [SafeUploadAdmissionEvidence.Client.Native]::GetPipeAvailableBytes($Pipe.SafePipeHandle) -lt 0) {
                    throw [IO.EndOfStreamException]::new('Admission evidence pipe closed mid-frame.')
                }
                throw
            }
            if ($read -le 0) { throw [IO.EndOfStreamException]::new('Admission evidence pipe closed mid-frame.') }
            $ResponseFile.Write($buffer, 0, $read)
            [void]$Sha.TransformBlock($buffer, 0, $read, $buffer, 0)
            $memory.Write($buffer, 0, $read)
            $ResponseCounter.Value += $read
            $remaining -= $read
        }
        return ,$memory.ToArray()
    }
    finally { $memory.Dispose() }
}

function Receive-AdmissionEvidenceFrames([IO.Stream] $Pipe, [IO.Stream] $ResponseFile,
    [Security.Cryptography.SHA256] $Sha, $ResponseCounter,
    [Diagnostics.Stopwatch] $Clock, [int] $TimeoutMilliseconds, $Expected, $State) {
    $state = $State
    while (-not $state.Terminal) {
        if ($state.FrameCount -ge $script:AdmissionEvidenceMaxFrames) {
            throw [IO.InvalidDataException]::new('Admission evidence frame count bound exceeded.')
        }
        $prefix = Read-AdmissionEvidenceExact $Pipe $ResponseFile $Sha $ResponseCounter 4 $Clock $TimeoutMilliseconds
        $bodyLength = [uint32][BitConverter]::ToUInt32($prefix, 0)
        if ($bodyLength -lt 8 -or $bodyLength -gt $script:AdmissionEvidenceMaxFrameBytes) {
            throw [IO.InvalidDataException]::new('Admission evidence frame length is invalid.')
        }
        if ($ResponseCounter.Value -gt ($script:AdmissionEvidenceMaxResponseBytes - [long]$bodyLength)) {
            throw [IO.InvalidDataException]::new('Admission evidence response byte bound exceeded.')
        }
        $body = Read-AdmissionEvidenceExact $Pipe $ResponseFile $Sha $ResponseCounter ([int]$bodyLength) $Clock $TimeoutMilliseconds
        Add-AdmissionEvidenceFrameToState $state $body $Expected
    }
    return $state
}

function Confirm-AdmissionEvidenceTerminalPipeClose([IO.Pipes.NamedPipeClientStream] $Pipe,
    [IO.Stream] $ResponseFile, [Security.Cryptography.SHA256] $Sha, $ResponseCounter,
    [Diagnostics.Stopwatch] $Clock, [int] $TimeoutMilliseconds) {
    $buffer = New-Object byte[] 8192
    $sawTrailingBytes = $false
    while ($true) {
        $remaining = Get-AdmissionEvidenceRemainingMilliseconds $Clock $TimeoutMilliseconds
        if ($remaining -le 0) { return [pscustomobject]@{ Closed = $false; TrailingBytes = $sawTrailingBytes; BoundExceeded = $false } }
        $available = [SafeUploadAdmissionEvidence.Client.Native]::GetPipeAvailableBytes($Pipe.SafePipeHandle)
        if ($available -lt 0) { return [pscustomobject]@{ Closed = $true; TrailingBytes = $sawTrailingBytes; BoundExceeded = $false } }
        if ($available -eq 0) {
            [Threading.Thread]::Sleep([Math]::Min(10, $remaining))
            continue
        }
        $sawTrailingBytes = $true
        $remainingBound = $script:AdmissionEvidenceMaxResponseBytes - [long]$ResponseCounter.Value
        if ($remainingBound -le 0) { return [pscustomobject]@{ Closed = $false; TrailingBytes = $true; BoundExceeded = $true } }
        $requestCount = [int][Math]::Min([Math]::Min([long]$available, [long]$buffer.Length), $remainingBound)
        $read = $Pipe.Read($buffer, 0, $requestCount)
        if ($read -le 0) { return [pscustomobject]@{ Closed = $true; TrailingBytes = $sawTrailingBytes; BoundExceeded = $false } }
        $ResponseFile.Write($buffer, 0, $read)
        [void]$Sha.TransformBlock($buffer, 0, $read, $buffer, 0)
        $ResponseCounter.Value += $read
        if ($read -lt $available -and $requestCount -eq $remainingBound) {
            return [pscustomobject]@{ Closed = $false; TrailingBytes = $true; BoundExceeded = $true }
        }
    }
}

function Get-AdmissionEvidenceJsonPropertyCount([string] $Json, [string] $Name) {
    $names = Get-AdmissionEvidenceJsonTopLevelNames $Json
    if ($null -eq $names) { $names = @() }
    return @($names | Where-Object { $_ -ceq $Name }).Count
}

function Get-AdmissionEvidenceJsonTopLevelNames([string] $Json) {
    # ConvertFrom-Json accepts duplicate object keys on Windows PowerShell 5.1.
    # Walk only the top-level member names so duplicates and unknown schema
    # fields cannot be hidden by last-value-wins deserialization.
    $position = 0
    $backslash = [char]92
    while ($position -lt $Json.Length -and [char]::IsWhiteSpace($Json[$position])) { $position++ }
    if ($position -ge $Json.Length -or $Json[$position] -cne '{') { throw 'Summary payload is not a JSON object.' }
    $position++
    $names = New-Object 'System.Collections.Generic.List[string]'
    while ($true) {
        while ($position -lt $Json.Length -and [char]::IsWhiteSpace($Json[$position])) { $position++ }
        if ($position -lt $Json.Length -and $Json[$position] -ceq '}') { $position++; break }
        if ($position -ge $Json.Length -or $Json[$position] -cne '"') { throw 'Summary JSON member name is invalid.' }
        $keyStart = $position
        $position++
        $keyClosed = $false
        while ($position -lt $Json.Length) {
            if ($Json[$position] -ceq $backslash) { $position += 2; continue }
            if ($Json[$position] -ceq '"') { $position++; $keyClosed = $true; break }
            $position++
        }
        if (-not $keyClosed) { throw 'Summary JSON member name is unterminated.' }
        $keyToken = $Json.Substring($keyStart, $position - $keyStart)
        if ($keyToken.IndexOf($backslash) -ge 0) { throw 'Summary JSON member names must use the canonical producer spelling.' }
        $key = $keyToken.Substring(1, $keyToken.Length - 2)
        [void]$names.Add([string]$key)
        while ($position -lt $Json.Length -and [char]::IsWhiteSpace($Json[$position])) { $position++ }
        if ($position -ge $Json.Length -or $Json[$position] -cne ':') { throw 'Summary JSON member separator is invalid.' }
        $position++
        while ($position -lt $Json.Length -and [char]::IsWhiteSpace($Json[$position])) { $position++ }
        if ($position -ge $Json.Length) { throw 'Summary JSON member value is missing.' }

        if ($Json[$position] -ceq '"') {
            $position++
            while ($position -lt $Json.Length) {
                if ($Json[$position] -ceq $backslash) { $position += 2; continue }
                if ($Json[$position] -ceq '"') { $position++; break }
                $position++
            }
        } elseif ($Json[$position] -ceq '{' -or $Json[$position] -ceq '[') {
            $stack = New-Object 'System.Collections.Generic.Stack[char]'
            if ($Json[$position] -ceq '{') { $stack.Push([char]'}') } else { $stack.Push([char]']') }
            $position++
            $insideString = $false
            while ($position -lt $Json.Length -and $stack.Count -gt 0) {
                $current = $Json[$position]
                if ($insideString) {
                    if ($current -ceq $backslash) { $position += 2; continue }
                    if ($current -ceq '"') { $insideString = $false }
                } elseif ($current -ceq '"') {
                    $insideString = $true
                } elseif ($current -ceq '{') {
                    $stack.Push([char]'}')
                } elseif ($current -ceq '[') {
                    $stack.Push([char]']')
                } elseif ($current -ceq '}' -or $current -ceq ']') {
                    if ($stack.Count -eq 0 -or $stack.Peek() -cne $current) { throw 'Summary JSON nesting is invalid.' }
                    [void]$stack.Pop()
                }
                $position++
            }
            if ($stack.Count -ne 0 -or $insideString) { throw 'Summary JSON member value is unterminated.' }
        } else {
            while ($position -lt $Json.Length -and $Json[$position] -cne ',' -and $Json[$position] -cne '}') { $position++ }
        }
        while ($position -lt $Json.Length -and [char]::IsWhiteSpace($Json[$position])) { $position++ }
        if ($position -lt $Json.Length -and $Json[$position] -ceq ',') { $position++; continue }
        if ($position -lt $Json.Length -and $Json[$position] -ceq '}') { $position++; break }
        throw 'Summary JSON object separator is invalid.'
    }
    while ($position -lt $Json.Length -and [char]::IsWhiteSpace($Json[$position])) { $position++ }
    if ($position -ne $Json.Length) { throw 'Summary JSON contains trailing bytes.' }
    return $names.ToArray()
}

function Test-AdmissionEvidenceAllZero([byte[]] $Bytes) {
    foreach ($value in $Bytes) { if ($value -ne 0) { return $false } }
    return $true
}

function Get-AdmissionEvidenceRawJsonNumber([string] $Json, [string] $Name) {
    $pattern = '"' + [Regex]::Escape($Name) + '"\s*:\s*(?<n>0|[1-9][0-9]*)\s*[,}]'
    $matches = [Regex]::Matches($Json, $pattern)
    if ($matches.Count -ne 1) { throw 'Summary unsigned numeric field is missing or duplicated.' }
    return [string]$matches[0].Groups['n'].Value
}

function Get-AdmissionEvidenceRawJsonNullableNumber([string] $Json, [string] $Name) {
    $pattern = '"' + [Regex]::Escape($Name) + '"\s*:\s*(?<n>null|0|[1-9][0-9]*)\s*[,}]'
    $matches = [Regex]::Matches($Json, $pattern)
    if ($matches.Count -ne 1) { throw 'Summary nullable numeric field is missing or duplicated.' }
    return [string]$matches[0].Groups['n'].Value
}

function Get-AdmissionEvidenceCountAssessment([uint64] $Count) {
    if ($Count -eq 0) { return 'Absent' }
    if ($Count -eq 1) { return 'Unique' }
    return 'Ambiguous'
}

function ConvertFrom-AdmissionEvidenceSummary([byte[]] $Payload, $Expected) {
    $json = $script:AdmissionEvidenceUtf8Strict.GetString($Payload)
    $required = @('RunId', 'RequestId', 'HookOrdinal', 'VolumeGuid', 'VolumeSerial', 'FileIdHex', 'Outcome', 'Reason',
        'StableActivatingSnapshot', 'RawActivatingBytes', 'TargetEntryMatches', 'TargetAssessment', 'TargetState',
        'TargetGeneration', 'TargetH', 'TargetS', 'TargetC', 'TargetT', 'TargetW', 'TargetUnknownReasons',
        'VolumeGuidMatchesBefore', 'VolumeGuidMatchesAfter', 'VolumeGuidAssessmentBefore',
        'VolumeGuidAssessmentAfter', 'VolumeSnapshotsByteIdentical', 'PolicyGenerationBefore',
        'EpochGenerationBefore', 'PolicyGenerationAfter', 'EpochGenerationAfter', 'ActivatingPolicyGeneration',
        'ActivatingChangeSequence', 'BindingGenerationStable', 'BindingGeneration', 'AcceptedPolicyVersion',
        'CanonicalCandidatePolicyFingerprint', 'BindingPolicyGeneration', 'BindingEpochGeneration',
        'BindingEpochFlags', 'BindingChangeSequence', 'ServiceProcessId', 'ServiceSid', 'CallerProcessId',
        'CallerSid', 'BindingReceiptIncluded', 'ReadyClaim')
    $propertyNames = Get-AdmissionEvidenceJsonTopLevelNames $json
    if ($null -eq $propertyNames) { $propertyNames = @() }
    if ($propertyNames.Count -ne $required.Count) { throw 'Summary field count differs from the strict producer schema.' }
    foreach ($name in $required) {
        if ((@($propertyNames | Where-Object { $_ -ceq $name }).Count) -ne 1) {
            throw 'Summary omitted, duplicated, or renamed a producer field.'
        }
    }
    $summary = ConvertFrom-Json -InputObject $json -ErrorAction Stop
    if ($null -eq $summary -or $summary -is [Array]) { throw 'Summary payload is not one JSON object.' }
    foreach ($name in @('StableActivatingSnapshot', 'VolumeSnapshotsByteIdentical', 'BindingGenerationStable',
        'BindingReceiptIncluded', 'ReadyClaim')) {
        if ($summary.$name -isnot [bool]) { throw 'Summary Boolean field has the wrong JSON type.' }
    }
    foreach ($name in @('RunId', 'RequestId', 'VolumeGuid', 'FileIdHex', 'Outcome', 'Reason',
        'TargetAssessment', 'VolumeGuidAssessmentBefore', 'VolumeGuidAssessmentAfter',
        'CanonicalCandidatePolicyFingerprint', 'ServiceSid', 'CallerSid')) {
        if ($summary.$name -isnot [string]) { throw 'Summary string field has the wrong JSON type.' }
    }
    if ([Guid]::Parse([string]$summary.RunId) -ne [Guid]$Expected.RunGuid -or
        [Guid]::Parse([string]$summary.RequestId) -ne [Guid]$Expected.RequestGuid -or
        (Get-AdmissionEvidenceRawJsonNumber $json 'HookOrdinal') -cne ([byte]$Expected.HookOrdinal).ToString([Globalization.CultureInfo]::InvariantCulture) -or
        [string]$summary.VolumeGuid -ine [string]$Expected.Identity.NativeVolumeGuid -or
        (Get-AdmissionEvidenceRawJsonNumber $json 'VolumeSerial') -cne ([uint64]$Expected.Identity.VolumeSerial).ToString([Globalization.CultureInfo]::InvariantCulture) -or
        [string]$summary.FileIdHex -cne [string]$Expected.Identity.FileIdHex -or
        (Get-AdmissionEvidenceRawJsonNumber $json 'ServiceProcessId') -cne ([uint32]$Expected.ServiceIdentity.ProcessId).ToString([Globalization.CultureInfo]::InvariantCulture)) {
        throw 'Summary target or request correlation did not match the request.'
    }
    $generationText = Get-AdmissionEvidenceRawJsonNumber $json 'BindingGeneration'
    $policyVersionText = Get-AdmissionEvidenceRawJsonNumber $json 'AcceptedPolicyVersion'
    if ($generationText -cne ([long]$Expected.FrameBinding.BindingGeneration).ToString([Globalization.CultureInfo]::InvariantCulture) -or
        $policyVersionText -cne ([int]$Expected.FrameBinding.AcceptedPolicyVersion).ToString([Globalization.CultureInfo]::InvariantCulture) -or
        [string]$summary.CanonicalCandidatePolicyFingerprint -cne [string]$Expected.FrameBinding.CanonicalCandidatePolicyFingerprint) {
        throw 'Summary binding identity differs from its raw call frames.'
    }
    if ([string]$summary.CanonicalCandidatePolicyFingerprint -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'Summary policy fingerprint is not one SHA-256 value.'
    }
    if ([string]$summary.Reason -notmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or
        [string]$summary.ServiceSid -cne 'S-1-5-18' -or
        [string]$summary.CallerSid -notmatch '^S-1-(?:[0-9]+-)*[0-9]+$') {
        throw 'Summary reason or service/caller SID is outside the bounded diagnostic schema.'
    }
    if ($summary.ReadyClaim -isnot [bool] -or $summary.ReadyClaim) {
        throw 'The endpoint summary made an unexpected Ready claim.'
    }
    if ([string]$summary.Outcome -cnotin @('EvidenceCaptured', 'EvidenceIncomplete')) {
        throw 'Summary outcome is outside the raw-capture contract.'
    }
    if ($summary.StableActivatingSnapshot -isnot [bool]) { throw 'Summary stability field is not Boolean.' }
    $assessments = @('Unavailable', 'Absent', 'Unique', 'Ambiguous')
    foreach ($name in @('TargetAssessment', 'VolumeGuidAssessmentBefore', 'VolumeGuidAssessmentAfter')) {
        if ([string]$summary.$name -cnotin $assessments) {
            throw 'Summary target assessment is outside its explicit state set.'
        }
    }
    $countTexts = @(
        (Get-AdmissionEvidenceRawJsonNumber $json 'TargetEntryMatches'),
        (Get-AdmissionEvidenceRawJsonNumber $json 'VolumeGuidMatchesBefore'),
        (Get-AdmissionEvidenceRawJsonNumber $json 'VolumeGuidMatchesAfter'))
    $counts = @()
    foreach ($countText in $countTexts) {
        $countValue = [uint64]::Parse($countText, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture)
        if ($countValue -gt [uint32]::MaxValue) { throw 'Summary count exceeds the producer UINT32 bound.' }
        $counts += $countValue
    }
    $rawActivatingText = Get-AdmissionEvidenceRawJsonNumber $json 'RawActivatingBytes'
    $rawActivatingBytes = [uint64]::Parse($rawActivatingText,
        [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture)
    if ($rawActivatingBytes -gt [uint64]$script:AdmissionEvidenceMaxActivatingBytes -or
        $rawActivatingBytes -ne [uint64]$Expected.RawActivatingBytes) {
        throw 'Summary Control 19 byte count disagrees with the retained raw frames or producer budget.'
    }
    foreach ($name in @('PolicyGenerationBefore', 'EpochGenerationBefore', 'PolicyGenerationAfter',
        'EpochGenerationAfter', 'ActivatingPolicyGeneration', 'BindingPolicyGeneration',
        'BindingEpochGeneration', 'BindingEpochFlags')) {
        $value = Get-AdmissionEvidenceRawJsonNullableNumber $json $name
        if ($value -cne 'null' -and [uint64]::Parse($value,
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture) -gt [uint32]::MaxValue) {
            throw 'Summary generation field exceeds the producer UINT32 bound.'
        }
    }
    foreach ($name in @('ActivatingChangeSequence', 'BindingChangeSequence')) {
        $value = Get-AdmissionEvidenceRawJsonNullableNumber $json $name
        if ($value -cne 'null') {
            [void][uint64]::Parse($value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture)
        }
    }
    foreach ($name in @('TargetEntryMatches', 'VolumeGuidMatchesBefore', 'VolumeGuidMatchesAfter',
        'ServiceProcessId', 'CallerProcessId', 'HookOrdinal', 'AcceptedPolicyVersion')) {
        $value = [uint64]::Parse((Get-AdmissionEvidenceRawJsonNumber $json $name),
            [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture)
        if ($value -gt [uint32]::MaxValue) { throw 'Summary unsigned field exceeds the producer UINT32 bound.' }
    }
    if ([uint64]::Parse((Get-AdmissionEvidenceRawJsonNumber $json 'AcceptedPolicyVersion'),
        [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture) -gt [int]::MaxValue) {
        throw 'Summary policy version exceeds the producer Int32 bound.'
    }
    $targetExpected = if ($summary.StableActivatingSnapshot) {
        Get-AdmissionEvidenceCountAssessment ([uint64]$counts[0])
    } else { 'Unavailable' }
    $beforeExpected = if ([string]$summary.VolumeGuidAssessmentBefore -ceq 'Unavailable') {
        'Unavailable'
    } else { Get-AdmissionEvidenceCountAssessment ([uint64]$counts[1]) }
    $afterExpected = if ([string]$summary.VolumeGuidAssessmentAfter -ceq 'Unavailable') {
        'Unavailable'
    } else { Get-AdmissionEvidenceCountAssessment ([uint64]$counts[2]) }
    if ([string]$summary.TargetAssessment -cne $targetExpected -or
        [string]$summary.VolumeGuidAssessmentBefore -cne $beforeExpected -or
        [string]$summary.VolumeGuidAssessmentAfter -cne $afterExpected) {
        throw 'Summary assessments disagree with the explicit match counts.'
    }
    if (($beforeExpected -ceq 'Unavailable' -and $counts[1] -ne 0) -or
        ($afterExpected -ceq 'Unavailable' -and $counts[2] -ne 0)) {
        throw 'Unavailable volume assessments carry a nonzero match count.'
    }
    if (-not $summary.BindingReceiptIncluded -or
        ($summary.VolumeSnapshotsByteIdentical -and
            ($beforeExpected -ceq 'Unavailable' -or $afterExpected -ceq 'Unavailable' -or
             $counts[1] -ne $counts[2] -or $beforeExpected -cne $afterExpected))) {
        throw 'Summary receipt or Control 23 byte-identity metadata is inconsistent.'
    }
    if ($summary.BindingGenerationStable -and
        ($null -eq $summary.PolicyGenerationBefore -or $null -eq $summary.EpochGenerationBefore -or
         $null -eq $summary.PolicyGenerationAfter -or $null -eq $summary.EpochGenerationAfter -or
         $null -eq $summary.BindingPolicyGeneration -or $null -eq $summary.BindingEpochGeneration)) {
        throw 'Stable binding metadata omitted an observed generation.'
    }
    if ([string]$summary.Outcome -ceq 'EvidenceCaptured' -and
        (-not $summary.StableActivatingSnapshot -or $beforeExpected -ceq 'Unavailable' -or
         $afterExpected -ceq 'Unavailable' -or -not $summary.VolumeSnapshotsByteIdentical -or
         -not $summary.BindingGenerationStable -or $rawActivatingBytes -eq 0)) {
        throw 'EvidenceCaptured summary omits a stable producer observation.'
    }
    $targetFields = @('TargetState', 'TargetGeneration', 'TargetH', 'TargetS', 'TargetC', 'TargetT', 'TargetW', 'TargetUnknownReasons')
    foreach ($field in $targetFields) {
        if ([string]$summary.TargetAssessment -ceq 'Unique') {
            if ($null -eq $summary.$field) { throw 'Unique target assessment omitted a producer target field.' }
            $targetValue = [uint64]::Parse((Get-AdmissionEvidenceRawJsonNumber $json $field),
                [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture)
            if ($targetValue -gt [uint32]::MaxValue) { throw 'Unique target field exceeds the producer UINT32 bound.' }
        } elseif ($null -ne $summary.$field) {
            throw 'Non-unique target assessment included a target detail field.'
        }
    }
    $assessment = [ordered]@{}
    foreach ($name in @('TargetAssessment', 'VolumeGuidAssessmentBefore', 'VolumeGuidAssessmentAfter')) {
        if ($summary.PSObject.Properties[$name]) { $assessment[$name] = [string]$summary.$name }
    }
    return [pscustomobject]@{
        Outcome = [string]$summary.Outcome
        Reason = [string]$summary.Reason
        RawActivatingBytes = [uint64]$rawActivatingBytes
        TargetAssessment = $assessment.TargetAssessment
        VolumeGuidAssessmentBefore = $assessment.VolumeGuidAssessmentBefore
        VolumeGuidAssessmentAfter = $assessment.VolumeGuidAssessmentAfter
        TargetEntryMatches = [uint32]$counts[0]
        VolumeGuidMatchesBefore = [uint32]$counts[1]
        VolumeGuidMatchesAfter = [uint32]$counts[2]
        StableActivatingSnapshot = [bool]$summary.StableActivatingSnapshot
        BindingGeneration = [long]$Expected.FrameBinding.BindingGeneration
        AcceptedPolicyVersion = [int]$Expected.FrameBinding.AcceptedPolicyVersion
        CanonicalCandidatePolicyFingerprint = [string]$Expected.FrameBinding.CanonicalCandidatePolicyFingerprint
        ServiceProcessId = [uint32]$Expected.ServiceIdentity.ProcessId
        ReadyClaim = [bool]$summary.ReadyClaim
    }
}

function Add-AdmissionEvidenceFrameToState($State, [byte[]] $Body, $Expected) {
    if ($State.Terminal) { throw 'Bytes followed a terminal admission-evidence frame.' }
    if ($Body.Length -lt 8 -or $Body.Length -gt $script:AdmissionEvidenceMaxFrameBytes) {
        throw 'SAEF frame length is outside the protocol bound.'
    }
    if ([Text.Encoding]::ASCII.GetString($Body, 0, 4) -cne 'SAEF' -or
        [BitConverter]::ToUInt16($Body, 4) -ne 1 -or $Body[7] -gt 7) {
        throw 'SAEF frame magic, version, or hook ordinal is invalid.'
    }
    $kind = [int]$Body[6]
    $State.FrameCount++
    if ($State.FrameCount -gt $script:AdmissionEvidenceMaxFrames) { throw 'SAEF frame count bound exceeded.' }
    [void]$State.FrameKinds.Add($kind)

    if ($kind -eq 4) {
        if ($Body[7] -ne 0 -or $Body.Length -le 8 -or $Body.Length -gt 104) {
            throw 'SAEF error frame shape is invalid.'
        }
        $errorCode = [Text.Encoding]::ASCII.GetString($Body, 8, $Body.Length - 8)
        if ($errorCode -notmatch '^[A-Z0-9_]{1,96}$') { throw 'SAEF error code is not fixed ASCII.' }
        if ($State.FrameCount -gt 1 -and -not $State.BindingReceiptSeen) {
            throw 'A capture error followed an invalid frame prefix.'
        }
        $State.Terminal = $true
        $State.TerminalKind = 'Error'
        $State.ErrorCode = $errorCode
        return
    }

    if ($kind -eq 1 -or $kind -eq 2) {
        if ($Body.Length -lt 292) { throw 'SAEF raw-call header is truncated.' }
        $hook = [int]$Body[7]
        $flags = [int]$Body[8]
        $wireValid = [int]$Body[9]
        $validationLength = [int][BitConverter]::ToUInt16($Body, 10)
        $command = [uint32][BitConverter]::ToUInt32($Body, 44)
        $attempt = [uint32][BitConverter]::ToUInt32($Body, 48)
        $startIndex = [uint32][BitConverter]::ToUInt32($Body, 52)
        $hresult = [int][BitConverter]::ToInt32($Body, 56)
        $bytesReturned = [uint32][BitConverter]::ToUInt32($Body, 60)
        $inputLength = [int][BitConverter]::ToUInt32($Body, 64)
        $replyLength = [int][BitConverter]::ToUInt32($Body, 68)
        $startedUtcTicks = [long][BitConverter]::ToInt64($Body, 72)
        $finishedUtcTicks = [long][BitConverter]::ToInt64($Body, 80)
        $startedTimestamp = [long][BitConverter]::ToInt64($Body, 88)
        $finishedTimestamp = [long][BitConverter]::ToInt64($Body, 96)
        $stopwatchFrequency = [long][BitConverter]::ToInt64($Body, 104)
        $bindingGeneration = [long][BitConverter]::ToInt64($Body, 112)
        $acceptedPolicyVersion = [int][BitConverter]::ToInt32($Body, 120)
        $policyFingerprint = ConvertTo-AdmissionEvidenceHex ([byte[]]$Body[124..155])
        if (($flags -band 0xFC) -ne 0 -or $wireValid -gt 1 -or
            $validationLength -gt 1024 -or $inputLength -ne 16 -or
            $replyLength -ge $script:AdmissionEvidenceMaxFrameBytes -or
            $Body.Length -ne (292 + $validationLength + $inputLength + $replyLength) -or
            $bindingGeneration -le 0 -or $acceptedPolicyVersion -lt 0 -or
            $policyFingerprint -notmatch '^[A-F0-9]{64}$' -or
            $startedUtcTicks -le 0 -or $finishedUtcTicks -lt $startedUtcTicks -or
            $finishedUtcTicks -gt [DateTime]::MaxValue.Ticks -or $startedTimestamp -lt 0 -or
            $finishedTimestamp -lt $startedTimestamp -or $stopwatchFrequency -le 0) {
            throw 'SAEF raw-call lengths or flags are invalid.'
        }
        if ($null -eq $State.StopwatchFrequency) { $State.StopwatchFrequency = $stopwatchFrequency }
        elseif ($State.StopwatchFrequency -ne $stopwatchFrequency) { throw 'SAEF monotonic clock frequency changed within a capture.' }
        $frameBindingCandidate = [pscustomobject]@{
            BindingGeneration = $bindingGeneration
            AcceptedPolicyVersion = $acceptedPolicyVersion
            CanonicalCandidatePolicyFingerprint = $policyFingerprint
        }
        if ($null -ne $State.FrameBinding -and
            ($State.FrameBinding.BindingGeneration -ne $bindingGeneration -or
            $State.FrameBinding.AcceptedPolicyVersion -ne $acceptedPolicyVersion -or
            $State.FrameBinding.CanonicalCandidatePolicyFingerprint -cne $policyFingerprint)) {
            throw 'SAEF binding receipt/calls changed binding generation or policy fingerprint.'
        }
        if ($Expected.BindingContinuity.Bound -and
            ([long]$Expected.BindingContinuity.BindingGeneration -ne $bindingGeneration -or
             [int]$Expected.BindingContinuity.AcceptedPolicyVersion -ne $acceptedPolicyVersion -or
             [string]$Expected.BindingContinuity.CanonicalCandidatePolicyFingerprint -cne $policyFingerprint)) {
            throw 'SAEF binding identity changed across evidence streams.'
        }
        $runBytes = New-Object byte[] 16; [Array]::Copy($Body, 12, $runBytes, 0, 16)
        $requestBytes = New-Object byte[] 16; [Array]::Copy($Body, 28, $requestBytes, 0, 16)
        $rawInput = New-Object byte[] $inputLength
        [Array]::Copy($Body, 292 + $validationLength, $rawInput, 0, $inputLength)
        $rawReply = New-Object byte[] $replyLength
        [Array]::Copy($Body, 292 + $validationLength + $inputLength, $rawReply, 0, $replyLength)
        $inputHash = New-Object byte[] 32; [Array]::Copy($Body, 156, $inputHash, 0, 32)
        $replyHash = New-Object byte[] 32; [Array]::Copy($Body, 188, $replyHash, 0, 32)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $actualInputHash = $sha.ComputeHash($rawInput)
            $actualReplyHash = $sha.ComputeHash($rawReply)
        } finally { $sha.Dispose() }
        if ((ConvertTo-AdmissionEvidenceHex $actualInputHash) -cne (ConvertTo-AdmissionEvidenceHex $inputHash) -or
            (ConvertTo-AdmissionEvidenceHex $actualReplyHash) -cne (ConvertTo-AdmissionEvidenceHex $replyHash)) {
            throw 'SAEF raw-call content hash mismatch.'
        }
        $expectedCommand = [BitConverter]::ToUInt32($rawInput, 8)
        $protocolVersion = [BitConverter]::ToUInt32($rawInput, 0)
        $controlSize = [BitConverter]::ToUInt32($rawInput, 4)
        $reserved = [BitConverter]::ToUInt32($rawInput, 12)
        if ($protocolVersion -ne 18 -or $controlSize -ne 16 -or
            $expectedCommand -notin @(19, 20, 23) -or $command -ne $expectedCommand -or
            $startIndex -ne $reserved) {
            throw 'SAEF native input is outside the read-only status control allowlist.'
        }
        if (($expectedCommand -eq 19 -and ($reserved -gt 20480 -or ($reserved % 32) -ne 0)) -or
            ($expectedCommand -in @(20, 23) -and $reserved -ne 0)) {
            throw 'SAEF native control start index is outside its bound.'
        }
        if (($hresult -eq 0) -ne (($flags -band 0x02) -ne 0) -or
            ($replyLength -gt 0) -ne (($flags -band 0x01) -ne 0) -or
            ($hresult -ne 0 -and $replyLength -ne 0) -or
            ($wireValid -eq 1 -and ($hresult -ne 0 -or $validationLength -ne 0))) {
            throw 'SAEF returned-length or raw-reply availability flags are inconsistent.'
        }
        $expectedPayloadLength = switch ($expectedCommand) { 19 { 36136 } 20 { 32 } 23 { 6672 } }
        if ($wireValid -eq 1 -and ($replyLength -ne $expectedPayloadLength -or $bytesReturned -ne $expectedPayloadLength -or
            [BitConverter]::ToUInt32($rawReply, 0) -ne $expectedPayloadLength)) {
            throw 'SAEF valid-payload flag disagrees with the producer-sized response.'
        }

        if ($kind -eq 1) {
            if ($State.FrameCount -ne 1 -or $State.BindingReceiptSeen -or $hook -ne 0 -or
                -not (Test-AdmissionEvidenceAllZero $runBytes) -or
                -not (Test-AdmissionEvidenceAllZero $requestBytes) -or
                $expectedCommand -ne 20 -or $reserved -ne 0 -or $attempt -ne 0) {
                throw 'SAEF binding receipt is not the first uncorrelated Control 20 frame.'
            }
            $State.BindingReceiptSeen = $true
            $State.ProtocolPhase = 0
        } else {
            if (-not $State.BindingReceiptSeen -or $hook -ne [int]$Expected.HookOrdinal -or
                ([Guid]::new($runBytes) -ne [Guid]$Expected.RunGuid) -or
                ([Guid]::new($requestBytes) -ne [Guid]$Expected.RequestGuid)) {
                throw 'SAEF raw-call request correlation does not match.'
            }
            if ([BitConverter]::ToUInt64($Body, 220) -ne [uint64]$Expected.Identity.VolumeSerial -or
                (ConvertTo-AdmissionEvidenceHex ([byte[]]$Body[228..243])) -cne [string]$Expected.Identity.FileIdHex -or
                [Text.Encoding]::ASCII.GetString($Body, 244, 48) -ine [string]$Expected.Identity.NativeVolumeGuid) {
                throw 'SAEF raw-call target tuple does not match the caller handle.'
            }

            if ($expectedCommand -in @(20, 23) -and ($attempt -ne 0 -or $reserved -ne 0)) {
                throw 'SAEF scalar status call has an invalid attempt or start index.'
            }
            switch ($State.ProtocolPhase) {
                0 {
                    if ($expectedCommand -ne 20) { throw 'SAEF capture did not start with Control 20.' }
                    $State.ProtocolPhase = 1
                }
                1 {
                    if ($expectedCommand -ne 23) { throw 'SAEF capture did not place Control 23 after pre-sample Control 20.' }
                    $State.ProtocolPhase = 2
                }
                2 {
                    if ($expectedCommand -eq 19) {
                        if ($attempt -lt 1 -or $attempt -gt $script:AdmissionEvidenceMaxActivatingAttempts -or
                            $reserved -gt 20480 -or ($reserved % 32) -ne 0) {
                            throw 'SAEF Control 19 attempt or page index is outside its producer bound.'
                        }
                        if ($attempt -eq $State.ActivatingAttempt) {
                            if ($reserved -ne ($State.ActivatingLastStart + 32)) {
                                throw 'SAEF Control 19 page indices are not contiguous within an attempt.'
                            }
                        } else {
                            if ($State.ActivatingAttempt -ne 0 -and $attempt -ne ($State.ActivatingAttempt + 1)) {
                                throw 'SAEF Control 19 retry attempts are not contiguous.'
                            }
                            if ($reserved -ne 0 -or $attempt -ne ($State.ActivatingAttemptCount + 1)) {
                                throw 'SAEF Control 19 retry did not restart at page zero.'
                            }
                            $State.ActivatingAttempt = [int]$attempt
                            $State.ActivatingAttemptCount++
                            $State.ActivatingPagesInAttempt = 0
                        }
                        $State.ActivatingPagesInAttempt++
                        if ($State.ActivatingPagesInAttempt -gt $script:AdmissionEvidenceMaxActivatingPagesPerAttempt) {
                            throw 'SAEF Control 19 page count exceeds one producer attempt.'
                        }
                        $State.ActivatingLastStart = [uint32]$reserved
                        $State.RawActivatingBytes += [long]$replyLength
                        if ($State.RawActivatingBytes -gt $script:AdmissionEvidenceMaxActivatingBytes) {
                            throw 'SAEF Control 19 bytes exceed the per-capture producer budget.'
                        }
                    } elseif ($expectedCommand -eq 23 -and $State.ActivatingAttemptCount -gt 0) {
                        $State.ProtocolPhase = 3
                    } else {
                        throw 'SAEF capture omitted or misordered the Control 19 snapshot.'
                    }
                }
                3 {
                    if ($expectedCommand -ne 20) { throw 'SAEF capture did not place final Control 20 after Control 23.' }
                    $State.ProtocolPhase = 4
                }
                default { throw 'SAEF capture contains a call after final Control 20.' }
            }
        }
        if ($null -eq $State.FrameBinding) {
            $State.FrameBinding = $frameBindingCandidate
            $State.BindingGeneration = $bindingGeneration
            $State.AcceptedPolicyVersion = $acceptedPolicyVersion
            $State.CanonicalCandidatePolicyFingerprint = $policyFingerprint
        }
        if (-not $Expected.BindingContinuity.Bound) {
            $Expected.BindingContinuity.BindingGeneration = $bindingGeneration
            $Expected.BindingContinuity.AcceptedPolicyVersion = $acceptedPolicyVersion
            $Expected.BindingContinuity.CanonicalCandidatePolicyFingerprint = $policyFingerprint
            $Expected.BindingContinuity.Bound = $true
        }
        if ($kind -eq 2) { $State.RawCallCount++ }
        return
    }

    if ($kind -eq 3) {
        if ($Body[7] -ne 0 -or -not $State.BindingReceiptSeen -or $Body.Length -le 8 -or
            $State.ProtocolPhase -lt 0 -or $State.ProtocolPhase -gt 4) {
            throw 'SAEF summary frame is out of sequence or empty.'
        }
        $payload = New-Object byte[] ($Body.Length - 8)
        [Array]::Copy($Body, 8, $payload, 0, $payload.Length)
        if ($null -eq $State.FrameBinding) { throw 'Summary arrived without a binding receipt/call identity.' }
        $summaryExpected = [pscustomobject]@{
            Identity = $Expected.Identity
            ServiceIdentity = $Expected.ServiceIdentity
            RunGuid = $Expected.RunGuid
            RequestGuid = $Expected.RequestGuid
            HookOrdinal = $Expected.HookOrdinal
            FrameBinding = $State.FrameBinding
            RawActivatingBytes = $State.RawActivatingBytes
        }
        $summary = ConvertFrom-AdmissionEvidenceSummary $payload $summaryExpected
        if ($summary.Outcome -ceq 'EvidenceCaptured' -and
            ($State.ProtocolPhase -ne 4 -or $State.ActivatingAttemptCount -eq 0)) {
            throw 'EvidenceCaptured summary omitted one or more producer calls.'
        }
        $State.Terminal = $true
        $State.TerminalKind = 'Summary'
        $State.Summary = $summary
        $State.ServiceProcessId = [uint32]$summary.ServiceProcessId
        $State.BindingGeneration = $summary.BindingGeneration
        $State.AcceptedPolicyVersion = $summary.AcceptedPolicyVersion
        $State.CanonicalCandidatePolicyFingerprint = $summary.CanonicalCandidatePolicyFingerprint
        return
    }
    throw 'Unknown SAEF frame kind.'
}

function Complete-AdmissionEvidenceFrameState($State) {
    if (-not $State.Terminal) { return 'INCOMPLETE_NO_TERMINAL_FRAME' }
    if ($State.TerminalKind -eq 'Error') { return 'REMOTE_ERROR_RAW_ONLY' }
    if ($null -eq $State.Summary) { return 'PROTOCOL_INCOMPLETE' }
    if ($State.Summary.Outcome -eq 'EvidenceCaptured') { return 'CAPTURED_RAW_ONLY' }
    return 'CAPTURE_INCOMPLETE_RAW_ONLY'
}

function New-AdmissionEvidenceManifestPath([string] $EvidenceDirectory, [string] $Leaf) {
    return [IO.Path]::Combine($EvidenceDirectory, $Leaf)
}

function Invoke-AdmissionEvidenceCapture([IO.FileStream] $TargetStream,
    [SafeUploadAdmissionEvidence.Client.TargetIdentity] $ExpectedIdentity,
    [Parameter(Mandatory=$true)][SafeUploadAdmissionEvidence.Client.ProcessIdentity] $ExpectedServiceIdentity,
    [Parameter(Mandatory=$true)] $BindingContinuity,
    [Guid] $RunGuid, [Guid] $RequestGuid, [ValidateRange(2, 7)][byte] $HookOrdinal,
    [ValidatePattern('^[A-Za-z0-9_-]{1,32}$')][string] $TargetLabel,
    [string] $EvidenceDirectory,
    [ValidateRange(1000, 30000)][int] $ConnectTimeoutMilliseconds = 5000,
    [ValidateRange(10000, 300000)][int] $CaptureTimeoutMilliseconds = 300000) {

    $identity = $null
    $requestFile = $null
    $responseFile = $null
    $pipe = $null
    $responseSha = $null
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    $finishedUtc = $null
    $stateName = 'PREPARATION_FAILED'
    $failureCode = $null
    $terminalError = $null
    $summaryResult = $null
    $frameState = $null
    $responseCounter = [pscustomobject]@{ Value = [long]0 }
    $requestBytes = $null
    $requestPath = $null
    $responsePath = $null
    $manifestPath = $null
    $responseHashHex = $null
    $requestHashHex = $null
    $requestBytesHashHex = $null
    $responseStreamHashHex = $null
    $requestLeaf = $null
    $responseLeaf = $null
    $manifestLeaf = $null
    $pipeServerProcessId = $null
    $serviceIdentityBefore = $null
    $serviceIdentityBeforeSend = $null
    $serviceIdentityAfter = $null
    $serviceIdentityAfterValid = $false
    $targetIdentityAfterValid = $false

    try {
        if ($null -eq $TargetStream -or $null -eq $ExpectedIdentity -or $null -eq $ExpectedServiceIdentity -or
            $ExpectedServiceIdentity.ProcessId -le 0 -or
            [string]$ExpectedServiceIdentity.ImageSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
            $null -eq $BindingContinuity -or $BindingContinuity.PSObject.Properties['Bound'] -eq $null -or
            $BindingContinuity.PSObject.Properties['BindingGeneration'] -eq $null -or
            $BindingContinuity.PSObject.Properties['AcceptedPolicyVersion'] -eq $null -or
            $BindingContinuity.PSObject.Properties['CanonicalCandidatePolicyFingerprint'] -eq $null) {
            throw 'Target identity, pretracked service executable identity, and shared binding continuity are required.'
        }
        if ($RunGuid -eq [Guid]::Empty -or $RequestGuid -eq [Guid]::Empty) { throw 'Run and request GUIDs are required.' }
        if ([string]$TargetLabel -notmatch '^[A-Za-z0-9_-]{1,32}$') { throw 'A short safe target label is required.' }
        if ($ExpectedServiceIdentity.CreationTimeFileTime -le 0 -or
            [string]::IsNullOrWhiteSpace($ExpectedServiceIdentity.ImagePath) -or
            -not [IO.Path]::IsPathRooted([string]$ExpectedServiceIdentity.ImagePath) -or
            $null -eq $ExpectedServiceIdentity.ImageFileIdentity -or
            [string]$ExpectedServiceIdentity.ImageFileIdentity.FileIdHex -notmatch '^[A-Fa-f0-9]{32}$') {
            throw 'Expected service process identity must include birth time and a complete executable file identity.'
        }
        Assert-AdmissionEvidencePrivateRunDirectory $EvidenceDirectory $RunGuid
        $serviceIdentityBefore = [SafeUploadAdmissionEvidence.Client.Native]::GetProcessIdentity($ExpectedServiceIdentity.ProcessId)
        if (-not $ExpectedServiceIdentity.HasSameIdentity($serviceIdentityBefore)) {
            $stateName = 'SERVICE_IDENTITY_CHANGED_BEFORE_REQUEST'
            $failureCode = 'SERVICE_PROCESS_IDENTITY_MISMATCH'
            throw 'Tracked service process birth or executable identity changed before the sample.'
        }
        $identity = Get-AdmissionEvidenceTargetIdentity $TargetStream
        if (-not $ExpectedIdentity.HasSameTuple($identity)) {
            $stateName = 'IDENTITY_CHANGED_BEFORE_REQUEST'
            $failureCode = 'TARGET_TUPLE_CHANGED'
            throw 'Target identity changed before the sample.'
        }

        $expected = [pscustomobject]@{
            Identity = $ExpectedIdentity
            ServiceIdentity = $ExpectedServiceIdentity
            BindingContinuity = $BindingContinuity
            RunGuid = $RunGuid
            RequestGuid = $RequestGuid
            HookOrdinal = $HookOrdinal
        }
        $requestBytes = New-AdmissionEvidenceRequestBytes $ExpectedIdentity $RunGuid $RequestGuid $HookOrdinal
        $requestSha = [Security.Cryptography.SHA256]::Create()
        try { $requestBytesHashHex = ConvertTo-AdmissionEvidenceHex ($requestSha.ComputeHash($requestBytes)) }
        finally { $requestSha.Dispose() }
        if ($requestBytes.Length -gt (4 + $script:AdmissionEvidenceMaxRequestBytes)) { throw 'Request exceeds the outer protocol bound.' }
        $suffix = '-hook' + $HookOrdinal + '-' + $RequestGuid.ToString('N')
        $requestLeaf = $TargetLabel + $suffix + '.request.bin'
        $responseLeaf = $TargetLabel + $suffix + '.response.saef'
        $manifestLeaf = $TargetLabel + $suffix + '.receipt.json'
        $requestPath = New-AdmissionEvidenceManifestPath $EvidenceDirectory $requestLeaf
        $responsePath = New-AdmissionEvidenceManifestPath $EvidenceDirectory $responseLeaf
        $manifestPath = New-AdmissionEvidenceManifestPath $EvidenceDirectory $manifestLeaf

        $requestFile = [SafeUploadAdmissionEvidence.Client.Native]::CreatePrivateFile($requestPath)
        $requestFile.Write($requestBytes, 0, $requestBytes.Length)
        $requestFile.Flush($true)
        $requestFile.Dispose(); $requestFile = $null
        Assert-AdmissionEvidencePrivateAcl $requestPath
        $requestHashHex = Get-AdmissionEvidenceHash $requestPath

        $responseFile = [SafeUploadAdmissionEvidence.Client.Native]::CreatePrivateFile($responsePath)
        $responseSha = [Security.Cryptography.SHA256]::Create()
        $pipe = New-Object IO.Pipes.NamedPipeClientStream('.', $script:AdmissionEvidencePipeName,
            [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous,
            [Security.Principal.TokenImpersonationLevel]::Identification)
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $connectBudget = [Math]::Min($ConnectTimeoutMilliseconds, $CaptureTimeoutMilliseconds)
        $pipe.Connect([int]$connectBudget)
        $pipeServerProcessId = [SafeUploadAdmissionEvidence.Client.Native]::GetPipeServerProcessId($pipe.SafePipeHandle)
        if ($pipeServerProcessId -ne [uint32]$ExpectedServiceIdentity.ProcessId) {
            $stateName = 'SERVICE_PIPE_SERVER_MISMATCH_NO_REQUEST_SENT'
            $failureCode = 'PIPE_SERVER_PID_MISMATCH'
            throw 'Admission evidence pipe was not served by the expected live agent process.'
        }
        $serviceIdentityBeforeSend = [SafeUploadAdmissionEvidence.Client.Native]::GetProcessIdentity($ExpectedServiceIdentity.ProcessId)
        if (-not $ExpectedServiceIdentity.HasSameIdentity($serviceIdentityBeforeSend)) {
            $stateName = 'SERVICE_IDENTITY_CHANGED_NO_REQUEST_SENT'
            $failureCode = 'SERVICE_PROCESS_IDENTITY_MISMATCH'
            throw 'Tracked service process identity changed after pipe connection and before request send.'
        }
        $writeBudget = Get-AdmissionEvidenceRemainingMilliseconds $clock $CaptureTimeoutMilliseconds
        if ($writeBudget -le 0) { throw [TimeoutException]::new('Admission evidence transport deadline exceeded before request send.') }
        $writeAttemptState = [pscustomobject]@{ State = 'NOT_ATTEMPTED'; AbortedTask = $null }
        $stateName = 'REQUEST_DELIVERY_INDETERMINATE'
        Write-AdmissionEvidencePipeWithDeadline $pipe $requestBytes $clock $CaptureTimeoutMilliseconds $writeAttemptState
        if ($writeAttemptState.State -cne 'REQUEST_DELIVERY_COMPLETE') {
            throw 'Admission evidence request delivery did not complete.'
        }
        $stateName = 'TRANSPORT_IN_PROGRESS'

        $frameState = New-AdmissionEvidenceFrameState
        $frameState = Receive-AdmissionEvidenceFrames $pipe $responseFile $responseSha $responseCounter $clock $CaptureTimeoutMilliseconds $expected $frameState
        $summaryResult = $frameState.Summary
        $terminalError = $frameState.ErrorCode
        $stateName = Complete-AdmissionEvidenceFrameState $frameState
        $serviceIdentityAfter = [SafeUploadAdmissionEvidence.Client.Native]::GetProcessIdentity($ExpectedServiceIdentity.ProcessId)
        if (-not $ExpectedServiceIdentity.HasSameIdentity($serviceIdentityAfter)) {
            $stateName = 'SERVICE_IDENTITY_CHANGED_RAW_RETAINED'
            $failureCode = 'SERVICE_PROCESS_IDENTITY_CHANGED_DURING_CAPTURE'
        } else {
            $serviceIdentityAfterValid = $true
        }

        # A terminal frame is followed by server-side pipe disposal. Reject
        # unexpected trailing bytes, and bound the close wait by the same
        # monotonic capture deadline. Bounded PeekNamedPipe polling avoids
        # unsupported PipeStream timeout setters and distinguishes an open idle
        # pipe from terminal EOF.
        $closeResult = Confirm-AdmissionEvidenceTerminalPipeClose $pipe $responseFile $responseSha `
            $responseCounter $clock $CaptureTimeoutMilliseconds
        if ($closeResult.TrailingBytes) {
            $stateName = 'PROTOCOL_TRAILING_BYTES_RAW_RETAINED'
            $failureCode = if ($closeResult.BoundExceeded) { 'RESPONSE_BOUND_EXCEEDED' } else { 'TRAILING_BYTES_AFTER_TERMINAL' }
        } elseif (-not $closeResult.Closed) {
            $stateName = 'TRANSPORT_CLOSE_NOT_CONFIRMED_RAW_RETAINED'
            $failureCode = 'TERMINAL_PIPE_CLOSE_TIMEOUT'
        }
    }
    catch {
        if (-not $failureCode) {
            $failureCode = if ($_.Exception -is [TimeoutException]) { 'TRANSPORT_DEADLINE_EXCEEDED' }
                elseif ($_.Exception -is [IO.EndOfStreamException]) { 'TRANSPORT_EOF_MID_FRAME' }
                elseif ($_.Exception -is [IO.InvalidDataException]) { 'PROTOCOL_BOUND_OR_FRAME_ERROR' }
                elseif ($_.Exception -is [IO.IOException]) { 'TRANSPORT_IO_ERROR' }
                else { 'LOCAL_CAPTURE_ERROR' }
        }
        if ($stateName -in @('TRANSPORT_IN_PROGRESS', 'CAPTURED_RAW_ONLY', 'CAPTURE_INCOMPLETE_RAW_ONLY', 'REMOTE_ERROR_RAW_ONLY')) {
            $stateName = 'INCOMPLETE_RAW_RETAINED'
        }
        # Do not expose exception text, target paths, raw names, or PIDs.
    }
    finally {
        if ($null -ne $responseFile) {
            try { $responseFile.Flush($true) } catch { if (-not $failureCode) { $failureCode = 'RESPONSE_DURABLE_FLUSH_FAILED' } }
            try { $responseFile.Dispose() } catch { if (-not $failureCode) { $failureCode = 'RESPONSE_CLOSE_FAILED' } }
        }
        if ($null -ne $requestFile) { try { $requestFile.Dispose() } catch { } }
        if ($null -ne $pipe) { try { $pipe.Dispose() } catch { } }
        if ($null -ne $responseSha) {
            try {
                [void]$responseSha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
                $responseStreamHashHex = ConvertTo-AdmissionEvidenceHex ([byte[]]$responseSha.Hash)
            } catch { }
            $responseSha.Dispose()
        }
    }

    if ($null -ne $requestPath -and (Test-Path -LiteralPath $requestPath -PathType Leaf)) {
        try {
            Assert-AdmissionEvidenceNoReparseAncestors $EvidenceDirectory
            Assert-AdmissionEvidenceTrustedParent ([IO.Path]::GetDirectoryName($EvidenceDirectory))
            Assert-AdmissionEvidencePrivateAcl $requestPath
            $requestHashHex = Get-AdmissionEvidenceHash $requestPath
            if ($requestHashHex -cne $requestBytesHashHex) { throw 'Persisted request bytes differ from the single transmitted request.' }
        }
        catch { if (-not $failureCode) { $failureCode = 'REQUEST_EVIDENCE_VERIFY_FAILED' }; $stateName = 'EVIDENCE_PERSISTENCE_INCOMPLETE' }
    }
    if ($null -ne $responsePath -and (Test-Path -LiteralPath $responsePath -PathType Leaf)) {
        try {
            Assert-AdmissionEvidenceNoReparseAncestors $EvidenceDirectory
            Assert-AdmissionEvidenceTrustedParent ([IO.Path]::GetDirectoryName($EvidenceDirectory))
            Assert-AdmissionEvidencePrivateAcl $responsePath
            $responseHashHex = Get-AdmissionEvidenceHash $responsePath
            if ($responseHashHex -cne $responseStreamHashHex) { throw 'Persisted framed response differs from captured pipe bytes.' }
            if ((Get-Item -LiteralPath $responsePath -Force).Length -ne [long]$responseCounter.Value) {
                throw 'Persisted framed response length differs from bytes captured from the pipe.'
            }
        }
        catch { if (-not $failureCode) { $failureCode = 'RESPONSE_EVIDENCE_VERIFY_FAILED' }; $stateName = 'EVIDENCE_PERSISTENCE_INCOMPLETE' }
    }

    if ($null -ne $ExpectedServiceIdentity -and $null -ne $serviceIdentityBefore) {
        try {
            $serviceIdentityAfter = [SafeUploadAdmissionEvidence.Client.Native]::GetProcessIdentity($ExpectedServiceIdentity.ProcessId)
            if (-not $ExpectedServiceIdentity.HasSameIdentity($serviceIdentityAfter)) {
                $failureCode = 'SERVICE_PROCESS_IDENTITY_CHANGED_DURING_CAPTURE'
                $stateName = 'SERVICE_IDENTITY_CHANGED_RAW_RETAINED'
                $serviceIdentityAfterValid = $false
            } else { $serviceIdentityAfterValid = $true }
        } catch {
            if (-not $failureCode) { $failureCode = 'SERVICE_PROCESS_IDENTITY_RECHECK_FAILED' }
            $stateName = 'SERVICE_IDENTITY_RECHECK_INCOMPLETE_RAW_RETAINED'
            $serviceIdentityAfterValid = $false
        }
    }

    $postIdentity = $null
    if ($null -ne $ExpectedIdentity -and $null -ne $TargetStream) {
        try {
            $postIdentity = Get-AdmissionEvidenceTargetIdentity $TargetStream
            if (-not $ExpectedIdentity.HasSameTuple($postIdentity)) {
                $failureCode = 'TARGET_TUPLE_CHANGED_AFTER_SAMPLE'
                $stateName = 'IDENTITY_CHANGED_RAW_RETAINED'
            } else { $targetIdentityAfterValid = $true }
        } catch {
            if (-not $failureCode) { $failureCode = 'TARGET_IDENTITY_RECHECK_FAILED' }
            $stateName = 'IDENTITY_RECHECK_INCOMPLETE_RAW_RETAINED'
        }
    }
    if ($null -ne $frameState -and $null -ne $frameState.FrameBinding -and
        -not $BindingContinuity.Bound) {
        $BindingContinuity.BindingGeneration = $frameState.BindingGeneration
        $BindingContinuity.AcceptedPolicyVersion = $frameState.AcceptedPolicyVersion
        $BindingContinuity.CanonicalCandidatePolicyFingerprint = $frameState.CanonicalCandidatePolicyFingerprint
        $BindingContinuity.Bound = $true
    }
    $finishedUtc = [DateTime]::UtcNow.ToString('o')

    if ($null -ne $manifestPath -and $null -ne $requestPath -and $null -ne $responsePath) {
        try {
            Assert-AdmissionEvidencePrivateRunDirectory $EvidenceDirectory $RunGuid
            $manifest = [ordered]@{
                Schema = 'SafeUploadAdmissionEvidenceClientReceiptV1'
                RunGuid = $RunGuid.ToString('D')
                RequestGuid = $RequestGuid.ToString('D')
                HookOrdinal = [int]$HookOrdinal
                ExpectedServiceProcessId = [uint32]$ExpectedServiceIdentity.ProcessId
                ExpectedServiceCreationTimeFileTime = [long]$ExpectedServiceIdentity.CreationTimeFileTime
                ExpectedServiceImagePath = [string]$ExpectedServiceIdentity.ImagePath
                ExpectedServiceImageSha256 = [string]$ExpectedServiceIdentity.ImageSha256
                ExpectedServiceImageVolumeGuid = [string]$ExpectedServiceIdentity.ImageFileIdentity.NativeVolumeGuid
                ExpectedServiceImageVolumeSerial = ([uint64]$ExpectedServiceIdentity.ImageFileIdentity.VolumeSerial).ToString([Globalization.CultureInfo]::InvariantCulture)
                ExpectedServiceImageFileIdHex = [string]$ExpectedServiceIdentity.ImageFileIdentity.FileIdHex
                ServiceIdentityBeforeSendCreationTimeFileTime = if ($serviceIdentityBeforeSend) { [long]$serviceIdentityBeforeSend.CreationTimeFileTime } else { $null }
                ServiceIdentityBeforeSendImagePath = if ($serviceIdentityBeforeSend) { [string]$serviceIdentityBeforeSend.ImagePath } else { $null }
                ServiceIdentityBeforeSendImageSha256 = if ($serviceIdentityBeforeSend) { [string]$serviceIdentityBeforeSend.ImageSha256 } else { $null }
                ServiceIdentityBeforeSendImageVolumeGuid = if ($serviceIdentityBeforeSend) { [string]$serviceIdentityBeforeSend.ImageFileIdentity.NativeVolumeGuid } else { $null }
                ServiceIdentityBeforeSendImageVolumeSerial = if ($serviceIdentityBeforeSend) { ([uint64]$serviceIdentityBeforeSend.ImageFileIdentity.VolumeSerial).ToString([Globalization.CultureInfo]::InvariantCulture) } else { $null }
                ServiceIdentityBeforeSendImageFileIdHex = if ($serviceIdentityBeforeSend) { [string]$serviceIdentityBeforeSend.ImageFileIdentity.FileIdHex } else { $null }
                ServiceIdentityAfterProcessId = if ($serviceIdentityAfter) { [uint32]$serviceIdentityAfter.ProcessId } else { $null }
                ServiceIdentityAfterCreationTimeFileTime = if ($serviceIdentityAfter) { [long]$serviceIdentityAfter.CreationTimeFileTime } else { $null }
                ServiceIdentityAfterImagePath = if ($serviceIdentityAfter) { [string]$serviceIdentityAfter.ImagePath } else { $null }
                ServiceIdentityAfterImageSha256 = if ($serviceIdentityAfter) { [string]$serviceIdentityAfter.ImageSha256 } else { $null }
                ServiceIdentityAfterImageVolumeGuid = if ($serviceIdentityAfter) { [string]$serviceIdentityAfter.ImageFileIdentity.NativeVolumeGuid } else { $null }
                ServiceIdentityAfterImageVolumeSerial = if ($serviceIdentityAfter) { ([uint64]$serviceIdentityAfter.ImageFileIdentity.VolumeSerial).ToString([Globalization.CultureInfo]::InvariantCulture) } else { $null }
                ServiceIdentityAfterImageFileIdHex = if ($serviceIdentityAfter) { [string]$serviceIdentityAfter.ImageFileIdentity.FileIdHex } else { $null }
                ServiceIdentityAfterMatchesExpected = [bool]$serviceIdentityAfterValid
                PipeServerProcessId = if ($pipeServerProcessId) { $pipeServerProcessId } else { $null }
                TargetLabel = $TargetLabel
                VolumeGuid = if ($ExpectedIdentity) { [string]$ExpectedIdentity.NativeVolumeGuid } else { $null }
                VolumeSerial = if ($ExpectedIdentity) { ([uint64]$ExpectedIdentity.VolumeSerial).ToString([Globalization.CultureInfo]::InvariantCulture) } else { $null }
                FileIdHex = if ($ExpectedIdentity) { [string]$ExpectedIdentity.FileIdHex } else { $null }
                TargetIdentityAfterVolumeGuid = if ($postIdentity) { [string]$postIdentity.NativeVolumeGuid } else { $null }
                TargetIdentityAfterVolumeSerial = if ($postIdentity) { ([uint64]$postIdentity.VolumeSerial).ToString([Globalization.CultureInfo]::InvariantCulture) } else { $null }
                TargetIdentityAfterFileIdHex = if ($postIdentity) { [string]$postIdentity.FileIdHex } else { $null }
                TargetIdentityAfterMatchesExpected = [bool]$targetIdentityAfterValid
                StartedUtc = $startedUtc
                FinishedUtc = $finishedUtc
                State = $stateName
                FailureCode = $failureCode
                TerminalErrorCode = $terminalError
                SummaryOutcome = if ($summaryResult) { $summaryResult.Outcome } else { $null }
                TargetAssessment = if ($summaryResult) { $summaryResult.TargetAssessment } else { $null }
                VolumeGuidAssessmentBefore = if ($summaryResult) { $summaryResult.VolumeGuidAssessmentBefore } else { $null }
                VolumeGuidAssessmentAfter = if ($summaryResult) { $summaryResult.VolumeGuidAssessmentAfter } else { $null }
                ReadyClaim = $false
                RequestLeaf = $requestLeaf
                RequestLength = if ($requestPath -and (Test-Path -LiteralPath $requestPath)) { (Get-Item -LiteralPath $requestPath).Length } else { $null }
                RequestSha256 = $requestHashHex
                ResponseLeaf = $responseLeaf
                ResponseLength = if ($responsePath -and (Test-Path -LiteralPath $responsePath)) { (Get-Item -LiteralPath $responsePath).Length } else { [long]0 }
                ResponseSha256 = $responseHashHex
                FrameCount = if ($frameState) { $frameState.FrameCount } else { 0 }
                FrameKinds = if ($frameState) { @($frameState.FrameKinds) } else { @() }
                RawCallCount = if ($frameState) { $frameState.RawCallCount } else { 0 }
                BindingGeneration = if ($frameState) { $frameState.BindingGeneration } else { $null }
                AcceptedPolicyVersion = if ($frameState) { $frameState.AcceptedPolicyVersion } else { $null }
                CanonicalCandidatePolicyFingerprint = if ($frameState) { $frameState.CanonicalCandidatePolicyFingerprint } else { $null }
                BindingContinuityPinned = [bool]$BindingContinuity.Bound
                ConnectTimeoutMilliseconds = $ConnectTimeoutMilliseconds
                CaptureTimeoutMilliseconds = $CaptureTimeoutMilliseconds
            }
            $manifestBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((ConvertTo-Json -InputObject $manifest -Depth 6 -Compress))
            $manifestFile = [SafeUploadAdmissionEvidence.Client.Native]::CreatePrivateFile($manifestPath)
            try { $manifestFile.Write($manifestBytes, 0, $manifestBytes.Length); $manifestFile.Flush($true) }
            finally { $manifestFile.Dispose() }
            Assert-AdmissionEvidencePrivateRunDirectory $EvidenceDirectory $RunGuid
            Assert-AdmissionEvidencePrivateAcl $manifestPath
        } catch {
            if (-not $failureCode) { $failureCode = 'MANIFEST_PERSISTENCE_FAILED' }
            $stateName = 'EVIDENCE_PERSISTENCE_INCOMPLETE'
        }
    }

    return [pscustomobject]@{
        State = $stateName
        FailureCode = $failureCode
        TerminalErrorCode = $terminalError
        SummaryOutcome = if ($summaryResult) { $summaryResult.Outcome } else { $null }
        TargetAssessment = if ($summaryResult) { $summaryResult.TargetAssessment } else { $null }
        VolumeGuidAssessmentBefore = if ($summaryResult) { $summaryResult.VolumeGuidAssessmentBefore } else { $null }
        VolumeGuidAssessmentAfter = if ($summaryResult) { $summaryResult.VolumeGuidAssessmentAfter } else { $null }
        ReadyClaim = $false
        RequestLeaf = $requestLeaf
        ResponseLeaf = $responseLeaf
        ManifestLeaf = $manifestLeaf
        RequestSha256 = $requestHashHex
        ResponseSha256 = $responseHashHex
        ResponseLength = if ($responsePath -and (Test-Path -LiteralPath $responsePath)) { (Get-Item -LiteralPath $responsePath).Length } else { [long]0 }
        FrameCount = if ($frameState) { $frameState.FrameCount } else { 0 }
    }
}
