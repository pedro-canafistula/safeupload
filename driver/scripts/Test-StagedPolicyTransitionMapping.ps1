<#
Reproduce a writable mapping that predates the agent's first policy push and a
later live policy scope expansion. Run only on the recorded isolated
WIN10-DEBUGGED VM. With the feature filter attached and no agent or policy, a
GUID-scoped file pre-sized to the mapping capacity is opened, mapped writable and
its source handle closed while the section stays alive. The real agent then
pushes the baseline policy (fixture out of scope). The real policy file is
extended with the fixture directory and pushed by restarting the real agent. The
mapping is mutated after that update; no publication permit runs.

Revised 2 October 2026 for the fence slice (first version: commit 3b3bfa0): the feature driver hash is a
parameter (default: the original tested build); a refused flush through the old view is caught and
classified instead of aborting the run; a second independent observer reads with
FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH, and an unbuffered raw-volume observer checks the allocated
extent against a raw baseline of the complete 4096-byte fixture. Any byte difference from that baseline is
reported as exposure, not just a matching marker. Expansion is BLOCKED only after a successful mapped write
and view flush, successful file-buffer flush, successful disposal of that expansion-only view, and a successful
raw comparison showing the complete fixture unchanged. Filtered file-reader refusals do not replace or
invalidate the raw observer; missing flush, disposal, baseline, or raw evidence is INCONCLUSIVE.
Disposal/agent-stop errors are recorded without skipping policy or driver restoration.

The current source candidate extends this case with a policy shrink while the
old writable view and a second pre-shrink file handle remain alive. Fresh-open
refusal is recognized only for the expected sharing-violation result; other
errors are unclassified failures. The writable-section attempt is bracketed by
driver status snapshots from a hash-pinned Inspector run as LocalSystem. Only
Win32 ERROR_ACCESS_DENIED plus exactly one `sectionsDenied` increment and no
`sectionNameUnresolved` increment is reported as a correlated section-callback
denial. The counters are global and provide temporal correlation only, not
per-file attribution. Treat the one-increment result as useful only on the
isolated test machine with no other known section-creation test active. A raw
error 5 alone, an ambiguous counter delta, or missing/invalid status JSON is
never a callback pass. Exit 4 is accepted only when the Inspector still
returned valid status JSON, because it indicates incomplete sampled coverage
and is not used as a verdict here. The script checks the fixture's physical
NTFS extent through
an aligned unbuffered raw-volume read; an unobservable raw read or an
unconfirmed mapping disposal is a failed measurement. A privacy measurement
remains unavailable until scope-correct candidate coverage allows the original
policy to be accepted. The first isolated run stopped before the transition because
the approved baseline enables removable and network scopes; see
`evidence/2026-10-03/policy-transition-run22-shrink-assessment.txt`. No
byte-privacy result was produced.
Optional `-PolicyRejectionOnly` mode keeps those approved scopes unchanged and
measures the expected `ERROR_NOT_SUPPORTED` handshake. It requires no agent
ready signal, the exact `FilterPort.SetPolicy` exception and policy-push stack,
and stable pre/post fence generation and entry count with rejected-scan
telemetry. The service runs from a fresh extraction of the SHA-256-pinned
package, hashed and parsed through one held read-only handle. The extraction is
created as a direct child of the canonical Program Files folder after checking
that its local NTFS volume and every ancestor have trusted owners and ACLs.
The new directory's protected Administrators/SYSTEM ACL is set atomically at
creation. Member paths, ancestors, ACLs, and reparse points are checked before
execution and recursive cleanup. The current status protocol does not expose
policy generation, so this mode claims neither runtime generation readback nor
full-scope privacy; it never narrows the policy or enters the mapping scenarios.
The test does not force the exact kernel callback interleaving between policy
snapshots; a user-mode policy push cannot deterministically pause the callback.

The expansion case also retains a writable file-mapping section handle created
while the fixture is out of scope, without creating a process view until after
the candidate policy is accepted. It then writes through that late-created view
and measures the separate file extent through an independent raw-volume read.
This probes whether a retained section object with no process view is present in
the fence's user-writable-reference query, and whether a later view-map/write
can proceed after policy acceptance. Any changed byte in the complete raw extent
or the exact marker from the separate uncached reader is exposure; the uncached
reader is supplemental, and a refusal there is not a substitute for raw evidence.
A blocked result requires a successful mapped write, both view and file-buffer
flushes, confirmed disposal, and a complete unchanged raw comparison. Mapping,
flush, disposal, or raw-observer failures are inconclusive.
#>
param(
    [string] $ExpectedFeatureSha256 = 'ACED8226913E062E5D3EE6FD0CF96963C3FD2C1FB2242EDBEDBB00768CCD44F8',
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedInspectorSha256,
    [ValidateRange(5, 120)]
    [int] $InspectorTimeoutSeconds = 45,
    [switch] $Verifier,
    [switch] $PolicyRejectionOnly
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
Add-Type -Namespace SafeUploadRepro -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytes, out uint read, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, ExactSpelling=true)]
public static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protect, uint maxSizeHigh, uint maxSizeLow, string name);
[DllImport("kernel32.dll", SetLastError=false)]
public static extern void SetLastError(uint error);
public static IntPtr CreateFileMappingWWithError(IntPtr file, IntPtr attributes, uint protect, uint maxSizeHigh, uint maxSizeLow, string name, out int error) {
    SetLastError(0);
    IntPtr result = CreateFileMappingW(file, attributes, protect, maxSizeHigh, maxSizeLow, name);
    error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    return result;
}
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint offsetHigh, uint offsetLow, UIntPtr size);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool UnmapViewOfFile(IntPtr address);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushViewOfFile(IntPtr address, UIntPtr size);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushFileBuffers(IntPtr file);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint method);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
'@
# Uncached, write-through read of the first Length bytes through a NEW file object (sector-aligned buffer).
function Read-UncachedText([string] $Path, [int] $Length) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3,
        [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return 'OBSERVED_REFUSED: CreateFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = [SafeUploadRepro.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]4096), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) {
        $allocationError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
        return 'OBSERVED_REFUSED: VirtualAlloc error ' + $allocationError
    }
    try {
        [uint32] $read = 0
        if (-not [SafeUploadRepro.Native]::ReadFile($handle, $buffer, 4096, [ref]$read, [IntPtr]::Zero) -or $read -ne 4096) {
            return 'OBSERVED_REFUSED: ReadFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $bytes = New-Object byte[] $Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
        return [Text.Encoding]::UTF8.GetString($bytes)
    }
    finally {
        [void][SafeUploadRepro.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
    }
}

function Get-FirstLcn([string] $Path) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]128, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'extent query open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $input = [Runtime.InteropServices.Marshal]::AllocHGlobal(8); $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($input, 0)
        [uint32] $returned = 0
        if (-not [SafeUploadRepro.Native]::DeviceIoControl($handle, [uint32]0x00090073, $input, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
            throw 'FSCTL_GET_RETRIEVAL_POINTERS failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if ([Runtime.InteropServices.Marshal]::ReadInt32($output, 0) -lt 1) { throw 'No allocated extent for raw-byte observer.' }
        return [Runtime.InteropServices.Marshal]::ReadInt64($output, 24)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($input); [Runtime.InteropServices.Marshal]::FreeHGlobal($output)
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
    }
}

function Read-RawFixtureBytes([long] $Lcn, [int] $ClusterSize, [int] $Length) {
    if ($ClusterSize -lt 4096 -or ($ClusterSize % 4096) -ne 0) { throw 'Unsupported NTFS cluster size for aligned raw observation.' }
    if ($Length -le 0 -or $Length -gt $ClusterSize) { throw 'Fixture extent does not fit in one allocated cluster.' }
    $handle = [SafeUploadRepro.Native]::CreateFileW('\\.\C:', [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'raw volume open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = [SafeUploadRepro.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]$ClusterSize), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) { [void][SafeUploadRepro.Native]::CloseHandle($handle); throw 'raw read VirtualAlloc failed' }
    try {
        [long] $position = 0
        if (-not [SafeUploadRepro.Native]::SetFilePointerEx($handle, $Lcn * $ClusterSize, [ref]$position, 0)) {
            throw 'raw seek failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        [uint32] $read = 0
        if (-not [SafeUploadRepro.Native]::ReadFile($handle, $buffer, [uint32]$ClusterSize, [ref]$read, [IntPtr]::Zero) -or $read -lt $Length) {
            throw 'raw read failed/short: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $bytes = New-Object byte[] $Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
        return ,$bytes
    }
    finally {
        [void][SafeUploadRepro.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
    }
}

function Compare-RawFixtureToBaseline([long] $Lcn, [int] $ClusterSize, [byte[]] $Baseline) {
    $current = Read-RawFixtureBytes $Lcn $ClusterSize $Baseline.Length
    $differentBytes = 0
    $firstDifferentOffset = -1
    for ($index = 0; $index -lt $Baseline.Length; $index++) {
        if ($current[$index] -ne $Baseline[$index]) {
            $differentBytes++
            if ($firstDifferentOffset -lt 0) { $firstDifferentOffset = $index }
        }
    }
    $state = if ($differentBytes -eq 0) { 'IDENTICAL_TO_BASELINE' } else { 'UNEXPECTED_BYTES_CHANGED' }
    return [pscustomobject]@{
        State = $state
        ByteCount = $Baseline.Length
        DifferentBytes = $differentBytes
        FirstDifferentOffset = $firstDifferentOffset
    }
}

function Flush-TestFileBuffers($Stream) {
    if ($null -eq $Stream) { return 'UNAVAILABLE: file handle absent' }
    try {
        if ([SafeUploadRepro.Native]::FlushFileBuffers($Stream.SafeFileHandle.DangerousGetHandle())) { return 'SUCCESS' }
        return 'OBSERVED_REFUSED: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } catch { return 'OBSERVED_REFUSED: ' + $_.Exception.Message }
}

function New-PolicyTransitionServiceSecurity([bool] $Directory) {
    $security = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $security.SetAccessRuleProtection($true, $false)
    $administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $systemReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    $security.SetOwner($administrators)
    $inheritance = if ($Directory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $administrators, [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow))
    $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $system, $systemReadExecute,
        $inheritance, [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow))
    return $security
}

function Assert-PolicyTransitionServiceStagingParent([string] $Path) {
    $parent = [IO.Path]::GetFullPath($serviceStagingParent).TrimEnd('\')
    $canonicalProgramFiles = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($canonicalProgramFiles) -or
        -not $parent.Equals([IO.Path]::GetFullPath($canonicalProgramFiles).TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Service staging parent does not match the canonical Program Files folder.'
    }
    $driveRoot = [IO.Path]::GetPathRoot($parent)
    $drive = [IO.DriveInfo]::new($driveRoot)
    if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed -or $drive.DriveFormat -ne 'NTFS') {
        throw 'Service staging parent must be on a ready local fixed NTFS volume.'
    }
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not [IO.Path]::GetDirectoryName($candidate).Equals($parent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Service staging path is not a direct child of the configured trusted staging parent.'
    }
    $trusted = @{
        'S-1-5-18' = $true
        'S-1-5-32-544' = $true
    }
    $trustedInstaller = [System.Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller').Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $trusted[$trustedInstaller] = $true
    $pathMutationRights = [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    $directParentMutationMask = [long]$pathMutationRights -bor
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        0x40000000 -bor 0x10000000
    $ancestorMutationMask = [long]$pathMutationRights -bor 0x40000000 -bor 0x10000000

    $cursor = $parent
    while ($null -ne $cursor) {
        if (-not (Test-Path -LiteralPath $cursor -PathType Container)) { throw "Service staging ancestor is absent: $cursor" }
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Service staging ancestor is a reparse point: $cursor"
        }
        $ancestorAcl = [IO.Directory]::GetAccessControl($cursor)
        $ownerSid = $ancestorAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if (-not $trusted.ContainsKey($ownerSid)) {
            throw "Service staging ancestor has an untrusted owner $ownerSid : $cursor"
        }
        foreach ($rule in $ancestorAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $mutationMask = if ($cursor.Equals($parent, [StringComparison]::OrdinalIgnoreCase)) {
                $directParentMutationMask
            } else {
                $ancestorMutationMask
            }
            $isInheritOnly = ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
                $isInheritOnly -or
                ([long]$rule.FileSystemRights -band $mutationMask) -eq 0) { continue }
            $sid = $rule.IdentityReference.Value
            if (-not $trusted.ContainsKey($sid)) {
                throw "Untrusted principal $sid can modify service staging ancestor $cursor."
            }
        }
        if ($cursor.Equals([IO.Path]::GetPathRoot($cursor), [StringComparison]::OrdinalIgnoreCase)) { break }
        $parentInfo = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parentInfo) { throw 'Could not resolve service staging ancestors.' }
        $cursor = $parentInfo.FullName
    }
}

function Assert-PolicyTransitionServiceAcl([string] $Path, [bool] $Directory) {
    $security = if ($Directory) {
        [IO.Directory]::GetAccessControl($Path)
    } else {
        [IO.File]::GetAccessControl($Path)
    }
    $administrators = 'S-1-5-32-544'
    $system = 'S-1-5-18'
    if (-not $security.AreAccessRulesProtected -or
        $security.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $administrators) {
        throw "Service staging ACL or owner is not protected: $Path"
    }
    $rules = @($security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw "Unexpected service staging ACL rule count: $Path" }
    $seen = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        $expectedRights = if ($sid -eq $administrators) {
            [System.Security.AccessControl.FileSystemRights]::FullControl
        } elseif ($sid -eq $system) {
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
                [System.Security.AccessControl.FileSystemRights]::Synchronize
        } else {
            throw "Unexpected service staging ACL principal $sid at $Path"
        }
        $expectedInheritance = if ($Directory) {
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        } else {
            [System.Security.AccessControl.InheritanceFlags]::None
        }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne $expectedRights -or
            $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
            throw "Unexpected service staging ACL rights or inheritance at $Path"
        }
        if ($seen.ContainsKey($sid)) { throw "Duplicate service staging ACL principal $sid at $Path" }
        $seen[$sid] = $true
    }
    if (-not $seen.ContainsKey($administrators) -or -not $seen.ContainsKey($system)) {
        throw "Required service staging ACL principals are missing: $Path"
    }
}

function Assert-PolicyTransitionServiceTree([string] $Path, [switch] $RequireServiceExecutable) {
    Assert-PolicyTransitionServiceStagingParent $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Service staging directory is absent: $Path" }
    $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Service staging directory became a reparse point.' }
    Assert-PolicyTransitionServiceAcl $Path $true
    foreach ($child in @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop)) {
        if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Service staging tree contains a reparse point: $($child.FullName)"
        }
        Assert-PolicyTransitionServiceAcl $child.FullName $child.PSIsContainer
    }
    if ($RequireServiceExecutable -and
        -not (Test-Path -LiteralPath (Join-Path $Path 'SafeUpload.Agent.Service.exe') -PathType Leaf)) {
        throw 'Verified service executable is absent from the protected staging tree.'
    }
}

function Get-PolicyTransitionStreamSha256([IO.Stream] $Stream) {
    if ($null -eq $Stream -or -not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'Service package stream must be readable and seekable.'
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($Stream)).Replace('-', '')
    }
    finally { $sha256.Dispose() }
}

function Expand-VerifiedServicePackage([IO.Stream] $PackageStream, [string] $DestinationDirectory) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (-not (Test-Path -LiteralPath $DestinationDirectory -PathType Container) -or
        @(Get-ChildItem -LiteralPath $DestinationDirectory -Force).Count -ne 0) {
        throw 'Verified service extraction directory is absent or not empty.'
    }

    $PackageStream.Position = 0
    $archive = [IO.Compression.ZipArchive]::new($PackageStream,
        [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        $root = [IO.Path]::GetFullPath($DestinationDirectory) + [IO.Path]::DirectorySeparatorChar
        $members = New-Object System.Collections.ArrayList
        $seen = @{}
        $uncompressedBytes = 0L
        foreach ($entry in $archive.Entries) {
            $normalized = $entry.FullName.Replace('/', '\')
            $isDirectory = $normalized.EndsWith('\')
            $relative = $normalized.TrimEnd([char[]]@('\'))
            if ([string]::IsNullOrEmpty($relative) -or [IO.Path]::IsPathRooted($normalized) -or $normalized.Contains(':')) {
                throw "Unsafe service package path: $($entry.FullName)"
            }
            foreach ($segment in $relative.Split([char[]]@(92))) {
                if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -eq '..') {
                    throw "Unsafe service package path segment: $($entry.FullName)"
                }
            }
            if ($seen.ContainsKey($relative)) { throw "Duplicate service package path: $relative" }
            $seen[$relative] = $true

            $unixType = ($entry.ExternalAttributes -shr 16) -band 0xF000
            $dosAttributes = $entry.ExternalAttributes -band 0xFFFF
            if ($unixType -eq 0xA000 -or ($dosAttributes -band 0x400) -ne 0) {
                throw "Reparse-point or symbolic-link service package entry is unsupported: $relative"
            }
            $destination = [IO.Path]::GetFullPath((Join-Path $DestinationDirectory $relative))
            if (-not $destination.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Service package path escapes its extraction directory: $relative"
            }
            if (-not $isDirectory) {
                $uncompressedBytes += $entry.Length
                if ($uncompressedBytes -gt 1073741824) { throw 'Service package exceeds the 1 GiB extraction limit.' }
            }
            [void]$members.Add([pscustomobject]@{ Entry = $entry; Path = $destination; IsDirectory = $isDirectory })
        }

        $directorySecurity = New-PolicyTransitionServiceSecurity $true
        $fileSecurity = New-PolicyTransitionServiceSecurity $false
        foreach ($member in $members) {
            if ($member.IsDirectory) {
                [void][IO.Directory]::CreateDirectory($member.Path, $directorySecurity)
                continue
            }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($member.Path), $directorySecurity)
            $source = $null
            $destinationStream = $null
            try {
                $source = $member.Entry.Open()
                $destinationStream = [IO.FileStream]::new($member.Path, [IO.FileMode]::CreateNew,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [IO.FileShare]::None, 65536, [IO.FileOptions]::SequentialScan, $fileSecurity)
                $source.CopyTo($destinationStream)
                $destinationStream.Flush($true)
                if ($destinationStream.Length -ne $member.Entry.Length) {
                    throw "Service package entry length mismatch after extraction: $($member.Entry.FullName)"
                }
            }
            finally {
                if ($null -ne $destinationStream) { $destinationStream.Dispose() }
                if ($null -ne $source) { $source.Dispose() }
            }
        }

        $executable = Join-Path $DestinationDirectory 'SafeUpload.Agent.Service.exe'
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
            throw 'Pinned service package does not contain SafeUpload.Agent.Service.exe at its root.'
        }
        $header = New-Object byte[] 2
        $headerStream = [IO.File]::OpenRead($executable)
        try {
            if ($headerStream.Read($header, 0, 2) -ne 2) { throw 'Extracted service executable is shorter than its PE header.' }
        }
        finally { $headerStream.Dispose() }
        if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) { throw 'Extracted service executable has no PE header.' }
        Assert-PolicyTransitionServiceTree $DestinationDirectory -RequireServiceExecutable
        return [pscustomobject]@{
            Directory = $DestinationDirectory
            Executable = $executable
            ExecutableSHA256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
            EntryCount = $members.Count
            UncompressedBytes = $uncompressedBytes
        }
    }
    finally { $archive.Dispose() }
}

$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedFeature = $ExpectedFeatureSha256.ToUpperInvariant()
$expectedInspector = $ExpectedInspectorSha256.ToUpperInvariant()
$expectedServicePackage = 'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspectorSource = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$id = [guid]::NewGuid().ToString('N')
$serviceStagingParent = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
$serviceDirectory = Join-Path $serviceStagingParent ('SafeUpload-policy-transition-service-' + $id)
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$fixtureDirectory = Join-Path $documents ('SafeUpload-policy-transition-' + $id)
$fixtureExtension = '.maptest'
$target = Join-Path $fixtureDirectory ('synthetic' + $fixtureExtension)
$backup = Join-Path $documents ('SafeUpload-original-before-policy-transition-' + $id + '.sys')
$policyBackup = Join-Path $documents ('SafeUpload-policy-before-transition-' + $id + '.bin')
$inspectorProcessName = 'SafeUpload-policy-transition-inspector-' + $id
$inspectorCopy = Join-Path $documents ($inspectorProcessName + '.exe')
$baseLog = Join-Path $documents ('policy-transition-base-' + $id)
$updatedLog = Join-Path $documents ('policy-transition-updated-' + $id)
$mappingName = 'Local\SafeUpload-PolicyTransition-' + $id
$retainedMappingName = 'Local\SafeUpload-PolicyTransition-RetainedSection-' + $id
$originalText = 'PUBLIC BASELINE BEFORE POLICY CHANGE ' + $id
$changedText = 'MAPPED AFTER POLICY CHANGE ' + $id
$retainedOriginalText = 'RETAINED SECTION BASELINE ' + $id
$retainedChangedText = 'LATE VIEW AFTER POLICY CHANGE ' + $id
$originalBytes = [Text.Encoding]::UTF8.GetBytes($originalText)
$changedBytes = [Text.Encoding]::UTF8.GetBytes($changedText)
$retainedOriginalBytes = [Text.Encoding]::UTF8.GetBytes($retainedOriginalText)
$retainedChangedBytes = [Text.Encoding]::UTF8.GetBytes($retainedChangedText)
$shrinkMarker = [Text.Encoding]::ASCII.GetBytes(('SHRINK-' + $id).Substring(0, 32))
$mappingLength = 4096
$fixtureBytes = New-Object byte[] $mappingLength
[Array]::Copy($originalBytes, $fixtureBytes, $originalBytes.Length)
$retainedFixtureBytes = New-Object byte[] $mappingLength
[Array]::Copy($retainedOriginalBytes, $retainedFixtureBytes, $retainedOriginalBytes.Length)
$retainedMarkerBytes = [Text.Encoding]::UTF8.GetBytes($retainedChangedText)
$retainedTarget = Join-Path $fixtureDirectory ('retained-section' + $fixtureExtension)
$agent = $null
$activeTestAgents = New-Object System.Collections.ArrayList
$file = $null
$retainedFile = $null
$sectionFile = $null
$shrinkFile = $null
$mapping = $null
$view = $null
$shrinkMapping = $null
$shrinkView = $null
$sectionMappingHandle = [IntPtr]::Zero
$sectionView = [IntPtr]::Zero
$retainedMappingHandle = [IntPtr]::Zero
$retainedView = [IntPtr]::Zero
$rawCluster = -1L
$rawClusterSize = 0
$rawBaseline = $null
$retainedRawCluster = -1L
$retainedRawBaseline = $null
$rawBaselineFileBuffersOutcome = 'NOT_ATTEMPTED'
$expansionFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$shrinkSectionFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$oldViewShrinkFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$expansionRawComparison = 'UNOBSERVABLE'
$finalRawComparison = $null
$allMappingsReleased = $true
$expansionMappingsReleased = $false
$expansionPrivacyVerdict = 'NOT_RUN'
$retainedSectionCreateOutcome = 'NOT_RUN'
$retainedSectionCreateError = -1
$retainedViewWriteOutcome = 'NOT_ATTEMPTED'
$retainedViewFlushOutcome = 'NOT_ATTEMPTED'
$retainedFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$retainedViewReleased = $false
$retainedMappingReleased = $false
$retainedFileReleased = $false
$retainedUncachedText = 'UNOBSERVABLE'
$retainedRawComparison = 'UNOBSERVABLE'
$retainedPrivacyVerdict = 'NOT_RUN'
$policyBytes = $null
$inspectorCopyCreated = $false
$inspectorCopyRemoved = $false
$serviceDirectoryCreationAttempted = $false
$serviceDirectoryCreated = $false
$serviceDirectoryRemoved = $false
$inspectorTaskNames = New-Object System.Collections.ArrayList
$inspectorCleanupMessages = New-Object System.Collections.ArrayList
$script:PolicyTransitionInspectorCopy = $inspectorCopy
$script:PolicyTransitionInspectorProcessName = $inspectorProcessName
$script:PolicyTransitionInspectorTaskNames = $inspectorTaskNames
$script:PolicyTransitionInspectorCleanupMessages = $inspectorCleanupMessages
$replaced = $false
$loaded = $false
$fixtureCreated = $false
$verifierEnabled = $false
$expansionWriteOutcome = 'NOT_RUN'
$expansionFlushOutcome = 'NOT_RUN'
$shrinkSectionWriteOutcome = 'NOT_ATTEMPTED'
$shrinkSectionFlushOutcome = 'NOT_ATTEMPTED'
$shrinkSectionMeasurementOutcome = 'NOT_RUN'
$shrinkSectionMeasurementUnknown = $false
$oldViewShrinkWriteOutcome = 'NOT_ATTEMPTED'
$oldViewShrinkFlushOutcome = 'NOT_ATTEMPTED'
$shrinkSectionWriteAttempted = $false

function Start-TestAgentAndWaitForPolicy([string] $LogPrefix) {
    # ReadySignal is emitted only after SetPolicy succeeds. Waiting on the
    # named event avoids reading a live redirected log that the child process
    # owns exclusively and that is itself subject to the file filter.
    $ready = New-Object System.Threading.EventWaitHandle(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        'Global\SafeUploadServiceReady')
    $newAgent = $null
    try {
        [void]$ready.Reset()
        Assert-PolicyTransitionServiceTree $serviceDirectory -RequireServiceExecutable
        $newAgent = Start-StagedTestAgent $serviceDirectory $LogPrefix
        if ($null -ne $newAgent) { [void]$script:activeTestAgents.Add($newAgent) }
        if (-not $ready.WaitOne([TimeSpan]::FromSeconds(45))) {
            throw 'Agent did not signal policy acceptance within 45 seconds.'
        }
        return $newAgent
    }
    catch {
        # Keep a successfully returned process in activeTestAgents. The outer
        # finally retries stop independently of policy and driver restoration.
        throw
    }
    finally { $ready.Dispose() }
}

function Stop-TestAgentTracked($Target) {
    if ($null -eq $Target) { return }
    Stop-StagedTestAgent $Target
    [void]$script:activeTestAgents.Remove($Target)
}

function ConvertTo-PolicyTransitionPowerShellLiteral([string] $Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-PolicyTransitionInspectorProcesses {
    $filter = "Name='$($script:PolicyTransitionInspectorProcessName).exe'"
    return @(Get-CimInstance -ClassName Win32_Process -Filter $filter -ErrorAction Stop |
        Where-Object { $_.ExecutablePath -ieq $script:PolicyTransitionInspectorCopy })
}

function Invoke-PolicyTransitionFenceStatus([int] $TimeoutSeconds) {
    $callId = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedTest-PolicyFenceStatus-' + $callId
    $launcher = Join-Path $env:TEMP ('SafeUpload-policy-fence-status-' + $callId + '.ps1')
    $pidFile = $launcher + '.pid'
    $exitFile = $launcher + '.exit'
    $stdoutFile = $launcher + '.stdout'
    $stderrFile = $launcher + '.stderr'
    $launcherTemplate = @'
$ErrorActionPreference = 'Stop'
try {
    $process = Start-Process -FilePath __EXE__ -ArgumentList '--admission-fence-status' `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput __STDOUT__ -RedirectStandardError __STDERR__
    [IO.File]::WriteAllText(__PID__, [string]$process.Id)
    $process.WaitForExit()
    [IO.File]::WriteAllText(__EXIT__, [string]$process.ExitCode)
} catch {
    [IO.File]::WriteAllText(__STDERR__, $_.Exception.ToString())
    [IO.File]::WriteAllText(__EXIT__, '255')
}
'@
    $launcherBody = $launcherTemplate.Replace('__EXE__', (ConvertTo-PolicyTransitionPowerShellLiteral $script:PolicyTransitionInspectorCopy))
    $launcherBody = $launcherBody.Replace('__STDOUT__', (ConvertTo-PolicyTransitionPowerShellLiteral $stdoutFile))
    $launcherBody = $launcherBody.Replace('__STDERR__', (ConvertTo-PolicyTransitionPowerShellLiteral $stderrFile))
    $launcherBody = $launcherBody.Replace('__PID__', (ConvertTo-PolicyTransitionPowerShellLiteral $pidFile))
    $launcherBody = $launcherBody.Replace('__EXIT__', (ConvertTo-PolicyTransitionPowerShellLiteral $exitFile))

    $registered = $false
    $exitCode = -1
    $sectionsDenied = $null
    $sectionNameUnresolved = $null
    $statusComplete = $null
    $statusEntries = $null
    $statusGeneration = $null
    $statusLastStatus = $null
    $statusFailureLine = $null
    $statusStateFlags = $null
    $statusRefreshStarted = $null
    $statusRefreshCompleted = $null
    $statusRefreshFailed = $null
    $statusVolumeScopesSkipped = $null
    $dataValid = $false
    $cleanupComplete = $true
    $errorText = ''

    try {
        if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'Agent must be stopped before the section-callback status sample.'
        }
        if ((Get-PolicyTransitionInspectorProcesses).Count -ne 0) {
            throw 'A policy-transition Inspector process is already running.'
        }
        Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding UTF8
        $taskArgument = '-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgument
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds($TimeoutSeconds + 15))
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        [void]$script:PolicyTransitionInspectorTaskNames.Add($taskName)
        Start-ScheduledTask -TaskName $taskName

        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not (Test-Path -LiteralPath $exitFile) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $exitFile)) {
            throw "Inspector status query exceeded $TimeoutSeconds seconds."
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
        if (-not $taskStopped) { throw 'Inspector status task did not stop after writing its exit code.' }

        $exitCode = [int]([IO.File]::ReadAllText($exitFile))
        $stdout = [IO.File]::ReadAllText($stdoutFile)
        if ($exitCode -notin @(0, 4)) {
            $stderr = if (Test-Path -LiteralPath $stderrFile) { [IO.File]::ReadAllText($stderrFile) } else { '' }
            throw "Inspector status exit $exitCode is not an accepted status response: $stderr"
        }
        $status = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop
        $requiredStatusProperties = @(
            'fence','entries','generation','lastStatus','failureLine','stateFlags',
            'refreshStarted','refreshCompleted','refreshFailed','volumeScopesSkipped',
            'sectionsDenied','sectionNameUnresolved','complete')
        if ($null -eq $status -or $status.fence -ne $true) {
            throw 'Inspector status JSON is missing the fence status object.'
        }
        foreach ($propertyName in $requiredStatusProperties) {
            if ($null -eq $status.PSObject.Properties[$propertyName]) {
                throw "Inspector status JSON is missing required field $propertyName."
            }
        }
        $sectionsDenied = [uint64]$status.sectionsDenied
        $sectionNameUnresolved = [uint64]$status.sectionNameUnresolved
        $statusComplete = [bool]$status.complete
        $statusEntries = [uint32]$status.entries
        $statusGeneration = [uint32]$status.generation
        $statusLastStatus = [string]$status.lastStatus
        $statusFailureLine = [uint32]$status.failureLine
        $statusStateFlags = [uint32]$status.stateFlags
        $statusRefreshStarted = [uint64]$status.refreshStarted
        $statusRefreshCompleted = [uint64]$status.refreshCompleted
        $statusRefreshFailed = [uint64]$status.refreshFailed
        $statusVolumeScopesSkipped = [uint64]$status.volumeScopesSkipped
        $dataValid = $true
    }
    catch {
        $errorText = $_.Exception.Message
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        try {
            foreach ($process in @(Get-PolicyTransitionInspectorProcesses)) {
                Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
            }
            $processesGone = $false
            for ($attempt = 0; $attempt -lt 20; $attempt++) {
                if ((Get-PolicyTransitionInspectorProcesses).Count -eq 0) {
                    $processesGone = $true
                    break
                }
                Start-Sleep -Milliseconds 250
            }
            $taskRemains = $null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
            if (-not $processesGone -or $taskRemains) {
                $cleanupComplete = $false
                $errorText = (($errorText + '; ') + 'Inspector process/task cleanup could not be verified.').Trim('; ')
            }
        }
        catch {
            $cleanupComplete = $false
            $errorText = (($errorText + '; ') + 'Inspector process/task cleanup failed: ' + $_.Exception.Message).Trim('; ')
        }

        if ($cleanupComplete) {
            try {
                Remove-Item -LiteralPath $launcher,$pidFile,$exitFile,$stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
                $temporaryFiles = @($launcher,$pidFile,$exitFile,$stdoutFile,$stderrFile)
                $remainingTemporaryFiles = @($temporaryFiles | Where-Object { Test-Path -LiteralPath $_ })
                if ($remainingTemporaryFiles.Count -ne 0) {
                    $cleanupComplete = $false
                    $errorText = (($errorText + '; ') + 'Inspector temporary-file removal could not be verified.').Trim('; ')
                }
            }
            catch {
                $cleanupComplete = $false
                $errorText = (($errorText + '; ') + 'Inspector temporary-file cleanup failed: ' + $_.Exception.Message).Trim('; ')
            }
        } else {
            [void]$script:PolicyTransitionInspectorCleanupMessages.Add(
                "RetainedInspectorTaskArtifacts=$launcher; Process/task cleanup incomplete; Inspector copy retained at $script:PolicyTransitionInspectorCopy")
        }
    }

    return [pscustomobject]@{
        Valid = ($dataValid -and $cleanupComplete)
        ExitCode = $exitCode
        SectionsDenied = $sectionsDenied
        SectionNameUnresolved = $sectionNameUnresolved
        Complete = $statusComplete
        Entries = $statusEntries
        Generation = $statusGeneration
        LastStatus = $statusLastStatus
        FailureLine = $statusFailureLine
        StateFlags = $statusStateFlags
        RefreshStarted = $statusRefreshStarted
        RefreshCompleted = $statusRefreshCompleted
        RefreshFailed = $statusRefreshFailed
        VolumeScopesSkipped = $statusVolumeScopesSkipped
        CleanupComplete = $cleanupComplete
        Error = $errorText
    }
}

function Test-PolicyTransitionFenceSamplesEqual($Before, $After) {
    return ($Before.Generation -eq $After.Generation -and
        $Before.Entries -eq $After.Entries -and
        $Before.LastStatus -eq $After.LastStatus -and
        $Before.FailureLine -eq $After.FailureLine -and
        $Before.StateFlags -eq $After.StateFlags -and
        $Before.RefreshStarted -eq $After.RefreshStarted -and
        $Before.RefreshCompleted -eq $After.RefreshCompleted -and
        $Before.RefreshFailed -eq $After.RefreshFailed -and
        $Before.VolumeScopesSkipped -eq $After.VolumeScopesSkipped)
}

function Wait-PolicyTransitionFenceStable([int] $TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $previous = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $sample = Invoke-PolicyTransitionFenceStatus $TimeoutSeconds
        if (-not $sample.Valid) {
            throw "Fence status is invalid while waiting for a stable sample: $($sample.Error)"
        }
        if ($sample.StateFlags -eq 0 -and $null -ne $previous -and
            (Test-PolicyTransitionFenceSamplesEqual $previous $sample)) {
            return $sample
        }
        if ($sample.StateFlags -eq 0) { $previous = $sample }
        else { $previous = $null }
        Start-Sleep -Milliseconds 500
    }
    throw "Fence status did not produce two stable, quiescent samples within $TimeoutSeconds seconds."
}

function Test-PolicyTransitionExpectedRejection([string] $LogPrefix, [int] $TimeoutSeconds) {
    $ready = New-Object System.Threading.EventWaitHandle(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        'Global\SafeUploadServiceReady')
    $testAgent = $null
    $accepted = $false
    $serviceExitedBeforeCleanup = $false
    $serviceExitCode = $null
    $combinedLog = ''
    try {
        [void]$ready.Reset()
        Assert-PolicyTransitionServiceTree $serviceDirectory -RequireServiceExecutable
        $testAgent = Start-StagedTestAgent $serviceDirectory $LogPrefix
        if ($null -ne $testAgent) { [void]$script:activeTestAgents.Add($testAgent) }
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($ready.WaitOne(0)) { $accepted = $true; break }
            if ($testAgent.Process.HasExited) { break }
            Start-Sleep -Milliseconds 250
        }
        if ($ready.WaitOne(0)) { $accepted = $true }
        $serviceExitedBeforeCleanup = $testAgent.Process.HasExited
        if ($serviceExitedBeforeCleanup) { $serviceExitCode = $testAgent.Process.ExitCode }
        Stop-TestAgentTracked $testAgent
        $testAgent = $null

        foreach ($suffix in @('-out.log','-err.log')) {
            $logPath = $LogPrefix + $suffix
            if (Test-Path -LiteralPath $logPath) {
                $combinedLog += [IO.File]::ReadAllText($logPath) + "`n"
            }
        }
        if ($accepted) { throw 'The unchanged approved policy was unexpectedly accepted.' }
        $setPolicyFailure = $combinedLog -match '(?m)^\s*System\.ComponentModel\.Win32Exception \(0x80070032\): Envio da politica falhou: 0x80070032\s*$'
        $setPolicyFrame = $combinedLog -match '(?m)^\s*at SafeUpload\.Agent\.Minifilter\.FilterPort\.SetPolicy\('
        $pushPolicyFrame = $combinedLog -match '(?m)^\s*at SafeUpload\.Agent\.Service\.Interception\.MinifilterInterceptor\.TryPushPolicy\('
        if (-not $setPolicyFailure -or -not $setPolicyFrame -or -not $pushPolicyFrame) {
            throw "Agent log did not contain the exact SetPolicy rejection signature (Win32Exception=$setPolicyFailure; SetPolicyFrame=$setPolicyFrame; TryPushPolicyFrame=$pushPolicyFrame)."
        }
        return [pscustomobject]@{
            ExpectedError = 'ERROR_NOT_SUPPORTED (0x80070032)'
            SetPolicyFailureObserved = $setPolicyFailure
            SetPolicyFrameObserved = $setPolicyFrame
            TryPushPolicyFrameObserved = $pushPolicyFrame
            ProcessExitCode = $serviceExitCode
            ServiceExitedBeforeCleanup = $serviceExitedBeforeCleanup
            LogPrefix = $LogPrefix
            ReadySignaled = $false
        }
    }
    finally {
        if ($null -ne $testAgent) { Stop-TestAgentTracked $testAgent }
        $ready.Dispose()
    }
}

function Assert-OutsideBaselineScopes([string] $Path, $PolicyDocument) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    foreach ($configured in @($PolicyDocument.monitoredScopes.destinationPaths)) {
        if ([string]::IsNullOrWhiteSpace($configured)) { continue }
        $scope = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($configured)).TrimEnd('\')
        if ($candidate.Equals($scope, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith($scope + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $scope.StartsWith($candidate + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "The GUID fixture intersects an existing monitored scope: $scope"
        }
    }
}

function Read-FreshDestinationBytes {
    $fresh = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $observed = New-Object byte[] $changedBytes.Length
        $count = $fresh.Read($observed, 0, $observed.Length)
        if ($count -ne $observed.Length) { throw "Short fresh-file-object read: $count" }
        return [Text.Encoding]::UTF8.GetString($observed)
    }
    finally { $fresh.Dispose() }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
$verifierQuery = & verifier.exe /query 2>&1 | Out-String
$verifierSettings = & verifier.exe /querysettings 2>&1 | Out-String
if ($verifierQuery -notmatch 'No drivers are currently verified' -or
    $verifierSettings -notmatch 'Verifier Flags:\s+0x00000000') { throw 'Verifier must be off at baseline.' }
$service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
if ($service.StartMode -ne 'Manual' -or $service.State -ne 'Stopped') { throw 'Original service baseline mismatch.' }
if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) { throw 'A SafeUpload service process is already running.' }
if (@(Get-ScheduledTask | Where-Object { $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)' }).Count -ne 0) { throw 'A SafeUpload experiment task is already active.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $expectedFeature) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspectorSource -Algorithm SHA256).Hash -ne $expectedInspector) { throw 'Inspector source hash mismatch.' }
if (-not (Test-Path -LiteralPath $servicePackage -PathType Leaf)) { throw 'Pinned service package is absent.' }
if (Test-Path -LiteralPath $fixtureDirectory) { throw 'GUID fixture collision.' }
if (Test-Path -LiteralPath $inspectorCopy) { throw 'GUID Inspector copy collision.' }
if (Test-Path -LiteralPath $serviceDirectory) { throw 'GUID service extraction collision.' }
Assert-PolicyTransitionServiceStagingParent $serviceDirectory
if ((Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx')) -or
    (Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx.txt'))) { throw 'An owned-stream VHDX is already present.' }

$policyBytes = [IO.File]::ReadAllBytes($policy)
$baselinePolicy = [Text.Encoding]::UTF8.GetString($policyBytes) | ConvertFrom-Json
Assert-OutsideBaselineScopes $fixtureDirectory $baselinePolicy
$monitoredExtensions = @($baselinePolicy.monitoredScopes.extensions | ForEach-Object {
    $extension = [string]$_
    if (-not $extension.StartsWith('.')) { $extension = '.' + $extension }
    $extension.ToLowerInvariant()
})
if ($monitoredExtensions -contains $fixtureExtension.ToLowerInvariant()) {
    throw "Fixture extension is inspected by the baseline policy: $fixtureExtension"
}

'TestTimestampUTC=' + [DateTime]::UtcNow.ToString('o')
'Host=' + $env:COMPUTERNAME
'UUID=' + (Get-CimInstance Win32_ComputerSystemProduct).UUID
'OriginalInstalledSHA256=' + $expectedOriginal
'FeatureDriverSHA256=' + $expectedFeature
'ExpectedInspectorSHA256=' + $expectedInspector
'InspectorInputSHA256=' + (Get-FileHash -LiteralPath $inspectorSource -Algorithm SHA256).Hash
'ExpectedServicePackageSHA256=' + $expectedServicePackage
'OriginalPolicySHA256=' + $expectedPolicy
'FilterUnloaded=True; VerifierFlags=0; VerifiedDrivers=None; Service=Manual/Stopped'
'ConcurrentAgentProcesses=0; SafeUploadTestTasks=0'
'OwnedVhdxPresent=False'
'PolicyShrinkAtomicRace=NOT_RUN_NO_DETERMINISTIC_KERNEL_BARRIER'
"FixtureOutsideBaselinePolicy=True; Path=$fixtureDirectory"
"FixtureExtension=$fixtureExtension; BaselineSourceExtensionMonitored=False"

try {
    # Hash and parse one read-only archive handle, then extract to an
    # administrator/SYSTEM-only tree created with its ACL already applied.
    # The held FileShare.Read handle prevents replacement or writes between
    # the hash and ZIP reads.
    $servicePackageStream = $null
    try {
        $servicePackageStream = [IO.File]::Open($servicePackage, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $actualServicePackageHash = Get-PolicyTransitionStreamSha256 $servicePackageStream
        if ($actualServicePackageHash -ne $expectedServicePackage) { throw 'Service package hash mismatch.' }
        $servicePackageStream.Position = 0
        'ServicePackageSHA256=' + $actualServicePackageHash

        $serviceDirectoryCreationAttempted = $true
        $serviceDirectorySecurity = New-PolicyTransitionServiceSecurity $true
        Assert-PolicyTransitionServiceStagingParent $serviceDirectory
        [void][IO.Directory]::CreateDirectory($serviceDirectory, $serviceDirectorySecurity)
        Assert-PolicyTransitionServiceTree $serviceDirectory
        $serviceDirectoryCreated = $true
        $serviceExtraction = Expand-VerifiedServicePackage $servicePackageStream $serviceDirectory
    }
    finally {
        if ($null -ne $servicePackageStream) {
            $servicePackageStream.Dispose()
            $servicePackageStream = $null
        }
    }
    "VerifiedServiceExtraction=$($serviceExtraction.Directory); Entries=$($serviceExtraction.EntryCount); UncompressedBytes=$($serviceExtraction.UncompressedBytes)"
    'VerifiedServiceExecutableSHA256=' + $serviceExtraction.ExecutableSHA256

    # The GUID path is known to be absent from the baseline gate, so mark this
    # name as owned before copying; finally can then remove a partial copy too.
    $inspectorCopyCreated = $true
    Copy-Item -LiteralPath $inspectorSource -Destination $inspectorCopy
    $copiedInspectorHash = (Get-FileHash -LiteralPath $inspectorCopy -Algorithm SHA256).Hash
    if ($copiedInspectorHash -ne $expectedInspector) { throw 'Copied Inspector hash mismatch.' }
    'InspectorCopySHA256=' + $copiedInspectorHash

    if (-not $PolicyRejectionOnly) {
        [void][IO.Directory]::CreateDirectory($fixtureDirectory)
        $fixtureCreated = $true
    }
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedFeature) { throw 'Feature driver install hash mismatch.' }
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B (special pool, IRQL, pool tracking, I/O, deadlock, DDI)'
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
    $loaded = $true

    if ($PolicyRejectionOnly) {
        if (-not [bool]$baselinePolicy.monitoredScopes.removableDrives -or
            -not [bool]$baselinePolicy.monitoredScopes.networkPaths) {
            throw 'Policy-rejection mode requires the pinned approved policy with removable and network scopes enabled.'
        }
        if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) {
            throw 'Approved policy changed before the rejection-only measurement.'
        }

        $rejectionBefore = Wait-PolicyTransitionFenceStable $InspectorTimeoutSeconds
        "PolicyRejectionFenceBefore=Valid:$($rejectionBefore.Valid); Generation:$($rejectionBefore.Generation); Entries:$($rejectionBefore.Entries); LastStatus:$($rejectionBefore.LastStatus); StateFlags:$($rejectionBefore.StateFlags); RefreshFailed:$($rejectionBefore.RefreshFailed); VolumeScopesSkipped:$($rejectionBefore.VolumeScopesSkipped)"
        if (-not $rejectionBefore.Valid -or $rejectionBefore.StateFlags -ne 0) {
            throw 'The pre-rejection fence status was not valid and quiescent.'
        }

        $rejectionResult = Test-PolicyTransitionExpectedRejection $baseLog $InspectorTimeoutSeconds
        "PolicyRejectionAgent=ExpectedError:$($rejectionResult.ExpectedError); ExactSetPolicyException:$($rejectionResult.SetPolicyFailureObserved); SetPolicyFrame:$($rejectionResult.SetPolicyFrameObserved); TryPushPolicyFrame:$($rejectionResult.TryPushPolicyFrameObserved); ReadySignaled:$($rejectionResult.ReadySignaled); ServiceExitedBeforeCleanup:$($rejectionResult.ServiceExitedBeforeCleanup); ExitCode:$($rejectionResult.ProcessExitCode); Logs:$($rejectionResult.LogPrefix)"
        if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) {
            throw 'The approved policy file changed during the rejection measurement.'
        }

        $rejectionAfter = Wait-PolicyTransitionFenceStable $InspectorTimeoutSeconds
        "PolicyRejectionFenceAfter=Valid:$($rejectionAfter.Valid); Generation:$($rejectionAfter.Generation); Entries:$($rejectionAfter.Entries); LastStatus:$($rejectionAfter.LastStatus); FailureLine:$($rejectionAfter.FailureLine); StateFlags:$($rejectionAfter.StateFlags); RefreshFailed:$($rejectionAfter.RefreshFailed); VolumeScopesSkipped:$($rejectionAfter.VolumeScopesSkipped)"
        if (-not $rejectionAfter.Valid -or $rejectionAfter.StateFlags -ne 0 -or
            $rejectionAfter.Generation -ne $rejectionBefore.Generation -or
            $rejectionAfter.Entries -ne $rejectionBefore.Entries -or
            $rejectionAfter.RefreshFailed -le $rejectionBefore.RefreshFailed -or
            $rejectionAfter.LastStatus -ine '0xC00000BB' -or
            $rejectionAfter.VolumeScopesSkipped -eq 0) {
            throw 'Rejected policy changed the fence generation/table, omitted the expected scan failure, or left the fence non-quiescent.'
        }
        'PolicyGenerationRuntimeObservation=NOT_EXPOSED_BY_CURRENT_PROTOCOL'
        'PolicyRejectionFencePreservation=PASS; FenceGenerationAndEntriesUnchanged=True; RefreshFailureObserved=True'
        return
    }

    [IO.File]::WriteAllBytes($target, $fixtureBytes)
    $rawClusterSize = [int](Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'").BlockSize
    $rawCluster = Get-FirstLcn $target
    "RawObserverFixtureCluster=$rawCluster; ClusterSize=$rawClusterSize"
    # Keep a second FILE_OBJECT opened before the policy expands. It has no writable section yet;
    # after shrink, CreateFileMapping on this old handle must be refused by section-object identity.
    $sectionFile = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $shrinkFile = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $file = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    if ($file.Length -ne $mappingLength) { throw "Fixture EOF $($file.Length) does not match mapping size $mappingLength." }
    $rawBaselineFileBuffersOutcome = Flush-TestFileBuffers $file
    "RawBaselineFlushFileBuffers=$rawBaselineFileBuffersOutcome"
    if ($rawBaselineFileBuffersOutcome -ne 'SUCCESS') { throw 'Could not flush fixture baseline before raw capture.' }
    $rawBaseline = Read-RawFixtureBytes $rawCluster $rawClusterSize $fixtureBytes.Length
    $baselineDifferenceCount = 0
    for ($baselineIndex = 0; $baselineIndex -lt $fixtureBytes.Length; $baselineIndex++) {
        if ($rawBaseline[$baselineIndex] -ne $fixtureBytes[$baselineIndex]) { $baselineDifferenceCount++ }
    }
    "RawBaselineExtent=IDENTICAL_TO_FIXTURE; Bytes=$($fixtureBytes.Length); DifferentBytes=$baselineDifferenceCount"
    if ($baselineDifferenceCount -ne 0) { throw 'Raw baseline did not match the complete fixture contents.' }
    [IO.File]::WriteAllBytes($retainedTarget, $retainedFixtureBytes)
    $retainedRawCluster = Get-FirstLcn $retainedTarget
    "RetainedSectionRawObserverFixtureCluster=$retainedRawCluster; ClusterSize=$rawClusterSize"
    $retainedFile = [IO.FileStream]::new($retainedTarget, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    if ($retainedFile.Length -ne $mappingLength) { throw "Retained fixture EOF $($retainedFile.Length) does not match mapping size $mappingLength." }
    $retainedBaselineFlush = Flush-TestFileBuffers $retainedFile
    "RetainedSectionRawBaselineFlushFileBuffers=$retainedBaselineFlush"
    if ($retainedBaselineFlush -ne 'SUCCESS') { throw 'Could not flush retained-section baseline before raw capture.' }
    $retainedRawBaseline = Read-RawFixtureBytes $retainedRawCluster $rawClusterSize $retainedFixtureBytes.Length
    $retainedBaselineDifferenceCount = 0
    for ($baselineIndex = 0; $baselineIndex -lt $retainedFixtureBytes.Length; $baselineIndex++) {
        if ($retainedRawBaseline[$baselineIndex] -ne $retainedFixtureBytes[$baselineIndex]) { $retainedBaselineDifferenceCount++ }
    }
    "RetainedSectionRawBaselineExtent=IDENTICAL_TO_FIXTURE; Bytes=$($retainedFixtureBytes.Length); DifferentBytes=$retainedBaselineDifferenceCount"
    if ($retainedBaselineDifferenceCount -ne 0) { throw 'Retained-section raw baseline did not match the complete fixture contents.' }
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($file, $mappingName,
        [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, $mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $shrinkMapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($shrinkFile,
        ('Local\SafeUpload-PolicyShrinkOriginal-' + $id), [long]$mappingLength,
        [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $shrinkView = $shrinkMapping.CreateViewAccessor(0, $mappingLength,
        [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $initial = New-Object byte[] $originalBytes.Length
    $view.ReadArray(0, $initial, 0, $initial.Length)
    if ([Text.Encoding]::UTF8.GetString($initial) -ne $originalText) { throw 'Baseline mapping bytes mismatch.' }
    $shrinkInitial = New-Object byte[] $originalBytes.Length
    $shrinkView.ReadArray(0, $shrinkInitial, 0, $shrinkInitial.Length)
    if ([Text.Encoding]::UTF8.GetString($shrinkInitial) -ne $originalText) { throw 'Baseline shrink mapping bytes mismatch.' }
    $file.Dispose()
    $file = $null
    'FilterAttached=True; ExpansionAndShrinkMappingsCreatedBeforeFirstPolicyPush=True; MappingCapacityEqualsFileEOF=True; PreChangeFileHandleClosed=True; TwoWritableSectionsRetained=True'

    $agent = Start-TestAgentAndWaitForPolicy $baseLog
    'BaselinePolicyAcceptedByRealAgentAndDriver=True; MappingPredatesBaselinePolicy=True'

    # Create the writable section object under the accepted baseline policy,
    # while its file remains outside scope. Deliberately leave it without a
    # process view until after the candidate expansion is accepted.
    $retainedMappingHandle = [SafeUploadRepro.Native]::CreateFileMappingWWithError(
        $retainedFile.SafeFileHandle.DangerousGetHandle(), [IntPtr]::Zero, [uint32]4, [uint32]0,
        [uint32]$mappingLength, $retainedMappingName, [ref]$retainedSectionCreateError)
    if ($retainedMappingHandle -eq [IntPtr]::Zero) {
        $retainedSectionCreateOutcome = 'FAILED: Win32Error ' + $retainedSectionCreateError
        throw 'Could not create the pre-expansion writable section handle.'
    }
    if ($retainedSectionCreateError -eq 183) {
        $retainedSectionCreateOutcome = 'UNOBSERVABLE_NAMED_MAPPING_ALREADY_EXISTS'
        throw 'A named section already existed; refusing to use a mapping object not created by this test.'
    }
    $retainedSectionCreateOutcome = 'CREATED_WITHOUT_VIEW'
    "RetainedSectionHandleCreatedUnderBaselinePolicy=True; LastError=$retainedSectionCreateError; RetainedViewCreatedBeforeExpansion=False"

    Stop-TestAgentTracked $agent
    $agent = $null
    [IO.File]::WriteAllBytes($policyBackup, $policyBytes)
    $updatedPolicy = $baselinePolicy
    $updatedPolicy.monitoredScopes.destinationPaths = @($baselinePolicy.monitoredScopes.destinationPaths) + @($fixtureDirectory)
    $updatedPolicyBytes = [Text.Encoding]::UTF8.GetBytes(($updatedPolicy | ConvertTo-Json -Depth 10))
    [IO.File]::WriteAllBytes($policy, $updatedPolicyBytes)
    $updatedPolicyHash = (Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash
    "ExpandedPolicySHA256=$updatedPolicyHash"
    'ExpandedPolicyIncludesFixture=True'

    $agent = Start-TestAgentAndWaitForPolicy $updatedLog
    'ExpandedPolicyAcceptedByRealAgentAndDriver=True'

    $mapped = New-Object byte[] 4096
    [Array]::Copy($changedBytes, $mapped, $changedBytes.Length)
    $expansionWriteOutcome = 'SUCCESS'
    try {
        $view.WriteArray(0, $mapped, 0, $mapped.Length)
    }
    catch {
        $expansionWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message
    }
    if ($expansionWriteOutcome -eq 'SUCCESS') {
        try {
            $view.Flush()
            $expansionFlushOutcome = 'SUCCESS'
        }
        catch {
            $expansionFlushOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message
        }
    }
    "MappedWriteResult=$expansionWriteOutcome; MappedFlushResult=$expansionFlushOutcome"

    # The retained section handle predates candidate-scope acceptance, but it
    # had no mapped view during either union scan. Create its first view only
    # after the expansion has committed, then measure the separate file extent.
    $retainedViewWriteOutcome = 'UNOBSERVABLE_MAP_VIEW_FAILURE'
    if ($retainedMappingHandle -ne [IntPtr]::Zero) {
        $retainedView = [SafeUploadRepro.Native]::MapViewOfFile($retainedMappingHandle,
            [uint32]2, [uint32]0, [uint32]0, [UIntPtr]::new([uint64]$mappingLength))
        if ($retainedView -ne [IntPtr]::Zero) {
            $retainedViewWriteOutcome = 'SUCCESS'
            $retainedData = New-Object byte[] $mappingLength
            [Array]::Copy($retainedMarkerBytes, $retainedData, $retainedMarkerBytes.Length)
            try {
                [Runtime.InteropServices.Marshal]::Copy($retainedData, 0, $retainedView, $retainedData.Length)
            } catch { $retainedViewWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
            if ($retainedViewWriteOutcome -eq 'SUCCESS') {
                if ([SafeUploadRepro.Native]::FlushViewOfFile($retainedView, [UIntPtr]::new([uint64]$mappingLength))) {
                    $retainedViewFlushOutcome = 'SUCCESS'
                } else {
                    $retainedViewFlushOutcome = 'OBSERVED_REFUSED: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                }
                $retainedFileBuffersFlushOutcome = Flush-TestFileBuffers $retainedFile
            }
        } else {
            $retainedMapViewError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $retainedViewWriteOutcome = 'UNOBSERVABLE_MAP_VIEW_FAILURE: Win32Error ' + $retainedMapViewError
        }
    } else {
        $retainedViewWriteOutcome = 'UNOBSERVABLE_SECTION_HANDLE_MISSING'
    }
    "RetainedSectionHandleCreated=$retainedSectionCreateOutcome; FirstViewAfterExpansion=$($retainedView -ne [IntPtr]::Zero); MappedWrite=$retainedViewWriteOutcome; FlushViewOfFile=$retainedViewFlushOutcome; FlushFileBuffers=$retainedFileBuffersFlushOutcome"
    if ($retainedViewWriteOutcome -eq 'SUCCESS') {
        $retainedUncachedText = Read-UncachedText $retainedTarget $retainedMarkerBytes.Length
    }
    "RetainedSectionFreshUncachedObserver=$retainedUncachedText"

    if ($retainedView -ne [IntPtr]::Zero) {
        if ([SafeUploadRepro.Native]::UnmapViewOfFile($retainedView)) {
            $retainedView = [IntPtr]::Zero
            $retainedViewReleased = $true
        } else {
            $allMappingsReleased = $false
            'RetainedSectionViewUnmap=FAILED; LastError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    }
    if ($retainedMappingHandle -ne [IntPtr]::Zero) {
        if ([SafeUploadRepro.Native]::CloseHandle($retainedMappingHandle)) {
            $retainedMappingHandle = [IntPtr]::Zero
            $retainedMappingReleased = $true
        } else {
            $allMappingsReleased = $false
            'RetainedSectionHandleClose=FAILED; LastError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    }
    if ($null -ne $retainedFile) {
        try {
            $retainedFile.Dispose()
            $retainedFile = $null
            $retainedFileReleased = $true
        } catch {
            $allMappingsReleased = $false
            'RetainedSectionFileClose=FAILED; Error=' + $_.Exception.Message
        }
    }
    "RetainedSectionDisposal=View:$retainedViewReleased; Section:$retainedMappingReleased; File:$retainedFileReleased"

    $retainedRawComparison = 'UNOBSERVABLE'
    try {
        for ($rawTry = 0; $rawTry -lt 20; $rawTry++) {
            $retainedRawComparison = Compare-RawFixtureToBaseline $retainedRawCluster $rawClusterSize $retainedRawBaseline
            if ($retainedRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED') { break }
            Start-Sleep -Milliseconds 500
        }
    } catch {
        $retainedRawComparison = 'UNOBSERVABLE: ' + $_.Exception.Message
        "RetainedSectionRawObserverError=$($_.Exception.Message)"
    }
    if ($retainedRawComparison -is [string]) { "RetainedSectionRawExtentComparison=$retainedRawComparison" }
    else { "RetainedSectionRawExtentComparison=$($retainedRawComparison.State); Bytes=$($retainedRawComparison.ByteCount); DifferentBytes=$($retainedRawComparison.DifferentBytes); FirstDifferentOffset=$($retainedRawComparison.FirstDifferentOffset)" }
    $retainedExposureObserved = $retainedUncachedText -eq $retainedChangedText -or
        ($retainedRawComparison -isnot [string] -and $retainedRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED')
    $retainedMeasurementComplete = $retainedSectionCreateOutcome -eq 'CREATED_WITHOUT_VIEW' -and
        $retainedViewWriteOutcome -eq 'SUCCESS' -and $retainedViewFlushOutcome -eq 'SUCCESS' -and
        $retainedFileBuffersFlushOutcome -eq 'SUCCESS' -and $retainedViewReleased -and
        $retainedMappingReleased -and $retainedFileReleased -and $retainedRawComparison -isnot [string]
    if ($retainedExposureObserved) { $retainedPrivacyVerdict = 'REPRODUCED' }
    elseif ($retainedMeasurementComplete -and $retainedRawComparison.State -eq 'IDENTICAL_TO_BASELINE') { $retainedPrivacyVerdict = 'BLOCKED' }
    else { $retainedPrivacyVerdict = 'INCONCLUSIVE' }
    "RetainedSectionPrivacyVerdict=$retainedPrivacyVerdict; MeasurementComplete=$retainedMeasurementComplete"

    # Independent observers: each opens a NEW file object after the policy change.
    $observedText = 'UNOBSERVABLE'
    $freshReadSucceeded = $false
    try { $observedText = Read-FreshDestinationBytes; $freshReadSucceeded = $true }
    catch { $observedText = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    $uncachedText = Read-UncachedText $target $changedBytes.Length
    $uncachedReadSucceeded = $uncachedText -notlike 'OBSERVED_REFUSED:*'
    "FreshFileObjectBytes=$observedText"
    "FreshUncachedObserver=$uncachedText; ReadSucceeded=$uncachedReadSucceeded"

    # Release the expansion-only mapping before observing raw bytes. A separate
    # untouched preexisting view remains alive for the shrink scenario below.
    $expansionMappingsReleased = $true
    if ($null -ne $view) {
        try { $view.Dispose(); $view = $null }
        catch { $expansionMappingsReleased = $false; $allMappingsReleased = $false; 'ExpansionViewDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $mapping) {
        try { $mapping.Dispose(); $mapping = $null }
        catch { $expansionMappingsReleased = $false; $allMappingsReleased = $false; 'ExpansionMappingDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $file) {
        try { $file.Dispose(); $file = $null }
        catch { $expansionMappingsReleased = $false; $allMappingsReleased = $false; 'ExpansionFileDisposeObserved=' + $_.Exception.Message }
    }
    "ExpansionMappingDisposalConfirmed=$expansionMappingsReleased"
    if ($expansionFlushOutcome -eq 'SUCCESS') {
        $expansionFileBuffersFlushOutcome = Flush-TestFileBuffers $shrinkFile
    }
    "ExpansionFlushFileBuffers=$expansionFileBuffersFlushOutcome"

    $expansionRawComparison = 'UNOBSERVABLE'
    try {
        for ($rawTry = 0; $rawTry -lt 20; $rawTry++) {
            $expansionRawComparison = Compare-RawFixtureToBaseline $rawCluster $rawClusterSize $rawBaseline
            if ($expansionRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        $expansionRawComparison = 'UNOBSERVABLE: ' + $_.Exception.Message
        "ExpansionRawObserverError=$($_.Exception.Message)"
    }
    if ($expansionRawComparison -is [string]) { "ExpansionRawExtentComparison=$expansionRawComparison" }
    else { "ExpansionRawExtentComparison=$($expansionRawComparison.State); Bytes=$($expansionRawComparison.ByteCount); DifferentBytes=$($expansionRawComparison.DifferentBytes); FirstDifferentOffset=$($expansionRawComparison.FirstDifferentOffset)" }
    $expansionRawReadSucceeded = $expansionRawComparison -isnot [string]
    $expansionExposureObserved = $observedText -eq $changedText -or $uncachedText -eq $changedText -or
        ($expansionRawReadSucceeded -and $expansionRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED')
    "ExpansionObserverState=FreshRead:$freshReadSucceeded; UncachedRead:$uncachedReadSucceeded; RawRead:$expansionRawReadSucceeded"
    $expansionMeasurementComplete = $expansionWriteOutcome -eq 'SUCCESS' -and
        $expansionFlushOutcome -eq 'SUCCESS' -and $expansionMappingsReleased -and
        $expansionFileBuffersFlushOutcome -eq 'SUCCESS' -and $expansionRawReadSucceeded
    if ($expansionExposureObserved) { $expansionPrivacyVerdict = 'REPRODUCED' }
    elseif ($expansionMeasurementComplete -and $expansionRawComparison.State -eq 'IDENTICAL_TO_BASELINE') { $expansionPrivacyVerdict = 'BLOCKED' }
    else { $expansionPrivacyVerdict = 'INCONCLUSIVE' }
    "ExpansionPrivacyVerdict=$expansionPrivacyVerdict; MeasurementComplete=$expansionMeasurementComplete"

    # Shrink back to the original policy while both the old writable view and a separate, pre-shrink
    # file handle remain alive. Then exercise both the fresh-reader name gate and the new-section SOP gate.
    Stop-TestAgentTracked $agent
    $agent = $null
    [IO.File]::WriteAllBytes($policy, $policyBytes)
    $agent = Start-TestAgentAndWaitForPolicy (Join-Path $documents ('policy-transition-shrunk-' + $id))
    'PolicyShrinkAcceptedByRealAgentAndDriver=True'
    Stop-TestAgentTracked $agent
    $agent = $null
    'PolicyShrinkAgentStoppedBeforeSectionAttribution=True'

    $freshOpenHandle = [SafeUploadRepro.Native]::CreateFileW($target, [uint32]2147483648,
        [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($freshOpenHandle -ne [IntPtr](-1)) {
        $freshOpenOutcome = 'ALLOWED'
        [void][SafeUploadRepro.Native]::CloseHandle($freshOpenHandle)
        $freshOpenError = 0
    } else {
        $freshOpenError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($freshOpenError -eq 32) { $freshOpenOutcome = 'PROTECTED_REFUSAL_SHARING_VIOLATION' }
        else { $freshOpenOutcome = 'UNCLASSIFIED_FAILURE' }
    }
    "PolicyShrinkFreshReaderOpen=$freshOpenOutcome; Win32Error=$freshOpenError"

    $sectionStatusBefore = Invoke-PolicyTransitionFenceStatus $InspectorTimeoutSeconds
    "PolicyShrinkFenceStatusBefore=Valid:$($sectionStatusBefore.Valid); ExitCode:$($sectionStatusBefore.ExitCode); SectionsDenied:$($sectionStatusBefore.SectionsDenied); SectionNameUnresolved:$($sectionStatusBefore.SectionNameUnresolved); Complete:$($sectionStatusBefore.Complete)"
    if ($sectionStatusBefore.Error) { "PolicyShrinkFenceStatusBeforeError=$($sectionStatusBefore.Error -replace '[\r\n;]', ' ')" }

    $sectionNativeException = ''
    try {
        $sectionMappingHandle = [SafeUploadRepro.Native]::CreateFileMappingW(
            $sectionFile.SafeFileHandle.DangerousGetHandle(), [IntPtr]::Zero, [uint32]4, [uint32]0,
            [uint32]4096, ('Local\SafeUpload-PolicyShrink-' + $id))
    }
    catch {
        $sectionMappingHandle = [IntPtr]::Zero
        $sectionNativeException = $_.Exception.Message
    }
    $sectionCreateError = if ($sectionMappingHandle -eq [IntPtr]::Zero) {
        if ($sectionNativeException) { -1 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    } else { 0 }
    $sectionStatusAfter = Invoke-PolicyTransitionFenceStatus $InspectorTimeoutSeconds
    "PolicyShrinkFenceStatusAfter=Valid:$($sectionStatusAfter.Valid); ExitCode:$($sectionStatusAfter.ExitCode); SectionsDenied:$($sectionStatusAfter.SectionsDenied); SectionNameUnresolved:$($sectionStatusAfter.SectionNameUnresolved); Complete:$($sectionStatusAfter.Complete)"
    if ($sectionStatusAfter.Error) { "PolicyShrinkFenceStatusAfterError=$($sectionStatusAfter.Error -replace '[\r\n;]', ' ')" }

    $sectionDeniedDelta = $null
    $sectionUnresolvedDelta = $null
    $sectionCallbackCorrelation = 'UNOBSERVABLE'
    if ($sectionStatusBefore.Valid -and $sectionStatusAfter.Valid) {
        $sectionDeniedDelta = [decimal]$sectionStatusAfter.SectionsDenied - [decimal]$sectionStatusBefore.SectionsDenied
        $sectionUnresolvedDelta = [decimal]$sectionStatusAfter.SectionNameUnresolved - [decimal]$sectionStatusBefore.SectionNameUnresolved
        if ($sectionCreateError -ne 5) {
            $sectionCallbackCorrelation = 'UNOBSERVABLE_OTHER_CREATE_RESULT'
        } elseif ($sectionDeniedDelta -lt 0 -or $sectionUnresolvedDelta -lt 0) {
            $sectionCallbackCorrelation = 'UNOBSERVABLE_COUNTER_REGRESSION'
        } elseif ($sectionUnresolvedDelta -gt 0 -or $sectionDeniedDelta -gt 1) {
            $sectionCallbackCorrelation = 'AMBIGUOUS'
        } elseif ($sectionDeniedDelta -eq 0) {
            $sectionCallbackCorrelation = 'UNATTRIBUTED'
        } elseif ($sectionDeniedDelta -eq 1 -and $sectionUnresolvedDelta -eq 0) {
            $sectionCallbackCorrelation = 'TEMPORALLY_CORRELATED'
        } else {
            $sectionCallbackCorrelation = 'UNOBSERVABLE_COUNTER_DELTA'
        }
    }
    $deniedDeltaOutput = if ($null -eq $sectionDeniedDelta) { 'UNAVAILABLE' } else { [string]$sectionDeniedDelta }
    $unresolvedDeltaOutput = if ($null -eq $sectionUnresolvedDelta) { 'UNAVAILABLE' } else { [string]$sectionUnresolvedDelta }
    "PolicyShrinkSectionCallbackCorrelation=$sectionCallbackCorrelation; Win32Error=$sectionCreateError; SectionsDeniedDelta=$deniedDeltaOutput; SectionNameUnresolvedDelta=$unresolvedDeltaOutput"
    if ($sectionNativeException) { "PolicyShrinkWritableSectionNativeError=$($sectionNativeException -replace '[\r\n;]', ' ')" }

    if ($sectionMappingHandle -ne [IntPtr]::Zero) {
        $sectionCreateOutcome = 'ALLOWED'
        $shrinkSectionMeasurementOutcome = 'SECTION_CREATED'
    } elseif ($sectionCreateError -eq 5 -and $sectionCallbackCorrelation -eq 'TEMPORALLY_CORRELATED') {
        $sectionCreateOutcome = 'EXPECTED_ACCESS_DENIED_TEMPORALLY_CORRELATED'
        $shrinkSectionMeasurementOutcome = 'ACCESS_DENIED_TEMPORALLY_CORRELATED'
    } elseif ($sectionCreateError -eq 5) {
        $sectionCreateOutcome = 'ACCESS_DENIED_' + $sectionCallbackCorrelation
        $shrinkSectionMeasurementOutcome = 'UNOBSERVABLE_' + $sectionCallbackCorrelation
        $shrinkSectionMeasurementUnknown = $true
    } else {
        $sectionCreateOutcome = 'UNCLASSIFIED_FAILURE'
        $shrinkSectionMeasurementOutcome = 'UNOBSERVABLE_UNCLASSIFIED_CREATE_ERROR'
        $shrinkSectionMeasurementUnknown = $true
    }
    "PolicyShrinkWritableSectionCreate=$sectionCreateOutcome; Win32Error=$sectionCreateError"
    if ($sectionMappingHandle -ne [IntPtr]::Zero) {
        $sectionView = [SafeUploadRepro.Native]::MapViewOfFile($sectionMappingHandle, [uint32]2, [uint32]0, [uint32]0,
            [UIntPtr]::new([uint64]4096))
        if ($sectionView -ne [IntPtr]::Zero) {
            $shrinkSectionMeasurementOutcome = 'WRITABLE_VIEW_ACQUIRED'
            $sectionData = New-Object byte[] 4096
            [Array]::Copy($shrinkMarker, $sectionData, $shrinkMarker.Length)
            $shrinkSectionWriteAttempted = $true
            try {
                [Runtime.InteropServices.Marshal]::Copy($sectionData, 0, $sectionView, $sectionData.Length)
                $shrinkSectionWriteOutcome = 'SUCCESS'
            }
            catch { $shrinkSectionWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
            if ($shrinkSectionWriteOutcome -eq 'SUCCESS') {
                if ([SafeUploadRepro.Native]::FlushViewOfFile($sectionView, [UIntPtr]::new([uint64]4096))) {
                    $shrinkSectionFlushOutcome = 'SUCCESS'
                    $shrinkSectionFileBuffersFlushOutcome = Flush-TestFileBuffers $sectionFile
                } else {
                    $shrinkSectionFlushOutcome = 'OBSERVED_REFUSED: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                }
            }
            "PolicyShrinkWritableSectionMappedWrite=$shrinkSectionWriteOutcome; FlushViewOfFile=$shrinkSectionFlushOutcome; FlushFileBuffers=$shrinkSectionFileBuffersFlushOutcome"
            if ([SafeUploadRepro.Native]::UnmapViewOfFile($sectionView)) {
                $sectionView = [IntPtr]::Zero
            } else {
                $allMappingsReleased = $false
                'PolicyShrinkWritableSectionUnmap=FAILED; LastError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            }
        } else {
            $mapViewError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $shrinkSectionMeasurementOutcome = 'UNOBSERVABLE_MAP_VIEW_FAILURE'
            $shrinkSectionMeasurementUnknown = $true
            "PolicyShrinkWritableSectionMapView=UNOBSERVABLE; Win32Error=$mapViewError"
        }
        if ([SafeUploadRepro.Native]::CloseHandle($sectionMappingHandle)) {
            $sectionMappingHandle = [IntPtr]::Zero
        } else {
            $allMappingsReleased = $false
            'PolicyShrinkSectionHandleClose=FAILED; LastError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    }
    "PolicyShrinkSectionMeasurement=$shrinkSectionMeasurementOutcome; Unknown=$shrinkSectionMeasurementUnknown"

    $shrinkData = New-Object byte[] 4096
    [Array]::Copy($shrinkMarker, $shrinkData, $shrinkMarker.Length)
    $oldViewShrinkWriteOutcome = 'SUCCESS'
    try {
        $shrinkView.WriteArray(0, $shrinkData, 0, $shrinkData.Length)
    }
    catch { $oldViewShrinkWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    if ($oldViewShrinkWriteOutcome -eq 'SUCCESS') {
        try {
            $shrinkView.Flush()
            $oldViewShrinkFlushOutcome = 'SUCCESS'
            $oldViewShrinkFileBuffersFlushOutcome = Flush-TestFileBuffers $shrinkFile
        }
        catch { $oldViewShrinkFlushOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    }
    "PreShrinkMappedViewWriteAfterShrink=$oldViewShrinkWriteOutcome; Flush=$oldViewShrinkFlushOutcome; FlushFileBuffers=$oldViewShrinkFileBuffersFlushOutcome"

    if ($null -ne $shrinkView) {
        try { $shrinkView.Dispose(); $shrinkView = $null }
        catch { $allMappingsReleased = $false; 'ViewDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $shrinkMapping) {
        try { $shrinkMapping.Dispose(); $shrinkMapping = $null }
        catch { $allMappingsReleased = $false; 'MappingDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $shrinkFile) { $shrinkFile.Dispose(); $shrinkFile = $null }
    if ($null -ne $sectionFile) { $sectionFile.Dispose(); $sectionFile = $null }

    # Compare the complete fixture data extent against the saved raw baseline.
    # Any byte change is unexpected exposure; a failed file-buffer flush or raw
    # read is unknown, never evidence of physical absence.
    $finalRawComparison = 'UNOBSERVABLE'
    try {
        for ($rawTry = 0; $rawTry -lt 60; $rawTry++) {
            $finalRawComparison = Compare-RawFixtureToBaseline $rawCluster $rawClusterSize $rawBaseline
            if ($finalRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        $finalRawComparison = 'UNOBSERVABLE: ' + $_.Exception.Message
        "RawDestinationObservationError=$($_.Exception.Message)"
    }
    if ($finalRawComparison -is [string]) { "RawDestinationExtentComparison=$finalRawComparison" }
    else { "RawDestinationExtentComparison=$($finalRawComparison.State); Bytes=$($finalRawComparison.ByteCount); DifferentBytes=$($finalRawComparison.DifferentBytes); FirstDifferentOffset=$($finalRawComparison.FirstDifferentOffset)" }
    "MappingDisposalConfirmed=$allMappingsReleased"
    $privacyGap = $expansionPrivacyVerdict -eq 'REPRODUCED' -or
        $retainedPrivacyVerdict -eq 'REPRODUCED' -or
        ($finalRawComparison -isnot [string] -and $finalRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED')
    $privacyUnknown = $expansionPrivacyVerdict -eq 'INCONCLUSIVE' -or
        $retainedPrivacyVerdict -eq 'INCONCLUSIVE' -or $retainedPrivacyVerdict -eq 'NOT_RUN' -or
        -not $allMappingsReleased -or
        ($shrinkSectionWriteAttempted -and
            ($shrinkSectionWriteOutcome -ne 'SUCCESS' -or $shrinkSectionFlushOutcome -ne 'SUCCESS' -or
             $shrinkSectionFileBuffersFlushOutcome -ne 'SUCCESS')) -or
        $shrinkSectionMeasurementUnknown -or
        ($oldViewShrinkWriteOutcome -ne 'SUCCESS' -or $oldViewShrinkFlushOutcome -ne 'SUCCESS' -or
         $oldViewShrinkFileBuffersFlushOutcome -ne 'SUCCESS') -or
        $expansionFileBuffersFlushOutcome -ne 'SUCCESS' -or $finalRawComparison -is [string]
    "ExpansionPrivacyMeasurement=$expansionPrivacyVerdict"
    "RetainedSectionPrivacyMeasurement=$retainedPrivacyVerdict"
    "PrivacyExposure=$(if ($privacyGap) { 'OBSERVED_UNEXPECTED_BYTES' } else { 'NOT_OBSERVED' })"
    $privacyObservation = if ($privacyGap) {
        'UNEXPECTED_BYTES_EXPOSED'
    } elseif ($oldViewShrinkWriteOutcome -ne 'SUCCESS' -or
        $oldViewShrinkFlushOutcome -ne 'SUCCESS' -or $oldViewShrinkFileBuffersFlushOutcome -ne 'SUCCESS') {
        'UNOBSERVABLE'
    } elseif ($privacyUnknown) { 'UNOBSERVABLE' }
    else { 'NO_UNEXPECTED_BYTES_OBSERVED' }
    "PrivacyObservation=$privacyObservation"
    $freshReaderRefusedByFence = $freshOpenOutcome -eq 'PROTECTED_REFUSAL_SHARING_VIOLATION'
    # The generic callback contracts permit accurate failure status. Count only ERROR_ACCESS_DENIED
    # with one driver counter increment in the bracket; that global delta is temporal correlation,
    # not per-file attribution. All other results remain non-passing.
    $sectionCreateRefusedByContract = $sectionCreateOutcome -eq 'EXPECTED_ACCESS_DENIED_TEMPORALLY_CORRELATED' -and
        $sectionCallbackCorrelation -eq 'TEMPORALLY_CORRELATED'
    if ($privacyGap -or $privacyUnknown -or -not $freshReaderRefusedByFence -or
        -not $sectionCreateRefusedByContract) {
        'PolicyShrinkProtection=FAIL'
        'PolicyShrinkSectionCallbackStatus=' + $(if ($sectionCreateRefusedByContract) { 'EXPECTED_ACCESS_DENIED_TEMPORALLY_CORRELATED' } else { 'NOT_EXPECTED_DENIAL' })
        throw 'Policy-shrink protection is not a pass: see raw-byte outcome, old-view result, fresh-reader result, and exact section-create error.'
    }
    'PolicyShrinkProtection=PASS'
    'PolicyShrinkSectionCallbackStatus=EXPECTED_ACCESS_DENIED_TEMPORALLY_CORRELATED'
}
finally {
    $cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
    $policyRestoreSucceeded = $false
    $policyHashVerified = $false
    $driverRestoreSucceeded = $false
    $driverHashVerified = $false
    $filterUnloadedVerified = $false
    $agentQuiescenceVerified = $false

    # Stop every process returned by the helper, including a process whose
    # startup wait failed before assignment to $agent. Continue on stop errors.
    foreach ($trackedAgent in @($activeTestAgents)) {
        try {
            Stop-StagedTestAgent $trackedAgent
            [void]$activeTestAgents.Remove($trackedAgent)
        } catch { [void]$cleanupFailures.Add('Stop agent: ' + $_.Exception.Message) }
    }

    $inspectorProcessCleanupVerified = $false
    $inspectorTaskCleanupVerified = $false
    try {
        foreach ($taskName in @($inspectorTaskNames)) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        $inspectorTaskCleanupVerified = $true
        foreach ($taskName in @($inspectorTaskNames)) {
            if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
                $inspectorTaskCleanupVerified = $false
            }
        }
    } catch {
        [void]$cleanupFailures.Add('Inspector task cleanup: ' + $_.Exception.Message)
    }
    try {
        $namedInspectorProcesses = @(Get-Process -Name $inspectorProcessName -ErrorAction SilentlyContinue)
        $matchingInspectorProcesses = @(Get-PolicyTransitionInspectorProcesses)
        if ($namedInspectorProcesses.Count -ne $matchingInspectorProcesses.Count) {
            throw 'Could not verify the image path of every policy-transition Inspector process.'
        }
        foreach ($process in $matchingInspectorProcesses) {
            Stop-Process -Id ([int]$process.ProcessId) -Force -ErrorAction Stop
        }
        $inspectorProcessCleanupVerified = $false
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            if (@(Get-Process -Name $inspectorProcessName -ErrorAction SilentlyContinue).Count -eq 0) {
                $inspectorProcessCleanupVerified = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
    } catch {
        [void]$cleanupFailures.Add('Inspector process cleanup: ' + $_.Exception.Message)
    }
    if ($inspectorCopyCreated) {
        if ($inspectorProcessCleanupVerified -and $inspectorTaskCleanupVerified) {
            try {
                Remove-Item -LiteralPath $inspectorCopy -Force -ErrorAction Stop
                $inspectorCopyRemoved = -not (Test-Path -LiteralPath $inspectorCopy)
                if (-not $inspectorCopyRemoved) { throw 'Inspector copy still exists after removal.' }
            } catch {
                [void]$cleanupFailures.Add('Remove Inspector copy: ' + $_.Exception.Message)
                'RetainedInspectorCopy=' + $inspectorCopy
            }
        } else {
            [void]$cleanupFailures.Add('Inspector copy retained because process/task cleanup was not verified.')
            'RetainedInspectorCopy=' + $inspectorCopy
        }
    } else {
        $inspectorCopyRemoved = -not (Test-Path -LiteralPath $inspectorCopy)
    }
    foreach ($inspectorCleanupMessage in $inspectorCleanupMessages) { $inspectorCleanupMessage }

    if ($sectionView -ne [IntPtr]::Zero) {
        try {
            if ([SafeUploadRepro.Native]::UnmapViewOfFile($sectionView)) { $sectionView = [IntPtr]::Zero }
            else { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Unmap section view: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        } catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Unmap section view: ' + $_.Exception.Message) }
    }
    if ($retainedView -ne [IntPtr]::Zero) {
        try {
            if ([SafeUploadRepro.Native]::UnmapViewOfFile($retainedView)) {
                $retainedView = [IntPtr]::Zero
                $retainedViewReleased = $true
            } else {
                $allMappingsReleased = $false
                [void]$cleanupFailures.Add('Unmap retained-section view: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
        } catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Unmap retained-section view: ' + $_.Exception.Message) }
    }
    if ($sectionMappingHandle -ne [IntPtr]::Zero) {
        try {
            if ([SafeUploadRepro.Native]::CloseHandle($sectionMappingHandle)) { $sectionMappingHandle = [IntPtr]::Zero }
            else { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Close section mapping handle: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        } catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Close section mapping handle: ' + $_.Exception.Message) }
    }
    if ($retainedMappingHandle -ne [IntPtr]::Zero) {
        try {
            if ([SafeUploadRepro.Native]::CloseHandle($retainedMappingHandle)) {
                $retainedMappingHandle = [IntPtr]::Zero
                $retainedMappingReleased = $true
            } else {
                $allMappingsReleased = $false
                [void]$cleanupFailures.Add('Close retained-section mapping handle: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
        } catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Close retained-section mapping handle: ' + $_.Exception.Message) }
    }
    foreach ($item in @(
        @{ Name = 'view'; Value = $view }, @{ Name = 'mapping'; Value = $mapping },
        @{ Name = 'shrink view'; Value = $shrinkView }, @{ Name = 'shrink mapping'; Value = $shrinkMapping },
        @{ Name = 'file'; Value = $file }, @{ Name = 'retained-section file'; Value = $retainedFile },
        @{ Name = 'section file'; Value = $sectionFile },
        @{ Name = 'shrink file'; Value = $shrinkFile }
    )) {
        if ($null -ne $item.Value) {
            try {
                $item.Value.Dispose()
                if ($item.Name -eq 'retained-section file') {
                    $retainedFile = $null
                    $retainedFileReleased = $true
                }
            }
            catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Dispose ' + $item.Name + ': ' + $_.Exception.Message) }
        }
    }

    # Restoration actions are independent: a failed agent stop or handle close
    # must not skip policy restoration, driver restoration, or final checks.
    if ($null -ne $policyBytes) {
        try {
            $restorePolicy = $policyBytes
            if (Test-Path -LiteralPath $policyBackup) {
                try {
                    $backupPolicyHash = (Get-FileHash -LiteralPath $policyBackup -Algorithm SHA256).Hash
                    if ($backupPolicyHash -eq $expectedPolicy) { $restorePolicy = [IO.File]::ReadAllBytes($policyBackup) }
                    else { [void]$cleanupFailures.Add('Policy backup hash mismatch; falling back to in-memory baseline') }
                } catch { [void]$cleanupFailures.Add('Read/verify policy backup: ' + $_.Exception.Message) }
            }
            # Preserve the baseline file and its metadata when a rejection-only
            # run left the approved policy bytes unchanged.
            $policyNeedsRestore = -not (Test-Path -LiteralPath $policy -PathType Leaf)
            if (-not $policyNeedsRestore) {
                try {
                    $policyNeedsRestore = (Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy
                } catch { $policyNeedsRestore = $true }
            }
            if ($policyNeedsRestore) {
                [IO.File]::WriteAllBytes($policy, $restorePolicy)
            }
            $policyRestoreSucceeded = $true
        } catch { [void]$cleanupFailures.Add('Restore policy: ' + $_.Exception.Message) }
    }
    try {
        if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) {
            [void]$cleanupFailures.Add('Original policy hash mismatch after restoration')
        } else { $policyHashVerified = $true }
    } catch { [void]$cleanupFailures.Add('Verify policy restoration: ' + $_.Exception.Message) }

    if ($replaced) {
        try { Restore-StagedTestDriver $backup $loaded $verifierEnabled; $driverRestoreSucceeded = $true }
        catch { [void]$cleanupFailures.Add('Restore driver: ' + $_.Exception.Message) }
    }
    if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) {
        try { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force }
        catch { [void]$cleanupFailures.Add('Remove fixture: ' + $_.Exception.Message) }
    }
    try {
        if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) { [void]$cleanupFailures.Add('Policy-transition fixture remains') }
    } catch { [void]$cleanupFailures.Add('Verify fixture cleanup: ' + $_.Exception.Message) }
    try {
        if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
            [void]$cleanupFailures.Add('Original driver hash mismatch after restoration')
        } else { $driverHashVerified = $true }
    } catch { [void]$cleanupFailures.Add('Verify driver restoration: ' + $_.Exception.Message) }
    try {
        if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { [void]$cleanupFailures.Add('SafeUpload filter remained loaded') }
        else { $filterUnloadedVerified = $true }
    } catch { [void]$cleanupFailures.Add('Verify filter unload: ' + $_.Exception.Message) }

    try {
        $activeAgentCount = @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count
        $activeTaskCount = @(Get-ScheduledTask | Where-Object { $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)' }).Count
        if ($activeAgentCount -eq 0 -and $activeTaskCount -eq 0) { $agentQuiescenceVerified = $true }
        else {
            [void]$cleanupFailures.Add("Agent/task cleanup incomplete: processes=$activeAgentCount tasks=$activeTaskCount")
        }
    } catch { [void]$cleanupFailures.Add('Verify agent/task cleanup: ' + $_.Exception.Message) }

    if ($serviceDirectoryCreated) {
        if ($agentQuiescenceVerified) {
            try {
                if (Test-Path -LiteralPath $serviceDirectory) {
                    Assert-PolicyTransitionServiceTree $serviceDirectory
                    Remove-Item -LiteralPath $serviceDirectory -Recurse -Force -ErrorAction Stop
                }
                $serviceDirectoryRemoved = -not (Test-Path -LiteralPath $serviceDirectory)
                if (-not $serviceDirectoryRemoved) { throw 'Verified service extraction still exists after removal.' }
            } catch {
                [void]$cleanupFailures.Add('Remove verified service extraction: ' + $_.Exception.Message)
                'RetainedVerifiedServiceExtraction=' + $serviceDirectory
            }
        } else {
            [void]$cleanupFailures.Add('Verified service extraction retained because process/task cleanup was not verified.')
            'RetainedVerifiedServiceExtraction=' + $serviceDirectory
        }
    } else {
        $serviceDirectoryRemoved = -not (Test-Path -LiteralPath $serviceDirectory)
        if ($serviceDirectoryCreationAttempted -and -not $serviceDirectoryRemoved) {
            [void]$cleanupFailures.Add('Unverified service staging directory retained without recursive cleanup.')
            'RetainedUnverifiedServiceStagingDirectory=' + $serviceDirectory
        }
    }

    if ($agentQuiescenceVerified) {
        try {
            if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $expectedPolicy) { $policyHashVerified = $true }
            else { $policyHashVerified = $false; [void]$cleanupFailures.Add('Policy changed after initial restoration verification') }
        } catch { $policyHashVerified = $false; [void]$cleanupFailures.Add('Final policy restoration verification: ' + $_.Exception.Message) }
    } else { $policyHashVerified = $false }

    'PolicyTransitionInspectorProcessCleanupVerified=' + $inspectorProcessCleanupVerified
    'PolicyTransitionInspectorTaskCleanupVerified=' + $inspectorTaskCleanupVerified
    'PolicyTransitionInspectorCopyRemoved=' + $inspectorCopyRemoved
    'VerifiedServiceExtractionRemoved=' + $serviceDirectoryRemoved
    if ($PolicyRejectionOnly) {
        'RetainedSectionDisposalConfirmed=NOT_APPLICABLE_POLICY_REJECTION_ONLY'
    } else {
        'RetainedSectionDisposalConfirmed=View:' + $retainedViewReleased + '; Section:' + $retainedMappingReleased + '; File:' + $retainedFileReleased
    }
    if (-not $inspectorTaskCleanupVerified -or -not $inspectorProcessCleanupVerified -or -not $inspectorCopyRemoved) {
        [void]$cleanupFailures.Add('Policy-transition Inspector cleanup was not fully verified')
    }

    # Remove recovery copies independently, and only after the corresponding
    # restore and verification succeeded. Failed recovery keeps a named copy.
    try {
        if ($policyRestoreSucceeded -and $policyHashVerified -and $agentQuiescenceVerified) {
            if (Test-Path -LiteralPath $policyBackup) {
                try { Remove-Item -LiteralPath $policyBackup -Force }
                catch { [void]$cleanupFailures.Add('Remove verified policy backup: ' + $_.Exception.Message); 'RetainedPolicyBackup=' + $policyBackup }
            }
        } elseif (Test-Path -LiteralPath $policyBackup) {
            'RetainedPolicyBackup=' + $policyBackup + '; Reason=policy restore/hash/agent verification incomplete'
        } elseif ($null -ne $policyBytes) {
            'RequiredPolicyBackupUnavailable=' + $policyBackup
        }
    } catch { [void]$cleanupFailures.Add('Verify/remove policy backup: ' + $_.Exception.Message); 'RetainedPolicyBackup=' + $policyBackup }
    try {
        if ($driverRestoreSucceeded -and $driverHashVerified -and $filterUnloadedVerified) {
            if (Test-Path -LiteralPath $backup) {
                try { Remove-Item -LiteralPath $backup -Force }
                catch { [void]$cleanupFailures.Add('Remove verified driver backup: ' + $_.Exception.Message); 'RetainedDriverBackup=' + $backup }
            }
        } elseif (Test-Path -LiteralPath $backup) {
            'RetainedDriverBackup=' + $backup + '; Reason=driver restore/hash/filter verification incomplete'
        } elseif ($replaced) {
            'RequiredDriverBackupUnavailable=' + $backup
        }
    } catch { [void]$cleanupFailures.Add('Verify/remove driver backup: ' + $_.Exception.Message); 'RetainedDriverBackup=' + $backup }
    try {
        $finalSettings = & verifier.exe /querysettings 2>&1 | Out-String
        if ($finalSettings -notmatch 'Verifier Flags:\s+0x00000000') { [void]$cleanupFailures.Add('Verifier settings changed during probe') }
    } catch { [void]$cleanupFailures.Add('Verify verifier settings: ' + $_.Exception.Message) }
    'MappingDisposalConfirmed=' + $allMappingsReleased
    if ($cleanupFailures.Count -eq 0) {
        'OriginalDriverAndPolicyRestored=True; VerifierOff=True; FilterUnloaded=True'
        'VerifiedServiceExtractionRemoved=True'
        if ($PolicyRejectionOnly) {
            'AgentProcesses=0; AgentTasks=0; PolicyRejectionOnlyFixtureCreated=False'
        } else {
            'AgentProcesses=0; AgentTasks=0; PolicyTransitionFixtureRemoved=True'
        }
    } else {
        foreach ($cleanupFailure in $cleanupFailures) { 'CleanupFailure=' + $cleanupFailure }
        throw ('Cleanup incomplete after all restoration attempts: ' + ($cleanupFailures -join '; '))
    }
}
