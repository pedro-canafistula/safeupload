#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfCheckOnly)
# One unprotected NTFS measurement, not a driver or SeAssignSecurityEx gate.
# SYSTEM creator baseline only; ordinary/restricted/low-level subjects remain open.
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'writer-permission-native-control.ps1') -SelfCheckOnly
& (Join-Path $PSScriptRoot 'bound-publication-native-control.ps1') -SelfCheckOnly
$method = [BoundPublicationNativeControl].GetMethod('CreateRelativeWithDescriptor')
if ($null -eq $method -or $method.GetParameters().Count -ne 3 -or
    $method.GetParameters()[2].ParameterType -ne [byte[]] -or
    [WriterPermissionNativeControl].GetMethod('SecurityBinary').ReturnType -ne [byte[]]) {
    throw 'Security round-trip native signatures are invalid.'
}
Write-Output 'SecurityRoundTripSignatureSelfCheck=PASS NativeCalls=False'
if ($SelfCheckOnly) { return }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { if (-not $identity.IsSystem) { throw 'The publication measurement requires SYSTEM; no subject fallback is allowed.' } }
finally { $identity.Dispose() }

function New-SuppliedDescriptor([string]$Sddl, [bool]$Defaulted = $false) {
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    $bytes = New-Object byte[] $raw.BinaryLength
    $raw.GetBinaryForm($bytes, 0)
    if ($Defaulted) { $bytes[2] = $bytes[2] -bor 8 }
    return ,$bytes
}
function Get-CompactDescriptor([byte[]]$Bytes) {
    # Raw ACLs preserve ACE order/payload; do not round-trip through SDDL.
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor($Bytes, 0)
    $compact = New-Object byte[] $raw.BinaryLength
    $raw.GetBinaryForm($compact, 0)
    return ,$compact
}
function Get-Hex([byte[]]$Bytes) { return [BitConverter]::ToString($Bytes).Replace('-', '') }
function Set-ParentFixture([string]$Path, [string]$EveryoneRights) {
    [void][IO.Directory]::CreateDirectory($Path)
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm(('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;' + $EveryoneRights + ';;;WD)'))
    [IO.Directory]::SetAccessControl($Path, $security)
}
function Reset-FileFixture([string]$Path) {
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)', [Security.AccessControl.AccessControlSections]::Access)
    [IO.File]::SetAccessControl($Path, $security)
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-security-roundtrip-' + [Guid]::NewGuid().ToString('N'))
$beforePrivileges = [WriterPermissionNativeControl]::ProcessPrivileges()
$cases = @(
    @{Name='inherited-null-input';Sddl=$null;Defaulted=$false;Moved=$false},
    @{Name='protected-read-only';Sddl='O:SYG:SYD:P(A;;FR;;;SY)';Defaulted=$false;Moved=$false},
    @{Name='unprotected-defaulted';Sddl='O:SYG:SYD:(A;;FR;;;SY)';Defaulted=$true;Moved=$false},
    @{Name='protected-empty-dacl';Sddl='O:SYG:SYD:P';Defaulted=$false;Moved=$false},
    @{Name='null-dacl';Sddl='O:SYG:SYD:NO_ACCESS_CONTROL';Defaulted=$false;Moved=$false},
    @{Name='explicit-low-label';Sddl='O:SYG:SYD:P(A;;FR;;;SY)S:(ML;;NW;;;LW)';Defaulted=$false;Moved=$false},
    @{Name='moved-inherited-target';Sddl=$null;Defaulted=$false;Moved=$true}
)
$rows = New-Object 'Collections.Generic.List[object]'
try {
    Set-ParentFixture $root 'FR'
    Write-Output ('FixtureRoot=' + $root)
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Output ('NativeControlPlatform=' + $os.Caption + ' Version=' + $os.Version)
    Write-Output ('WindowsPowerShell=' + $PSVersionTable.PSVersion + ' Subject=SYSTEM PrivateCreatorRestoreDisabled=True')
    & whoami.exe /priv /fo csv
    if ($LASTEXITCODE -ne 0) { throw 'Process privilege inventory failed.' }
    foreach ($case in $cases) {
        $folder = Join-Path $root $case.Name
        $firstParent = Join-Path $folder 'original'
        $secondParent = Join-Path $folder 'destination'
        Set-ParentFixture $firstParent 'FR'
        Set-ParentFixture $secondParent 'FA'
        $path = Join-Path $firstParent 'source.txt'
        $supplied = $null
        if ($null -ne $case.Sddl) { $supplied = New-SuppliedDescriptor $case.Sddl $case.Defaulted }
        $writer = $null; $source = $null; $temporary = $null; $tempMetadata = $null; $parent = $null; $parentMetadata = $null
        try {
            $writer = [WriterPermissionNativeControl]::OpenWithDescriptor($path, 0x00100002, 0, 2, $supplied)
            if (-not $writer.Accepted -or $writer.Information -ne 2 -or $writer.GrantedAccess -ne 0x00100002) {
                throw ('Native initial writer CREATE failed or changed grant: ' + $case.Name + ' status=0x{0:X8}' -f $writer.Status)
            }
            $initialId = [BoundPublicationNativeControl]::Identity($writer.Handle)
            if ($case.Moved) {
                $writer.Dispose(); $writer = $null
                $moved = Join-Path $secondParent 'source.txt'
                [IO.File]::Move($path, $moved)
                $path = $moved
                $writer = [WriterPermissionNativeControl]::Open($path, 0x00100002, 0, 1)
                if (-not $writer.Accepted -or $writer.GrantedAccess -ne 0x00100002) { throw 'Moved target writer lease failed.' }
                if ([BoundPublicationNativeControl]::Identity($writer.Handle) -ne $initialId) { throw 'Move changed the exact target identity.' }
            }
            $source = [WriterPermissionNativeControl]::SystemMetadata($path, $false)
            Write-Output ([pscustomobject]@{Control='SourceMetadata';Case=$case.Name;
                Status=('0x{0:X8}' -f $source.Status);IoStatus=$source.IoStatus;
                Granted=('0x{0:X8}' -f $source.GrantedAccess)} | ConvertTo-Json -Compress)
            if (-not $source.Accepted -or $source.GrantedAccess -ne 0x01020000 -or
                [BoundPublicationNativeControl]::Identity($source.Handle) -ne $initialId) { throw 'Metadata observer failed under writer share zero.' }
            $stored = [WriterPermissionNativeControl]::SecurityBinary($source.Handle)
            $sourceCompact = Get-CompactDescriptor $stored
            $parentPath = Split-Path -Parent $path
            $parent = [BoundPublicationNativeControl]::Parent($parentPath)
            $parentId = [BoundPublicationNativeControl]::Identity($parent)
            $parentMetadata = [WriterPermissionNativeControl]::SystemMetadata($parentPath, $true)
            if (-not $parentMetadata.Accepted -or
                [BoundPublicationNativeControl]::Identity($parentMetadata.Handle) -ne $parentId) { throw 'Parent metadata observer failed.' }
            $parentSecurity = [WriterPermissionNativeControl]::SecurityBinary($parentMetadata.Handle)
            $leaf = 'publication.tmp'
            $temporary = [BoundPublicationNativeControl]::CreateRelativeWithDescriptor($parent, $leaf, $stored)
            [BoundPublicationNativeControl]::RequireHandleContract($temporary)
            $temporaryPath = Join-Path $parentPath $leaf
            $tempMetadata = [WriterPermissionNativeControl]::SystemMetadata($temporaryPath, $false)
            if (-not $tempMetadata.Accepted -or $tempMetadata.GrantedAccess -ne 0x01020000 -or
                [BoundPublicationNativeControl]::Identity($tempMetadata.Handle) -ne
                [BoundPublicationNativeControl]::Identity($temporary)) { throw 'Temporary metadata observer failed under share zero.' }
            $actual = [WriterPermissionNativeControl]::SecurityBinary($tempMetadata.Handle)
            $actualCompact = Get-CompactDescriptor $actual
            if ((Get-Hex ([WriterPermissionNativeControl]::SecurityBinary($source.Handle))) -ne (Get-Hex $stored) -or
                (Get-Hex ([WriterPermissionNativeControl]::SecurityBinary($parentMetadata.Handle))) -ne (Get-Hex $parentSecurity) -or
                [BoundPublicationNativeControl]::Identity($parent) -ne $parentId) { throw 'Control changed source security or parent identity.' }
            $row = [pscustomobject]@{Case=$case.Name;CreatorStatus='0x00000000';CreatorGrant='0x00100002';
                SourceId=$initialId;MetadataGrant='0x01020000';MetadataPrivateSeSecurityEnabled=$true;TempGrant='0x00110082';IoMode='0x2A';
                SuppliedInputHex=$(if ($null -eq $supplied) {$null} else {Get-Hex $supplied});
                StoredSourceHex=(Get-Hex $stored);TempStoredHex=(Get-Hex $actual);
                SuppliedControl=$(if ($null -eq $supplied) {$null} else {[BitConverter]::ToUInt16($supplied,2)});
                SourceControl=[BitConverter]::ToUInt16($stored,2);TempControl=[BitConverter]::ToUInt16($actual,2);
                RawStoredEqual=((Get-Hex $stored) -eq (Get-Hex $actual));
                CompactStoredEqual=((Get-Hex $sourceCompact) -eq (Get-Hex $actualCompact));
                SourceSddl=([WriterPermissionNativeControl]::Security($source.Handle));
                TempSddl=([WriterPermissionNativeControl]::Security($tempMetadata.Handle))}
            $rows.Add($row)
            Write-Output ($row | ConvertTo-Json -Compress)
        } finally {
            foreach ($handle in @($tempMetadata,$temporary,$parentMetadata,$parent,$source,$writer)) { if ($null -ne $handle) {$handle.Dispose()} }
        }
    }
    if ([WriterPermissionNativeControl]::ProcessPrivileges() -ne $beforePrivileges) { throw 'Control changed process privileges.' }
    $different = @($rows | Where-Object {-not $_.CompactStoredEqual})
    Write-Output ('NativeSecurityRoundTripRows=' + $rows.Count + ' StoredMismatches=' + $different.Count + ' ProcessPrivilegesRetained=PASS')
    Write-Output 'SecurityRoundTripMeasurement=PASS Qualification=False KernelConstructorAndOtherSubjects=False'
} finally {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -File -Recurse -Force | ForEach-Object {Reset-FileFixture $_.FullName}
        Remove-Item -LiteralPath $root -Recurse -Force
    }
    if ([WriterPermissionNativeControl]::ProcessPrivileges() -ne $beforePrivileges) { throw 'Fixture cleanup changed process privileges.' }
    Write-Output ('FixtureRemoved=' + (-not (Test-Path -LiteralPath $root)))
}
