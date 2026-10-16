#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfCheckOnly, [switch]$CompareAutoInheritanceRequests,
    [switch]$CompareNativeInheritance, [switch]$CompareAutoInheritConversion, [switch]$CompareMarkerBehavior)
# One unprotected NTFS measurement, not a driver or SeAssignSecurityEx gate.
# SYSTEM creator baseline only; ordinary/restricted/low-level subjects remain open.
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'writer-permission-native-control.ps1') -SelfCheckOnly
& (Join-Path $PSScriptRoot 'bound-publication-native-control.ps1') -SelfCheckOnly
& (Join-Path $PSScriptRoot 'security-roundtrip-native-control.SelfCheck.ps1')
$method = [BoundPublicationNativeControl].GetMethod('CreateRelativeWithDescriptor')
if ($null -eq $method -or $method.GetParameters().Count -ne 3 -or
    $method.GetParameters()[2].ParameterType -ne [byte[]] -or
    [WriterPermissionNativeControl].GetMethod('SecurityBinary').ReturnType -ne [byte[]]) {
    throw 'Security round-trip native signatures are invalid.'
}
Write-Output 'SecurityRoundTripSignatureSelfCheck=PASS NativeCalls=False'

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
function Get-DescriptorField([byte[]]$Bytes, [int]$Offset) {
    if ($Offset -ge $Bytes.Length) { return 'Absent' }
    if ($Offset -lt 20) {
        if ($Offset -eq 0) { return 'Revision' }
        if ($Offset -eq 1) { return 'ResourceManagerControl' }
        if ($Offset -lt 4) { return 'Control' }
        return @('OwnerOffset','GroupOffset','SaclOffset','DaclOffset')[[int][Math]::Floor(($Offset-4)/4)]
    }
    foreach ($component in @(@('Owner',4),@('Group',8),@('Sacl',12),@('Dacl',16))) {
        $start = [BitConverter]::ToUInt32($Bytes, $component[1])
        if ($start -eq 0) { continue }
        if ($component[1] -lt 12) { $length = 8 + 4 * $Bytes[$start+1] }
        else { $length = [BitConverter]::ToUInt16($Bytes, $start+2) }
        if ($Offset -ge $start -and $Offset -lt ($start+$length)) { return ($component[0] + '+' + ($Offset-$start)) }
    }
    return 'Padding'
}
function Get-DescriptorDifference([byte[]]$Expected, [byte[]]$Actual) {
    $differences = New-Object 'Collections.Generic.List[object]'
    for ($i=0; $i -lt [Math]::Max($Expected.Length,$Actual.Length); $i++) {
        if ($i -lt $Expected.Length -and $i -lt $Actual.Length -and $Expected[$i] -eq $Actual[$i]) { continue }
        $differences.Add([pscustomobject]@{Offset=$i;ExpectedField=(Get-DescriptorField $Expected $i);ActualField=(Get-DescriptorField $Actual $i);
            Expected=$(if ($i -lt $Expected.Length) {'{0:X2}' -f $Expected[$i]} else {$null});
            Actual=$(if ($i -lt $Actual.Length) {'{0:X2}' -f $Actual[$i]} else {$null})})
    }
    return $differences.ToArray()
}
function Assert-ControlDeadline {
    if ($script:controlTimer.Elapsed.TotalSeconds -ge 180) { throw 'Native control exceeded its monotonic deadline.' }
}
function Register-Fixture([string]$Path, [bool]$Directory, $Handle = $null) {
    $observer = $null
    try {
        if ($null -eq $Handle) {
            $observer = [WriterPermissionNativeControl]::SystemMetadata($Path,$Directory)
            if (-not $observer.Accepted) { throw ('Cannot register fixture identity: ' + $Path) }
            $Handle = $observer.Handle
        }
        if ($script:fixtures.ContainsKey($Path)) { throw ('Fixture already registered: ' + $Path) }
        $script:fixtures.Add($Path,[pscustomobject]@{Id=[BoundPublicationNativeControl]::Identity($Handle);Directory=$Directory})
    } finally { if ($null -ne $observer) { $observer.Dispose() } }
}
function Assert-FixtureIdentity([string]$Path) {
    if (-not $script:fixtures.ContainsKey($Path)) { throw ('Unregistered fixture: ' + $Path) }
    $entry = $script:fixtures[$Path]
    $observer = [WriterPermissionNativeControl]::SystemMetadata($Path,$entry.Directory)
    try {
        if (-not $observer.Accepted -or [BoundPublicationNativeControl]::Identity($observer.Handle) -ne $entry.Id -or
            ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('Fixture identity/type changed; retained for diagnosis: ' + $Path)
        }
    } finally { $observer.Dispose() }
}
function Get-FixtureDescriptor([string]$Path, [bool]$Directory = $false) {
    Assert-FixtureIdentity $Path
    $observer = [WriterPermissionNativeControl]::SystemMetadata($Path,$Directory)
    try {
        if (-not $observer.Accepted -or $observer.GrantedAccess -ne 0x01020000 -or
            [BoundPublicationNativeControl]::Identity($observer.Handle) -ne $script:fixtures[$Path].Id) { throw 'Complete descriptor observer failed.' }
        return ,([WriterPermissionNativeControl]::SecurityBinary($observer.Handle))
    } finally { $observer.Dispose() }
}
function Set-ParentFixture([string]$Path, [string]$EveryoneRights) {
    [void][IO.Directory]::CreateDirectory($Path)
    Register-Fixture $Path $true
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm(('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;' + $EveryoneRights + ';;;WD)'))
    [IO.Directory]::SetAccessControl($Path, $security)
}
function Reset-FileFixture([string]$Path) {
    $security = New-Object Security.AccessControl.FileSecurity
    $security.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)', [Security.AccessControl.AccessControlSections]::Access)
    [IO.File]::SetAccessControl($Path, $security)
}

if ($SelfCheckOnly) { return }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { if (-not $identity.IsSystem) { throw 'The publication measurement requires SYSTEM; no subject fallback is allowed.' } }
finally { $identity.Dispose() }
[WriterPermissionNativeControl]::NativeProjectionSelfCheck()
$script:controlTimer = [Diagnostics.Stopwatch]::StartNew()
$script:fixtures = @{}

function New-MarkerPair([string]$Directory, [bool]$Moved) {
    Set-ParentFixture $Directory 'FR'
    $original = Join-Path $Directory 'original'
    $destination = Join-Path $Directory 'destination'
    Set-ParentFixture $original 'FR'
    Set-ParentFixture $destination $(if ($Moved) {'FA'} else {'FR'})
    $reference = Join-Path $original 'reference.txt'
    $writer = [WriterPermissionNativeControl]::OpenWithDescriptor($reference,0x00100002,0,2,$null)
    try {
        if (-not $writer.Accepted -or $writer.Information -ne 2 -or $writer.GrantedAccess -ne 0x00100002) { throw 'Marker reference CREATE contract failed.' }
        Register-Fixture $reference $false $writer.Handle
    } finally { $writer.Dispose() }
    if ($Moved) {
        $old = $reference; $reference = Join-Path $destination 'reference.txt'
        [IO.File]::Move($old,$reference)
        $script:fixtures.Add($reference,$script:fixtures[$old]); $script:fixtures.Remove($old)
    } else { $destination = $original }
    $expected = Get-FixtureDescriptor $reference
    $parent = [BoundPublicationNativeControl]::Parent($destination)
    $candidate = Join-Path $destination 'candidate.txt'
    $file = $null
    try {
        $file = [BoundPublicationNativeControl]::CreateRelativeWithDescriptor($parent,'candidate.txt',$expected)
        Register-Fixture $candidate $false $file
        [BoundPublicationNativeControl]::RequireHandleContract($file)
    } finally { if ($null -ne $file) { $file.Dispose() }; $parent.Dispose() }
    $actual = Get-FixtureDescriptor $candidate
    $withoutMarker = [byte[]]$expected.Clone(); $withoutMarker[3] = $withoutMarker[3] -band 0xFB
    if (([BitConverter]::ToUInt16($expected,2) -band 0x0400) -eq 0 -or
        (Get-Hex $withoutMarker) -ne (Get-Hex $actual)) { throw 'Marker pair is not the exact 0x0400-only counterexample; baseline changed.' }
    return [pscustomobject]@{Parent=$destination;Reference=$reference;Candidate=$candidate}
}
function Write-MarkerComparison($Pair, [string]$Case, [string]$Operation, [string]$Reference = '', [string]$Candidate = '') {
    Assert-ControlDeadline
    if ($Reference -eq '') { $Reference = $Pair.Reference }
    if ($Candidate -eq '') { $Candidate = $Pair.Candidate }
    $left = Get-FixtureDescriptor $Reference; $right = Get-FixtureDescriptor $Candidate
    $leftAccess = @([SecurityDescriptorNativeControl]::AccessMatrix($left))
    $rightAccess = @([SecurityDescriptorNativeControl]::AccessMatrix($right))
    $accessEqual = ($leftAccess | ConvertTo-Json -Depth 4 -Compress) -eq ($rightAccess | ConvertTo-Json -Depth 4 -Compress)
    $delta = @(Get-DescriptorDifference $left $right)
    $row = [pscustomobject]@{Control='MarkerBehavior';Case=$Case;Operation=$Operation;
        Result=$(if ($delta.Count -eq 0 -and $accessEqual) {'EQUIVALENT'} else {'DIFFERENT'});
        DescriptorEqual=($delta.Count -eq 0);AccessMatrixEqual=$accessEqual;Differences=$delta;
        ReferenceId=$script:fixtures[$Reference].Id;CandidateId=$script:fixtures[$Candidate].Id;
        ReferenceHex=(Get-Hex $left);CandidateHex=(Get-Hex $right);ReferenceAccess=$leftAccess;CandidateAccess=$rightAccess;
        ParentHex=(Get-Hex (Get-FixtureDescriptor $Pair.Parent $true));
        AccessScope='SYSTEM-derived restricted-SID probes; non-SYSTEM subjects not covered';Explorer='out of scope'}
    Write-Output ($row | ConvertTo-Json -Depth 8 -Compress)
    $script:markerRows.Add($row)
}
function Get-BehaviorParentDescriptor([bool]$Moved, [string]$ExtraRights) {
    $everyone = if ($Moved) {'FA'} else {'FR'}
    $extra = if ($ExtraRights -eq '') {''} else {'(A;OICI;' + $ExtraRights + ';;;BU)'}
    return ,(New-SuppliedDescriptor ('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;' + $everyone + ';;;WD)' + $extra))
}
function Invoke-Icacls([string[]]$Arguments) {
    Assert-ControlDeadline
    & icacls.exe @Arguments | Write-Output
    if ($LASTEXITCODE -ne 0) { throw ('icacls failed: exit=' + $LASTEXITCODE) }
    Assert-ControlDeadline
}
function Invoke-MarkerControls([string]$Root) {
    $script:markerRows = New-Object 'Collections.Generic.List[object]'
    foreach ($moved in @($false,$true)) {
        $caseName = if ($moved) {'moved-inherited-target'} else {'inherited-null-input'}
        foreach ($experiment in @('parent-ace','tree-keep-explicit','tree-remove-explicit','icacls','backup')) {
            Assert-ControlDeadline
            $pair = New-MarkerPair (Join-Path $Root ($caseName + '-' + $experiment)) $moved
            Write-MarkerComparison $pair $caseName ($experiment + '-baseline')
            if ($experiment -eq 'parent-ace') {
                foreach ($step in @(@('add','FR'),@('change','FW'),@('remove',''))) {
                    Assert-FixtureIdentity $pair.Parent
                    [SecurityDescriptorNativeControl]::SetParentDacl($pair.Parent,(Get-BehaviorParentDescriptor $moved $step[1]))
                    Write-MarkerComparison $pair $caseName ('parent-ace-' + $step[0])
                }
            } elseif ($experiment -like 'tree-*') {
                Assert-FixtureIdentity $pair.Parent
                $receipts = [SecurityDescriptorNativeControl]::ResetTree($pair.Parent,(Get-BehaviorParentDescriptor $moved 'FW'),($experiment -eq 'tree-keep-explicit'))
                Write-Output ([pscustomobject]@{Control='TreeResetReceipts';Case=$caseName;Operation=$experiment;Objects=$receipts} | ConvertTo-Json -Depth 4 -Compress)
                foreach ($path in @($pair.Reference,$pair.Candidate)) {
                    if (@($receipts | Where-Object {$_.Name -eq $path -and $_.Status -eq 0 -and $_.SecuritySet}).Count -ne 1) {
                        throw ('Tree reset did not report a successful security update for: ' + $path)
                    }
                }
                Write-MarkerComparison $pair $caseName $experiment
            } elseif ($experiment -eq 'icacls') {
                # Save relative file names, then restore each file's own saved DACL.
                foreach ($path in @($pair.Reference,$pair.Candidate)) {
                    $save = $path + '.acl'
                    [IO.File]::WriteAllBytes($save,(New-Object byte[] 0)); Register-Fixture $save $false
                    Push-Location $pair.Parent
                    try { Invoke-Icacls -Arguments @([IO.Path]::GetFileName($path),'/save',$save) }
                    finally { Pop-Location }
                    Write-Output ([pscustomobject]@{Control='IcaclsSave';Case=$caseName;File=$path;SaveHex=(Get-Hex ([IO.File]::ReadAllBytes($save)))} | ConvertTo-Json -Compress)
                }
                Write-MarkerComparison $pair $caseName 'icacls-save'
                # Make restore observable, rather than merely applying a save to an untouched DACL.
                foreach ($path in @($pair.Reference,$pair.Candidate)) { Assert-FixtureIdentity $path; Reset-FileFixture $path }
                Write-MarkerComparison $pair $caseName 'icacls-pre-restore'
                foreach ($path in @($pair.Reference,$pair.Candidate)) {
                    Assert-FixtureIdentity $path
                    Assert-FixtureIdentity ($path + '.acl')
                    Invoke-Icacls -Arguments @($pair.Parent,'/restore',($path + '.acl'))
                }
                Write-MarkerComparison $pair $caseName 'icacls-restore'
            } elseif ($experiment -eq 'backup') {
                $restored = @()
                foreach ($path in @($pair.Reference,$pair.Candidate)) {
                    $copy = $path + '.restored'
                    [IO.File]::WriteAllBytes($copy,(New-Object byte[] 0)); Register-Fixture $copy $false
                    $before = Get-FixtureDescriptor $path
                    $stream = [SecurityDescriptorNativeControl]::BackupRoundTrip($path,$copy)
                    Assert-FixtureIdentity $copy
                    if ((Get-Hex (Get-FixtureDescriptor $path)) -ne (Get-Hex $before)) { throw 'Backup changed source security.' }
                    Write-Output ([pscustomobject]@{Control='BackupSecurityStream';Case=$caseName;Source=$path;SecurityStreamHex=(Get-Hex $stream);
                        RestoredHex=(Get-Hex (Get-FixtureDescriptor $copy));SourceHex=(Get-Hex $before);
                        SourceToRestoredDifferences=@(Get-DescriptorDifference $before (Get-FixtureDescriptor $copy))} | ConvertTo-Json -Depth 6 -Compress)
                    $restored += $copy
                }
                Write-MarkerComparison $pair $caseName 'backup-sources-after'
                Write-MarkerComparison $pair $caseName 'backup-restored' $restored[0] $restored[1]
            }
        }
    }
    if ($script:markerRows.Count -ne 30) { throw ('Incomplete marker behavior matrix: ' + $script:markerRows.Count) }
    Write-Output ('MarkerBehaviorRows=' + $script:markerRows.Count + ' Explorer=out of scope NonSYSTEMSubjects=not covered Approval=False')
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
$constructions = @('stored')
if ($CompareAutoInheritanceRequests) { $constructions += 'dacl-auto-inherit-request' }
if ($CompareNativeInheritance) { $constructions += 'native-inheritance' }
if ($CompareAutoInheritConversion) { $constructions += 'auto-inherit-conversion' }
try {
    Set-ParentFixture $root 'FR'
    Write-Output ('FixtureRoot=' + $root)
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Output ('NativeControlPlatform=' + $os.Caption + ' Version=' + $os.Version)
    Write-Output ('WindowsPowerShell=' + $PSVersionTable.PSVersion + ' Subject=SYSTEM PrivateCreatorRestoreDisabled=True')
    Write-Output 'MeasurementOnly=True Approval=False NonSYSTEMSubjects=not covered Explorer=out of scope'
    & whoami.exe /priv /fo csv
    if ($LASTEXITCODE -ne 0) { throw 'Process privilege inventory failed.' }
    foreach ($case in $cases) {
        Assert-ControlDeadline
        $folder = Join-Path $root $case.Name
        Set-ParentFixture $folder 'FR'
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
            if ($writer.Accepted) { Register-Fixture $path $false $writer.Handle }
            if (-not $writer.Accepted -or $writer.Information -ne 2 -or $writer.GrantedAccess -ne 0x00100002) {
                throw ('Native initial writer CREATE failed or changed grant: ' + $case.Name + ' status=0x{0:X8}' -f $writer.Status)
            }
            $initialId = [BoundPublicationNativeControl]::Identity($writer.Handle)
            if ($case.Moved) {
                $writer.Dispose(); $writer = $null
                $moved = Join-Path $secondParent 'source.txt'
                [IO.File]::Move($path, $moved)
                $script:fixtures.Add($moved,$script:fixtures[$path]); $script:fixtures.Remove($path)
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
            foreach ($construction in $constructions) {
                Assert-ControlDeadline
                $inputDescriptor = [byte[]]$stored.Clone()
                $leaf = 'publication.tmp'
                if ($construction -eq 'dacl-auto-inherit-request') {
                    # Request native assignment on CREATE, without masking any
                    # expected stored bit, changing ACEs or adding protection.
                    $inputDescriptor[3] = $inputDescriptor[3] -bor 1 # SE_DACL_AUTO_INHERIT_REQ = 0x0100.
                    $leaf = 'publication-auto-request.tmp'
                } elseif ($construction -eq 'native-inheritance') {
                    $inputDescriptor = $null
                    $leaf = 'publication-native-inheritance.tmp'
                } elseif ($construction -eq 'auto-inherit-conversion') {
                    $inputDescriptor = [SecurityDescriptorNativeControl]::Convert($parentSecurity,$stored)
                    $inputDifference = @(Get-DescriptorDifference $stored $inputDescriptor)
                    Write-Output ([pscustomobject]@{Control='AutoInheritConversion';Case=$case.Name;
                        Result=$(if ($inputDifference.Count -eq 0) {'CLOSED'} else {'DISTINCT'});
                        CreateAttempted=($inputDifference.Count -ne 0);RejectedReplayInputHex=(Get-Hex $stored);
                        ConvertedInputHex=(Get-Hex $inputDescriptor);Differences=$inputDifference;
                        ParentId=$parentId;ParentHex=(Get-Hex $parentSecurity)} | ConvertTo-Json -Depth 6 -Compress)
                    if ($inputDifference.Count -eq 0) {
                        $rows.Add([pscustomobject]@{Case=$case.Name;Construction=$construction;Result='CLOSED';CreateAttempted=$false})
                        continue
                    }
                    $leaf = 'publication-converted.tmp'
                }
                try {
                    $temporary = [BoundPublicationNativeControl]::CreateRelativeWithDescriptor($parent, $leaf, $inputDescriptor)
                    Register-Fixture (Join-Path $parentPath $leaf) $false $temporary
                    [BoundPublicationNativeControl]::RequireHandleContract($temporary)
                    $temporaryPath = Join-Path $parentPath $leaf
                    $tempMetadata = [WriterPermissionNativeControl]::SystemMetadata($temporaryPath, $false)
                    if (-not $tempMetadata.Accepted -or $tempMetadata.GrantedAccess -ne 0x01020000 -or
                        [BoundPublicationNativeControl]::Identity($tempMetadata.Handle) -ne
                        [BoundPublicationNativeControl]::Identity($temporary)) { throw 'Temporary metadata observer failed under share zero.' }
                    $actual = [WriterPermissionNativeControl]::SecurityBinary($tempMetadata.Handle)
                    $actualCompact = Get-CompactDescriptor $actual
                    $byteDifferences = @(Get-DescriptorDifference $stored $actual)
                    if ((Get-Hex ([WriterPermissionNativeControl]::SecurityBinary($source.Handle))) -ne (Get-Hex $stored) -or
                        (Get-Hex ([WriterPermissionNativeControl]::SecurityBinary($parentMetadata.Handle))) -ne (Get-Hex $parentSecurity) -or
                        [BoundPublicationNativeControl]::Identity($parent) -ne $parentId) { throw 'Control changed source security or parent identity.' }
                    $row = [pscustomobject]@{Case=$case.Name;Construction=$construction;CreatorStatus='0x00000000';CreatorGrant='0x00100002';
                        SourceId=$initialId;MetadataGrant='0x01020000';MetadataPrivateSeSecurityEnabled=$true;TempGrant='0x00110082';IoMode='0x2A';
                        SuppliedInputHex=$(if ($null -eq $supplied) {$null} else {Get-Hex $supplied});
                        ConstructionInputHex=$(if ($null -eq $inputDescriptor) {$null} else {Get-Hex $inputDescriptor});
                        ConstructionControl=$(if ($null -eq $inputDescriptor) {$null} else {[BitConverter]::ToUInt16($inputDescriptor,2)});
                        StoredSourceHex=(Get-Hex $stored);TempStoredHex=(Get-Hex $actual);
                        SuppliedControl=$(if ($null -eq $supplied) {$null} else {[BitConverter]::ToUInt16($supplied,2)});
                        SourceControl=[BitConverter]::ToUInt16($stored,2);TempControl=[BitConverter]::ToUInt16($actual,2);
                        RawStoredEqual=((Get-Hex $stored) -eq (Get-Hex $actual));
                        CompactStoredEqual=((Get-Hex $sourceCompact) -eq (Get-Hex $actualCompact));
                        Result=$(if ($byteDifferences.Count -eq 0) {'EXACT'} else {'DIFFERENT'});Differences=$byteDifferences;CreateAttempted=$true;
                        TempId=[BoundPublicationNativeControl]::Identity($temporary);ParentId=$parentId;DestinationParent=$parentPath;
                        NonSYSTEMSubjects='not covered';Approval=$false;
                        SourceSddl=([WriterPermissionNativeControl]::Security($source.Handle));
                        TempSddl=([WriterPermissionNativeControl]::Security($tempMetadata.Handle))}
                    $rows.Add($row)
                    Write-Output ($row | ConvertTo-Json -Depth 6 -Compress)
                    if ($construction -eq 'native-inheritance' -and $case.Moved -and $byteDifferences.Count -eq 0) {
                        throw 'Moved-from-another-parent NULL-input control unexpectedly matched; baseline changed.'
                    }
                } finally {
                    foreach ($handle in @($tempMetadata,$temporary)) { if ($null -ne $handle) {$handle.Dispose()} }
                    $tempMetadata = $null; $temporary = $null
                }
            }
        } finally {
            foreach ($handle in @($tempMetadata,$temporary,$parentMetadata,$parent,$source,$writer)) { if ($null -ne $handle) {$handle.Dispose()} }
        }
    }
    if ($CompareMarkerBehavior) {
        $markerRoot = Join-Path $root 'marker-behavior'
        Set-ParentFixture $markerRoot 'FR'
        Invoke-MarkerControls $markerRoot
    }
    if ([WriterPermissionNativeControl]::ProcessPrivileges() -ne $beforePrivileges) { throw 'Control changed process privileges.' }
    $different = @($rows | Where-Object {$_.CreateAttempted -and -not $_.CompactStoredEqual})
    foreach ($construction in $constructions) {
        $constructionRows = @($rows | Where-Object {$_.Construction -eq $construction})
        if ($constructionRows.Count -ne $cases.Count) { throw 'Native construction measurements are incomplete.' }
        Write-Output ('NativeConstruction=' + $construction + ' Rows=' + $constructionRows.Count +
            ' StoredMismatches=' + @($constructionRows | Where-Object {$_.CreateAttempted -and -not $_.CompactStoredEqual}).Count +
            ' RawStoredMismatches=' + @($constructionRows | Where-Object {$_.CreateAttempted -and -not $_.RawStoredEqual}).Count +
            ' ClosedWithoutCreate=' + @($constructionRows | Where-Object {$_.Result -eq 'CLOSED'}).Count)
    }
    Write-Output ('NativeSecurityRoundTripRows=' + $rows.Count + ' StoredMismatches=' + $different.Count +
        ' RawStoredMismatches=' + @($rows | Where-Object {$_.CreateAttempted -and -not $_.RawStoredEqual}).Count + ' ProcessPrivilegesRetained=PASS')
    Write-Output 'SecurityRoundTripMeasurement=PASS Qualification=False KernelConstructorAndOtherSubjects=False'
} finally {
    if (Test-Path -LiteralPath $root) {
        # Never authorize deletion from a path alone, including on a failed measurement.
        foreach ($entryPath in @($script:fixtures.Keys)) { Assert-FixtureIdentity $entryPath }
        $found = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
        foreach ($entry in $found) {
            if (-not $script:fixtures.ContainsKey($entry.FullName)) { throw ('Unregistered fixture retained: ' + $entry.FullName) }
        }
        foreach ($entryPath in @($script:fixtures.Keys | Sort-Object Length -Descending)) {
            Assert-FixtureIdentity $entryPath
            if ($script:fixtures[$entryPath].Directory) {
                $security = New-Object Security.AccessControl.DirectorySecurity
                $security.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)',[Security.AccessControl.AccessControlSections]::Access)
                [IO.Directory]::SetAccessControl($entryPath,$security)
            } else { Reset-FileFixture $entryPath }
            Assert-FixtureIdentity $entryPath
            if ($script:fixtures[$entryPath].Directory) { [IO.Directory]::Delete($entryPath,$false) }
            else { [IO.File]::Delete($entryPath) }
        }
    }
    if ([WriterPermissionNativeControl]::ProcessPrivileges() -ne $beforePrivileges) { throw 'Fixture cleanup changed process privileges.' }
    Write-Output ('FixtureRemoved=' + (-not (Test-Path -LiteralPath $root)))
}
