# No driver/service dependency. Synthetic mode needs neither elevation nor a raw volume.
[CmdletBinding()]
param([string] $Live = '')
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'Stop'
$script:Passed = 0; $script:Failed = 0
function Report-IO([string] $Name, [bool] $Ok, [string] $Facts) {
    $Facts = $Facts.Replace("`r", ' ').Replace("`n", ' ').Replace(';PASS', '').Replace(';FAIL', '')
    if ($Ok) { $script:Passed++; Write-Output ('IO_' + $Name + '=' + $Facts + ';PASS') }
    else { $script:Failed++; Write-Output ('IO_' + $Name + '=' + $Facts + ';FAIL') }
}
function Check-IO([string] $Name, [scriptblock] $Body) {
    try { $ok = & $Body; Report-IO $Name ([bool]$ok) 'synthetic' }
    catch { Report-IO $Name $false $_.Exception.ToString() }
}
function Reject-IO([string] $Name, [scriptblock] $Body) {
    try { $null = & $Body; Report-IO $Name $false 'malformed input accepted' }
    catch {
        $e = $_.Exception
        while ($null -ne $e.InnerException) { $e = $e.InnerException }
        Report-IO $Name ($e -is [StagedInvariant.ObservationException] -or $e -is [OverflowException]) ('rejected:' + $e.GetType().Name + ':' + $e.Message)
    }
}
function Put16([byte[]] $B, [int] $O, [uint16] $V) { [Array]::Copy([BitConverter]::GetBytes($V), 0, $B, $O, 2) }
function Put32([byte[]] $B, [int] $O, [uint32] $V) { [Array]::Copy([BitConverter]::GetBytes($V), 0, $B, $O, 4) }
function Put64([byte[]] $B, [int] $O, [long] $V) { [Array]::Copy([BitConverter]::GetBytes($V), 0, $B, $O, 8) }
function TinyRecord([bool] $NonResident) {
    $b = [byte[]]::new(1024); [Array]::Copy([Text.Encoding]::ASCII.GetBytes('FILE'), 0, $b, 0, 4)
    Put16 $b 4 48; Put16 $b 6 3; Put16 $b 16 3; Put16 $b 20 56; Put16 $b 22 1
    Put32 $b 28 1024; Put32 $b 44 7; Put16 $b 48 0xEEEE; Put16 $b 50 0x1122; Put16 $b 52 0x3344
    Put16 $b 510 0xEEEE; Put16 $b 1022 0xEEEE
    Put32 $b 56 0x80; Put16 $b 70 1
    if ($NonResident) {
        Put32 $b 60 80; $b[64] = 1; Put16 $b 68 0x8000
        Put64 $b 72 0; Put64 $b 80 7; Put16 $b 88 64
        Put64 $b 96 24576; Put64 $b 104 32768; Put64 $b 112 32768
        $runs = [byte[]]@(0x11,2,10,0x11,3,5,0x01,2,0x11,1,0xFD,0)
        [Array]::Copy($runs, 0, $b, 120, $runs.Length); Put32 $b 136 ([uint32]::MaxValue); Put32 $b 24 144
    } else {
        Put32 $b 60 32; Put32 $b 72 3; Put16 $b 76 24
        $b[80] = 0x11; $b[81] = 0x22; $b[82] = 0x33
        Put32 $b 88 ([uint32]::MaxValue); Put32 $b 24 96
    }
    return ,$b
}
function TinyRoot {
    $b = [byte[]]::new(224); Put32 $b 0 0x30; Put32 $b 4 1; Put32 $b 8 4096; $b[12] = 1
    Put32 $b 16 16; Put32 $b 20 208; Put32 $b 24 208
    for ($i = 0; $i -lt 2; $i++) {
        $p = 32 + 88 * $i; Put64 $b $p (844424930131968 + 7 + $i); Put16 $b ($p + 8) 88; Put16 $b ($p + 10) 68
        Put64 $b ($p + 16) 1407374883553285; Put64 $b ($p + 16 + 48) (3 + $i)
        $b[$p + 16 + 64] = 1; $b[$p + 16 + 65] = 1
        $b[$p + 16 + 66] = 65 + $i
    }
    Put16 $b 216 16; Put16 $b 220 2
    return ,$b
}
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    Report-IO 'Runtime' $false ('Windows PowerShell 5.1 required;found:' + $PSVersionTable.PSVersion)
    Write-Output ('IO_Summary=passed:' + $script:Passed + ';failed:' + $script:Failed); exit 1
}
if ($PSBoundParameters.ContainsKey('Live') -and [string]::IsNullOrWhiteSpace($Live)) {
    Report-IO 'LiveArgument' $false 'Explicit -Live requires a nonempty fixture folder.'
    Write-Output ('IO_Summary=passed:' + $script:Passed + ';failed:' + $script:Failed); exit 1
}
try { Import-Module (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') -Force -DisableNameChecking -ErrorAction Stop }
catch { Report-IO 'Import' $false $_.Exception.ToString(); Write-Output ('IO_Summary=passed:' + $script:Passed + ';failed:' + $script:Failed); exit 1 }
# Real checked handle-disposal controls on a disposable builder file. These do
# not pretend that a constructed pin qualifies raw-volume capture or rebind.
$readerFixture=Join-Path $env:TEMP ('safeupload-observer-reader-'+[guid]::NewGuid().ToString('N')+'.txt')
$readerHandle=$null
try {
    [IO.File]::WriteAllBytes($readerFixture,[Text.Encoding]::ASCII.GetBytes('reader-release-control'))
    $readerHandle=[StagedInvariant.Native]::Open($readerFixture,$false,$false)
    $readerIdentity=[StagedInvariant.Native]::GetIdentity($readerHandle)
    $pin=[StagedInvariant.Image]::new();$pin.Identity=$readerIdentity
    $entry=@{Handle=$readerHandle;NativeOriginal=$pin;Original=@{Path=$readerFixture};Version='Baseline'}
    $readerContext=[pscustomobject]@{Status='OK';Closed=$false;CaseId='C01';BaselineCaptured=$true;
        Handles=@{};BootId='builder-stimulus-only';ObserverPid=$PID;ObserverSid=([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)}
    $readerContext.Handles[$readerIdentity.FileId]=$entry
    Check-IO 'ActivationReaderUnsupportedCaseRejected' {
        (Close-InvariantActivationReader $readerContext $readerIdentity.FileId).Status -ceq 'ERROR' -and -not $readerHandle.Value.IsClosed
    }
    $readerContext.CaseId='A01'
    Check-IO 'ActivationReaderWrongKeyRejected' {
        (Close-InvariantActivationReader $readerContext 'wrong-file-id').Status -ceq 'ERROR' -and -not $readerHandle.Value.IsClosed
    }
    $pin.Identity=[StagedInvariant.Native]::GetIdentity($readerHandle);$pin.Identity.VolumeSerial=$pin.Identity.VolumeSerial -bxor 1
    Check-IO 'ActivationReaderWrongVolumeRejected' {
        (Close-InvariantActivationReader $readerContext $readerIdentity.FileId).Status -ceq 'ERROR' -and -not $readerHandle.Value.IsClosed
    }
    $pin.Identity=[StagedInvariant.Native]::GetIdentity($readerHandle)
    Check-IO 'ActivationReaderCheckedNativeClose' {
        $r=Close-InvariantActivationReader $readerContext $readerIdentity.FileId
        $r.Status -ceq 'OK' -and $r.NativeHandleClosed -and $readerHandle.Value.IsClosed -and
            $r.FileId -ceq $readerIdentity.FileId -and $r.End.Qpc -ge $r.Start.Qpc -and -not $r.Rebound
    }
    Check-IO 'ActivationReaderDuplicateCloseRejected' {
        (Close-InvariantActivationReader $readerContext $readerIdentity.FileId).Status -ceq 'ERROR'
    }
    Check-IO 'ActivationReaderRebindWrongIdentityRejected' {
        (Open-InvariantActivationReader $readerContext 'wrong-file-id' ('A'*64) 22).Status -ceq 'ERROR'
    }
    Check-IO 'ActivationReaderRebindMalformedDigestRejected' {
        (Open-InvariantActivationReader $readerContext $readerIdentity.FileId 'malformed' 22).Status -ceq 'ERROR'
    }
    Check-IO 'ActivationReaderRebindNegativeLengthRejected' {
        (Open-InvariantActivationReader $readerContext $readerIdentity.FileId ('A'*64) -1).Status -ceq 'ERROR'
    }
    # Raw MFT times lag the handle's (lazy $STANDARD_INFORMATION write); identity and layout must still match exactly.
    $identityHandle=[StagedInvariant.Native]::Open($readerFixture,$false,$false)
    try{$handleIdentity=[StagedInvariant.Native]::GetIdentity($identityHandle);$lagged=[StagedInvariant.Native]::GetIdentity($identityHandle)}finally{$identityHandle.Dispose()}
    $lagged.Modified-=10000000;$lagged.Changed-=10000000;$lagged.Accessed-=10000000
    Check-IO 'RawVersusHandleIdentityIgnoresLazyTimes' {
        [StagedInvariant.Native]::SameRawAndHandleIdentity($lagged,$handleIdentity) -and -not [StagedInvariant.Native]::SameIdentity($lagged,$handleIdentity)
    }
    $mutations=@{FileId={param($x)$x.FileId='0'*32};Reference={param($x)$x.Reference++};VolumeSerial={param($x)$x.VolumeSerial=$x.VolumeSerial -bxor 1};
        Eof={param($x)$x.Eof++};Allocation={param($x)$x.Allocation+=4096};Attributes={param($x)$x.Attributes=$x.Attributes -bxor 1};
        Links={param($x)$x.Links++};DeletePending={param($x)$x.DeletePending=$true}}
    foreach($field in $mutations.Keys){
        $identityHandle=[StagedInvariant.Native]::Open($readerFixture,$false,$false)
        try{$changed=[StagedInvariant.Native]::GetIdentity($identityHandle)}finally{$identityHandle.Dispose()}
        & $mutations[$field] $changed
        Check-IO ('RawVersusHandleIdentityRejects'+$field) { -not [StagedInvariant.Native]::SameRawAndHandleIdentity($changed,$handleIdentity) }
    }
}finally{
    if($null -ne $readerHandle){$readerHandle.Dispose()}
    if(Test-Path -LiteralPath $readerFixture){Remove-Item -LiteralPath $readerFixture -Force}
}
$record = TinyRecord $false; $nonresident = TinyRecord $true; $root = TinyRoot
function MftFixtureVolume {
    $v=[StagedInvariant.Volume]::new()
    $v.Geometry=[StagedInvariant.Geometry]::new();$v.Geometry.Sector=512;$v.Geometry.Cluster=1024
    $v.Geometry.RecordSize=1024;$v.Geometry.MftLcn=10;$v.Geometry.TotalBytes=1048576
    $a=[StagedInvariant.Run]::new();$a.Vcn=0;$a.NextVcn=2;$a.Lcn=10
    $b=[StagedInvariant.Run]::new();$b.Vcn=2;$b.NextVcn=4;$b.Lcn=20
    $v.MftRuns=[StagedInvariant.Run[]]@($a,$b);return $v
}
function MftFixtureRecord([byte[]]$Runs,[int]$Clusters) {
    $b=TinyRecord $true;Put32 $b 44 0;Put16 $b 68 0;Put64 $b 80 ($Clusters-1)
    Put64 $b 96 ($Clusters*1024);Put64 $b 104 ($Clusters*1024);Put64 $b 112 ($Clusters*1024)
    [Array]::Clear($b,120,16);[Array]::Copy($Runs,0,$b,120,$Runs.Length);return ,$b
}
$mftGrowth=MftFixtureRecord ([byte[]]@(0x11,1,10,0x11,1,1,0x11,4,9,0)) 6
$mftTarget=TinyRecord $false;Put32 $mftTarget 44 4
Check-IO 'MftGrowthRefreshSucceedsOnce' {
    $v=MftFixtureVolume;$r=[StagedInvariant.Native]::SelfCheckMftRefresh($v,4,$mftGrowth,$mftTarget)
    $r.Number -eq 4 -and $v.MftRefreshes.Count -eq 1 -and $v.MftRefreshes[0].Status -ceq 'OK' -and
        $v.MftRefreshes[0].OldRuns[1].NextVcn -eq 4 -and $v.MftRefreshes[0].NewRuns[2].NextVcn -eq 6 -and
        $v.MftRefreshes[0].Containers.Count -eq 1 -and $v.MftRefreshes[0].EndQpc -ge $v.MftRefreshes[0].StartQpc
}
Check-IO 'MftChangedPrefixRejected' {
    $v=MftFixtureVolume;$old=$v.MftRuns;$bad=MftFixtureRecord ([byte[]]@(0x11,2,10,0x11,4,11,0)) 6
    $rejected=$false
    try{$null=[StagedInvariant.Native]::SelfCheckMftRefresh($v,4,$bad,$mftTarget)}catch{$rejected=$_.Exception.InnerException.Message -like 'Changed cached MFT map prefix*'}
    $rejected -and [object]::ReferenceEquals($old,$v.MftRuns) -and $v.MftRefreshes.Count -eq 1 -and
        $v.MftRefreshes[0].Status -ceq 'ERROR' -and $v.MftRefreshes[0].NewRuns[1].Lcn -eq 21
}
Check-IO 'MftStillTruncatedRejected' {
    $v=MftFixtureVolume;$old=$v.MftRuns;$short=MftFixtureRecord ([byte[]]@(0x11,2,10,0x11,2,10,0)) 4
    $rejected=$false
    try{$null=[StagedInvariant.Native]::SelfCheckMftRefresh($v,4,$short,$mftTarget)}catch{$rejected=$_.Exception.InnerException.Message -like 'Still-truncated MFT map after one refresh*'}
    $rejected -and [object]::ReferenceEquals($old,$v.MftRuns) -and $v.MftRefreshes.Count -eq 1 -and $v.MftRefreshes[0].Status -ceq 'ERROR'
}
Check-IO 'MftRefreshCorruptFixupRejected' {
    $v=MftFixtureVolume;$old=$v.MftRuns;$bad=[byte[]]$mftGrowth.Clone();Put16 $bad 1022 0x1234
    $rejected=$false
    try{$null=[StagedInvariant.Native]::SelfCheckMftRefresh($v,4,$bad,$mftTarget)}catch{$rejected=$_.Exception.InnerException.Phase -ceq 'USA'}
    $rejected -and [object]::ReferenceEquals($old,$v.MftRuns) -and $v.MftRefreshes.Count -eq 1 -and
        $v.MftRefreshes[0].Status -ceq 'ERROR' -and $v.MftRefreshes[0].Containers.Count -eq 1
}
Check-IO 'MftCoveredRecordDoesNotRefresh' {
    $v=MftFixtureVolume;$target=TinyRecord $false;Put32 $target 44 3
    $r=[StagedInvariant.Native]::SelfCheckMftRefresh($v,3,([byte[]]@(0)),$target)
    $r.Number -eq 3 -and $v.MftRefreshes.Count -eq 0
}
Check-IO 'MftRejectedRefreshPreventsLaterCachedReads' {
    $v=MftFixtureVolume;$bad=MftFixtureRecord ([byte[]]@(0x11,2,10,0x11,4,11,0)) 6
    try{$null=[StagedInvariant.Native]::SelfCheckMftRefresh($v,4,$bad,$mftTarget)}catch{}
    $target=TinyRecord $false;Put32 $target 44 3;$rejected=$false
    try{$null=[StagedInvariant.Native]::SelfCheckMftRefresh($v,3,$mftGrowth,$target)}catch{$rejected=$_.Exception.InnerException.Message -like 'Prior MFT refresh rejected*'}
    $rejected -and $v.MftRefreshes.Count -eq 1 -and $null -ne $v.MftMapFailure
}
Check-IO 'MftRefreshEvidenceRetainsBothMapsAndRawRecord' {
    $dir=Join-Path ([IO.Path]::GetTempPath()) ('mft-refresh-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
    try{
        $v=MftFixtureVolume;$null=[StagedInvariant.Native]::SelfCheckMftRefresh($v,4,$mftGrowth,$mftTarget)
        $context=[pscustomobject]@{Volume=$v;EvidenceDirectory=$dir;SavedMftRefreshCount=0}
        $saved=@(& (Get-Module StagedInvariantObserver) {param($c) Save-IOMftRefreshes $c} $context)
        $again=@(& (Get-Module StagedInvariantObserver) {param($c) Save-IOMftRefreshes $c} $context)
        $saved.Count -eq 1 -and $saved[0].OldRuns.Count -eq 2 -and $saved[0].NewRuns.Count -eq 3 -and
            $saved[0].Containers[0].Offset -eq 10240 -and $again.Count -eq 0 -and
            [StagedInvariant.Native]::Hash([IO.File]::ReadAllBytes($saved[0].Containers[0].Artifact.Path)) -ceq [StagedInvariant.Native]::Hash($mftGrowth)
    }finally{[IO.Directory]::Delete($dir,$true)}
}
Check-IO 'CachedFileRecordUsesAppliedFixups' {
    $fixed=[StagedInvariant.Native]::DecodeRecord($record,512,7).Fixed
    $cached=[StagedInvariant.Native]::DecodeCachedRecord($fixed,512,7)
    $cached.Number -eq 7 -and $cached.Sequence -eq 3 -and $cached.Attributes[0].Value.Length -eq 3
}
Check-IO 'CachedFileRecordAppliesRawFixups' {
    $cached=[StagedInvariant.Native]::DecodeCachedRecord($record,512,7)
    $cached.Number -eq 7 -and $cached.Sequence -eq 3 -and $cached.Attributes[0].Value.Length -eq 3
}
Check-IO 'CachedFileRecordAcceptsClearedApiUsa' {
    $copy=[StagedInvariant.Native]::DecodeRecord($record,512,7).Fixed
    Put16 $copy 50 0;Put16 $copy 52 0
    $cached=[StagedInvariant.Native]::DecodeCachedRecord($copy,512,7)
    $cached.Number -eq 7 -and $cached.Attributes[0].Value.Length -eq 3
}
Reject-IO 'CachedFileRecordRejectsMixedFixups' {
    $copy=[byte[]]$record.Clone();Put16 $copy 510 1234
    [StagedInvariant.Native]::DecodeCachedRecord($copy,512,7)
}
Reject-IO 'CachedFileRecordRejectsWrongNumber' {
    $fixed=[StagedInvariant.Native]::DecodeRecord($record,512,7).Fixed
    [StagedInvariant.Native]::DecodeCachedRecord($fixed,512,8)
}
Reject-IO 'CachedFileRecordRejectsNotInUse' {
    $fixed=[StagedInvariant.Native]::DecodeRecord($record,512,7).Fixed;Put16 $fixed 22 0
    [StagedInvariant.Native]::DecodeCachedRecord($fixed,512,7)
}
$directoryPage=[byte[]]::new(240);Put32 $directoryPage 0 120;Put32 $directoryPage 60 10;Put64 $directoryPage 96 844424930131975
[Array]::Copy([Text.Encoding]::Unicode.GetBytes('stage'),0,$directoryPage,104,10)
Put32 $directoryPage 180 10;Put64 $directoryPage 216 844424930131976
[Array]::Copy([Text.Encoding]::Unicode.GetBytes('other'),0,$directoryPage,224,10)
Check-IO 'CachedPrivateDirectoryReference' {
    $count=[int]0;$reference=[StagedInvariant.Native]::DecodePrivateDirectoryPage($directoryPage,'stage',[ref]$count)
    $count -eq 2 -and $reference -eq 844424930131975
}
Reject-IO 'CachedPrivateDirectoryDuplicateName' {
    $copy=[byte[]]$directoryPage.Clone();[Array]::Copy([Text.Encoding]::Unicode.GetBytes('stage'),0,$copy,224,10)
    $count=[int]0;[StagedInvariant.Native]::DecodePrivateDirectoryPage($copy,'stage',[ref]$count)
}
Reject-IO 'CachedPrivateDirectoryTruncation' {
    $count=[int]0;[StagedInvariant.Native]::DecodePrivateDirectoryPage([StagedInvariant.Native]::Slice($directoryPage,0,113),'stage',[ref]$count)
}
Reject-IO 'CachedPrivateDirectoryMisalignment' {
    $copy=[byte[]]$directoryPage.Clone();Put32 $copy 0 118;$count=[int]0
    [StagedInvariant.Native]::DecodePrivateDirectoryPage($copy,'stage',[ref]$count)
}
Reject-IO 'CachedPrivateDirectorySequenceRequired' {
    $copy=[byte[]]$directoryPage.Clone();Put64 $copy 96 7;$count=[int]0
    [StagedInvariant.Native]::DecodePrivateDirectoryPage($copy,'stage',[ref]$count)
}
Check-IO 'Fixups' {
    $r = [StagedInvariant.Native]::DecodeRecord($record, 512, 7)
    $r.Number -eq 7 -and $r.Sequence -eq 3 -and [StagedInvariant.Native]::U16($r.Fixed, 510) -eq 0x1122 -and
        [StagedInvariant.Native]::U16($r.Fixed, 1022) -eq 0x3344 -and [StagedInvariant.Native]::U16($r.Raw, 510) -eq 0xEEEE
}
Check-IO 'ResidentValue' {
    $a = [StagedInvariant.Native]::DecodeRecord($record, 512, 7).Attributes[0]
    -not $a.NonResident -and $a.Name -ceq '' -and $a.Value.Length -eq 3 -and ([BitConverter]::ToString($a.Value) -ceq '11-22-33')
}
Check-IO 'SeveralRunsWithSparseAndNegativeDelta' {
    $a = [StagedInvariant.Native]::DecodeRecord($nonresident, 512, 7).Attributes[0]; $r = $a.Runs
    $a.NonResident -and $a.Eof -eq 32768 -and $r.Count -eq 4 -and $r[0].Lcn -eq 10 -and $r[1].Lcn -eq 15 -and
        $r[2].Lcn -eq -1 -and $r[2].Vcn -eq 5 -and $r[2].NextVcn -eq 7 -and $r[3].Lcn -eq 12 -and $r[3].NextVcn -eq 8
}
Check-IO 'IndexRootTwoNamesAndSequence' {
    $n = [StagedInvariant.Native]::DecodeIndexRoot($root)
    $n.Count -eq 2 -and $n[0].Name -ceq 'A' -and $n[1].Name -ceq 'B' -and $n[0].Namespace -eq 1 -and
        $n[0].Reference -eq 844424930131975 -and $n[1].Reference -eq 844424930131976
}
Check-IO 'EmptyResident' {
    $b = [byte[]]$record.Clone(); Put32 $b 72 0
    [StagedInvariant.Native]::DecodeRecord($b,512,7).Attributes[0].Value.Length -eq 0
}
Reject-IO 'BadFixup' { $b = [byte[]]$record.Clone(); $b[510] = 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'BadUsaCount' { $b = [byte[]]$record.Clone(); Put16 $b 6 2; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'BadUsaOffset' { $b = [byte[]]$record.Clone(); Put16 $b 4 510; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'TruncatedRecord' { [StagedInvariant.Native]::DecodeRecord([StagedInvariant.Native]::Slice($record,0,1000),512,7) }
Reject-IO 'WrongRecordNumber' { [StagedInvariant.Native]::DecodeRecord($record,512,8) }
Reject-IO 'ZeroSequence' { $b = [byte[]]$record.Clone(); Put16 $b 16 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'NotInUse' { $b = [byte[]]$record.Clone(); Put16 $b 22 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'BadSignature' { $b = [byte[]]$record.Clone(); $b[0] = 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'AttributeZeroLength' { $b = [byte[]]$record.Clone(); Put32 $b 60 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'AttributeTruncated' { $b = [byte[]]$record.Clone(); Put32 $b 60 1024; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'ResidentValueTruncated' { $b = [byte[]]$record.Clone(); Put32 $b 72 100; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'MissingAttributeTerminator' { $b = [byte[]]$record.Clone(); Put32 $b 88 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'NameOutsideAttribute' { $b = [byte[]]$record.Clone(); $b[65] = 3; Put16 $b 66 31; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'RunlistTruncated' { [StagedInvariant.Native]::DecodeRuns([byte[]]@(0x11,2),0,2,0,1) }
Reject-IO 'RunlistMissingTerminator' { [StagedInvariant.Native]::DecodeRuns([byte[]]@(0x11,2,10),0,3,0,1) }
Reject-IO 'RunlistZeroRun' { [StagedInvariant.Native]::DecodeRuns([byte[]]@(0x11,0,10,0),0,4,0,1) }
Reject-IO 'RunlistNegativeLcn' { [StagedInvariant.Native]::DecodeRuns([byte[]]@(0x11,1,0xFF,0),0,4,0,0) }
Reject-IO 'RunlistVcnGap' { [StagedInvariant.Native]::DecodeRuns([byte[]]@(0x11,2,10,0),0,4,0,2) }
Reject-IO 'RunlistCountCap' {
    $b=[byte[]]::new(3*8193+1)
    for ($i=0;$i -lt 8193;$i++) { $b[3*$i]=0x11; $b[3*$i+1]=1; if ($i -eq 0) { $b[2]=1 } }
    [StagedInvariant.Native]::DecodeRuns($b,0,$b.Length,0,8192)
}
Reject-IO 'RunlistOverflow' { [StagedInvariant.Native]::DecodeRuns([byte[]]@(0x18,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,1,0),0,11,0,1) }
Reject-IO 'HoleWithoutFlags' { $b = [byte[]]$nonresident.Clone(); Put16 $b 68 0; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'BadVdl' { $b = [byte[]]$nonresident.Clone(); Put64 $b 112 32769; [StagedInvariant.Native]::DecodeRecord($b,512,7) }
Reject-IO 'IndexTruncated' { [StagedInvariant.Native]::DecodeIndexRoot([StagedInvariant.Native]::Slice($root,0,223)) }
Reject-IO 'IndexZeroEntryLength' { $b = [byte[]]$root.Clone(); Put16 $b 40 0; [StagedInvariant.Native]::DecodeIndexRoot($b) }
Reject-IO 'IndexNameTruncated' { $b = [byte[]]$root.Clone(); $b[112] = 20; [StagedInvariant.Native]::DecodeIndexRoot($b) }
Reject-IO 'IndexBadNamespace' { $b = [byte[]]$root.Clone(); $b[113] = 4; [StagedInvariant.Native]::DecodeIndexRoot($b) }
Reject-IO 'IndexMissingTerminal' { $b = [byte[]]$root.Clone(); Put16 $b 220 0; [StagedInvariant.Native]::DecodeIndexRoot($b) }
Reject-IO 'IndexChildFlagMismatch' { $b=[byte[]]$root.Clone(); $b[28]=1; [StagedInvariant.Native]::DecodeIndexRoot($b) }
Reject-IO 'IndexZeroSequence' { $b=[byte[]]$root.Clone(); Put64 $b 32 7; [StagedInvariant.Native]::DecodeIndexRoot($b) }
Reject-IO 'DirectoryCaseAmbiguity' {
    $b=[byte[]]$root.Clone(); $b[202]=97
    [StagedInvariant.Native]::ValidateNames([StagedInvariant.Native]::DecodeIndexRoot($b))
}
Check-IO 'DosName' { $b = [byte[]]$root.Clone(); $b[113] = 2; [StagedInvariant.Native]::DecodeIndexRoot($b)[0].Namespace -eq 2 }
Check-IO 'AlignedTransfer' { [StagedInvariant.Native]::ValidateTransfer(4096,4096,4096,4096); $true }
Reject-IO 'UnalignedBuffer' { [StagedInvariant.Native]::ValidateTransfer(4097,4096,4096,4096) }
Reject-IO 'UnalignedOffset' { [StagedInvariant.Native]::ValidateTransfer(4096,4097,4096,4096) }
Reject-IO 'UnalignedLength' { [StagedInvariant.Native]::ValidateTransfer(4096,4096,4095,4096) }
Reject-IO 'BadAlignmentPower' { [StagedInvariant.Native]::ValidateTransfer(4096,4096,4096,513) }
Check-IO 'ReadFullTransfer' { [StagedInvariant.Native]::ValidateReadResult(0,512,512,512,512,$false,0); $true }
Check-IO 'ReadAlignedTailAtEof' { [StagedInvariant.Native]::ValidateReadResult(0,600,4096,4096,600,$true,600); $true }
Reject-IO 'RawShortRead' { [StagedInvariant.Native]::ValidateReadResult(0,512,512,512,511,$false,0) }
Reject-IO 'ReaderShortBeforeEof' { [StagedInvariant.Native]::ValidateReadResult(0,600,4096,4096,599,$true,600) }
Reject-IO 'ReadOversized' { [StagedInvariant.Native]::ValidateReadResult(0,512,512,512,513,$false,0) }
Check-IO 'Sha256Uppercase' { [StagedInvariant.Native]::Hash([byte[]]@(97,98,99)) -ceq 'BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD' }
$page = [byte[]]::new(48); Put32 $page 0 2; Put64 $page 8 0
Put64 $page 16 2; Put64 $page 24 10; Put64 $page 32 5; Put64 $page 40 20
Check-IO 'RetrievalPage' { $r = [StagedInvariant.Native]::DecodeRetrievalPage($page,48,0); $r.Count -eq 2 -and $r[1].NextVcn -eq 5 }
Check-IO 'RetrievalNextPage' {
    $b = [byte[]]::new(32); Put32 $b 0 1; Put64 $b 8 5; Put64 $b 16 8; Put64 $b 24 30
    [StagedInvariant.Native]::DecodeRetrievalPage($b,32,5)[0].Vcn -eq 5
}
Reject-IO 'RetrievalShortPage' { [StagedInvariant.Native]::DecodeRetrievalPage($page,47,0) }
Reject-IO 'RetrievalNoProgress' { $b=[byte[]]$page.Clone(); Put64 $b 16 0; [StagedInvariant.Native]::DecodeRetrievalPage($b,48,0) }
Reject-IO 'RetrievalWrongStart' { [StagedInvariant.Native]::DecodeRetrievalPage($page,48,1) }
Reject-IO 'RetrievalNegativeLcn' { $b=[byte[]]$page.Clone(); Put64 $b 24 -2; [StagedInvariant.Native]::DecodeRetrievalPage($b,48,0) }
$list = [byte[]]::new(32); Put32 $list 0 0x80; Put16 $list 4 32; Put64 $list 16 1125899906842632; Put16 $list 24 1
Check-IO 'AttributeList' { $e=[StagedInvariant.Native]::DecodeAttributeList($list)[0]; $e.Id -eq 1 -and $e.Reference -eq 1125899906842632 }
Reject-IO 'AttributeListShort' { [StagedInvariant.Native]::DecodeAttributeList([StagedInvariant.Native]::Slice($list,0,25)) }
Reject-IO 'AttributeListZeroLength' { $b=[byte[]]$list.Clone(); Put16 $b 4 0; [StagedInvariant.Native]::DecodeAttributeList($b) }
Reject-IO 'AttributeListBadName' { $b=[byte[]]$list.Clone(); $b[6]=4; $b[7]=31; [StagedInvariant.Native]::DecodeAttributeList($b) }
$basis = [StagedInvariant.Native]::DecodeRecord($record,512,7)
$extBytes = [byte[]]$record.Clone(); Put32 $extBytes 44 8; Put16 $extBytes 16 4; Put64 $extBytes 32 844424930131975
$extension = [StagedInvariant.Native]::DecodeRecord($extBytes,512,8)
Reject-IO 'AttributeListCountCap' {
    $b=[byte[]]::new(32*1025)
    for ($i=0;$i -lt 1025;$i++) { [Array]::Copy($list,0,$b,32*$i,32); Put64 $b (32*$i+8) $i }
    [StagedInvariant.Native]::DecodeAttributeList($b)
}
Check-IO 'ExtensionReference' { [StagedInvariant.Native]::ValidateExtension($basis,$extension,1125899906842632); $true }
Reject-IO 'ExtensionWrongSequence' { [StagedInvariant.Native]::ValidateExtension($basis,$extension,844424930131976) }
Reject-IO 'ExtensionWrongBase' {
    $b=[byte[]]$extBytes.Clone(); Put64 $b 32 844424930131977
    [StagedInvariant.Native]::ValidateExtension($basis,[StagedInvariant.Native]::DecodeRecord($b,512,8),1125899906842632)
}
$boot = [byte[]]::new(512); [Array]::Copy([Text.Encoding]::ASCII.GetBytes('NTFS    '),0,$boot,3,8)
Put16 $boot 11 512; $boot[13]=8; Put64 $boot 40 1048576; Put64 $boot 48 4; $boot[64]=246; $boot[68]=244; Put16 $boot 510 0xAA55
Check-IO 'BootGeometry' { $g=[StagedInvariant.Native]::DecodeBoot($boot); $g.RecordSize -eq 1024 -and $g.IndexSize -eq 4096 -and $g.Cluster -eq 4096 }
Reject-IO 'BootTruncated' { [StagedInvariant.Native]::DecodeBoot([StagedInvariant.Native]::Slice($boot,0,511)) }
Reject-IO 'BootNonPowerSector' { $b=[byte[]]$boot.Clone(); Put16 $b 11 513; [StagedInvariant.Native]::DecodeBoot($b) }
Reject-IO 'BootBadMftAddress' { $b=[byte[]]$boot.Clone(); Put64 $b 48 -1; [StagedInvariant.Native]::DecodeBoot($b) }
# LZNT1 one compressed 4096-byte chunk: literal zero then distance=1,length=4095.
Check-IO 'Lznt1CompressedUnit' {
    $b = [StagedInvariant.Native]::DecodeLznt1([byte[]]@(0x03,0xB0,0x02,0x00,0xFC,0x0F),4096)
    $b.Length -eq 4096 -and [StagedInvariant.Native]::Hash($b) -ceq [StagedInvariant.Native]::Hash([byte[]]::new(4096))
}
Check-IO 'Lznt1UncompressedChunk' {
    $input = [byte[]]::new(4098); $input[0] = 0xFF; $input[1] = 0x3F
    for ($i=0; $i -lt 4096; $i++) { $input[$i+2] = [byte]($i % 251) }
    $b = [StagedInvariant.Native]::DecodeLznt1($input,4096)
    [StagedInvariant.Native]::Hash($b) -ceq [StagedInvariant.Native]::Hash([StagedInvariant.Native]::Slice($input,2,4096))
}
Reject-IO 'Lznt1Truncated' { [StagedInvariant.Native]::DecodeLznt1([byte[]]@(0x03,0xB0,0x02),4096) }
Reject-IO 'Lznt1OutputBound' { [StagedInvariant.Native]::DecodeLznt1([byte[]]@(0x03,0xB0,0x02,0x00,0xFC,0x0F),1) }
# Entirely fabricated predicate inputs: no filesystem observation or platform claim.
function SyntheticPredicate([string] $Variant) {
    $dir=Join-Path ([IO.Path]::GetTempPath()) ('io-logic-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($dir)
    try {
        $original=[byte[]]@(1,2,3,4); $actual=[byte[]]$original.Clone()
        if ($Variant -eq 'Changed' -or $Variant -eq 'Partial' -or $Variant -eq 'Forbidden' -or $Variant -eq 'LostArtifact') { $actual[2]=99 }
        $bp=Join-Path $dir 'baseline.bin'; $ap=Join-Path $dir 'sample.bin'
        [IO.File]::WriteAllBytes($bp,$original); [IO.File]::WriteAllBytes($ap,$actual)
        $ba=[pscustomobject]@{ Path=$bp; Length=4; Sha256=[StagedInvariant.Native]::Hash($original) }
        $aa=[pscustomobject]@{ Path=$ap; Length=4; Sha256=[StagedInvariant.Native]::Hash($actual) }
        $metadata=[pscustomobject]@{ Attributes=0; Creation=0; Modified=0; Changed=0; Accessed=0; Links=1; SecurityId=0; Sddl='synthetic' }
        $identity=[pscustomobject]@{ FileId='synthetic-id'; Attributes=0; Creation=0; Modified=0; Changed=0; Accessed=0; Links=1 }
        $bimage=[pscustomobject]@{ Role='Current'; Path='synthetic-file'; Absent=$false; Identity=$identity; RawMetadata=$metadata; Containers=@(); LogicalArtifact=$ba; Length=4; Sha256=$ba.Sha256 }
        $simage=[pscustomobject]@{ Role='Current'; Path='synthetic-file'; Absent=$false; Identity=$identity; RawMetadata=$metadata; Containers=@(); LogicalArtifact=$aa; Length=4; Sha256=$aa.Sha256; Runs=@(); SecurityId=0; Sddl='synthetic' }
        # S00 setup attempts all precede the baseline; neither the gap nor the
        # capture overlaps an actor attempt. These are fabricated QPC facts.
        $frequency=1000
        $baseline=[pscustomobject]@{ Status='OK'; CaseId='S00-observer-control'; Images=@($bimage); Time=[pscustomobject]@{ Qpc=2000; QpcFrequency=$frequency; BootId='fabricated' }; Build='19045.2965'; ObserverPid=10; ObserverSid='S-1-5-18'; Geometry=[pscustomobject]@{ Cluster=4096 } }
        $readers=@($false,$true | ForEach-Object { [pscustomobject]@{ Path='synthetic-file'; Unbuffered=$_; Status='OK'; Result=[pscustomobject]@{ Digest=$aa.Sha256; Length=4 } } })
        $sample=[pscustomobject]@{ Status='OK'; Sequence=1; OperationSequence=1; Phase='synthetic'; Start=[pscustomobject]@{ Qpc=2010; QpcFrequency=$frequency; BootId='fabricated'; Utc='2026-10-04T00:00:00Z' }; End=[pscustomobject]@{ Qpc=2011; QpcFrequency=$frequency; BootId='fabricated'; Utc='2026-10-04T00:00:00.001Z' }; GapMs=10; DurationMs=1; CadenceMs=10
            CleanupErrors=@(); Images=@($simage); Readers=$readers; Captures=@([pscustomobject]@{ Status='OK'; Images=@($simage); Readers=$readers }) }
        if ($Variant -eq 'Partial') { $sample.Status='ERROR'; $sample.Captures[0].Status='ERROR' }
        $exactMetadata=[pscustomobject]@{ Raw=$metadata; Api=$identity; AccessRule='Exact'; SecurityId=0; Sddl='synthetic' }
        $expect=[pscustomobject]@{ Path='synthetic-file'; Kind='Final'; Version='Baseline'; Generation=0; FileId='synthetic-id'; ZeroPadding=$false; Metadata=$exactMetadata }
        $timeline=[pscustomobject]@{ ForbiddenBlocks=@(); AllowedMutations=@(); ExpectedDenials=@(); AccountedGapSequences=@()
            WriterIdentities=@([pscustomobject]@{ Pid=11; Sid='S-1-5-21-1-2-3-1000'; SessionId=1; Elevated=$false; IsAdministrator=$false; BootId='fabricated' })
            Operations=@(for ($n=0; $n -le 100; $n++) { [pscustomobject]@{ Trial=$n; Class='writer-open-deny'; NativeCode=5; StartQpc=100+$n*10; EndQpc=101+$n*10 } })
            WriterFence=[pscustomobject]@{ Complete=$true; BootId='fabricated'; QpcFrequency=$frequency; ReleasedQpc=50; CompletedQpc=1500; ExpectedAttempts=101 }
            CadenceProof=$null
            ExternalEvidence=[pscustomobject]@{ Provenance='SyntheticTestEvidence'; Build='19045.2965'; PrepareBootId='fabricated-prepare'; ActiveBootId='fabricated'; ObserverPid=10; ObserverSid='S-1-5-18'
                ActorProvenance=[pscustomobject]@{ OwnerSid='S-1-5-21-1-2-3-1000'; Pid=11; SessionId=1 }
                ObserverProcess=[pscustomobject]@{ OwnerSid='S-1-5-18'; Pid=10 }; Restoration=[pscustomobject]@{ Known=$true } }
            PlatformValidated=$true; ObserverIndependent=$true; StandardUserWriters=$true; ContinuousObservationComplete=$true; RestorationKnown=$true
            Checkpoints=@([pscustomobject]@{ OperationSequence=1; Phase='synthetic'; State='Protected'; Storage=@($expect); Directories=@(); ReadDenials=@() }) }
        $denied=[pscustomobject]@{ Sequence=1; PostComplete=$true; LowerAdmitted=$false; DeniedBeforeLower=$true; NativeResult=5
            FileId='synthetic-id'; VolumeSerial=1; SopIdentity='sop'; EpochGeneration=1; Operation='Write'; Paging=$false; Offset=0; Length=4
            AttemptId=''; PolicyGeneration=1; DestinationGeneration=1; PayloadSha256=$aa.Sha256; Path='synthetic-file' }
        $timeline.ExpectedDenials=@($denied)
        $ledger=[pscustomobject]@{ Provenance='SyntheticTestLedger'; Complete=$true; Overflow=$false; FirstSequence=1; LastSequence=1; Entries=@($denied) }
        if ($Variant -eq 'MissingLedger') { $ledger.Complete=$false }
        if ($Variant -eq 'WriteErase') { $denied.LowerAdmitted=$true; $denied.DeniedBeforeLower=$false; $denied.NativeResult=0 }
        if ($Variant -eq 'LostCompletion') { $denied.PostComplete=$false }
        if ($Variant -eq 'Forbidden') { $timeline.ForbiddenBlocks=,([byte[]]@(99,4)); $sample.Status='ERROR' }
        if ($Variant -eq 'LostArtifact') { [IO.File]::Delete($ap) }
        if ($Variant -eq 'FlatMetadata') { $expect.Metadata=$metadata }
        if ($Variant -eq 'MissingRawMetadata') { $exactMetadata.Raw=$null }
        if ($Variant -eq 'MissingApiMetadata') { $exactMetadata.Api=$null }
        if ($Variant -eq 'MissingProvenance') { $ledger.Provenance=$null }
        if ($Variant -eq 'MissingExternalProvenance') { $timeline.ExternalEvidence.Provenance=$null }
        if ($Variant -eq 'LedgerInRealRun') { $timeline.ExternalEvidence.Provenance=$null }
        if ($Variant -eq 'ExternalInRealRun') { $ledger.Provenance=$null }
        if ($Variant -eq 'RealMissingLedger') {
            $ledger.Provenance=$null; $ledger.Complete=$false; $ledger.Entries=@()
            $timeline.ExternalEvidence.Provenance=$null
        }
        if($Variant -like 'DirectoryReadWindow*'){
            $accessTime=[DateTime]::Parse('2026-10-03T23:59:59Z').ToUniversalTime().ToFileTimeUtc()
            $metadata.Accessed=$accessTime;$identity.Accessed=$accessTime
            $identity | Add-Member NoteProperty Reference 17
            $path=Join-Path $dir 'marker.bin';$bimage.Path=$path;$simage.Path=$path;$expect.Path=$path;$denied.Path=$path
            foreach($reader in $readers){$reader.Path=$path}
            $simage.RawMetadata=[pscustomobject]@{Attributes=0;Creation=0;Modified=0;Changed=0;Accessed=($accessTime+2000);Links=1}
            $simage.Identity=[pscustomobject]@{FileId='synthetic-id';Reference=17;Attributes=0;Creation=0;Modified=0;Changed=0;Accessed=($accessTime+2500);Links=1}
            $simage | Add-Member NoteProperty CrossCheckErrors @()
            $exactMetadata.AccessRule='NtfsReadWindow'
            $exactMetadata | Add-Member NoteProperty AccessWindowStartFileTime ($accessTime+1000)
            $exactMetadata | Add-Member NoteProperty VolumeGuid 'synthetic-volume'
            $exactMetadata | Add-Member NoteProperty AccessReason 'Synthetic same-identity read-side index update'
            $entries=@(for($n=0;$n -lt 2;$n++){
                [pscustomobject]@{Name='marker.bin';Namespace=3;Reference=17;Parent=9;Eof=4;Allocated=4;Attributes=0;Creation=0;Modified=0;Changed=0;Accessed=$accessTime}
            })
            $entries[1].Accessed=$accessTime+1500
            $beforeParent=[pscustomobject]@{Role='Parent';Path=$dir;DirectoryEntries=@($entries[0]);SecurityId=0;Sddl='synthetic';Containers=@()}
            $afterParent=[pscustomobject]@{Role='Parent';Path=$dir;DirectoryEntries=@($entries[1]);SecurityId=0;Sddl='synthetic';Containers=@()}
            $baseline.Images+=$beforeParent;$sample.Images+=$afterParent;$sample.Captures[0].Images+=$afterParent
            $timeline.Checkpoints[0].Directories=@([pscustomobject]@{Path=$dir;Entries=@($entries[0]);SecurityId=0;Sddl='synthetic';EntryAccessRule='NtfsReadWindow'})
            $policy=[pscustomobject]@{Status='OK';Before=[pscustomobject]@{Value=2;Management='System';UpdatesDisabled=$false;BootId='fabricated';VolumeGuid='synthetic-volume';Qpc=1999};After=[pscustomobject]@{Value=2;Management='System';UpdatesDisabled=$false;BootId='fabricated';VolumeGuid='synthetic-volume';Qpc=2012}}
            $timeline | Add-Member NoteProperty LastAccessPolicy $policy
            switch($Variant){
                'DirectoryReadWindowOtherTimestamp'{$entries[1].Modified++}
                'DirectoryReadWindowExternalName'{$entries[1].Name='source.txt'}
                'DirectoryReadWindowExtra'{$afterParent.DirectoryEntries+=[pscustomobject]@{Name='cached.txt';Namespace=3;Reference=18;Parent=9;Eof=4;Allocated=4;Attributes=0;Creation=0;Modified=0;Changed=0;Accessed=$accessTime}}
                'DirectoryReadWindowAheadRaw'{$entries[1].Accessed=$accessTime+2001}
                'DirectoryReadWindowNoPolicy'{$timeline.LastAccessPolicy=$null}
            }
        }
        $timeline.CadenceProof=Test-InvariantCadence $baseline @($sample) $timeline.Operations $timeline.WriterFence
        return Test-NoUnapprovedByte $baseline @() @($sample) $ledger $timeline -SyntheticRun:($Variant -notin @('UnmarkedSynthetic','LedgerInRealRun','ExternalInRealRun','RealMissingLedger'))
    } finally { [IO.Directory]::Delete($dir,$true) }
}
Check-IO 'PredicateCompleteAllowedImage' {
    $v=SyntheticPredicate 'Unchanged'
    $v.Verdict -eq 'PASS' -and $v.SyntheticRun -and @($v.Assertions | Where-Object { $_.Verdict -ne 'PASS' }).Count -eq 0 -and
        (SyntheticPredicate 'UnmarkedSynthetic').Verdict -eq 'INCONCLUSIVE' -and
        (SyntheticPredicate 'LedgerInRealRun').Verdict -eq 'INCONCLUSIVE' -and
        (SyntheticPredicate 'ExternalInRealRun').Verdict -eq 'INCONCLUSIVE' -and
        (SyntheticPredicate 'MissingProvenance').Verdict -eq 'INCONCLUSIVE' -and
        (SyntheticPredicate 'MissingExternalProvenance').Verdict -eq 'INCONCLUSIVE'
}
Check-IO 'PredicateWholeImageChange' {
    $v=SyntheticPredicate 'Changed'
    $v.Verdict -eq 'FAIL' -and @($v.Assertions | Where-Object { $_.Name -eq 'CompleteImage' -and $_.Verdict -eq 'FAIL' }).Count -gt 0
}
Check-IO 'PredicatePartialViolationWins' {
    $v=SyntheticPredicate 'Partial'
    $v.Verdict -eq 'FAIL' -and @($v.Assertions | Where-Object { $_.Name -eq 'CompleteImage' -and $_.Verdict -eq 'FAIL' }).Count -gt 0 -and
        @($v.Assertions | Where-Object { $_.Name -eq 'CaptureCoverage' -and $_.Verdict -eq 'INCONCLUSIVE' }).Count -gt 0
}
Check-IO 'PredicatePartialForbiddenBlock' { $v=SyntheticPredicate 'Forbidden'; $v.Verdict -eq 'FAIL' -and $v.ForbiddenByteCount -gt 0 }
Check-IO 'PredicateMissingLedger' {
    $synthetic=SyntheticPredicate 'MissingLedger'; $real=SyntheticPredicate 'RealMissingLedger'
    $synthetic.Verdict -eq 'INCONCLUSIVE' -and $real.Verdict -eq 'INCONCLUSIVE' -and -not $real.SyntheticRun -and
        @($real.Assertions | Where-Object { $_.Name -eq 'PredicateCoverage' -and $_.Reason -like '*Driver lower admission/completion mutation ledger unavailable:*' }).Count -eq 1
}
Check-IO 'PredicateWriteThenErase' {
    $v=SyntheticPredicate 'WriteErase'
    $v.Verdict -eq 'FAIL' -and @($v.Assertions | Where-Object { $_.Name -eq 'LowerMutation' -and $_.Verdict -eq 'FAIL' }).Count -eq 1
}
Check-IO 'PredicateLostArtifactCannotHideViolation' {
    $v=SyntheticPredicate 'LostArtifact'
    $v.Verdict -eq 'FAIL' -and @($v.Assertions | Where-Object { $_.Name -eq 'CompleteImage' -and $_.Verdict -eq 'FAIL' }).Count -gt 0 -and
        @($v.Assertions | Where-Object { $_.Name -eq 'ArtifactCoverage' -and $_.Verdict -eq 'INCONCLUSIVE' }).Count -gt 0
}
Check-IO 'PredicateLostCompletion' {
    $v=SyntheticPredicate 'LostCompletion'
    $ok=$v.Verdict -eq 'INCONCLUSIVE' -and @($v.Assertions | Where-Object { $_.Name -eq 'PredicateCoverage' -and $_.Reason -like '*Ledger gap/missing lower completion.*' }).Count -eq 1
    foreach ($variant in @('FlatMetadata','MissingRawMetadata','MissingApiMetadata')) {
        $v=SyntheticPredicate $variant
        $view=if ($variant -eq 'MissingApiMetadata') { 'Api' } else { 'Raw' }
        $ok=$ok -and $v.Verdict -eq 'INCONCLUSIVE' -and
            @($v.Assertions | Where-Object { $_.Name -eq 'MetadataCoverage' -and $_.Reason -ceq ('Exact per-fixture metadata ' + $view + ' expectation missing.') }).Count -eq 1 -and
            @($v.Assertions | Where-Object { $_.Name -eq 'AllowedImageCoverage' }).Count -eq 0
    }
    $ok
}
Check-IO 'PredicateDirectoryReadWindow' {
    $v=SyntheticPredicate 'DirectoryReadWindow'
    $v.Verdict -ceq 'PASS' -and $v.ForbiddenByteCount -eq 0 -and @($v.Assertions | Where-Object Verdict -cne 'PASS').Count -eq 0
}
foreach($variant in @('OtherTimestamp','ExternalName','Extra','AheadRaw','NoPolicy')){
    Check-IO ('PredicateDirectoryReadWindowRejects'+$variant) {
        $v=SyntheticPredicate ('DirectoryReadWindow'+$variant)
        $v.Verdict -ceq 'FAIL' -and @($v.Assertions | Where-Object {$_.Name -ceq 'DirectoryMetadata' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1
    }
}
function FixtureBytes([int] $Length, [int] $Seed) {
    $b = [byte[]]::new($Length)
    for ($i=0; $i -lt $Length; $i++) { $b[$i] = [byte](($i * 17 + $Seed) % 251) }
    return ,$b
}
function WriteFixture([string] $Path, [byte[]] $Bytes, [bool] $Append) {
    $mode = [IO.FileMode]::CreateNew; if ($Append) { $mode = [IO.FileMode]::Append }
    $s = [IO.FileStream]::new($Path,$mode,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete,65536,[IO.FileOptions]::WriteThrough)
    try { $s.Write($Bytes,0,$Bytes.Length); $s.Flush($true) } finally { $s.Dispose() }
}
function PatchFixture([string] $Path, [long] $Offset, [byte] $Value) {
    $s = [IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete,4096,[IO.FileOptions]::WriteThrough)
    try { $null = $s.Seek($Offset,[IO.SeekOrigin]::Begin); $s.WriteByte($Value); $s.Flush($true) } finally { $s.Dispose() }
}
function FlushFixture([string] $Folder) {
    # Driver-off fixture preparation ONLY. The module itself never flushes a subject.
    Get-Volume -FilePath $Folder -ErrorAction Stop | Write-VolumeCache -ErrorAction Stop | Out-Null
}
function FixtureTimeline($Baseline, $Sample) {
    $storage = @()
    foreach ($image in @($Baseline.Images | Where-Object { $_.Role -eq 'Current' })) {
        if ($image.Absent) { $storage += [pscustomobject]@{ Path=$image.Path; Kind='Absent' }; continue }
        $storage += [pscustomobject]@{ Path=$image.Path; Kind='Final'; Version='Baseline'; FileId=$image.Identity.FileId; Generation=0; ZeroPadding=$false
            Metadata=[pscustomobject]@{ Attributes=$image.RawMetadata.Attributes; Creation=$image.RawMetadata.Creation; Modified=$image.RawMetadata.Modified
                Changed=$image.RawMetadata.Changed; Accessed=$image.RawMetadata.Accessed; Links=$image.RawMetadata.Links; SecurityId=$image.SecurityId; Sddl=$image.Sddl } }
    }
    $dirs = @($Baseline.Images | Where-Object { $_.Role -eq 'Parent' } | ForEach-Object {
        [pscustomobject]@{ Path=$_.Path; Entries=$_.DirectoryEntries; Sddl=$_.Sddl; SecurityId=$_.SecurityId }
    })
    return [pscustomobject]@{ ForbiddenBlocks=@(); AllowedMutations=@(); ExpectedDenials=@(); WriterIdentities=@(); AccountedGapSequences=@($Sample.Sequence)
        PlatformValidated=$true; ObserverIndependent=$false; StandardUserWriters=$false; ContinuousObservationComplete=$false; RestorationKnown=$false
        Checkpoints=@([pscustomobject]@{ Phase=$Sample.Phase; OperationSequence=$Sample.OperationSequence; State='Protected'; Storage=$storage; Directories=$dirs; ReadDenials=@() }) }
}
function FixtureVerdict($Baseline, $Sample) {
    # No driver lower ledger exists in this test. The final verdict must stay INCONCLUSIVE unless a leak is found.
    $ledger = [pscustomobject]@{ Complete=$false; Overflow=$false; FirstSequence=0; LastSequence=0; Entries=@() }
    return Test-NoUnapprovedByte $Baseline @() @($Sample) $ledger (FixtureTimeline $Baseline $Sample)
}
if (-not [string]::IsNullOrWhiteSpace($Live)) {
    $context = $null; $scope = $null; $evidence = $null
    try {
        $liveRoot = [IO.Path]::GetFullPath($Live)
        if (-not (Test-Path -LiteralPath $liveRoot -PathType Container)) { throw '-Live must be an existing fixed-NTFS fixture folder.' }
        $run = [guid]::NewGuid().ToString('N')
        $scope = Join-Path $liveRoot ('io-fixtures-' + $run)
        $evidence = Join-Path $liveRoot ('io-evidence-' + $run)
        [void][IO.Directory]::CreateDirectory($scope)
        $guid = [StagedInvariant.Native]::ResolveGuid($scope)
        $context = Open-InvariantObserver $guid $scope $evidence ('SelfCheck-' + $run)
        Report-IO 'LiveOpen' ($context.Status -eq 'OK') ('scope:' + $scope + ';evidence:' + $evidence)
        if ($context.Status -ne 'OK') { throw ($context.Error | ConvertTo-Json -Depth 12 -Compress) }
        $expected = @{
            'one.bin' = (FixtureBytes 1 19); 'six-hundred.bin' = (FixtureBytes 600 23)
            'four-k.bin' = (FixtureBytes 4096 29); 'empty.bin' = [byte[]]::new(0); 'new-name.bin' = $null
        }
        foreach ($name in @('one.bin','six-hundred.bin','four-k.bin','empty.bin')) { WriteFixture (Join-Path $scope $name) $expected[$name] $false }
        # Enough names to force a nonresident $I30 allocation on a normal NTFS volume.
        for ($i=0; $i -lt 400; $i++) { WriteFixture (Join-Path $scope ('index-growth-{0:D4}.bin' -f $i)) ([byte[]]::new(0)) $false }
        # Do not rely on first-LCN: require the actual observed fragmentation below.
        $independent = [IO.MemoryStream]::new()
        try {
            for ($round=0; $round -lt 128; $round++) {
                for ($file=0; $file -lt 12; $file++) {
                    $chunk = FixtureBytes 16384 ($round + 31 * $file)
                    WriteFixture (Join-Path $scope ('fragment-{0:D2}.bin' -f $file)) $chunk $true
                    if ($file -eq 0) { $independent.Write($chunk,0,$chunk.Length) }
                }
            }
            $expected['fragment-00.bin'] = $independent.ToArray()
        } finally { $independent.Dispose() }
        FlushFixture $scope
        $names = [string[]]@('one.bin','six-hundred.bin','four-k.bin','fragment-00.bin','empty.bin','new-name.bin')
        $baseline = Capture-InvariantBaseline $context $names $expected
        Report-IO 'LiveBaseline' ($baseline.Status -eq 'OK') 'raw images versus independent generated bytes'
        if ($baseline.Status -ne 'OK') { throw ($baseline.Error | ConvertTo-Json -Depth 12 -Compress) }
        foreach ($name in @('one.bin','six-hundred.bin','four-k.bin','empty.bin')) {
            $image = @($baseline.Images | Where-Object { $_.Role -eq 'Current' -and $_.Path -eq (Join-Path $scope $name) })[0]
            $ok = $image.Length -eq $expected[$name].Length
            if ($name -eq 'one.bin' -or $name -eq 'six-hundred.bin') { $ok = $ok -and $image.Resident }
            Report-IO ('LiveRepresentation_' + $name.Replace('.','_').Replace('-','_')) $ok ('length:' + $image.Length + ';resident:' + $image.Resident + ';runs:' + $image.Runs.Count)
        }
        $parents = @($baseline.Images | Where-Object { $_.Role -eq 'Parent' })
        $indexContainers = @($parents | ForEach-Object { $_.Containers } | Where-Object { $_.Kind -eq 'INDEX_ALLOCATION' })
        Report-IO 'LiveDirectoryAllocation' ($indexContainers.Count -gt 0) ('physical-index-containers:' + $indexContainers.Count)
        $sample = Capture-InvariantSample $context $baseline 'Unchanged' 1
        $v = FixtureVerdict $baseline $sample
        if ($sample.Status -ne 'OK') { Write-Output ('IO_LiveSampleErrorDetail=' + (($sample.Error | ConvertTo-Json -Depth 8 -Compress))) }
        Report-IO 'LiveUnchangedBytes' ($sample.Status -eq 'OK' -and @($v.Assertions | Where-Object { $_.Verdict -eq 'FAIL' }).Count -eq 0) ('sample:' + $sample.Status + ';verdict:' + $v.Verdict)
        Report-IO 'LiveMissingLedgerCannotPass' ($v.Verdict -eq 'INCONCLUSIVE') ('verdict:' + $v.Verdict)
        $fresh = @($sample.Readers | Where-Object { $_.Status -eq 'OK' -and $null -ne $_.Path })
        Report-IO 'LiveFreshReaders' ($fresh.Count -eq 10) ('successful-readers:' + $fresh.Count)
        $target = Join-Path $scope 'fragment-00.bin'
        $image = @($baseline.Images | Where-Object { $_.Role -eq 'Current' -and $_.Path -eq $target })[0]
        $runs = @($image.Runs | Where-Object { $_.Lcn -ge 0 -and $_.Vcn * $context.Geometry.Cluster -lt $image.Length })
        Report-IO 'LiveFragmentation' ($runs.Count -ge 3) ('allocated-logical-extents:' + $runs.Count + ';required:3')
        $seq = 1
        foreach ($which in @('First','Middle','Last')) {
            if ($runs.Count -lt 3) { Report-IO ('LiveChange' + $which) $false 'insufficient observed extents; stimulus not established'; continue }
            $index = 0
            if ($which -eq 'Middle') { $index = [int][Math]::Floor($runs.Count/2) }
            if ($which -eq 'Last') { $index = $runs.Count - 1 }
            $offset = [long]($runs[$index].Vcn * $context.Geometry.Cluster)
            $original = $expected['fragment-00.bin'][[int]$offset]
            PatchFixture $target $offset ([byte](($original + 1) % 256)); FlushFixture $scope; $seq++
            $s = Capture-InvariantSample $context $baseline ('Changed' + $which) $seq
            $verdict = FixtureVerdict $baseline $s
            $detected = @($verdict.Assertions | Where-Object { $_.Name -eq 'CompleteImage' -and $_.Verdict -eq 'FAIL' -and $_.Path -eq $target }).Count -gt 0
            Report-IO ('LiveChange' + $which) ($s.Status -eq 'OK' -and $detected) ('extent:' + $index + ';offset:' + $offset + ';sample:' + $s.Status + ';verdict:' + $verdict.Verdict)
            PatchFixture $target $offset $original; FlushFixture $scope
        }
        WriteFixture (Join-Path $scope 'new-name.bin') ([byte[]]@(0x41)) $false; FlushFixture $scope; $seq++
        $s = Capture-InvariantSample $context $baseline 'ChangedMetadata' $seq
        $verdict = FixtureVerdict $baseline $s
        if ($s.Status -ne 'OK') { Write-Output ('IO_LiveMetadataSampleErrorDetail=' + (($s.Error | ConvertTo-Json -Depth 8 -Compress))) }
        $detected = @($verdict.Assertions | Where-Object { $_.Verdict -eq 'FAIL' -and ($_.Name -eq 'DirectoryMetadata' -or $_.Name -eq 'DestinationPresence') }).Count -gt 0
        Report-IO 'LiveMetadataChange' ($s.Status -eq 'OK' -and $detected) ('new-name.bin;sample:' + $s.Status + ';verdict:' + $verdict.Verdict)
    } catch { Report-IO 'LiveException' $false $_.Exception.ToString() }
    finally {
        if ($null -ne $context -and $context.Status -eq 'OK') {
            $close = Close-InvariantObserver $context
            Report-IO 'LiveCheckedClose' ($close.Status -eq 'OK') ($close | ConvertTo-Json -Depth 12 -Compress)
        }
        # Retain only this run's fixtures and evidence for diagnosis, even on failure. No broad cleanup.
        if ($null -ne $scope) { Report-IO 'LiveRetained' $true ('fixtures:' + $scope + ';evidence:' + $evidence) }
    }
}
Write-Output ('IO_Summary=passed:' + $script:Passed + ';failed:' + $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
exit 0
