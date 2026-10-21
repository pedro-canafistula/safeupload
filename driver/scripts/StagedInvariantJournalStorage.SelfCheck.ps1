#requires -Version 5.1
# Pure retained-byte controls. No native file authority or Windows result claimed.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
foreach($name in @('ConvertFrom-ServiceDriverEpoch','ConvertFrom-ServiceArchive','ConvertFrom-ServiceJournalRecord','Test-ServiceJournalStateReachable','Get-ServiceDestinationPaths','Assert-ServiceManifestPath','Test-CachedJournalSequence','Test-ServiceJournalDelta','Test-X01Versions','Test-B02Versions')){
    $fn=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false))
    if($fn.Count -ne 1){throw ('Missing unique function '+$name)}
    Invoke-Expression $fn[0].Extent.Text
}
$checks=0
function Check([bool]$Good,[string]$Label){if(-not $Good){throw $Label};$script:checks++}
function Reject([scriptblock]$Body,[string]$Label){$rejected=$false;try{& $Body | Out-Null}catch{$rejected=$true};Check $rejected $Label}
function Bytes($Value){return ,([Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 24 -Compress)))}
function Clone-StorageFixture($Value){return [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($Value,32))}
$epoch=@{DriverInstanceId='11111111-1111-1111-1111-111111111111';AcceptedAtUtc='2026-10-20T00:00:00Z';DrainRequestId=$null;DrainNonce=$null;DrainedAtUtc=$null}
Check ((ConvertFrom-ServiceDriverEpoch (Bytes $epoch)).DriverInstanceId -ceq $epoch.DriverInstanceId) 'Active epoch'
$drained=Clone-StorageFixture $epoch;$drained.DrainRequestId=1;$drained.DrainNonce=2;$drained.DrainedAtUtc='2026-10-20T00:01:00Z'
Check ((ConvertFrom-ServiceDriverEpoch (Bytes $drained)).DrainNonce -eq 2) 'Paired drain'
foreach($field in @('DriverInstanceId','AcceptedAtUtc','DrainRequestId','DrainNonce','DrainedAtUtc')){
    $bad=Clone-StorageFixture $drained;$bad.Remove($field);Reject {ConvertFrom-ServiceDriverEpoch (Bytes $bad)} ('Missing epoch '+$field)
}
$bad=Clone-StorageFixture $drained;$bad.DrainNonce='2';Reject {ConvertFrom-ServiceDriverEpoch (Bytes $bad)} 'String nonce'
$bad=Clone-StorageFixture $drained;$bad.DrainedAtUtc='2026-10-19T00:00:00Z';Reject {ConvertFrom-ServiceDriverEpoch (Bytes $bad)} 'Backwards drain'
$id=[guid]'22222222-2222-2222-2222-222222222222';$digest='A'*64
$manifest=@{Transfer=@{TransferId=$id.ToString();ProcessId=123;SessionId=1;ProcessName='writer';Destination=0;DestinationPath='C:\fixture\cached.txt';StagePath='C:\private\stage.txt'};
    State=5;Sha256Hex=$digest;UpdatedAtUtc='2026-10-20T00:01:00Z';SealedOnce=$true;DestinationGeneration=1;NamespaceTombstones=$null;PendingRename=$null;
    LastRenameTransactionId=0;LastRenameDestination=$null;LastRenameCommitted=$false;StageDeleted=$true;StageCleanupStarted=$false;HandbackState=0}
function Segment($Manifest,[guid]$FrameId=$id){
    [byte[]]$payload=Bytes $Manifest;[byte[]]$b=New-Object byte[] (4096+60+$payload.Length)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x43415553),0,$b,0,4);[Array]::Copy([BitConverter]::GetBytes([int]1),0,$b,4,4)
    [Array]::Copy([BitConverter]::GetBytes([long]$b.Length),0,$b,8,8)
    $sha=[Security.Cryptography.SHA256]::Create()
    try{[Array]::Copy($sha.ComputeHash($b,0,16),0,$b,16,32)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x414A5553),0,$b,4096,4);[Array]::Copy([BitConverter]::GetBytes([int]1),0,$b,4100,4)
        [Array]::Copy([BitConverter]::GetBytes([int]$payload.Length),0,$b,4104,4);[Array]::Copy($FrameId.ToByteArray(),0,$b,4108,16)
        [Array]::Copy($sha.ComputeHash($payload),0,$b,4124,32);[Array]::Copy($payload,0,$b,4156,$payload.Length)
    }finally{$sha.Dispose()}
    return ,$b
}
$journal='/tmp/staging-journal'
$records=@(@{Path='C:/private/staging-journal/completed/segments.state';Bytes=(Bytes @{Version=1;SegmentCount=1});Artifact='inventory'},
    @{Path='C:/private/staging-journal/completed/00000001.pack';Bytes=(Segment $manifest);Artifact='pack';Owner='S-1-5-18';Sddl='authenticated fixture'})
# Pure path composition works on Linux; manifests retain real Windows paths.
$rows=ConvertFrom-ServiceArchive $records $journal
Check ($rows.Count -eq 1 -and $rows[0].Bytes.Length -eq (Bytes $manifest).Length -and $rows[0].FrameOffset -eq 4096 -and $rows[0].Artifact -ceq 'pack') 'Retain full container provenance and exact payload'
Check ((ConvertFrom-ServiceJournalRecord $rows[0]).StateName -ceq 'Released') 'Archived receipt reaches same parser'
$before=@{Status='OK';Journal=@($rows[0])};$after=Clone-StorageFixture $before
Check ((Test-ServiceJournalDelta $before $after $true).Complete) 'Logical transfer remains byte-identical through relocation'
foreach($offset in @(0,4,8,16,4096,4100,4104,4108,4124,4156)){
    $bad=Clone-StorageFixture $records;$bad[1].Bytes[$offset]=$bad[1].Bytes[$offset] -bxor 1
    Reject {ConvertFrom-ServiceArchive $bad $journal} ('Corrupt archive offset '+$offset)
}
$bad=Clone-StorageFixture $records;$bad[0].Bytes=Bytes @{Version=1;SegmentCount=2};Reject {ConvertFrom-ServiceArchive $bad $journal} 'Missing segment'
$bad=Clone-StorageFixture $records;$bad[1].Path='C:/private/staging-journal/completed/00000002.pack';Reject {ConvertFrom-ServiceArchive $bad $journal} 'Segment gap'
$bad=Clone-StorageFixture $records;$bad+=Clone-StorageFixture $records[1];$bad[0].Bytes=Bytes @{Version=1;SegmentCount=2};$bad[2].Path='C:/private/staging-journal/completed/00000002.pack';Reject {ConvertFrom-ServiceArchive $bad $journal} 'Duplicate transfer across segments'
$bad=Clone-StorageFixture $manifest;$bad.StageDeleted=$false;$badRecords=Clone-StorageFixture $records;$badRecords[1].Bytes=Segment $bad;Reject {ConvertFrom-ServiceArchive $badRecords $journal} 'Unfinished archive work'
$bad=Clone-StorageFixture $manifest;$bad.BoundAllocation=@{ReservationId=$id};$badRecords[1].Bytes=Segment $bad;Reject {ConvertFrom-ServiceArchive $badRecords $journal} 'Unsupported bound archive cannot authorize anything'
$cleaned=Clone-StorageFixture $manifest;$cleaned.State=6;$cleaned.HandbackState=2;$cleaned.JustificationWindowClosed=$true;$cleaned.SealedLength=12288
$cleaned.StageIdentity=@{VolumeSerialNumber=7;FileIdHigh=0;FileIdLow=42}
$cleaned.BlockedDeletionReceipt=@{Version=@{TransferId=$id.ToString();DestinationGeneration=1;StageIdentity=(Clone-StorageFixture $cleaned.StageIdentity)};CommittedRenames=0;Length=12288;Sha256Hex=$digest}
$cleanedRecords=Clone-StorageFixture $records;$cleanedRecords[1].Bytes=Segment $cleaned
Check ((ConvertFrom-ServiceArchive $cleanedRecords $journal).Count -eq 1) 'Exact archived blocked cleanup tuple'
foreach($field in @('TransferId','DestinationGeneration','StageIdentity')){
    $bad=Clone-StorageFixture $cleaned
    switch($field){'TransferId'{$bad.BlockedDeletionReceipt.Version.TransferId=[guid]::NewGuid().ToString()}'DestinationGeneration'{$bad.BlockedDeletionReceipt.Version.DestinationGeneration=2}'StageIdentity'{$bad.BlockedDeletionReceipt.Version.StageIdentity.FileIdLow=43}}
    $badRecords[1].Bytes=Segment $bad;Reject {ConvertFrom-ServiceArchive $badRecords $journal} ('Wrong cleanup '+$field)
}
$bad=Clone-StorageFixture $cleaned;$bad.BlockedDeletionReceipt=$null;$badRecords[1].Bytes=Segment $bad;Reject {ConvertFrom-ServiceArchive $badRecords $journal} 'Missing exact cleanup receipt'
foreach($field in @('Length','CommittedRenames')){
    $bad=Clone-StorageFixture $cleaned;$bad.BlockedDeletionReceipt.$field=[string]$bad.BlockedDeletionReceipt.$field;$badRecords[1].Bytes=Segment $bad;Reject {ConvertFrom-ServiceArchive $badRecords $journal} ('String cleanup '+$field)
}
$pending=Clone-StorageFixture $manifest;$pending.State=10;$pending.SealedOnce=$false;$pending.Sha256Hex=$null
Check ((ConvertFrom-ServiceJournalRecord @{Path=($id.ToString('N')+'.json');Bytes=(Bytes $pending)}).StateName -ceq 'SealPending') 'Exact numeric state 10'
$pending.SealedOnce=$true;Reject {ConvertFrom-ServiceJournalRecord @{Path=($id.ToString('N')+'.json');Bytes=(Bytes $pending)}} 'First pending seal is not a measured seal'
$history=@('Allocated','SealPending','Sealed','Inspecting','Approved','Publishing','Released')
$transitions=@(@{StateName='Allocated';State=0;TransferId=$id;DestinationGeneration=1},@{StateName='Released';State=5;TransferId=$id;DestinationGeneration=1;SealedOnce=$true;Sha256Hex=$digest;History=$history})
Check ((Test-CachedJournalSequence $transitions 'APPROVE' $digest)[0].Verdict -ceq 'PASS') 'Exact current durable history'
foreach($changed in @(@('Allocated','SealPending','Inspecting','Approved','Publishing','Released'),@('Allocated','Sealed','SealPending','Inspecting','Approved','Publishing','Released'),@('Allocated','SealPending','SealPending','Sealed','Inspecting','Approved','Publishing','Released'),@('Allocated','SealPending','Sealed','Inspecting','Approved','Publishing','Released','Released'))){
    $bad=Clone-StorageFixture $transitions;$bad[-1].History=$changed;Check ((Test-CachedJournalSequence $bad 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'No missing/reordered/duplicate required state'
}
$bad=Clone-StorageFixture $transitions;$bad=@($bad[0],@{StateName='Retained';State=7},$bad[-1]);Check ((Test-CachedJournalSequence $bad 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'Final exact history cannot hide a contradictory observed state'
$blocked=@{StateName='Blocked';TransferId=$id.ToString();DestinationGeneration=1;SealedOnce=$true;Sha256Hex=$digest;History=@('Allocated','SealPending','Sealed','Inspecting','Blocked')}
$released=@{StateName='Released';TransferId='33333333-3333-3333-3333-333333333333';DestinationGeneration=2;SealedOnce=$true;Sha256Hex=('B'*64);History=$history}
Check (@(Test-X01Versions $blocked $released $digest ('B'*64) | ForEach-Object {$_} | Where-Object Verdict -ne 'PASS').Count -eq 0) 'X01 retains exact v1/v2 sequence assertions'
$released.History=@('Allocated','SealPending','Sealed','Inspecting','Blocked','Inspecting','Approved','Publishing','Released')
Check (@(Test-B02Versions $blocked $released $digest ('B'*64) | ForEach-Object {$_} | Where-Object Verdict -ne 'PASS').Count -eq 0) 'B02 retains exact reinspection sequence'
'JournalStorageSelfCheck=PASS;Checks='+$checks+';Qualification=False'
