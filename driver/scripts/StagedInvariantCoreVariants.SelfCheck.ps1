#requires -Version 5.1
# Cheap pure row-evaluator controls. No driver, service, protected mutation,
# native build, VM, or product qualification is performed by this self-check.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
foreach($name in @('Load-State','Get-B02JustificationClientBody','Get-WriterBody','Get-ActivatingWriterBody','ConvertTo-PowerShellLiteral','Get-A05WriterBody','Get-X01WriterBody','Test-A05Holder','Test-A05Promotion','Test-ActivationRetiredPromotion','Add-A05WholeSample','Test-X01Versions','Test-X01PublicSequence','Test-X01FinalListing','Test-X01Receipt')){
    $fn=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($fn.Count -ne 1){throw ('Unique function unavailable: '+$name)}
    Invoke-Expression $fn[0].Extent.Text
}
$count=0
function Assert-Control([bool]$Good,[string]$Label){if(-not $Good){throw ('Core control failed: '+$Label)};$script:count++}
function Copy-Fixture($Value){return [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($Value,16))}
function Test-CachedImage($Image,$Geometry,[byte[]]$Expected,[string]$Label){return ,@(@{Name=($Label+'Image');Verdict='PASS'})}
function Get-ActivationSha256([byte[]]$Bytes){return '0123456789ABCDEF'}
function Add-ActivationAssertion($Trial,[string]$Name,[string]$Verdict,[string]$Reason,$Evidence){$Trial.Assertions+=@(@{Name=$Name;Verdict=$Verdict;Reason=$Reason;Evidence=$Evidence})}
$nt='\Device\HarddiskVolume3\fixture\marker.txt';$id='000000000000002a'
$held=@{Entries=@(@{fileId=$id;path=$nt;state='Activating';generation=3;H=1;W=0;unknownReasons='0x00000000';openerPids=@(123)});Snapshot=@{Record=@{policyGeneration=9}}}
Assert-Control ((Test-A05Holder $held $id $nt 123 9).Verdict -ceq 'PASS') 'exact live physical holder'
foreach($field in @('state','fileId','path','H','W','unknownReasons','openerPids')){
    $bad=Copy-Fixture $held
    switch($field){
        'state' {$bad.Entries[0].state='Protected'}
        'fileId' {$bad.Entries[0].fileId='other'}
        'path' {$bad.Entries[0].path='other'}
        'H' {$bad.Entries[0].H=0}
        'W' {$bad.Entries[0].W=1}
        'unknownReasons' {$bad.Entries[0].unknownReasons='0x00000001'}
        'openerPids' {$bad.Entries[0].openerPids=@(124)}
    }
    Assert-Control ((Test-A05Holder $bad $id $nt 123 9).Verdict -ceq 'FAIL') ('reject held '+$field)
}
$bad=Copy-Fixture $held;$bad.Entries[0].Remove('W');Assert-Control ((Test-A05Holder $bad $id $nt 123 9).Verdict -ceq 'FAIL') 'missing W rejected'
Assert-Control ((Test-A05Holder $held $id $nt 123 8).Verdict -ceq 'FAIL') 'wrong policy generation'
$bad=Copy-Fixture $held;$bad.Entries+=@($bad.Entries[0]);Assert-Control ((Test-A05Holder $bad $id $nt 123 9).Verdict -ceq 'FAIL') 'ambiguous target rejected'
$protected=@{registryEntry=$true;historyPresent=$true;nameMatches=$true;fileId=$id;state='Protected';free=$true;H=0;S='NO';C=0;T=0;unknownReasons='0x00000000'}
$trace=@{Summary=@{completeSnapshot=$true};Batches=@(@{lostEvents=0;overwrittenEvents=0;flags=0});Entries=@(@{fileId=$id;stateBefore=1;stateAfter=2;Hsample=0;Wsample=0;Tsample=0;CforSopSample=0;unknownReasonsSample=0;qpc=30})}
Assert-Control ((Test-A05Promotion $protected $trace $id 20 10).Verdict -ceq 'PASS') 'drained same-file promotion after release'
foreach($field in @('H','S','C','T','historyPresent','free','unknownReasons')){
    $bad=Copy-Fixture $protected
    switch($field){'S'{$bad.S='YES'}'historyPresent'{$bad.historyPresent=$false}'free'{$bad.free=$false}'unknownReasons'{$bad.unknownReasons='0x00000001'}default{$bad[$field]=1}}
    Assert-Control ((Test-A05Promotion $bad $trace $id 20 10).Verdict -ceq 'FAIL') ('reject promotion '+$field)
}
foreach($field in @('Hsample','Wsample','Tsample','CforSopSample','unknownReasonsSample','qpc')){
    $bad=Copy-Fixture $trace;$bad.Entries[0][$field]=if($field -ceq 'qpc'){19}else{1}
    Assert-Control ((Test-A05Promotion $protected $bad $id 20 10).Verdict -ceq 'FAIL') ('reject promotion edge '+$field)
}
Assert-Control ((Test-A05Promotion $protected $trace $id 20 21).Verdict -ceq 'FAIL') 'operations after release rejected'
$bad=Copy-Fixture $trace;$bad.Entries+=@($bad.Entries[0]);Assert-Control ((Test-A05Promotion $protected $bad $id 20 10).Verdict -ceq 'FAIL') 'duplicate promotion rejected'
$bad=Copy-Fixture $trace;$bad.Batches[0].lostEvents=1;Assert-Control ((Test-A05Promotion $protected $bad $id 20 10).Verdict -ceq 'FAIL') 'lossy promotion trace rejected'
$bad=Copy-Fixture $trace;$bad.Summary.completeSnapshot=$false;Assert-Control ((Test-A05Promotion $protected $bad $id 20 10).Verdict -ceq 'FAIL') 'incomplete promotion snapshot rejected'
$retiredRecord=Copy-Fixture $protected;$retiredRecord.historyPresent=$false;$retiredRecord.volumeSerial='0x000000000000002A'
$boot='synthetic-boot';$frequency=[Diagnostics.Stopwatch]::Frequency
$release=@{NativeCode=0;HolderReleased=$true;BootId=$boot;QpcFrequency=$frequency;StartQpc=20;EndQpc=21;Pid=123}
$retiredCas=@{fileId=$id;stateBefore=1;stateAfter=2;volumeSerial='0x000000000000002A';policyGenerationSample=9;activationGenerationSample=9;qpc=30;markerGenerationExpected=4;markerGenerationAtCas=4;Hsample=0;Wsample=0;Tsample=0;CforSopSample=0;lastSsample=1;unknownReasonsSample=0;renameInFlightSample=0;spilledMutatingIoCountSample=0;unknownWriterCountSample=0;predicateFlags=15;snapshotFlags=1;testDisableTaint=1;policyFlagsSample=32}
$retiredTrace=@{Summary=@{completeSnapshot=$true;firstAvailableSequence=1};Batches=@(@{lostEvents=0;overwrittenEvents=0;flags=0});Entries=@($retiredCas)}
$retiredSnapshot=@{Record=$retiredRecord;Qpc=40}
$retiredProof=Test-ActivationRetiredPromotion $retiredSnapshot $retiredTrace $release $id '0x000000000000002A' 9 $boot
Assert-Control ($retiredProof.Verdict -ceq 'PASS') 'pruned history requires and accepts the complete exact CAS receipt'
Assert-Control ((Test-A05Promotion $retiredRecord $retiredTrace $id 20 10 $retiredProof).Verdict -ceq 'PASS') 'A05 accepts retired history only through the exact CAS receipt'
Assert-Control ((Test-A05Promotion $retiredRecord $retiredTrace $id 20 10).Verdict -ceq 'FAIL') 'A05 cannot accept pruned history without CAS proof'
$bad=Copy-Fixture $retiredTrace;$bad.Entries[0].Wsample=1
$badProof=Test-ActivationRetiredPromotion $retiredSnapshot $bad $release $id '0x000000000000002A' 9 $boot
Assert-Control ($badProof.Verdict -cne 'PASS') 'retired CAS with outstanding W is rejected'
$image=@{Role='Current';Path='C:\fixture\marker.txt';Absent=$false}
$readerFailure=@(@{Unbuffered=$false;Status='ERROR';NativeCode=5},@{Unbuffered=$true;Status='ERROR';NativeCode=5})
$heldSample=@{Status='OK';Captures=@(@{Images=@($image)});C01Readers=$readerFailure}
$heldTrial=@{Assertions=@();ForbiddenByteCount=0}
Add-A05WholeSample $heldTrial $heldSample @{Geometry=@{}} ([byte[]](1,2,3)) 'C:\fixture\marker.txt' 'A05AllowedPU'
Assert-Control (@($heldTrial.Assertions | Where-Object Name -like 'A05AllowedPUReader').Count -eq 0) 'Activating checkpoint keeps raw P/U proof without requiring denied new readers'
$bad=Copy-Fixture $heldSample;$bad.Status='ERROR';$rawRejected=$false
try{Add-A05WholeSample @{Assertions=@();ForbiddenByteCount=0} $bad @{Geometry=@{}} ([byte[]](1,2,3)) 'C:\fixture\marker.txt' 'A05AllowedPU'}catch{$rawRejected=$true}
Assert-Control $rawRejected 'A05 activating checkpoint still rejects an unavailable exact raw P/U capture'
$postReaders=@(@{Unbuffered=$false;Status='OK';Result=@{Digest='0123456789ABCDEF';Length=3}},@{Unbuffered=$true;Status='OK';Result=@{Digest='0123456789ABCDEF';Length=3}})
$postSample=@{Status='OK';Captures=@(@{Images=@($image)});C01Readers=$postReaders}
$postTrial=@{Assertions=@();ForbiddenByteCount=0}
Add-A05WholeSample $postTrial $postSample @{Geometry=@{}} ([byte[]](1,2,3)) 'C:\fixture\marker.txt' 'A05StablePU'
Assert-Control (@($postTrial.Assertions | Where-Object {$_.Name -like 'A05StablePUReader' -and $_.Verdict -ceq 'PASS'}).Count -eq 2) 'Protected checkpoint still requires both fresh and uncached P/U readers'
$bad=Copy-Fixture $postSample;$bad.C01Readers[1].Result.Digest='Torn'
$badTrial=@{Assertions=@();ForbiddenByteCount=0}
Add-A05WholeSample $badTrial $bad @{Geometry=@{}} ([byte[]](1,2,3)) 'C:\fixture\marker.txt' 'A05StablePU'
Assert-Control (@($badTrial.Assertions | Where-Object {$_.Name -ceq 'A05StablePUReader' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1) 'Protected reader regression remains a hard failure'
$d1='1'*64;$d2='2'*64;$db='b'*64
$first=@{TransferId='00000000-0000-0000-0000-000000000001';DestinationGeneration=1;StateName='Blocked';SealedOnce=$true;Sha256Hex=$d1;History=@('Allocated','Sealed','Inspecting','Blocked')}
$latest=@{TransferId='00000000-0000-0000-0000-000000000002';DestinationGeneration=2;StateName='Released';SealedOnce=$true;Sha256Hex=$d2;History=@('Allocated','Sealed','Inspecting','Approved','Publishing','Released')}
Assert-Control (@((Test-X01Versions $first $latest $d1 $d2) | Where-Object Verdict -cne 'PASS').Count -eq 0) 'distinct BLOCK then latest APPROVE'
$bad=Copy-Fixture $latest;$bad.DestinationGeneration=1;Assert-Control (@((Test-X01Versions $first $bad $d1 $d2) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'generation reuse rejected'
$bad=Copy-Fixture $latest;$bad.TransferId=$first.TransferId;Assert-Control (@((Test-X01Versions $first $bad $d1 $d2) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'same transfer rejected'
$bad=Copy-Fixture $first;$bad.History+=@('Approved','Publishing','Released');Assert-Control (@((Test-X01Versions $bad $latest $d1 $d2) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'superseded version release rejected'
$bad=Copy-Fixture $latest;$bad.History+=@('Released');Assert-Control (@((Test-X01Versions $first $bad $d1 $d2) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'duplicate Released rejected'
$bad=Copy-Fixture $latest;$bad.Sha256Hex=$d1;Assert-Control (@((Test-X01Versions $first $bad $d1 $d2) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'stale digest rejected'
$receipts=@();foreach($channel in @('Raw','Fresh','Uncached')){$receipts+=@{Channel=$channel;Digest=$db;Length=12288;BeforePublication=$true;Sequence=1}}
foreach($channel in @('Raw','Fresh','Uncached')){$receipts+=@{Channel=$channel;Digest=$d2;Length=12288;BeforePublication=$false;Sequence=2}}
Assert-Control (@((Test-X01PublicSequence $receipts $db $d2 12288) | Where-Object Verdict -cne 'PASS').Count -eq 0) 'B to v2 whole images on all channels'
$bad=Copy-Fixture $receipts;$bad[3].Digest=$d1;Assert-Control (@((Test-X01PublicSequence $bad $db $d2 12288) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'v1 public rejected'
$bad=Copy-Fixture $receipts;$bad[4].Digest='torn-image';Assert-Control (@((Test-X01PublicSequence $bad $db $d2 12288) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'torn/spliced image rejected'
$bad=Copy-Fixture $receipts;$bad[0].Digest=$d2;Assert-Control (@((Test-X01PublicSequence $bad $db $d2 12288) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'publication before close rejected'
$bad=Copy-Fixture $receipts;$bad+=@{Channel='Uncached';Digest=$db;Length=12288;BeforePublication=$false;Sequence=3};Assert-Control (@((Test-X01PublicSequence $bad $db $d2 12288) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'reader regression rejected'
$bad=Copy-Fixture $receipts;$bad[3].Length=4096;Assert-Control (@((Test-X01PublicSequence $bad $db $d2 12288) | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'short image rejected'
Assert-Control (@((Test-X01PublicSequence @() $db $d2 12288) | Where-Object Verdict -cne 'PASS').Count -gt 0) 'missing evidence cannot pass'
$target='C:\fixture\cached.txt'
$listing=@{Images=@(@{Role='Parent';Path='C:\fixture';DirectoryEntries=@(@{Name='marker.bin';Eof=12288},@{Name='cached.txt';Eof=12288})},@{Role='Current';Path=$target;Absent=$false;Length=12288})}
Assert-Control ((Test-X01FinalListing $listing $listing $target).Verdict -ceq 'PASS') 'one target exact final names'
$bad=Copy-Fixture $listing;$bad.Images[0].DirectoryEntries+=@{Name='cached.txt';Eof=12288};Assert-Control ((Test-X01FinalListing $bad $listing $target).Verdict -ceq 'FAIL') 'duplicate target rejected'
$bad=Copy-Fixture $listing;$bad.Images[0].DirectoryEntries+=@{Name='save.tmp.txt';Eof=12288};Assert-Control ((Test-X01FinalListing $bad $listing $target).Verdict -ceq 'FAIL') 'user temp rejected'
$bad=Copy-Fixture $listing;$bad.Images[0].DirectoryEntries[1].Eof=1;Assert-Control ((Test-X01FinalListing $bad $listing $target).Verdict -ceq 'FAIL') 'wrong target EOF rejected'
$actor=@{Pid=123;Sid='S-1-5-21-1-2-3-4';BootId='boot'};$slot=@{Token='token'};$receipt=@{Pid=123;Sid=$actor.Sid;BootId='boot';Token='token'}
Test-X01Receipt $receipt $actor $slot;Assert-Control $true 'exact actor receipt'
foreach($field in @('Pid','Sid','BootId','Token')){
    $bad=Copy-Fixture $receipt;$bad[$field]=if($field -ceq 'Pid'){124}else{'other'};$rejected=$false
    try{Test-X01Receipt $bad $actor $slot}catch{$rejected=$_.Exception.Message -ceq 'X01 receipt identity/token/boot mismatch'}
    Assert-Control $rejected ('reject receipt '+$field)
}
foreach($body in @((Get-A05WriterBody),(Get-X01WriterBody "C:\fixture\input's.clixml" 'C:\fixture\actor'))){
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
    Assert-Control ($errors.Count -eq 0) 'generated actor PS5 syntax'
}
Assert-Control ((Get-A05WriterBody).Contains("'a05-unpermitted-write'")) 'actual unpermitted write dispatch'
Write-Output ('CoreVariantsSelfCheck=PASS;Controls='+$count+';Qualification=False')
