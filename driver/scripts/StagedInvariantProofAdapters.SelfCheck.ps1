# Host-safe evaluation and temporary identity-publication tests. No Windows APIs,
# driver, service or guest operations.
# Run on Windows PowerShell 5.1 before qualification; Linux PS7 is authoring QA only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
try {
function Import-EvaluationFunctions([string]$File,[string[]]$Names) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($File,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($name in $Names){
        $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
        if($functions.Count -ne 1){throw ('Missing/ambiguous evaluation function: '+$name)}
        # Define at script scope without importing the module's native decoder.
        $definition=$functions[0].Extent.Text.Replace(('function '+$name),('function script:'+$name))
        Invoke-Expression $definition
    }
}
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') @('New-IORecord','New-IOAssertion','Get-IOEntryKey','Test-IODirectoryVersion','Test-InvariantCadence','Test-InvariantMetadata','Test-InvariantExternalCoverage')
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1') @('Test-ActivationMappingOnly','Test-ActivationRetiredPromotion','Test-ActivationChildWindow','Get-ActivationFileObjectLifetimeEvents','Add-ActivationAssertion','Test-ActivationDuplicateCleanup','Test-ActivationRawWholeImage','Get-ActivationSha256','Get-ActivationPendingEntry','Get-ActivationFullPendingEntry','ConvertFrom-NtfsLastAccessOutput','Wait-WriterIdentity','Load-State','Get-ActivatingWriterBody','Get-ExpectedCheckpoint','Test-ServiceJournalStateReachable','Assert-ServiceManifestPath','ConvertFrom-ServiceJournalRecord','Test-ServiceJournalDelta','Get-ServiceDestinationPaths','Test-ServiceFixtureEntry','Get-NotificationTailCoverage','Get-NotificationFenceWaitDecision','ConvertFrom-NotificationRecord','Test-NotificationWindow','ConvertFrom-AgentEventXml','Test-AgentLogContinuity','Read-AgentLogWindow','Test-NotificationLocationUnchanged','Test-AgentDidNotRun','Get-ServiceTimeline','Test-CachedJournalSequence','Test-CachedNotifications','Test-CachedHandBackAcl','Test-CachedSample','Test-CachedImage','Test-CachedActorCalls','Add-CachedHeldJournal','Test-CachedNamespaceCommit','Get-B02JustificationClientBody','Get-WriterBody','Get-ActivationActorIdentity','Publish-ActivationActorCommand')
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Clone($Value){return ($Value | ConvertTo-Json -Depth 32 | ConvertFrom-Json)}
# A temporary callback source cannot contaminate the subsequent map-only claim.
$mapId='AA'*16;$mapPath='\Device\HarddiskVolume3\fixture.txt';$mapSerial='0x0000000000000011'
$mapActor=@{Pid=10;BootId='fixture'}
$mapClose=@{NativeCode=0;IdentityCode=0;ProbeClosed=$true;OriginalSourceClosed=$true;FileId=$mapId;VolumeSerial=$mapSerial;Pid=10;BootId='fixture';QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=100;EndQpc=110}
$mapNative=@{Snapshot=@{Qpc=120;Record=@{policyGeneration=1}};Entries=@(@{fileId=$mapId;path=$mapPath;state='Activating';H=0;W=0;C=0;T=0;S='YES';unknownReasons='0x00000000'})}
Check ((Test-ActivationMappingOnly $mapClose $mapNative $mapId $mapPath $mapSerial 1 $mapActor).Verdict -ceq 'PASS') 'Checked same-target probe close and native Activating H=0/S=YES passes.'
foreach($change in @(@('NativeCode',5),@('IdentityCode',6),@('ProbeClosed',$false),@('OriginalSourceClosed',$false),@('FileId','wrong'),@('VolumeSerial','wrong'),@('Pid',11),@('BootId','old'),@('QpcFrequency',1),@('StartQpc',0),@('EndQpc',99))){
 $bad=Clone $mapClose;$bad.($change[0])=$change[1]
 Check ((Test-ActivationMappingOnly $bad $mapNative $mapId $mapPath $mapSerial 1 $mapActor).Verdict -ceq 'INCONCLUSIVE') ('Map-only rejects probe close '+$change[0]+'.')
}
foreach($change in @(@('H',1),@('W',1),@('C',1),@('T',1),@('S','NO'),@('state','Protected'),@('fileId','other'),@('path','other'),@('unknownReasons','0x00000001'))){
 $bad=Clone $mapNative;$bad.Entries[0].($change[0])=$change[1]
 Check ((Test-ActivationMappingOnly $mapClose $bad $mapId $mapPath $mapSerial 1 $mapActor).Verdict -ceq 'INCONCLUSIVE') ('Map-only rejects native '+$change[0]+'.')
}
$bad=Clone $mapNative;$bad.Entries[0].PSObject.Properties.Remove('H')
Check ((Test-ActivationMappingOnly $mapClose $bad $mapId $mapPath $mapSerial 1 $mapActor).Verdict -ceq 'INCONCLUSIVE') 'Missing map-only H cannot default to zero.'
$bad=Clone $mapNative;$bad.Snapshot.Qpc=109
Check ((Test-ActivationMappingOnly $mapClose $bad $mapId $mapPath $mapSerial 1 $mapActor).Verdict -ceq 'INCONCLUSIVE') 'Map-only native sample must follow completed probe close.'
$bad=Clone $mapNative;$bad.Snapshot.Record.policyGeneration=2
Check ((Test-ActivationMappingOnly $mapClose $bad $mapId $mapPath $mapSerial 1 $mapActor).Verdict -ceq 'INCONCLUSIVE') 'Map-only accepted generation must match.'
# A retired entry needs the actual native same-ID CAS; Free alone is not proof.
$retiredId='AA'*16;$retiredSerial='0x0000000000000011'
$retiredCurrent=@{Record=@{registryEntry=$true;historyPresent=$false;nameMatches=$true;fileId=$retiredId;volumeSerial=$retiredSerial;state='Protected';free=$true;S='NO';H=0;C=0;T=0;unknownReasons='0x00000000'};Qpc=600}
$retiredRelease=@{NativeCode=0;HolderReleased=$true;BootId='fixture';QpcFrequency=[Diagnostics.Stopwatch]::Frequency;StartQpc=500;EndQpc=510}
$retiredEdge=@{fileId=$retiredId;volumeSerial=$retiredSerial;stateBefore=1;stateAfter=2;policyGenerationSample=1;activationGenerationSample=1;qpc=550;markerGenerationExpected=3;markerGenerationAtCas=3;Hsample=0;Wsample=0;Tsample=0;CforSopSample=0;lastSsample=1;unknownReasonsSample=0;renameInFlightSample=0;spilledMutatingIoCountSample=0;unknownWriterCountSample=0;predicateFlags=31;snapshotFlags=1;testDisableTaint=1;policyFlagsSample=48}
$retiredTrace=@{Summary=@{completeSnapshot=$true;firstAvailableSequence=1};Entries=@($retiredEdge)}
Check ((Test-ActivationRetiredPromotion $retiredCurrent $retiredTrace $retiredRelease $retiredId $retiredSerial 1 'fixture').Verdict -ceq 'PASS') 'Retired history requires complete native same-ID CAS in the exact release/query window.'
foreach($field in @('Hsample','Wsample','Tsample','CforSopSample','unknownReasonsSample','renameInFlightSample','spilledMutatingIoCountSample','unknownWriterCountSample')){
 $bad=Clone $retiredTrace;$bad.Entries[0].$field=1
 Check ((Test-ActivationRetiredPromotion $retiredCurrent $bad $retiredRelease $retiredId $retiredSerial 1 'fixture').Verdict -ceq 'INCONCLUSIVE') ('Retired history rejects nonzero CAS '+$field+'.')
}
foreach($bad in @(@{Summary=$retiredTrace.Summary;Entries=@()},@{Summary=$retiredTrace.Summary;Entries=@($retiredEdge,$retiredEdge)},@{Summary=@{completeSnapshot=$false;firstAvailableSequence=1};Entries=@($retiredEdge)},@{Summary=@{completeSnapshot=$true;firstAvailableSequence=2};Entries=@($retiredEdge)})){
 Check ((Test-ActivationRetiredPromotion $retiredCurrent $bad $retiredRelease $retiredId $retiredSerial 1 'fixture').Verdict -ceq 'INCONCLUSIVE') 'Missing/duplicate/incomplete/lost native CAS cannot be replaced by current Free.'
}
foreach($change in @(@('fileId','wrong'),@('volumeSerial','wrong'),@('policyGenerationSample',2),@('activationGenerationSample',2),@('qpc',499),@('qpc',601),@('markerGenerationAtCas',4),@('lastSsample',2),@('predicateFlags',13),@('predicateFlags',63),@('snapshotFlags',0),@('testDisableTaint',0),@('policyFlagsSample',16))){
 $bad=Clone $retiredTrace;$bad.Entries[0].($change[0])=$change[1]
 Check ((Test-ActivationRetiredPromotion $retiredCurrent $bad $retiredRelease $retiredId $retiredSerial 1 'fixture').Verdict -ceq 'INCONCLUSIVE') ('Retired history rejects CAS '+$change[0]+'='+$change[1]+'.')
}
$bad=Clone $retiredTrace;$bad.Entries[0].PSObject.Properties.Remove('Wsample')
Check ((Test-ActivationRetiredPromotion $retiredCurrent $bad $retiredRelease $retiredId $retiredSerial 1 'fixture').Verdict -ceq 'INCONCLUSIVE') 'Missing native W sample cannot default to zero.'
foreach($change in @(@('NativeCode',5),@('BootId','old'),@('HolderReleased',$false),@('QpcFrequency',1),@('StartQpc',0),@('EndQpc',499))){
 $bad=Clone $retiredRelease;$bad.($change[0])=$change[1]
 Check ((Test-ActivationRetiredPromotion $retiredCurrent $retiredTrace $bad $retiredId $retiredSerial 1 'fixture').Verdict -ceq 'INCONCLUSIVE') ('Retired history rejects release '+$change[0]+'.')
}

# Kernel FILETIME and actor QPC are separate clocks; post-clear physicalFO/PID
# binding qualifies independently of their unrelated numerical values.
$childFixture=@{Pid=123;BootId='fixture'};$releaseFixture=@{Pid=123;BootId='fixture';NativeCode=0;HolderReleased=$true;StartQpc=100;EndQpc=200}
# Same shape as ConvertFrom-ActivationTrace: the lifetime filter reads the complete AllEntries list.
function New-TraceFixture($Entries){return [pscustomobject]@{Entries=@($Entries);AllEntries=@($Entries)}}
$cleanupFixture=New-TraceFixture @(@{event='file_cleanup';pid=123;targetFileObject='0x0000000000000123';timestamp=134000000000000000})
$writeFixture=@{CompletedWritePairs=@(@{Begin=@{targetFileObject='0x0000000000000123'}})}
Check ((Test-ActivationDuplicateCleanup $cleanupFixture $writeFixture $childFixture $releaseFixture).Verdict -ceq 'PASS') 'Exact post-clear child physicalFO cleanup accepts independent FILETIME/QPC domains.'
foreach($bad in @((New-TraceFixture @()),(New-TraceFixture @($cleanupFixture.Entries[0],$cleanupFixture.Entries[0])),(New-TraceFixture @(@{event='file_cleanup';pid=124;targetFileObject='0x0000000000000123'})),(New-TraceFixture @(@{event='file_cleanup';pid=123;targetFileObject='0x0000000000000124'})))){
 Check ((Test-ActivationDuplicateCleanup $bad $writeFixture $childFixture $releaseFixture).Verdict -ceq 'INCONCLUSIVE') 'Missing/duplicate/wrong PID/physicalFO cleanup cannot qualify.'
}
$badWrites=@{CompletedWritePairs=@(@{Begin=@{targetFileObject='0x0000000000000000'}})}
Check ((Test-ActivationDuplicateCleanup $cleanupFixture $badWrites $childFixture $releaseFixture).Verdict -ceq 'INCONCLUSIVE') 'Zero physicalFO cannot qualify.'
$badRelease=Clone $releaseFixture;$badRelease.NativeCode=5
Check ((Test-ActivationDuplicateCleanup $cleanupFixture $writeFixture $childFixture $badRelease).Verdict -ceq 'INCONCLUSIVE') 'Failed native close cannot qualify.'

# Full raw P+U checks use the final successful image, not failed retry frames.
$rawFixturePath=Join-Path ([IO.Path]::GetTempPath()) ('a04-raw-'+[guid]::NewGuid().ToString('N'))
$rawBytes=[Text.Encoding]::ASCII.GetBytes('known P plus U')
try{
 [IO.File]::WriteAllBytes($rawFixturePath,$rawBytes)
 $rawFixture=@{Status='OK';Images=@(@{Role='Current';Path='target';Absent=$false;LogicalArtifact=@{Path=$rawFixturePath;Length=$rawBytes.Length;Sha256=(Get-ActivationSha256 $rawBytes)}})}
 Check ((Test-ActivationRawWholeImage $rawFixture 'target' $rawBytes).Verdict -ceq 'PASS') 'Exact independently constructed whole raw U passes.'
 $wrong=[byte[]]$rawBytes.Clone();$wrong[0]=[byte]($wrong[0]+1)
 Check ((Test-ActivationRawWholeImage $rawFixture 'target' $wrong).Verdict -ceq 'FAIL') 'Whole raw U mismatch fails.'
 $rawFixture.Images[0].LogicalArtifact.Sha256='wrong'
 Check ((Test-ActivationRawWholeImage $rawFixture 'target' $rawBytes).Verdict -ceq 'INCONCLUSIVE') 'Corrupt retained raw U artifact cannot qualify.'
 $rawFixture.Status='ERROR'
 Check ((Test-ActivationRawWholeImage $rawFixture 'target' $rawBytes).Verdict -ceq 'INCONCLUSIVE') 'Failed raw sample cannot qualify U.'
}finally{if(Test-Path $rawFixturePath){Remove-Item -LiteralPath $rawFixturePath -Force}}
# Valid historical/fence-short records are missing coverage, not read errors.
$tailFixture=@{BootId='old';QpcFrequency=1000;Qpc=10}
$tailProof=Get-NotificationTailCoverage $tailFixture 'active' 1000 20
Check ($tailProof.Status -ceq 'INCONCLUSIVE' -and $tailProof.HistoricalTail -and $tailProof.RecordedBootId -ceq 'old') 'Historical authenticated chain cannot provide current-boot coverage.'
$tailFixture.BootId='active';$tailProof=Get-NotificationTailCoverage $tailFixture 'active' 1000 20
Check ($tailProof.Status -ceq 'INCONCLUSIVE' -and -not $tailProof.HistoricalTail) 'Fence-short valid tail is missing coverage.'
$tailFixture.Qpc=20
Check ((Get-NotificationTailCoverage $tailFixture 'active' 1000 20).Status -ceq 'OK') 'Current same-frequency tail covers fence.'
$tailFixture.QpcFrequency=1001;$rejected=$false;try{$null=Get-NotificationTailCoverage $tailFixture 'active' 1000 20}catch{$rejected=$_.Exception.Message -ceq 'Notification tail QPC frequency mismatch.'}
Check $rejected 'Same-boot QPC frequency mismatch remains a collector error.'
# Predicate controls use fixed QPC values; no sleeps or wall-clock deadlines.
$tailFixture=@{BootId='active';QpcFrequency=1000;Qpc=19}
$coverage=Get-NotificationTailCoverage $tailFixture 'active' 1000 20
Check ((Get-NotificationFenceWaitDecision $coverage 99 100) -ceq 'Wait') 'Authenticated fence-short tail waits before the QPC deadline.'
Check ((Get-NotificationFenceWaitDecision $coverage 100 100) -ceq 'TimedOut') 'Fence-short tail at the exact deadline times out INCONCLUSIVE.'
Check ((Get-NotificationFenceWaitDecision $coverage 101 100) -ceq 'TimedOut') 'Fence-short tail after the deadline cannot qualify.'
foreach($kind in @('Transfer','Heartbeat')){
    $tailFixture=@{BootId='active';QpcFrequency=1000;Qpc=20;Kind=$kind}
    $coverage=Get-NotificationTailCoverage $tailFixture 'active' 1000 20
    Check ((Get-NotificationFenceWaitDecision $coverage 99 100) -ceq 'Covered') ('Authenticated '+$kind+' at the fence finishes the wait.')
}
$tailFixture.Qpc=21
Check ((Get-NotificationFenceWaitDecision (Get-NotificationTailCoverage $tailFixture 'active' 1000 20) 99 100) -ceq 'Covered') 'Newer authenticated tail covers the fence.'
Check ((Get-NotificationFenceWaitDecision (Get-NotificationTailCoverage $tailFixture 'active' 1000 20) 100 100) -ceq 'Covered') 'Covered tail at the exact deadline is within the QPC budget.'
Check ((Get-NotificationFenceWaitDecision (Get-NotificationTailCoverage $tailFixture 'active' 1000 20) 101 100) -ceq 'TimedOut') 'Coverage collected after the QPC deadline remains INCONCLUSIVE.'
$tailFixture.BootId='old';$tailFixture.Qpc=100000
$coverage=Get-NotificationTailCoverage $tailFixture 'active' 1000 20
Check ((Get-NotificationFenceWaitDecision $coverage 99 100) -ceq 'Wait') 'A high QPC in a historical boot never covers the active fence.'
Check ((Get-NotificationFenceWaitDecision $coverage 100 100) -ceq 'TimedOut') 'Historical tail still times out without current-boot coverage.'
$rejected=$false;try{$null=Get-NotificationFenceWaitDecision @{Status='ERROR'} 99 100}catch{$rejected=$true}
Check $rejected 'A reader failure is not authenticated coverage eligible to finish the wait.'

# Machine-wide page completeness and exact target uniqueness are separate.
function Get-ActivationInspectorJson { return [pscustomobject]@{Record=$script:activatingFixture} }
$script:activatingFixture=@{activatingStatus=$true;totalEntries=3;entries=@(
    @{path='target';fileId='id';S='YES'},@{path='outside1';fileId='other1'},@{path='outside2';fileId='other2'})}
$selected=Get-ActivationFullPendingEntry 'target' 'id' 'fixture'
Check ($selected.Entries.Count -eq 1 -and $selected.Snapshot.Record.totalEntries -eq 3) 'Unrelated machine-wide entries must not invalidate the one exact target.'
$script:activatingFixture.totalEntries=4
$rejected=$false;try{$null=Get-ActivationFullPendingEntry 'target' 'id' 'fixture'}catch{$rejected=$true}
Check $rejected 'Incomplete machine-wide page count must fail.'
$script:activatingFixture.totalEntries=3
$script:activatingFixture.entries[2]=@{path='target';fileId='id'}
Check ((Get-ActivationFullPendingEntry 'target' 'id' 'fixture').Entries.Count -eq 2) 'Duplicate exact target remains ambiguous for caller rejection.'
$script:activatingFixture.entries[2]=@{path='target';fileId='other'}
Check ((Get-ActivationFullPendingEntry 'target' 'id' 'fixture').Entries.Count -eq 1) 'A path with another identity must not become an exact target.'
# Exact-target point reads explicitly distinguish scope from machine-wide pages.
$script:activatingFixture=@{activatingTarget=$true;requestedPath='target';matchCount=1;flags=0;policyGeneration=2;
 entries=@(@{path='target';fileId=('a'*32);generation=2;H=1;S='NO';C=0;T=0;W=0})}
$targetFixture=Clone $script:activatingFixture
Check ((Get-ActivationPendingEntry 'target' ('a'*32) 'fixture' 'C:\fixture').Entries.Count -eq 1) 'One exact target is complete without a machine-wide page claim.'
Check ((Get-ActivationPendingEntry 'target' ('b'*32) 'fixture' 'C:\fixture').Entries.Count -eq 0) 'Different file ID is not the target.'
$script:activatingFixture.matchCount=0;$script:activatingFixture.entries=@()
Check ((Get-ActivationPendingEntry 'target' ('a'*32) 'fixture' 'C:\fixture').Entries.Count -eq 0) 'Missing history is absent evidence.'
foreach($field in @('activatingTarget','requestedPath','matchCount','flags','policyGeneration')){
 $script:activatingFixture=Clone $targetFixture
 switch($field){'activatingTarget'{$script:activatingFixture.activatingTarget=$false}'requestedPath'{$script:activatingFixture.requestedPath='wrong'}'matchCount'{$script:activatingFixture.matchCount=2}'flags'{$script:activatingFixture.flags=1}'policyGeneration'{$script:activatingFixture.policyGeneration=0}}
 $rejected=$false;try{$null=Get-ActivationPendingEntry 'target' ('a'*32) 'fixture' 'C:\fixture'}catch{$rejected=$true}
 Check $rejected ('Wrong exact-target header fails: '+$field)
}
$script:activatingFixture=Clone $targetFixture;$script:activatingFixture.entries[0].W='0'
$rejected=$false;try{$null=Get-ActivationPendingEntry 'target' ('a'*32) 'fixture' 'C:\fixture'}catch{$rejected=$true}
Check $rejected 'String counter is not native target evidence.'
$script:activatingFixture=Clone $targetFixture;$script:activatingFixture.entries=@()
$rejected=$false;try{$null=Get-ActivationPendingEntry 'target' ('a'*32) 'fixture' 'C:\fixture'}catch{$rejected=$true}
Check $rejected 'One claimed match must include one retained entry.'
Remove-Item Function:\Get-ActivationInspectorJson
# Name visibility, an open write handle and partial serialization are distinct
# from complete identity publication. Exercise all three with temporary files.
$identityDirectory=Join-Path ([IO.Path]::GetTempPath()) ('proof-identity-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($identityDirectory)
$identityPath=Join-Path $identityDirectory 'identity.clixml';$identityWriter=$null;$publisher=$null
try {
    $identityBytes=[Text.Encoding]::UTF8.GetBytes([Management.Automation.PSSerializer]::Serialize(@{Pid=123;Sid='fixture-sid';BootId='fixture-boot'},32))
    $identityWriter=[IO.FileStream]::new($identityPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    $identityWriter.Write($identityBytes,0,$identityBytes.Length);$identityWriter.Flush($true)
    Check ((Wait-WriterIdentity $identityPath 2).Pid -eq 123) 'Identity read must share with an unclosed writer.'
    $identityWriter.SetLength(0);$identityWriter.Position=0;$identityWriter.Write($identityBytes,0,40);$identityWriter.Flush($true)
    $publisher=[PowerShell]::Create()
    $null=$publisher.AddScript('param($writer,$bytes) Start-Sleep -Milliseconds 250; $writer.SetLength(0); $writer.Position=0; $writer.Write($bytes,0,$bytes.Length); $writer.Flush($true)').AddArgument($identityWriter).AddArgument($identityBytes)
    $publication=$publisher.BeginInvoke()
    Check ((Wait-WriterIdentity $identityPath 3).BootId -ceq 'fixture-boot') 'Partial identity must retry until complete publication.'
    $null=$publisher.EndInvoke($publication)
    if($publisher.HadErrors){throw ($publisher.Streams.Error | Out-String)}
    # The activation actor consumes command CLIXML through the same bounded
    # reader used for shared state; name visibility is not a complete command.
    $identityWriter.SetLength(0);$identityWriter.Position=0;$identityWriter.Write($identityBytes,0,40);$identityWriter.Flush($true)
    $publisher.Dispose();$publisher=[PowerShell]::Create()
    $null=$publisher.AddScript('param($writer,$bytes) Start-Sleep -Milliseconds 250; $writer.SetLength(0); $writer.Position=0; $writer.Write($bytes,0,$bytes.Length); $writer.Flush($true); $writer.Dispose()').AddArgument($identityWriter).AddArgument($identityBytes)
    $publication=$publisher.BeginInvoke()
    Check ((Load-State $identityPath).Pid -eq 123) 'Shared state/activation command read retries the live write handle and partial CLIXML.'
    $null=$publisher.EndInvoke($publication)
    Check ((Get-ActivatingWriterBody).Contains('$command=Load-State $commandPath')) 'Activation actor must use bounded shared-state command publication.'
    $identityWriter.Dispose();$identityWriter=$null
    foreach($badPath in @((Join-Path $identityDirectory 'missing.clixml'),$identityPath)){
        if($badPath -ceq $identityPath){[IO.File]::WriteAllText($identityPath,'<Objs><broken>')}
        $timer=[Diagnostics.Stopwatch]::StartNew();$refused=$false
        try{$null=Wait-WriterIdentity $badPath 1}catch{$refused=$_.Exception.Message -like '*after bounded retry*'}
        Check ($refused -and $timer.Elapsed.TotalSeconds -lt 5) 'Missing/malformed identity publication must have a bounded failure.'
    }
}finally{
    if($null -ne $publisher){$publisher.Dispose()};if($null -ne $identityWriter){$identityWriter.Dispose()}
    [IO.Directory]::Delete($identityDirectory,$true)
}
$boot='fixture/boot';$frequency=1000
$baseline=[pscustomobject]@{CaseId='S00-observer-control';Build='19045.2965';ObserverPid=999;ObserverSid='S-1-5-18';Time=[pscustomobject]@{Qpc=10000;QpcFrequency=$frequency;BootId=$boot};Geometry=@{Guid='volume'};Images=@()}
$operations=@(for($n=0;$n -le 100;$n++){[pscustomobject]@{Trial=$n;Class='writer-open-deny';NativeCode=5;StartQpc=100+$n*10;EndQpc=101+$n*10}})
$fence=[pscustomobject]@{Complete=$true;BootId=$boot;QpcFrequency=$frequency;ReleasedQpc=50;CompletedQpc=2000;ExpectedAttempts=101}
$samples=@(for($n=1;$n -le 2;$n++){[pscustomobject]@{Status='OK';Sequence=$n;Start=[pscustomobject]@{Qpc=10000+$n*100;QpcFrequency=$frequency;BootId=$boot};End=[pscustomobject]@{Qpc=10050+$n*100;QpcFrequency=$frequency;BootId=$boot;Utc='2026-10-04T22:00:00Z'};DurationMs=50;GapMs=50;CadenceMs=100}})
$proof=Test-InvariantCadence $baseline $samples $operations $fence
Check ($proof.Complete -and $proof.Intervals.Count -eq 4) 'Operation-free long gaps and captures must have receipts.'
$changed=Clone $samples;$changed[0].Start.Qpc=1000;$changed[0].End.Qpc=1100
$earlier=Clone $baseline;$earlier.Time.Qpc=900
$proof=Test-InvariantCadence $earlier $changed $operations $fence
Check (-not $proof.Complete -and @($proof.Assertions | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0) 'Overlap must remain INCONCLUSIVE.'
Check (-not (Test-InvariantCadence $baseline $samples $operations[0..99] $fence).Complete) 'Missing operation must invalidate negative cadence proof.'
$bad=Clone $samples;$bad[1].End.BootId='other-boot'
Check (-not (Test-InvariantCadence $baseline $bad $operations $fence).Complete) 'Cross-boot sample must invalidate cadence.'
Check (-not (Test-InvariantCadence $baseline $samples $operations $null).Complete) 'Missing fence must invalidate cadence.'
$calls=@(for($n=0;$n -le 100;$n++){foreach($c in @('writer-open','cached-write','flush','close')){[pscustomobject]@{Trial=$n;Class=$c;NativeCode=0;StartQpc=100+$n*10+@('writer-open','cached-write','flush','close').IndexOf($c)*2;EndQpc=101+$n*10+@('writer-open','cached-write','flush','close').IndexOf($c)*2}}})
$live=Clone $samples;$live[0].Start.Qpc=102;$live[0].End.Qpc=103;$early=Clone $baseline;$early.Time.Qpc=102
Check (-not (Test-InvariantCadence $early $live $calls $fence).Complete) 'Whole open-to-close attempt must cover between-call intervals.'
$time=[DateTime]::Parse('2026-10-04T21:59:59Z').ToUniversalTime().ToFileTimeUtc()
$metadata=[pscustomobject]@{Attributes=32;Creation=$time;Modified=$time;Changed=$time;Accessed=$time;Links=1}
$image=[pscustomobject]@{Role='Current';Absent=$false;Path='fixture';Identity=(Clone $metadata);RawMetadata=(Clone $metadata);SecurityId=42;Sddl='exact';DirectoryEntries=@()}
$image.Identity | Add-Member NoteProperty FileId 'id'
$baseline.Images=@($image);$baseline | Add-Member NoteProperty CaptureStartedFileTime $time
$script:row=@{ExpectedTimeline=@('setup','boot','Unscoped');MetadataExpectations=@{Accessed='NtfsReadWindow';AccessReason='NTFS read-side in-memory time versus lazy disk update'}}
$expect=(Get-ExpectedCheckpoint $baseline 'Continuous' 1).Storage[0]
# Absent nested metadata used to index a null Properties array in the observer.
foreach($view in @('Raw','Api')) {
    $bad=Clone $expect;$bad.Metadata.$view=$null
    $result=@(Test-InvariantMetadata $image $bad $samples[0] $null)
    Check ($result.Count -eq 1 -and $result[0].Verdict -eq 'INCONCLUSIVE' -and $result[0].Reason -ceq ('Exact per-fixture metadata '+$view+' expectation missing.')) ('Absent '+$view+' metadata must have an exact reason, without throwing.')
}
$bad=Clone $expect;$bad.Metadata=Clone $metadata
$result=@(Test-InvariantMetadata $image $bad $samples[0] $null)
Check ($result.Count -eq 1 -and $result[0].Verdict -eq 'INCONCLUSIVE' -and $result[0].Reason -ceq 'Exact per-fixture metadata Raw expectation missing.') 'Legacy flat metadata must be INCONCLUSIVE without throwing.'
$bad=Clone $expect;$bad.Metadata=$null
$result=@(Test-InvariantMetadata $image $bad $samples[0] $null)
Check ($result.Count -eq 1 -and $result[0].Verdict -eq 'INCONCLUSIVE' -and $result[0].Reason -ceq 'Exact per-fixture metadata expectation missing.') 'Null metadata must be INCONCLUSIVE without throwing.'
$policy=[pscustomobject]@{Status='OK';Before=[pscustomobject]@{Value=3;Management='System';UpdatesDisabled=$true;BootId=$boot;VolumeGuid='volume';Qpc=0};After=[pscustomobject]@{Value=3;Management='System';UpdatesDisabled=$true;BootId=$boot;VolumeGuid='volume';Qpc=20000}}
foreach($pair in @(@(0,'User','Enabled'),@(1,'User','Disabled'),@(2,'System','Disabled'),@(3,'System','Enabled'))){
    $text='DisableLastAccess = '+$pair[0]+'  ('+$pair[1]+' Managed, '+$pair[2]+')'
    $parsed=ConvertFrom-NtfsLastAccessOutput $text 0
    Check ($parsed.Value -eq $pair[0] -and $parsed.Management -ceq $pair[1] -and $parsed.UpdatesDisabled -eq (($pair[0] -band 1) -ne 0)) 'Supported fsutil numeric update state is authoritative; display labels may describe the disable switch.'
}
foreach($text in @('DisableLastAccess = 2','DisableLastAccess = 2 (system managed, disabled)','DisableLastAccess = 2 (System Managed, Unknown)','DisableLastAccess = 0 (System Managed, Enabled)','DisableLastAccess = 3 (User Managed, Disabled)',"DisableLastAccess = 2 (System Managed, Disabled)`nDisableLastAccess = 2 (System Managed, Disabled)")){
    Check ($null -eq (ConvertFrom-NtfsLastAccessOutput $text 0).UpdatesDisabled) 'Missing/ambiguous fsutil mode label cannot authorize tolerance.'
}
Check ($null -eq (ConvertFrom-NtfsLastAccessOutput 'DisableLastAccess = 2 (System Managed, Disabled)' 1).UpdatesDisabled) 'Failed fsutil command cannot authorize tolerance.'
$image.Identity.Accessed=$time+10000
$assertions=@(Test-InvariantMetadata $image $expect $samples[0] $policy)
Check (@($assertions | Where-Object Verdict -ne 'PASS').Count -eq 0) 'Named bounded LastAccess divergence should be allowed.'
$bad=Clone $image;$bad.RawMetadata.Modified++
Check (@(Test-InvariantMetadata $bad $expect $samples[0] $policy | Where-Object Verdict -eq 'FAIL').Count -gt 0) 'Modified must never be tolerated.'
$bad=Clone $image;$bad.RawMetadata.Accessed++
Check (@(Test-InvariantMetadata $bad $expect $samples[0] $policy | Where-Object Verdict -eq 'FAIL').Count -gt 0) 'Disabled policy must preserve exact raw Accessed.'
$bad=Clone $image;$bad.Identity.Accessed=$time+[TimeSpan]::FromMinutes(2).Ticks
Check (@(Test-InvariantMetadata $bad $expect $samples[0] $policy | Where-Object Verdict -eq 'FAIL').Count -gt 0) 'Future API Accessed must fail.'
Check (@(Test-InvariantMetadata $image $expect $samples[0] $null | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0) 'Absent policy cannot authorize Accessed tolerance.'
$bad=Clone $policy;$bad.Before.PSObject.Properties.Remove('UpdatesDisabled')
Check (@(Test-InvariantMetadata $image $expect $samples[0] $bad | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0) 'Historical numeric-only policy cannot authorize tolerance.'
$bad=Clone $policy;$bad.After.UpdatesDisabled=$false
Check (@(Test-InvariantMetadata $image $expect $samples[0] $bad | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0) 'Enabled/disabled label change invalidates tolerance.'
$bad=Clone $policy;$bad.After.Value=0
Check (@(Test-InvariantMetadata $image $expect $samples[0] $bad | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0) 'Policy change invalidates tolerance.'
# Capture the same real ending receipt on successful and interrupted trials.
# Only the transport is mocked; the policy finalizer and observer are real.
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1') @('Complete-LastAccessEvidence','Get-ErrorChain')
$script:lastAccessReceipt=Clone $policy.After;$script:lastAccessFailure=$false
function Get-LastAccessEvidence {
    if($script:lastAccessFailure){throw 'LastAccess query transport failed'}
    return $script:lastAccessReceipt
}
foreach($interrupted in @($false,$true)){
    $partial=[ordered]@{Errors=@();LastAccessBefore=(Clone $policy.Before)}
    try{if($interrupted){throw 'BLOCK expiry recovery service Ready QPC timeout'}}
    catch{$partial.Errors+=Get-ErrorChain $_.Exception}
    finally{Complete-LastAccessEvidence $partial}
    Check ($partial.LastAccessAfter.Qpc -eq 20000 -and $partial.LastAccessPolicy.After.Qpc -eq 20000 -and
        $partial.LastAccessPolicy.Before.Qpc -eq 0 -and $partial.LastAccessPolicy.Status -ceq 'OK') 'Finalization retains two independent policy receipts after success or execution failure.'
    Check (@(Test-InvariantMetadata $image $expect $samples[0] $partial.LastAccessPolicy | Where-Object Verdict -cne 'PASS').Count -eq 0) 'Real paired finalization receipt binds the retained sample.'
    Check ($partial.Errors.Count -eq [int]$interrupted -and (-not $interrupted -or $partial.Errors[0].Message -ceq 'BLOCK expiry recovery service Ready QPC timeout')) 'Metadata finalization never removes the original execution error.'
}
$script:lastAccessReceipt=Clone $policy.After;$script:lastAccessReceipt.Value=2;$script:lastAccessReceipt.UpdatesDisabled=$false
$enabled=[ordered]@{Errors=@();LastAccessBefore=(Clone $script:lastAccessReceipt)};$enabled.LastAccessBefore.Qpc=0
Complete-LastAccessEvidence $enabled
Check (@(Test-InvariantMetadata $image $expect $samples[0] $enabled.LastAccessPolicy | Where-Object Verdict -cne 'PASS').Count -eq 0) 'System-managed value2 binds the same bounded read-side rule after finalization.'
foreach($field in @('boot','volume','lateBefore','earlyAfter','policy','missingValue')){
    $script:lastAccessReceipt=Clone $policy.After;$partial=[ordered]@{Errors=@();LastAccessBefore=(Clone $policy.Before)}
    switch($field){
        'boot'{$script:lastAccessReceipt.BootId='other'} 'volume'{$script:lastAccessReceipt.VolumeGuid='other'}
        'lateBefore'{$partial.LastAccessBefore.Qpc=$samples[0].Start.Qpc+1} 'earlyAfter'{$script:lastAccessReceipt.Qpc=$samples[0].End.Qpc-1}
        'policy'{$script:lastAccessReceipt.Value=2;$script:lastAccessReceipt.UpdatesDisabled=$false} 'missingValue'{$script:lastAccessReceipt.Value=$null}
    }
    Complete-LastAccessEvidence $partial
    Check (@(Test-InvariantMetadata $image $expect $samples[0] $partial.LastAccessPolicy | Where-Object Verdict -ceq 'INCONCLUSIVE').Count -gt 0) ('Finalized receipt cannot conceal wrong/missing binding: '+$field)
}
$partial=[ordered]@{Errors=@(@{Message='original execution error'});LastAccessBefore=(Clone $policy.Before);LastAccessAfter=(Clone $policy.After)}
$script:lastAccessFailure=$true
Complete-LastAccessEvidence $partial
Check ($null -eq $partial.LastAccessAfter -and $partial.LastAccessPolicy.Status -ceq 'INCONCLUSIVE' -and $partial.Errors.Count -eq 2 -and
    $partial.Errors[0].Message -ceq 'original execution error' -and $partial.Errors[1].Message -ceq 'LastAccess query transport failed') 'Failed final query records its error and cannot reuse an older ending receipt.'
Check (@(Test-InvariantMetadata $image $expect $samples[0] $partial.LastAccessPolicy | Where-Object Verdict -ceq 'INCONCLUSIVE').Count -gt 0) 'Failed final query cannot authorize metadata tolerance.'
$script:lastAccessFailure=$false
$tokens=$null;$errors=$null;$suiteAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
foreach($name in @('Invoke-CachedObservation','Invoke-SeedObservation','Invoke-R03Observation')){
    $fn=@($suiteAst.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false))[0]
    $finalizers=@($fn.Body.FindAll({param($n)$n -is [Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and
        $n.Finally.Extent.Text.Contains('Complete-LastAccessEvidence $trial')},$false))
    Check ($finalizers.Count -eq 1) ('Real metadata consumer always finalizes its policy receipt: '+$name)
}
# C05 p1c3: the index LastAccess advances lazily, after the child's raw value.
# These are fabricated same-capture facts, never raw-volume qualification.
$directoryPath=Join-Path ([IO.Path]::GetTempPath()) 'c05-directory-control'
$entry=[pscustomobject]@{Name='marker.bin';Namespace=3;Reference=17;Parent=9;Eof=12288;Allocated=12288;Attributes=32;Creation=$time;Modified=$time;Changed=$time;Accessed=$time}
$directoryParent=[pscustomobject]@{Role='Parent';Path=$directoryPath;DirectoryEntries=@($entry);SecurityId=42;Sddl='exact'}
$directoryChild=[pscustomobject]@{Role='Current';Path=(Join-Path $directoryPath 'marker.bin');Absent=$false;Identity=(Clone $metadata);RawMetadata=(Clone $metadata);SecurityId=42;Sddl='exact';CrossCheckErrors=@()}
$directoryChild.Identity | Add-Member NoteProperty FileId 'directory-child-id'
$directoryChild.Identity | Add-Member NoteProperty Reference 17
$directoryBaseline=Clone $baseline;$directoryBaseline.Images=@($directoryParent,$directoryChild);$directoryBaseline.CaptureStartedFileTime=$time+10000
$savedRow=$script:row
$script:row=@{ExpectedTimeline=@('setup','boot','Protected');MetadataExpectations=@{Accessed='NtfsReadWindow';DirectoryEntryAccessed='NtfsReadWindow';AccessReason='same identity read window'}}
$directoryCheckpoint=Get-ExpectedCheckpoint $directoryBaseline 'AfterRenameHandleHeld' 6
$directoryExpected=$directoryCheckpoint.Directories[0];$directoryStorage=$directoryCheckpoint.Storage
Check ($directoryExpected.EntryAccessRule -ceq 'NtfsReadWindow' -and $directoryExpected.Entries[0].Accessed -eq $time -and
    $directoryStorage[0].Metadata.AccessWindowStartFileTime -eq ($time+10000)) 'C05 checkpoint records opt-in and original index/child window, without rebaselining.'
$script:row=@{ExpectedTimeline=@('setup','boot','Protected');MetadataExpectations=@{Accessed='NtfsReadWindow'}}
$exactDirectory=(Get-ExpectedCheckpoint $directoryBaseline 'AfterRenameHandleHeld' 6).Directories[0]
Check ($null -eq $exactDirectory.PSObject.Properties['EntryAccessRule']) 'Rows without explicit directory opt-in keep exact index metadata.'
$script:row=$savedRow
$directoryActual=Clone $directoryParent;$directoryActual.DirectoryEntries[0].Accessed=$time+20000
$directoryCurrent=Clone $directoryChild;$directoryCurrent.RawMetadata.Accessed=$time+30000;$directoryCurrent.Identity.Accessed=$time+50000
$directorySample=[pscustomobject]@{Sequence=6;Start=[pscustomobject]@{BootId='directory-control';Qpc=100};End=[pscustomobject]@{Qpc=200;Utc=([DateTime]::FromFileTimeUtc($time+10000000).ToString('o'))}}
$directoryPolicy=[pscustomobject]@{Status='OK';Before=[pscustomobject]@{Value=2;Management='System';UpdatesDisabled=$false;BootId='directory-control';VolumeGuid='volume';Qpc=50};After=[pscustomobject]@{Value=2;Management='System';UpdatesDisabled=$false;BootId='directory-control';VolumeGuid='volume';Qpc=250}}
Check (Test-IODirectoryVersion $directoryParent $exactDirectory @() @() $directorySample $null $true) 'Exact index transition still passes without a tolerance or child read.'
Check (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($directoryCurrent) $directorySample $directoryPolicy $true) 'Same identity index Accessed may lag its proven raw LastAccess.'
$equalRaw=Clone $directoryActual;$equalRaw.DirectoryEntries[0].Accessed=$directoryCurrent.RawMetadata.Accessed
Check (Test-IODirectoryVersion $equalRaw $directoryExpected $directoryStorage @($directoryCurrent) $directorySample $directoryPolicy $true) 'Same identity index Accessed may equal its proven raw LastAccess.'
Check (-not (Test-IODirectoryVersion $directoryActual $exactDirectory $directoryStorage @($directoryCurrent) $directorySample $directoryPolicy $true)) 'No directory opt-in means LastAccess stays exact.'
Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($directoryCurrent) $directorySample $directoryPolicy $false)) 'Unstable capture cannot authorize changed index Accessed.'
foreach($field in @('Name','Namespace','Reference','Parent','Eof','Allocated','Attributes','Creation','Modified','Changed')){
    $bad=Clone $directoryActual
    if($field -ceq 'Name'){$bad.DirectoryEntries[0].Name='MARKER.bin'}else{$bad.DirectoryEntries[0].$field++}
    Check (-not (Test-IODirectoryVersion $bad $directoryExpected $directoryStorage @($directoryCurrent) $directorySample $directoryPolicy $true)) ('Read-side index tolerance must reject changed '+$field+'.')
}
foreach($change in @('extra','duplicate','missing','security-id','sddl','regressed','before-window','ahead-of-raw','future')){
    $bad=Clone $directoryActual
    switch($change){
        'extra'{$extra=Clone $entry;$extra.Name='cached.txt';$bad.DirectoryEntries+=$extra}
        'duplicate'{$bad.DirectoryEntries+=Clone $bad.DirectoryEntries[0]}
        'missing'{$bad.DirectoryEntries=@()}
        'security-id'{$bad.SecurityId++}
        'sddl'{$bad.Sddl='other'}
        'regressed'{$bad.DirectoryEntries[0].Accessed=$time-1}
        'before-window'{$bad.DirectoryEntries[0].Accessed=$time+1}
        'ahead-of-raw'{$bad.DirectoryEntries[0].Accessed=$time+30001}
        'future'{$bad.DirectoryEntries[0].Accessed=$time+10000001}
    }
    Check (-not (Test-IODirectoryVersion $bad $directoryExpected $directoryStorage @($directoryCurrent) $directorySample $directoryPolicy $true)) ('Directory transition rejects '+$change+'.')
}
foreach($change in @('absent','wrong-id','wrong-reference','wrong-path','missing-raw','missing-cross-check','cross-check-error','modified','api-before-raw','future-api')){
    $bad=Clone $directoryCurrent
    switch($change){
        'absent'{$bad.Absent=$true}
        'wrong-id'{$bad.Identity.FileId='other'}
        'wrong-reference'{$bad.Identity.Reference++}
        'wrong-path'{$bad.Path=Join-Path $directoryPath 'other.bin'}
        'missing-raw'{$bad.RawMetadata=$null}
        'missing-cross-check'{$bad.PSObject.Properties.Remove('CrossCheckErrors')}
        'cross-check-error'{$bad.CrossCheckErrors=@('raw/API identity mismatch')}
        'modified'{$bad.RawMetadata.Modified++}
        'api-before-raw'{$bad.Identity.Accessed=$time+29999}
        'future-api'{$bad.Identity.Accessed=$time+10000001}
    }
    Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($bad) $directorySample $directoryPolicy $true)) ('Directory Accessed requires child proof: '+$change+'.')
}
Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @() $directorySample $directoryPolicy $true)) 'Missing current child cannot authorize an index transition.'
Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($directoryCurrent,$directoryCurrent) $directorySample $directoryPolicy $true)) 'Duplicate current child cannot authorize an index transition.'
Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected @() @($directoryCurrent) $directorySample $directoryPolicy $true)) 'Missing baseline child expectation cannot authorize an index transition.'
$bad=Clone $directorySample;$bad.End.Utc='malformed'
Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($directoryCurrent) $bad $directoryPolicy $true)) 'Malformed window proof keeps the directory mismatch a FAIL.'
foreach($change in @('missing','changed','disabled','wrong-boot','wrong-volume','late-before','early-after','missing-disabled-bit')){
    $bad=Clone $directoryPolicy
    switch($change){
        'missing'{$bad=$null}
        'changed'{$bad.After.Value=0}
        'disabled'{$bad.Before.Value=3;$bad.After.Value=3;$bad.Before.UpdatesDisabled=$true;$bad.After.UpdatesDisabled=$true}
        'wrong-boot'{$bad.Before.BootId='other'}
        'wrong-volume'{$bad.Before.VolumeGuid='other'}
        'late-before'{$bad.Before.Qpc=101}
        'early-after'{$bad.After.Qpc=199}
        'missing-disabled-bit'{$bad.Before.PSObject.Properties.Remove('UpdatesDisabled')}
    }
    Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($directoryCurrent) $directorySample $bad $true)) ('Directory Accessed requires bound enabled policy: '+$change+'.')
}
$disabledPolicy=Clone $directoryPolicy;$disabledPolicy.Before.Value=3;$disabledPolicy.After.Value=3;$disabledPolicy.Before.UpdatesDisabled=$true;$disabledPolicy.After.UpdatesDisabled=$true
$disabledCurrent=Clone $directoryCurrent;$disabledCurrent.RawMetadata.Accessed=$time
Check (-not (Test-IODirectoryVersion $directoryActual $directoryExpected $directoryStorage @($disabledCurrent) $directorySample $disabledPolicy $true)) 'Disabled updates forbid an index advance even with valid unchanged raw metadata.'
$external=[pscustomobject]@{WriterIdentities=@([pscustomobject]@{Pid=1000;Sid='S-1-5-21-1-2-3-1000';SessionId=1;Elevated=$false;IsAdministrator=$false;BootId=$boot});CadenceProof=[pscustomobject]@{Complete=$true}
    ExternalEvidence=[pscustomobject]@{Provenance='SyntheticTestEvidence';Build=$baseline.Build;PrepareBootId='fixture/prepare';ActiveBootId=$boot;ObserverPid=$baseline.ObserverPid;ObserverSid=$baseline.ObserverSid
        ActorProvenance=[pscustomobject]@{OwnerSid='S-1-5-21-1-2-3-1000';Pid=1000;SessionId=1};ObserverProcess=[pscustomobject]@{OwnerSid=$baseline.ObserverSid;Pid=$baseline.ObserverPid};Restoration=[pscustomobject]@{Known=$true}}}
Check ((Test-InvariantExternalCoverage $baseline $external -SyntheticRun).Verdict -eq 'PASS') 'Complete synthetic external facts require an explicitly synthetic run.'
Check ((Test-InvariantExternalCoverage $baseline $external).Verdict -eq 'INCONCLUSIVE') 'Synthetic external facts cannot attest a real run.'
$bad=Clone $external;$bad.ExternalEvidence.Restoration.Known=$false
Check ((Test-InvariantExternalCoverage $baseline $bad -SyntheticRun).Verdict -eq 'INCONCLUSIVE') 'Synthetic mode cannot waive independent restoration.'
$bad=Clone $external;$bad.ExternalEvidence.Provenance=$null
Check ((Test-InvariantExternalCoverage $baseline $bad -SyntheticRun).Verdict -eq 'INCONCLUSIVE') 'Synthetic mode requires declared synthetic external provenance.'
# Mock only transport for pure service expectation evaluation.
function Save-State($Value,[string]$Path){}
function Get-WinEvent {param($LogName,$FilterXPath) if($FilterXPath -match 'Provider'){return};$a=[pscustomobject]@{};$a | Add-Member ScriptMethod ToXml {'anchor'};return $a}
function Read-AgentLogWindow($Before,$After,[string]$Name) {
    if($null -ne $script:absenceLogs){return $script:absenceLogs.$Name}
    return [pscustomobject]@{Status='INCONCLUSIVE';Reason='Synthetic log evidence missing.';Xmls=@()}
}
$script:evidenceDirectory=$PSScriptRoot;$script:protectedDirectory='C:\fixture'
$script:row.JournalExpectations=@('NoNewTransfer','NoApproved','NoReleased');$script:row.NotificationExpectations=@('NoApproval','NoRelease','NoHandBack')
$before=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;StartQpc=0;EndQpc=10;Journal=@();Application=@{Status='OK';OldestRecordId=1;NewestRecordId=5;NewestXml='anchor'}}
$after=Clone $before;$after.StartQpc=3000;$after.EndQpc=3100
$service=Get-ServiceTimeline $before $after $fence
Check (@($service.Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -ne 'PASS'}).Count -eq 0) 'Authenticated empty retained journal supports seed negative journal expectations.'
Check (@($service.Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 3) 'Empty Application log must not fabricate notification proof.'
function Make-JournalRecord($State=5) {
    $entry=[ordered]@{Transfer=@{TransferId='be720217-aa27-4c72-8ed8-032d251ba11d';StagePath='C:\stage\new.bin';DestinationPath='C:\fixture\new.bin';Destination=2;ProcessId=123;ProcessName='fixture.exe';SessionId=1};
        State=$State;Sha256Hex=('A'*64);UpdatedAtUtc='2026-10-04T22:00:00Z';SealedOnce=$true;DestinationGeneration=1;NamespaceTombstones=$null;PendingRename=$null;
        LastRenameTransactionId=0;LastRenameDestination=$null;LastRenameCommitted=$false}
    return [pscustomobject]@{Path='C:\journal\be720217aa274c728ed8032d251ba11d.json';Bytes=[Text.Encoding]::UTF8.GetBytes(($entry | ConvertTo-Json -Depth 32 -Compress))}
}
$after.Journal=@(Make-JournalRecord)
$service=Get-ServiceTimeline $before $after $fence
Check (@($service.Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 3) 'New released manifest contradicts all three journal expectations.'
$after.Status='INCONCLUSIVE'
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 3) 'Partial snapshots must preserve authenticated positive contradictions.'
$after.Journal=@()
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 3) 'Unauthenticated snapshot cannot establish negative journal evidence.'
# Pre-existing manifests are opaque even if legacy, released, malformed or
# in the fixture namespace. Every entry is reported and compared by bytes.
$legacy=[pscustomobject]@{Path='C:\journal\1807552b5e024c438a012a6a580b4de5.json';Bytes=[Text.Encoding]::UTF8.GetBytes('{"Transfer":{"TransferId":"1807552b-5e02-4c43-8a01-2a6a580b4de5","StagePath":"C:\\ProgramData\\SafeUpload\\staging\\1807552b5e024c438a012a6a580b4de5.txt","DestinationPath":"S:\\SafeUpload\\Escopo Monitorado\\safeupload-crossvolume-b341907236064b2bb4ffeea62520fc4a.txt.renamed.txt","Destination":0,"ProcessName":"powershell.exe","ProcessId":10472,"SessionId":0},"State":6,"Sha256Hex":"0FFEA1AF40A41CBA8889C64E1C0C4C85C8FE07C7F6EB273AD1DFABDD8343C99A","UpdatedAtUtc":"2026-10-01T03:29:01.338476+00:00","SealedOnce":true}')}
$prior=Clone $before;$prior.Journal=@($legacy)
$unchanged=Clone $prior;$unchanged.StartQpc=$after.StartQpc;$unchanged.EndQpc=$after.EndQpc
$service=Get-ServiceTimeline $prior $unchanged $fence
Check (@($service.Assertions | Where-Object {$_.Name -in @('JournalDelta','JournalExpectation') -and $_.Verdict -ne 'PASS'}).Count -eq 0) 'Unchanged legacy entry must PASS without current-schema parsing.'
Check ($service.JournalDelta.Entries[0].Classification -ceq 'pre-existing, unchanged') 'Legacy entry must be explicitly recorded as pre-existing, unchanged.'
$opaque=Clone $prior;$opaque.Journal[0].Bytes=[Text.Encoding]::UTF8.GetBytes('unparseable old payload');$opaqueAfter=Clone $opaque;$opaqueAfter.StartQpc=$after.StartQpc;$opaqueAfter.EndQpc=$after.EndQpc
Check ((Test-ServiceJournalDelta $opaque $opaqueAfter $true).Complete) 'Pre-existing bytes must never be interpreted as current JSON.'
$releasedBefore=Clone $prior;$releasedBefore.Journal=@(Make-JournalRecord)
$releasedAfter=Clone $releasedBefore;$releasedAfter.StartQpc=$after.StartQpc;$releasedAfter.EndQpc=$after.EndQpc
Check (@((Get-ServiceTimeline $releasedBefore $releasedAfter $fence).Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -ne 'PASS'}).Count -eq 0) 'Unchanged pre-existing released fixture entry must not count as a case-window transition.'
$modified=Clone $unchanged;$modified.Journal[0].Bytes+=[byte]32
$service=Get-ServiceTimeline $prior $modified $fence
Check (@($service.Assertions | Where-Object {$_.Name -in @('JournalDelta','JournalExpectation') -and $_.Verdict -eq 'FAIL'}).Count -eq 4) 'Any modified pre-existing bytes must FAIL even outside the fixture and without parsing.'
$removed=Clone $unchanged;$removed.Journal=@()
Check ((Test-ServiceJournalDelta $prior $removed $true).Findings.Count -eq 1) 'Removal of a pre-existing entry from a complete after inventory must FAIL.'
$malformed=Clone $after;$malformed.Status='OK';$malformed.Journal=@([pscustomobject]@{Path=$legacy.Path;Bytes=[Text.Encoding]::UTF8.GetBytes('invalid JSON')})
$service=Get-ServiceTimeline $before $malformed $fence
Check (@($service.Assertions | Where-Object {$_.Name -in @('JournalDelta','JournalExpectation') -and $_.Verdict -eq 'FAIL'}).Count -eq 4) 'New invalid JSON must FAIL independent of fixture path.'
$unc=Make-JournalRecord;$uncEntry=[Text.Encoding]::UTF8.GetString($unc.Bytes) | ConvertFrom-Json
$uncEntry.Transfer.DestinationPath='\\server\share\new.bin';$unc.Bytes=[Text.Encoding]::UTF8.GetBytes(($uncEntry | ConvertTo-Json -Depth 32 -Compress))
Check ((ConvertFrom-ServiceJournalRecord $unc).DestinationPaths[0] -ceq '\\server\share\new.bin') 'Current journal path validation must admit canonical UNC destinations.'
$invalid=Make-JournalRecord;$entry=[Text.Encoding]::UTF8.GetString($invalid.Bytes) | ConvertFrom-Json
$entry.PSObject.Properties.Remove('DestinationGeneration');$invalid.Bytes=[Text.Encoding]::UTF8.GetBytes(($entry | ConvertTo-Json -Depth 32 -Compress))
$malformed.Journal=@($invalid)
$service=Get-ServiceTimeline $before $malformed $fence
Check (($service.JournalDelta.Findings -join ' ') -like '*Missing current journal field: DestinationGeneration*') 'New legacy schema must identify the exact missing field.'
$partialBefore=Clone $before;$partialBefore.Status='INCONCLUSIVE'
$service=Get-ServiceTimeline $partialBefore $malformed $fence
Check ($service.JournalDelta.Findings.Count -eq 0 -and @($service.Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 3) 'Partial before inventory cannot classify uncollected legacy bytes as new.'
$missingBytes=Clone $unchanged;$missingBytes.Journal[0].PSObject.Properties.Remove('Bytes')
Check (-not (Test-ServiceJournalDelta $prior $missingBytes $true).Complete) 'Missing retained bytes must remain INCONCLUSIVE.'
$entry=([Text.Encoding]::UTF8.GetString((Make-JournalRecord).Bytes) | ConvertFrom-Json);$entry.State=7;$entry.SealedOnce=$false
$invalid.Bytes=[Text.Encoding]::UTF8.GetBytes(($entry | ConvertTo-Json -Depth 32 -Compress));$malformed.Journal=@($invalid)
Check ((Test-ServiceJournalDelta $before $malformed $true).Findings[0] -like '*cannot be reached through current agent transitions*') 'A new unsealed Retained state is legacy recovery behavior, not a current reachable state.'
$states=@(@{State=0;Sealed=$false},@{State=8;Sealed=$false})+@(1..7 | ForEach-Object {@{State=$_;Sealed=$true}})
foreach($state in $states){Check (Test-ServiceJournalStateReachable $state.State $state.Sealed) ('Current transition graph must admit state '+$state.State)}
# A valid new nonterminal state cannot prove absence of intermediate approval.
$nonterminal=Make-JournalRecord 1;$malformed.Journal=@($nonterminal)
$service=Get-ServiceTimeline $before $malformed $fence
Check (@($service.Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Expectation -in @('NoApproved','NoReleased') -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 2) 'Latest-state snapshots must not fabricate strict intermediate transition history.'

# Collection failures must identify the snapshot/object, not suggest a missing
# fence when the operation window is actually complete (notify1 regression).
$bad=Clone $before;$bad.Status='INCONCLUSIVE';$bad | Add-Member NoteProperty Errors @(@{Message='Service evidence object rejected: C:\ProgramData\SafeUpload; Non-exact journal ACE.'})
$good=Clone $after;$good.Status='OK'
$service=Get-ServiceTimeline $bad $good $fence
Check ($service.WindowBound -and $service.JournalFailures.Count -eq 1 -and $service.JournalFailures[0] -like '*Journal before snapshot*C:\ProgramData\SafeUpload*') 'Valid fence and rejected before ACL must be distinguished.'
Check ($service.Assertions[-1].Reason -like '*Journal before snapshot*') 'Aggregate timeline must retain the specific collection failure.'
$service=Get-ServiceTimeline $good $bad $fence
Check (($service.JournalFailures -join ' ') -like '*Journal after snapshot*') 'Rejected after snapshot must be named.'
$missing=Clone $fence;$missing.CompletedQpc=$null
$service=Get-ServiceTimeline $before $good $missing
Check (-not $service.WindowBound -and $service.JournalFailures[0] -like '*QPC operation fence*') 'Absent QPC receipts cannot be coerced to zero and pass.'
$gone=Clone $before;$gone.Journal=@(@{Path='prior-manifest';Entry=@{Transfer=@{DestinationPath='C:\elsewhere\old.bin'};LastRenameTransactionId=0;LastRenameDestination=$null;LastRenameCommitted=$false}})
$service=Get-ServiceTimeline $gone $good $fence
Check (($service.JournalFailures -join ' ') -like '*Prior journal manifest disappeared or duplicated: prior-manifest*') 'Missing prior manifest must be identified.'
$absent=[pscustomobject]@{Status='INCONCLUSIVE';Reason='Authenticated notification directory absent: C:\ProgramData\SafeUpload\notifications.';Entries=@()}
$diagnostic=Test-NotificationWindow $absent $absent $fence $true
Check (-not $diagnostic.Complete -and $diagnostic.Reason -like '*Notification before snapshot*directory absent*Notification after snapshot*directory absent*') 'Notification absence must retain both snapshot reasons without fabricating proof.'


# Synthetic durable notification records, including raw line hashes and head.
function Make-Notifications($Kinds=@('Heartbeat','Heartbeat','Heartbeat'),$Times=@(0,1000,2500)) {
    $lines=@();$hash='0'*64;$sha=[Security.Cryptography.SHA256]::Create()
    try {
        for($i=0;$i -lt $Kinds.Count;$i++){
            $entry=[ordered]@{Version=1;Sequence=$i+1;BootId=$boot;InstanceId='5d9c52d7-1f7e-4daf-9b09-607312ed5623';Utc='2026-10-04T22:00:00Z';Qpc=$Times[$i];QpcFrequency=$frequency;
                Kind=$Kinds[$i];TransferId=$(if($Kinds[$i] -eq 'Transfer'){'be720217-aa27-4c72-8ed8-032d251ba11d'}else{$null});EventId=$null;Phase=$(if($Kinds[$i] -eq 'Transfer'){'Released'}else{$null});TargetSessionId=$null;PreviousSha256=$hash;DroppedThroughSequence=0}
            $line=$entry | ConvertTo-Json -Compress;$lines+=$line
            $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($line)))).Replace('-','')
        }
    }finally{$sha.Dispose()}
    return [pscustomobject]@{Segments=@(@{Bytes=[Text.Encoding]::UTF8.GetBytes(($lines -join "`n")+"`n");Artifact='synthetic'});
        HeadBytes=[Text.Encoding]::UTF8.GetBytes((@{Version=1;Sequence=$Kinds.Count;Sha256=$hash} | ConvertTo-Json -Compress))}
}
$fixture=Make-Notifications
$parsed=ConvertFrom-NotificationRecord $fixture.Segments $fixture.HeadBytes
Check ($parsed.Entries.Count -eq 3) 'Raw notification chain should parse.'
$nb=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;Entries=@($parsed.Entries[0]);Head=@{Sequence=1;Sha256=$parsed.Entries[0].Hash}}
$na=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;Entries=$parsed.Entries;Head=$parsed.Head}
Check ((Test-NotificationWindow $nb $na $fence $true).Complete) 'Anchored notification chain should cover whole window.'
$before | Add-Member NoteProperty Notifications $nb -Force
$after.Status='OK';$after.Journal=@();$after | Add-Member NoteProperty Notifications $na -Force
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'PASS'}).Count -eq 3) 'Full durable absence coverage supports seed negative expectations.'
$script:row.NotificationExpectations=@('ExpectedNone')
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'PASS'}).Count -eq 1) 'ExpectedNone passes only with covered empty emission window.'
$positive=Make-Notifications @('Heartbeat','Transfer','Heartbeat')
$parsedPositive=ConvertFrom-NotificationRecord $positive.Segments $positive.HeadBytes
$changed=Clone $na;$changed.Entries=$parsedPositive.Entries;$changed.Head=$parsedPositive.Head;$after.Notifications=$changed
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 1) 'Real emission contradicts ExpectedNone.'
$script:row.NotificationExpectations=@('NoApproval','NoRelease','NoHandBack')
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 2) 'Released transfer contradicts approval and release expectations.'
foreach($fault in @('boot','restart','sequence','hash','gap','truncated','rotated','stop','start','head')) {
    $changed=Clone $na
    switch($fault){
        'boot' {$changed.Entries[1].Entry.BootId='other'}
        'restart' {$changed.Entries[1].Entry.InstanceId='7e216660-0447-4a7a-823d-0441a0555d39'}
        'sequence' {$changed.Entries[1].Entry.Sequence=10}
        'hash' {$changed.Entries[1].Entry.PreviousSha256='F'*64}
        'gap' {$changed.Entries[2].Entry.Qpc=9000}
        'truncated' {$changed.Entries=@($changed.Entries[0..1])}
        'rotated' {$changed.Entries=@($changed.Entries[1..2])}
        'stop' {$changed.Entries[1].Entry.Kind='Stop'}
        'start' {$changed.Entries[1].Entry.Kind='Start'}
        'head' {$changed.Head.Sha256='F'*64}
    }
    Check (-not (Test-NotificationWindow $nb $changed $fence $true).Complete) ('Notification '+$fault+' must defeat absence proof.')
}
Check (-not (Test-NotificationWindow $nb $na $fence $false).Complete) 'Unknown operation fence cannot prove absence.'
foreach($fault in @('edit','sequence','partial','tail','head','prefix')) {
    $fixture=Make-Notifications;$text=[Text.Encoding]::UTF8.GetString($fixture.Segments[0].Bytes)
    switch($fault){
        'edit' {$text=$text.Replace('fixture/boot','edited/boot')}
        'sequence' {$text=$text.Replace('"Sequence":2','"Sequence":9')}
        'partial' {$text=$text.TrimEnd([char]10)}
        'tail' {$text=($text.Split([char]10)[0..1] -join "`n")+"`n"}
        'prefix' {$text=($text.Split([char]10)[1..2] -join "`n")+"`n"}
        'head' {$fixture.HeadBytes=[Text.Encoding]::UTF8.GetBytes('{"Version":1,"Sequence":3,"Sha256":"bad"}')}
    }
    $fixture.Segments[0].Bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $refused=$false;try{$null=ConvertFrom-NotificationRecord $fixture.Segments $fixture.HeadBytes}catch{$refused=$true}
    Check $refused ('Raw notification '+$fault+' must be refused.')
}
# A valid rotation keeps the starting head and chain; announced older loss is
# permitted only outside the operation window.
$fixture=Make-Notifications @('Heartbeat','Heartbeat','Heartbeat','Heartbeat','Rotation','Heartbeat') @(-2000,-1000,0,1000,2000,2500)
$sourceLines=[Text.Encoding]::UTF8.GetString($fixture.Segments[0].Bytes).Split([char]10)
$lines=@();$sha=[Security.Cryptography.SHA256]::Create();$hash=$null
try {
    for($i=0;$i -lt 6;$i++){
        $entry=$sourceLines[$i] | ConvertFrom-Json
        if($i -ge 4){$entry.DroppedThroughSequence=2}
        if($null -ne $hash){$entry.PreviousSha256=$hash}
        $line=$entry | ConvertTo-Json -Compress
        $hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($line)))).Replace('-','');$lines+=$line
    }
}finally{$sha.Dispose()}
$segments=@(@{Bytes=[Text.Encoding]::UTF8.GetBytes(($lines[2..4] -join "`n")+"`n");Artifact='previous'},@{Bytes=[Text.Encoding]::UTF8.GetBytes($lines[5]+"`n");Artifact='active'})
$headBytes=[Text.Encoding]::UTF8.GetBytes((@{Version=1;Sequence=6;Sha256=$hash} | ConvertTo-Json -Compress))
$rotated=ConvertFrom-NotificationRecord $segments $headBytes
$rb=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;Entries=@($rotated.Entries[0]);Head=@{Sequence=3;Sha256=$rotated.Entries[0].Hash}}
$ra=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;Entries=$rotated.Entries;Head=$rotated.Head}
Check ((Test-NotificationWindow $rb $ra $fence $true).Complete) 'Announced rotation outside the retained window preserves absence proof.'
$segments[0].Bytes=[Text.Encoding]::UTF8.GetBytes(($lines[2..4] -join "`n").Replace('"Kind":"Rotation"','"Kind":"Heartbeat"')+"`n")
$refused=$false;try{$null=ConvertFrom-NotificationRecord $segments $headBytes}catch{$refused=$true}
Check $refused 'Silent rotation prefix loss must be refused.'
# Synthetic whole-window agent absence. Edge process samples alone, stopped SCM
# state alone, empty provider queries and absent directories never suffice.
function Make-AgentXml([string]$Channel,[long]$RecordId,[int]$Id=1,[string]$Provider='fixture',[string]$Data='') {
    return '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="'+$Provider+'"/><EventID>'+$Id+'</EventID><EventRecordID>'+$RecordId+'</EventRecordID><Channel>'+$Channel+'</Channel></System><EventData>'+$Data+'</EventData></Event>'
}
function Make-AgentLog([string]$Name) {
    $xmls=@(101..103 | ForEach-Object {Make-AgentXml $Name $_})
    return [pscustomobject]@{Status='OK';Name=$Name;Xmls=$xmls;Reason='Synthetic complete log.';
        Before=[pscustomobject]@{Status='OK';StartQpc=1;EndQpc=2;NewestRecordId=101;OldestRecordId=1;NewestXml=$xmls[0]};
        After=[pscustomobject]@{Status='OK';StartQpc=3006;EndQpc=3007;NewestRecordId=103;OldestRecordId=1;NewestXml=$xmls[2]}}
}
$script:absenceLogs=@{System=(Make-AgentLog 'System');Security=(Make-AgentLog 'Security')}
$downBefore=Clone $before;$downAfter=Clone $after;$downAfter.Notifications=$null
$execution=[pscustomobject]@{Status='OK';BootId=$boot;EndBootId=$boot;QpcFrequency=$frequency;StartQpc=1;EndQpc=8;InventoryStartQpc=3;InventoryEndQpc=5;
    Errors=@();CollectedByPid=100;ServiceSid='S-1-5-80-1-2-3-4-5';ImagePaths=@('C:\installed\SafeUpload.Agent.Service.exe','C:\seed\SafeUpload.Agent.Service.exe');
    Service=[pscustomobject]@{Name='SafeUploadAgent';Exists=$true;QueryStatus='OK';QuerySource='OpenSCManager/OpenService';DisplayName='SafeUpload Agent';State='Stopped';ProcessId=0;PathName='"C:\installed\SafeUpload.Agent.Service.exe"';StartMode='Disabled'};
    Audit=[pscustomobject]@{CreationFlags=1;PerUserPolicyCount=0};Processes=@([pscustomobject]@{Pid=100;Image='C:\Windows\System32\powershell.exe';TokenSids=@('S-1-5-18','S-1-5-32-544')});
    SystemBegin=$script:absenceLogs.System.Before;SecurityBegin=$script:absenceLogs.Security.Before}
$downBefore | Add-Member NoteProperty AgentExecution $execution -Force
$endExecution=Clone $execution;$endExecution.StartQpc=3001;$endExecution.EndQpc=3008;$endExecution.InventoryStartQpc=3003;$endExecution.InventoryEndQpc=3005
$endExecution | Add-Member NoteProperty SystemEnd $script:absenceLogs.System.After
$endExecution | Add-Member NoteProperty SecurityEnd $script:absenceLogs.Security.After
$downAfter | Add-Member NoteProperty AgentExecution $endExecution -Force
$location=[pscustomobject]@{Status='INCONCLUSIVE';LocationStatus='OK';BootId=$boot;QpcFrequency=$frequency;Directory='C:\ProgramData\SafeUpload\notifications';DirectoryExists=$false;
    ReadQpc=9;Reason='Authenticated notification directory absent.';LocationFiles=@();Entries=@()}
$downBefore.Notifications=$location;$downAfter.Notifications=Clone $location;$downAfter.Notifications.ReadQpc=3009
$script:row.NotificationExpectations=@('ExpectedNone','NoApproval','NoRelease','NoHandBack','NoNotification','None')
$none=Get-ServiceTimeline $downBefore $downAfter $fence
Check ($none.AgentAbsenceProof.Complete -and $none.NotificationLocationProof.Complete) 'Whole-window stopped/no-process evidence and absent locations support absence.'
Check (@($none.Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'PASS' -and $_.Reason -ceq 'agent did not run in window'}).Count -eq 6) 'Every supported negative reports the exact agent-did-not-run reason.'
$absentBefore=Clone $downBefore;$absentAfter=Clone $downAfter
foreach($snapshot in @($absentBefore,$absentAfter)){
    $snapshot.AgentExecution.Service=[pscustomobject]@{Name='SafeUploadAgent';Exists=$false;QueryStatus='OK';QuerySource='OpenSCManager/OpenService';AbsenceError=1060}
    $snapshot.AgentExecution.ImagePaths=@('C:\seed\SafeUpload.Agent.Service.exe')
}
$absent=Get-ServiceTimeline $absentBefore $absentAfter $fence
Check ($absent.AgentAbsenceProof.ScmProof.Complete -and $absent.AgentAbsenceProof.ScmProof.Verdict -ceq 'PASS' -and
    $absent.AgentAbsenceProof.ScmProof.Reason -like '*absent at both edges, never installed*') 'Authenticated absent service at both edges with System continuity satisfies the distinct SCM premise.'
Check ($absent.NotificationProof.Complete) 'Absent SCM service still requires image/SID/process, auditing, log and location coverage.'
foreach($fault in @('query','absent-error','installed-after','image','audit','collector','sid')){
    $b=Clone $absentBefore;$a=Clone $absentAfter
    switch($fault){
        'query' {$b.AgentExecution.Service.QueryStatus='INCONCLUSIVE'}
        'absent-error' {$a.AgentExecution.Service.AbsenceError=5}
        'installed-after' {$a.AgentExecution.Service=$downAfter.AgentExecution.Service}
        'image' {$b.AgentExecution.ImagePaths=@()}
        'audit' {$a.AgentExecution.Audit.CreationFlags=0}
        'collector' {$b.AgentExecution.Processes=@()}
        'sid' {$b.AgentExecution.Processes[0].TokenSids+= $b.AgentExecution.ServiceSid}
    }
    $result=Get-ServiceTimeline $b $a $fence
    Check (-not $result.NotificationProof.Complete) ('Absent service must not waive '+$fault+' evidence.')
    if($fault -eq 'audit'){Check ($result.AgentAbsenceProof.Verdict -ceq 'INCONCLUSIVE') 'Disabled auditing is INCONCLUSIVE, even with authenticated SCM absence.'}
}
$savedLogs=$script:absenceLogs
foreach($fault in @('started','installed','system-clear','security-clear')){
    $script:absenceLogs=Clone $savedLogs
    switch($fault){
        'started' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 7036 'Service Control Manager' '<Data Name="param1">SafeUpload Agent</Data><Data Name="param2">running</Data>'}
        'installed' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 7045 'Service Control Manager' '<Data Name="ServiceName">SafeUploadAgent</Data>'}
        'system-clear' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 104 'Microsoft-Windows-Eventlog'}
        'security-clear' {$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 1102 'Microsoft-Windows-Eventlog'}
    }
    $b=if($fault -eq 'started'){$downBefore}else{$absentBefore}
    $a=if($fault -eq 'started'){$downAfter}else{$absentAfter}
    $result=Get-ServiceTimeline $b $a $fence
    Check (-not $result.NotificationProof.Complete) ($fault+' in window cannot satisfy agent absence.')
    if($fault -in @('started','installed')){
        Check ($result.AgentAbsenceProof.ScmProof.Verdict -ceq 'FAIL' -and
            @($result.Assertions | Where-Object {$_.Name -ceq 'AgentAbsenceScm' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1) ($fault+' in window fails the SCM premise even with stopped/absent edges.')
    }else{Check ($result.AgentAbsenceProof.Verdict -ceq 'INCONCLUSIVE') ($fault+' in window leaves absence INCONCLUSIVE.')}
}
$script:absenceLogs=$savedLogs
# Stale/malformed record bytes can be unchanged without durable current-boot coverage.
$staleBefore=Clone $downBefore;$staleAfter=Clone $downAfter
foreach($snapshot in @($staleBefore,$staleAfter)){
    $snapshot.Notifications.DirectoryExists=$true;$snapshot.Notifications.LocationFiles=@(@{Name='emissions.jsonl';Bytes=[byte[]](1,2,3)},@{Name='head.json';Bytes=[byte[]](4,5)})
}
Check ((Get-ServiceTimeline $staleBefore $staleAfter $fence).NotificationProof.Complete) 'Byte-identical authenticated stale location plus agent absence supports absence.'
$staleAfter.Notifications.LocationFiles[0].Bytes=[byte[]](1,2,4)
Check (-not (Get-ServiceTimeline $staleBefore $staleAfter $fence).NotificationProof.Complete) 'Changed record bytes defeat absence even if SCM stayed stopped.'
foreach($fault in @('missing','partial','running','image','sid','restricted','unreadable','audit','override','boot','endboot','frequency','before-edge','after-edge','location','location-boot','location-qpc','appeared','location-path','null-receipt','identity','empty','writer-record','inventory-receipt','inventory-order')){
    $b=Clone $downBefore;$a=Clone $downAfter
    switch($fault){
        'missing' {$b.AgentExecution=$null}
        'partial' {$b.AgentExecution.Status='INCONCLUSIVE';$b.AgentExecution.Errors=@('PID 44 access denied')}
        'running' {$a.AgentExecution.Service.State='Running';$a.AgentExecution.Service.ProcessId=55}
        'image' {$b.AgentExecution.Processes[0].Image=$b.AgentExecution.ImagePaths[0]}
        'sid' {$a.AgentExecution.Processes[0].TokenSids+= $a.AgentExecution.ServiceSid}
        'restricted' {$b.AgentExecution.Processes[0].TokenSids=@($b.AgentExecution.ServiceSid)}
        'unreadable' {$b.AgentExecution.Processes[0].TokenSids=@()}
        'audit' {$b.AgentExecution.Audit.CreationFlags=0}
        'override' {$a.AgentExecution.Audit.PerUserPolicyCount=1}
        'boot' {$b.AgentExecution.BootId='other'}
        'endboot' {$a.AgentExecution.EndBootId='other'}
        'frequency' {$a.AgentExecution.QpcFrequency=7}
        'before-edge' {$b.AgentExecution.EndQpc=$fence.ReleasedQpc+1}
        'after-edge' {$a.AgentExecution.StartQpc=$fence.CompletedQpc-1}
        'location' {$a.Notifications.LocationStatus='INCONCLUSIVE';$a.Notifications.Reason='Parent ACL rejected'}
        'location-boot' {$a.Notifications.BootId='other'}
        'location-qpc' {$b.Notifications.ReadQpc=$fence.ReleasedQpc+1}
        'appeared' {$a.Notifications.DirectoryExists=$true}
        'location-path' {$a.Notifications.Directory='C:\other'}
        'null-receipt' {$a.AgentExecution.EndQpc=$null}
        'identity' {$a.AgentExecution.ImagePaths[0]='C:\changed.exe'}
        'empty' {$b.AgentExecution.Processes=@()}
        'inventory-receipt' {$b.AgentExecution.InventoryEndQpc=$null}
        'inventory-order' {$a.AgentExecution.InventoryStartQpc=$a.AgentExecution.InventoryEndQpc+1}
        'writer-record' {$a.Notifications.Entries=@(@{Entry=@{BootId=$boot;QpcFrequency=$frequency;Qpc=1000;Sequence=7}})}
    }
    $result=Get-ServiceTimeline $b $a $fence
    Check (-not $result.NotificationProof.Complete -and @($result.Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 6) ('Agent absence '+$fault+' must stay INCONCLUSIVE.')
    if($fault -eq 'partial'){Check ($result.NotificationProof.Reason -like '*PID 44 access denied*') 'Exact inventory failure must reach the notification assertion.'}
}
foreach($fault in @('gap','duplicate','tail','clear104','clear1102','drop1101','policy4719','token4696','scm7036','scm7045','scm7040','agent-create','other-create','anchor','wrap','log-missing','edge','channel','scm-identity','log-stop','audit-stop','full','error')){
    $savedLogs=$script:absenceLogs;$script:absenceLogs=Clone $savedLogs
    $name='System';$id=1;$provider='fixture';$data=''
    switch($fault){
        'gap' {$script:absenceLogs.System.Xmls=@($script:absenceLogs.System.Xmls[0],$script:absenceLogs.System.Xmls[2])}
        'duplicate' {$script:absenceLogs.System.Xmls[1]=$script:absenceLogs.System.Xmls[0]}
        'tail' {$script:absenceLogs.Security.Xmls=@($script:absenceLogs.Security.Xmls[0..1])}
        'clear104' {$id=104;$provider='Microsoft-Windows-Eventlog'}
        'clear1102' {$name='Security';$id=1102;$provider='Microsoft-Windows-Eventlog'}
        'drop1101' {$name='Security';$id=1101;$provider='Microsoft-Windows-Eventlog'}
        'policy4719' {$name='Security';$id=4719;$provider='Microsoft-Windows-Security-Auditing'}
        'log-stop' {$id=6006;$provider='EventLog'}
        'audit-stop' {$name='Security';$id=1100;$provider='Microsoft-Windows-Eventlog'}
        'full' {$name='Security';$id=1104;$provider='Microsoft-Windows-Eventlog'}
        'error' {$name='Security';$id=1108;$provider='Microsoft-Windows-Eventlog'}
        'token4696' {$name='Security';$id=4696;$provider='Microsoft-Windows-Security-Auditing'}
        'scm7036' {$id=7036;$provider='Service Control Manager';$data='<Data Name="param1">SafeUpload Agent</Data><Data Name="param2">running</Data>'}
        'scm7045' {$id=7045;$provider='Service Control Manager';$data='<Data Name="ServiceName">SafeUploadAgent</Data>'}
        'scm7040' {$id=7040;$provider='Service Control Manager';$data='<Data Name="param1">SafeUpload Agent</Data>'}
        'scm-identity' {$id=7036;$provider='Service Control Manager'}
        'agent-create' {$name='Security';$id=4688;$provider='Microsoft-Windows-Security-Auditing';$data='<Data Name="NewProcessName">C:\installed\SafeUpload.Agent.Service.exe</Data>'}
        'other-create' {$name='Security';$id=4688;$provider='Microsoft-Windows-Security-Auditing';$data='<Data Name="NewProcessName">C:\Windows\System32\benign.exe</Data>'}
        'anchor' {$script:absenceLogs.System.Before.NewestXml='changed'}
        'wrap' {$script:absenceLogs.System.After.OldestRecordId=102}
        'log-missing' {$script:absenceLogs.Security.Status='INCONCLUSIVE';$script:absenceLogs.Security.Reason='Security read access denied'}
        'edge' {$script:absenceLogs.System.Before.EndQpc=99}
        'channel' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'Application' 102}
    }
    if($id -ne 1){$script:absenceLogs.$name.Xmls[1]=Make-AgentXml $name 102 $id $provider $data}
    # Use unchanged snapshot anchors, so a forged/new proof cannot rebind them.
    $result=Get-ServiceTimeline $downBefore $downAfter $fence
    Check (-not $result.NotificationProof.Complete) ('Agent absence log '+$fault+' must defeat proof.')
    if($fault -eq 'other-create'){Check ($result.NotificationProof.Reason -like '*4688 lacks token group/restricted service-SID evidence*') 'Benign image names must not exempt unknown transient token SIDs.'}
    if($fault -eq 'agent-create'){Check ($result.NotificationProof.Reason -like '*Agent image/service SID process creation*') 'Positive creation evidence must identify the agent.'}
    $script:absenceLogs=$savedLogs
}
$badFence=Clone $fence;$badFence.Complete=$false
Check (-not (Get-ServiceTimeline $downBefore $downAfter $badFence).NotificationProof.Complete) 'Agent absence cannot waive a missing case fence.'
$script:row.NotificationExpectations=@('Unsupported')
Check (@((Get-ServiceTimeline $downBefore $downAfter $fence).Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 1) 'Agent absence must not approve unsupported expectations.'
# Even perfect stopped-edge evidence cannot suppress a real covered emission.
$script:row.NotificationExpectations=@('ExpectedNone')
$coveredBefore=Clone $downBefore;$coveredAfter=Clone $downAfter;$coveredBefore.Notifications=$nb;$coveredAfter.Notifications=$changed
# $changed may be a damaged chain from the negative loop; restore positive bytes.
$coveredAfter.Notifications=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;Entries=$parsedPositive.Entries;Head=$parsedPositive.Head}
$covered=Get-ServiceTimeline $coveredBefore $coveredAfter $fence
Check ($null -eq $covered.AgentAbsenceProof -and @($covered.Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 1) 'Covered durable emissions keep their existing contradiction rule unchanged.'

# R03's installed Disabled service can use the seed non-execution/location route
# only in its explicitly tagged offline window. Retain real historical chain bytes.
$savedCaseId=$script:CaseId;$savedExpectations=$script:row.NotificationExpectations;$savedLogs=$script:absenceLogs
$script:CaseId='R03';$script:row.NotificationExpectations=@('NoNotification','NoApproval','NoRelease','NoHandBack')
$r03Before=Clone $downBefore;$r03After=Clone $downAfter
$r03Before | Add-Member NoteProperty Tag 'r03-offline-before' -Force
$r03After | Add-Member NoteProperty Tag 'r03-offline-after' -Force
$currentBoot=$boot;$boot='previous-boot';$historical=Make-Notifications;$boot=$currentBoot
$historicalParsed=ConvertFrom-NotificationRecord $historical.Segments $historical.HeadBytes
$historicalTail=Get-NotificationTailCoverage $historicalParsed.Entries[-1].Entry $boot $frequency $fence.CompletedQpc
Check ($historicalTail.HistoricalTail -and $historicalTail.Status -ceq 'INCONCLUSIVE') 'R03 historical chain alone has no current-boot coverage.'
foreach($snapshot in @($r03Before,$r03After)){
    $n=$snapshot.Notifications;$n.DirectoryExists=$true;$n.Reason=$historicalTail.Reason
    $n.Entries=$historicalParsed.Entries
    $n.LocationFiles=@(@{Name='emissions.jsonl';Bytes=$historical.Segments[0].Bytes},@{Name='head.json';Bytes=$historical.HeadBytes},@{Name='writer.lock';Bytes=[byte[]]@()})
}
$script:absenceLogs=Clone $savedLogs
$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 4688 'Microsoft-Windows-Security-Auditing' '<Data Name="NewProcessName">C:\Windows\System32\benign.exe</Data><Data Name="SubjectUserSid">S-1-5-18</Data>'
$r03=Get-ServiceTimeline $r03Before $r03After $fence -R03Offline
Check ($r03.AgentAbsenceProof.Complete -and $r03.NotificationLocationProof.Complete -and $r03.NotificationProof.Source -ceq 'AgentDidNotRunAndUnchangedLocation') 'R03 historical tail plus complete disabled-agent non-execution and unchanged location supports offline absence.'
Check (@($r03.Assertions | Where-Object {$_.Name -ceq 'NotificationExpectation' -and $_.Verdict -ceq 'PASS' -and $_.Reason -ceq 'agent did not run in window'}).Count -eq 4 -and $r03.Assertions[-1].Verdict -ceq 'PASS') 'R03 offline negatives and ActualServiceTimelines PASS through the existing fallback.'
foreach($fault in @('before-running','after-running','image','sid','audit','inventory','enabled-before','enabled-after','bytes','inventory-change','location-acl','location-appeared','location-qpc','current-record','fence')){
    $b=Clone $r03Before;$a=Clone $r03After;$f=Clone $fence
    switch($fault){
        'before-running' {$b.AgentExecution.Service.State='Running';$b.AgentExecution.Service.ProcessId=55}
        'after-running' {$a.AgentExecution.Service.State='Running';$a.AgentExecution.Service.ProcessId=55}
        'image' {$b.AgentExecution.Processes[0].Image=$b.AgentExecution.ImagePaths[0]}
        'sid' {$a.AgentExecution.Processes[0].TokenSids+=$a.AgentExecution.ServiceSid}
        'audit' {$a.AgentExecution.Audit.CreationFlags=0}
        'inventory' {$b.AgentExecution.Status='INCONCLUSIVE';$b.AgentExecution.Errors=@('PID unreadable')}
        'enabled-before' {$b.AgentExecution.Service.StartMode='Manual'}
        'enabled-after' {$a.AgentExecution.Service.StartMode='Manual'}
        'bytes' {$a.Notifications.LocationFiles[0].Bytes[0]=0}
        'inventory-change' {$a.Notifications.LocationFiles=@($a.Notifications.LocationFiles[0..1])}
        'location-acl' {$a.Notifications.LocationStatus='INCONCLUSIVE'}
        'location-appeared' {$b.Notifications.DirectoryExists=$false}
        'location-qpc' {$a.Notifications.ReadQpc=$f.CompletedQpc-1}
        'current-record' {$a.Notifications.Entries[0].Entry.BootId=$boot;$a.Notifications.Entries[0].Entry.Qpc=1000}
        'fence' {$f.Complete=$false}
    }
    $result=Get-ServiceTimeline $b $a $f -R03Offline
    Check (-not $result.NotificationProof.Complete -and @($result.Assertions | Where-Object {$_.Name -ceq 'NotificationExpectation' -and $_.Verdict -ceq 'PASS'}).Count -eq 0 -and $result.Assertions[-1].Verdict -cne 'PASS') ('R03 offline '+$fault+' cannot PASS.')
}
foreach($fault in @('scm-start','scm-install','scm-mode','agent-create','sid-create','unknown-create','system-clear','security-clear','policy-change','log-gap')){
    $script:absenceLogs=Clone $savedLogs
    switch($fault){
        'scm-start' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 7036 'Service Control Manager' '<Data Name="param1">SafeUpload Agent</Data><Data Name="param2">running</Data>'}
        'scm-install' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 7045 'Service Control Manager' '<Data Name="ServiceName">SafeUploadAgent</Data>'}
        'scm-mode' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 7040 'Service Control Manager' '<Data Name="param1">SafeUpload Agent</Data>'}
        'agent-create' {$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 4688 'Microsoft-Windows-Security-Auditing' '<Data Name="NewProcessName">C:\installed\SafeUpload.Agent.Service.exe</Data><Data Name="SubjectUserSid">S-1-5-18</Data>'}
        'sid-create' {$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 4688 'Microsoft-Windows-Security-Auditing' '<Data Name="NewProcessName">C:\Windows\System32\benign.exe</Data><Data Name="SubjectUserSid">S-1-5-80-1-2-3-4-5</Data>'}
        'unknown-create' {$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 4688 'Microsoft-Windows-Security-Auditing'}
        'system-clear' {$script:absenceLogs.System.Xmls[1]=Make-AgentXml 'System' 102 104 'Microsoft-Windows-Eventlog'}
        'security-clear' {$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 1102 'Microsoft-Windows-Eventlog'}
        'policy-change' {$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 4719 'Microsoft-Windows-Security-Auditing'}
        'log-gap' {$script:absenceLogs.System.Xmls=@($script:absenceLogs.System.Xmls[0],$script:absenceLogs.System.Xmls[2])}
    }
    $result=Get-ServiceTimeline $r03Before $r03After $fence -R03Offline
    Check (-not $result.NotificationProof.Complete -and $result.Assertions[-1].Verdict -cne 'PASS') ('R03 offline '+$fault+' defeats absence even with unchanged historical bytes.')
}
$script:absenceLogs=Clone $savedLogs
$script:absenceLogs.Security.Xmls[1]=Make-AgentXml 'Security' 102 4688 'Microsoft-Windows-Security-Auditing' '<Data Name="NewProcessName">C:\Windows\System32\benign.exe</Data><Data Name="SubjectUserSid">S-1-5-18</Data>'
Check (-not (Get-ServiceTimeline $r03Before $r03After $fence).NotificationProof.Complete) 'R03 fallback requires explicit offline opt-in.'
$script:CaseId='S02'
Check (-not (Get-ServiceTimeline $r03Before $r03After $fence -R03Offline).NotificationProof.Complete) 'R03 disabled-service premise cannot relax seed/other installed-service windows.'
$script:CaseId='R03'
$onlineBefore=Clone $r03Before;$onlineAfter=Clone $r03After;$onlineBefore.Tag='r03-online-before';$onlineAfter.Tag='r03-online-after'
# Even perfect non-execution receipts cannot substitute for online current-boot coverage.
$script:absenceLogs=Clone $savedLogs
foreach($pair in @(@{Before=$onlineBefore;After=$onlineAfter},@{Before=$r03Before;After=$onlineAfter},@{Before=$onlineBefore;After=$r03After})){
    $result=Get-ServiceTimeline $pair.Before $pair.After $fence -R03Offline
    Check (-not $result.NotificationProof.Complete -and $null -eq $result.AgentAbsenceProof -and $result.Assertions[-1].Verdict -cne 'PASS') 'Online or mixed R03 tags cannot invoke the offline fallback.'
}
$onlineProof=Test-NotificationWindow $onlineBefore.Notifications $onlineAfter.Notifications $fence $true
Check (-not $onlineProof.Complete) 'R03 online save still requires current-boot durable notification coverage.'
$script:row.NotificationExpectations=@('Unsupported')
Check (@((Get-ServiceTimeline $r03Before $r03After $fence -R03Offline).Assertions | Where-Object {$_.Name -ceq 'NotificationExpectation' -and $_.Verdict -ceq 'INCONCLUSIVE'}).Count -eq 1) 'R03 offline absence cannot approve unsupported expectations.'
$script:row.NotificationExpectations=@('NoNotification')
$b=Clone $r03Before;$a=Clone $r03After;$b.Notifications=$nb;$a.Notifications=$coveredAfter.Notifications
$result=Get-ServiceTimeline $b $a $fence -R03Offline
Check ($null -eq $result.AgentAbsenceProof -and @($result.Assertions | Where-Object {$_.Name -ceq 'NotificationExpectation' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1) 'R03 covered emission remains FAIL and cannot be hidden by the offline fallback.'
$script:CaseId=$savedCaseId;$script:row.NotificationExpectations=$savedExpectations;$script:absenceLogs=$savedLogs
$script:absenceLogs=$null

# Exercise the actual collectors with synthetic OS APIs. This catches the
# notify5 early-abort cascade without executing a Windows API on the host.
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1') @('Initialize-AgentExecutionReader','Get-ProcessCreationAudit','Get-AgentLogAnchor','Get-AgentExecutionSnapshot','Read-AgentLogWindow','Get-ErrorChain')
Add-Type -TypeDefinition @'
using System;
public sealed class SUFixtureProcess { public int Pid; public string Image; public string[] TokenSids; }
public static class SUAgentExecution {
 public static bool Installed=false;
 public static bool ScmError=false;
 public static uint[] Audit(){return new uint[]{1,0};}
 public static bool ServiceExists(string name){if(ScmError)throw new Exception("fixture SCM access denied");return Installed;}
 public static string ServiceSid(string name){return "S-1-5-80-1-2-3-4-5";}
 public static SUFixtureProcess Process(int pid){return new SUFixtureProcess{Pid=pid,Image="fixture-powershell",TokenSids=new string[]{"S-1-5-18"}};}
}
'@
function Get-BootId {return 'fixture-collector-boot'}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter)
    if($ClassName -ceq 'Win32_Service'){throw 'fixture CIM service query denied'}
    if($ClassName -cne 'Win32_Process'){throw 'Unexpected fixture CIM query'}
    return @([pscustomobject]@{ProcessId=0},[pscustomobject]@{ProcessId=4},[pscustomobject]@{ProcessId=$PID})
}
$script:fixtureLogDisabled=$false
function Get-WinEvent {
    [CmdletBinding()]param([string]$ListLog,[string]$LogName,[switch]$Oldest,[int]$MaxEvents,[string]$FilterXPath)
    if($ListLog){return [pscustomobject]@{IsEnabled=(-not $script:fixtureLogDisabled);SecurityDescriptor='fixture-sddl'}}
    $id=if($Oldest){1}else{103}
    $record=[pscustomobject]@{RecordId=$id;Channel=$LogName}
    $record | Add-Member ScriptMethod ToXml {Make-AgentXml $this.Channel $this.RecordId}
    return $record
}
$script:serviceDirectory=[IO.Path]::GetTempPath()
$collected=Get-AgentExecutionSnapshot
Check ($collected.Status -ceq 'OK' -and $collected.Service.Exists -eq $false -and $collected.Service.AbsenceError -eq 1060) 'An absent native SCM query must publish a complete absence receipt.'
Check ($collected.ServiceSid -and @($collected.ImagePaths).Count -eq 1 -and @($collected.Processes | Where-Object {$_.Pid -eq $PID}).Count -eq 1) 'Service absence must still collect package image, SID and the collector token.'
Check ($collected.InventoryEndQpc -ge $collected.InventoryStartQpc -and $collected.SystemEnd.NewestRecordId -eq 103 -and
    $collected.SecurityEnd.OldestRecordId -eq 1) 'Service absence must still finish inventory and collect both first/last log anchors.'
[SUAgentExecution]::ScmError=$true
$collected=Get-AgentExecutionSnapshot
Check ($collected.Status -ceq 'INCONCLUSIVE' -and ($collected.Errors -join ';') -like '*fixture SCM access denied*' -and
    $collected.Processes.Count -eq 1 -and $collected.SystemEnd.Status -ceq 'OK' -and $collected.SecurityEnd.Status -ceq 'OK') 'SCM errors retain their cause and cannot suppress inventory or end anchors.'
[SUAgentExecution]::ScmError=$false;[SUAgentExecution]::Installed=$true
$collected=Get-AgentExecutionSnapshot
Check ($collected.Status -ceq 'INCONCLUSIVE' -and $collected.Service.QueryStatus -ceq 'INCONCLUSIVE' -and $collected.SystemEnd.Status -ceq 'OK') 'An installed-service identity query failure stays incomplete with end anchors retained.'
$missingAnchor=Read-AgentLogWindow $collected.SystemBegin $null 'System'
Check ($missingAnchor.Status -ceq 'INCONCLUSIVE' -and $missingAnchor.Reason -like '*after log anchor missing*') 'A missing end anchor must name its edge rather than emit empty reasons.'
$script:fixtureLogDisabled=$true
$disabled=Get-AgentLogAnchor 'Security'
Check ($disabled.Status -ceq 'INCONCLUSIVE' -and $disabled.Reason -ceq 'Log disabled.' -and $disabled.Errors.Count -gt 0) 'Log failures retain their actual error chain.'

# C01 extends these existing checks; no guest execution or synthetic approvals.
$digest='A'*64
$approve=@(foreach($name in @('Allocated','Sealed','Inspecting','Approved','Publishing','Released')){
    [pscustomobject]@{StateName=$name;SealedOnce=($name -cne 'Allocated');Sha256Hex=$(if($name -cin @('Approved','Publishing','Released')){$digest}else{$null})}
})
Check (@(Test-CachedJournalSequence $approve 'APPROVE' $digest | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C01 full observed approval state/digest order passes.'
$skipped=@($approve | Where-Object StateName -cne 'Approved')
Check ((Test-CachedJournalSequence $skipped 'APPROVE' $digest)[0].Verdict -ceq 'INCONCLUSIVE') 'C01 polling must not infer a skipped Approved transition.'
$reordered=@($approve[0],$approve[2],$approve[1],$approve[3],$approve[4],$approve[5])
Check ((Test-CachedJournalSequence $reordered 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'C01 observed reversed transitions fail.'
$blocked=@($approve[0],$approve[1],$approve[2],[pscustomobject]@{StateName='Blocked';SealedOnce=$true;Sha256Hex=$digest})
Check ((Test-CachedJournalSequence $blocked 'BLOCK' $digest)[0].Verdict -ceq 'PASS') 'C01 observed block path passes.'
Check ((Test-CachedJournalSequence @($blocked+$approve[3]) 'BLOCK' $digest)[0].Verdict -ceq 'FAIL') 'C01 cannot approve a Block variant.'
$wrong=Clone $approve;$wrong[-1].Sha256Hex='B'*64
Check ((Test-CachedJournalSequence $wrong 'APPROVE' $digest)[1].Verdict -ceq 'FAIL') 'C01 changed sealed digest fails.'
$notification=[pscustomobject]@{Complete=$true;Reason='fixture complete';Emissions=@(@{Entry=[pscustomobject]@{Kind='Transfer';TransferId='fixture-transfer';Phase='Released';TargetSessionId=0}})}
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'APPROVE' $digest)[0].Verdict -ceq 'PASS') 'C01 correlates outcome event by transfer/session.'
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'APPROVE' $digest)[1].Verdict -ceq 'INCONCLUSIVE') 'C01 cannot manufacture missing notification digest from the journal.'
Check ((Test-CachedNotifications $notification 'other-transfer' 0 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'C01 requires the owning transfer notification.'
Check ((Test-CachedNotifications $notification 'fixture-transfer' 1 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'C01 wrong session notification fails.'
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'BLOCK' $digest)[0].Verdict -ceq 'FAIL') 'C01 Released contradicts Block even with incomplete coverage.'
$notification.Emissions+=@{Entry=[pscustomobject]@{Kind='Event';EventId='fixture-transfer';Phase='Blocked';TargetSessionId=0}}
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'C01 Blocked audit emission contradicts Approve.'
$notification.Emissions=@($notification.Emissions[0])
$notification.Complete=$false
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'APPROVE' $digest)[0].Verdict -ceq 'INCONCLUSIVE') 'C01 incomplete durable notification window stays inconclusive.'
# Durable history resolves skipped polling; it must not hide a wrong state or digest.
$durable=Clone @($approve[0],$approve[-1]);$durable[-1] | Add-Member NoteProperty History @('Allocated','Sealed','Inspecting','Approved','Publishing','Released')
Check ((Test-CachedJournalSequence $durable 'APPROVE' $digest)[0].Verdict -ceq 'PASS') 'Complete durable StateHistory proves transitions skipped by polling.'
$durable[-1].History=@('Allocated','Sealed','Approved','Inspecting','Publishing','Released')
Check ((Test-CachedJournalSequence $durable 'APPROVE' $digest)[0].Verdict -ceq 'FAIL') 'Reordered durable StateHistory fails.'
$durable[-1].History=@('Allocated')
Check ((Test-CachedJournalSequence $durable 'APPROVE' $digest)[0].Verdict -ceq 'INCONCLUSIVE') 'One-element durable history remains an array and cannot prove completion.'
$renamedStates=Clone $approve
foreach($item in $renamedStates){$item | Add-Member NoteProperty TransferId 'rename-transfer';$item | Add-Member NoteProperty DestinationGeneration $(if($item.StateName -ceq 'Allocated'){1}else{2})}
$commit=@{Verified=$true;TransferId='rename-transfer';SourceGeneration=1;TargetGeneration=2}
Check (@(Test-CachedJournalSequence $renamedStates 'APPROVE' $digest $commit | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C04 committed rename explains the one source-to-target generation change.'
Check ((Test-CachedJournalSequence $renamedStates 'APPROVE' $digest)[-1].Verdict -ceq 'FAIL') 'Generation change without committed namespace evidence fails.'
$bad=Clone $renamedStates;$bad[-1].DestinationGeneration=1
Check ((Test-CachedJournalSequence $bad 'APPROVE' $digest $commit)[-1].Verdict -ceq 'FAIL') 'C04 cannot revert to the source generation after target commit.'
$bad=Clone $renamedStates;$bad[-1].TransferId='wrong-transfer'
Check ((Test-CachedJournalSequence $bad 'APPROVE' $digest $commit)[-1].Verdict -ceq 'FAIL') 'A namespace transaction cannot authorize a new transfer identity.'
# The held journal collector is mocked here; exercise the actual commit evaluator.
$script:cachedKind='replacement';$script:cachedDenial=$false
$record=Make-JournalRecord 0;$manifest=[Text.Encoding]::UTF8.GetString($record.Bytes) | ConvertFrom-Json
$manifest.SealedOnce=$false;$manifest.Sha256Hex=$null;$manifest.DestinationGeneration=2
$manifest.Transfer.DestinationPath='C:\fixture\cached.txt'
$manifest.LastRenameTransactionId=123;$manifest.LastRenameDestination=$manifest.Transfer.DestinationPath;$manifest.LastRenameCommitted=$true
$manifest.NamespaceTombstones=[pscustomobject]@{DestinationPath='C:\fixture\save.tmp.txt';Generation=2;Previous=$null}
$record.Bytes=[Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 32 -Compress))
$entry=[pscustomobject]@{State=0;StateName='Allocated';SealedOnce=$false;TransferId=$manifest.Transfer.TransferId;DestinationGeneration=2;Record=$record;Artifact='fixture-manifest'}
$script:heldJournalFixture=[pscustomobject]@{Status='OK';Entries=@($entry);Errors=@();Snapshot=@{Journal=@($record)}}
function script:Get-CachedJournalObservation {param($Tag,$Actor) return $script:heldJournalFixture}
$heldTrial=@{Assertions=@();JournalSnapshots=@();JournalTransitions=@(@{State=0;StateName='Allocated';TransferId=$entry.TransferId;DestinationGeneration=1});SeedBase=@{Transitions=@(@{DestinationGeneration=1})}}
$namespaceProof=Test-CachedNamespaceCommit $entry $heldTrial 'C:\fixture\save.tmp.txt' 'C:\fixture\cached.txt'
Check ($namespaceProof.Verified -and $namespaceProof.Assertion.Verdict -ceq 'PASS') 'C04 exact committed target, reserved generation and source tombstone pass while unsealed.'
$manifest.NamespaceTombstones=$null;$record.Bytes=[Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 32 -Compress))
$namespaceProof=Test-CachedNamespaceCommit $entry $heldTrial 'C:\fixture\save.tmp.txt' 'C:\fixture\cached.txt'
Check (-not $namespaceProof.Verified -and $namespaceProof.Assertion.Verdict -ceq 'FAIL') 'C04 missing source tombstone fails even with a successful native rename.'
$script:cachedKind='external-rename';$script:cachedDenial=$true
$heldTrial.Assertions=@();Add-CachedHeldJournal $heldTrial @{} 'fixture-illegal-transfer'
Check (@($heldTrial.Assertions | Where-Object Verdict -ceq 'FAIL').Count -eq 1) 'C05 any target transfer contradicts D while the physical handle lives.'
$script:heldJournalFixture.Status='INCONCLUSIVE';$script:heldJournalFixture.Entries=@();$heldTrial.Assertions=@()
Add-CachedHeldJournal $heldTrial @{} 'fixture-missing-journal'
Check (@($heldTrial.Assertions | Where-Object Verdict -ceq 'INCONCLUSIVE').Count -eq 1) 'C05 unauthenticated empty journal cannot prove no transfer.'
$script:cachedKind=$null;$script:cachedDenial=$false
$notification.Complete=$true;$notification.Emissions[0].Entry | Add-Member NoteProperty Sha256Hex $digest
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'APPROVE' $digest)[1].Verdict -ceq 'PASS') 'Actual Released notification digest equals A.'
$notification.Emissions[0].Entry.Sha256Hex='B'*64
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'APPROVE' $digest)[1].Verdict -ceq 'FAIL') 'Wrong Released digest fails.'
$notification.Emissions[0].Entry.Sha256Hex=$digest;$notification.Emissions[0].Entry.Phase='Blocked'
$notification.Emissions[0].Entry | Add-Member NoteProperty HandBackPath 'verified-handback'
$hb=@{Files=@(@{Path='verified-handback';Sha256=$digest;SingleLink=$true;NoReparse=$true})}
Check (@(Test-CachedNotifications $notification 'fixture-transfer' 0 'BLOCK' $digest $hb | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'Blocked digest and hand-back path bind to the verified file.'
$notification.Emissions[0].Entry.HandBackPath='wrong-handback'
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'BLOCK' $digest $hb)[2].Verdict -ceq 'FAIL') 'Wrong Blocked hand-back path fails.'
Check ((Test-CachedNotifications $notification 'fixture-transfer' 0 'BLOCK' $digest)[2].Verdict -ceq 'INCONCLUSIVE') 'Unverified hand-back path stays inconclusive.'
function Make-NativeCalls([string[]]$Names,[bool]$DenyRename=$false){
    return ,@(for($i=0;$i -lt $Names.Count;$i++){@{Class=$Names[$i];NativeCode=$(if($DenyRename -and $Names[$i] -ceq 'rename-ex'){5}else{0});StartQpc=100+$i*10;EndQpc=101+$i*10}})
}
$mapped=Make-NativeCalls @('writer-open','create-mapping','map-view','close-source','mapped-store','flush-view','unmap-view','close-section')
Check ((Test-CachedActorCalls $mapped 'mapped' 90 160)[0].Verdict -ceq 'PASS') 'C02 store after source close, flush, then view/section release passes.'
$bad=Clone $mapped;$bad[3].Class='mapped-store';$bad[4].Class='close-source'
Check ((Test-CachedActorCalls $bad 'mapped' 90 160)[0].Verdict -ceq 'FAIL') 'C02 source handle must close before mapped store.'
Check ((Test-CachedActorCalls $mapped 'mapped' 90 161)[0].Verdict -ceq 'FAIL') 'C02 cannot unmap before the observer release barrier.'
Check ((Test-CachedActorCalls $mapped[0..6] 'mapped' 90 160)[0].Verdict -ceq 'INCONCLUSIVE') 'C02 missing section disposal receipt stays inconclusive.'
$replacement=Make-NativeCalls @('writer-open','cached-write','flush','rename-ex','close')
Check ((Test-CachedActorCalls $replacement 'replacement' 90 140)[0].Verdict -ceq 'PASS') 'C04 rename before source cleanup passes.'
$denied=Make-NativeCalls @('writer-open','rename-ex','close') $true
Check ((Test-CachedActorCalls $denied 'external-rename' 90 120)[0].Verdict -ceq 'PASS') 'C05 exact access denial belongs to rename, with successful source open and cleanup.'
$bad=Clone $denied;$bad[1].NativeCode=32
Check ((Test-CachedActorCalls $bad 'external-rename' 90 120)[0].Verdict -ceq 'FAIL') 'C05 sharing failure cannot substitute for access denial.'
$bad=Clone $denied;$bad[1].NativeCode=0
Check ((Test-CachedActorCalls $bad 'external-rename' 90 120)[0].Verdict -ceq 'FAIL') 'C05 successful external rename violates D.'
$bad=Clone $denied;$bad[0].NativeCode=5
Check ((Test-CachedActorCalls $bad 'external-rename' 90 120)[0].Verdict -ceq 'FAIL') 'C05 source-open denial cannot count as rename denial.'
$body=Get-WriterBody;$bodyTokens=$null;$bodyErrors=$null
$bodyAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$bodyTokens,[ref]$bodyErrors)
Check ($bodyErrors.Count -eq 0) 'Generated cached/seed actor script parses.'
$native=@($bodyAst.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*public static class SUWriter*'},$true))
Check ($native.Count -eq 1) 'Actor native cached helper is retained in the existing writer body.'
Add-Type -TypeDefinition $native[0].Value
Check ($null -ne ('SUWriter' -as [type])) 'Cached writer native declarations compile without calling Windows APIs.'
Check ([SUWriter]::FileRenameInfoEx -eq 22) 'Win32 FileRenameInfoEx must use class 22 as in the existing tested rename fixtures.'
if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
    $sid='S-1-5-21-1-2-3-1000'
    Check (Test-CachedHandBackAcl ('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$sid+')') $sid) 'H exact actor/SYSTEM explicit protected ACL passes.'
    Check (-not (Test-CachedHandBackAcl ('O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;'+$sid+')(A;;FR;;;BU)') $sid)) 'H extra user grant fails.'
    Check (-not (Test-CachedHandBackAcl ('O:SYG:SYD:P(A;;FA;;;SY)(A;ID;FA;;;'+$sid+')') $sid)) 'H inherited user grant fails.'
}
# Compile the existing observer helper for its pure hash/byte comparison only.
# Neither native readers nor the NTFS decoder are called by these fixtures.
Import-Module (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') -Force -DisableNameChecking
$sampleDirectory=Join-Path ([IO.Path]::GetTempPath()) ('c01-sample-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($sampleDirectory)
try{
    $script:protectedDirectory=$sampleDirectory;$final=Join-Path $sampleDirectory 'cached.txt'
    $imageA=[Text.Encoding]::ASCII.GetBytes('patterned-A!');$hash=[StagedInvariant.Native]::Hash($imageA)
    $artifactPath=Join-Path $sampleDirectory 'raw.bin';[IO.File]::WriteAllBytes($artifactPath,$imageA)
    $artifact=@{Path=$artifactPath;Length=$imageA.Length;Sha256=$hash}
    $marker=[pscustomobject]@{Name='marker.bin';Reference=4;Eof=12;Attributes=32}
    $parent=[pscustomobject]@{Role='Parent';Path=$sampleDirectory;DirectoryEntries=@($marker)}
    $base=[pscustomobject]@{Geometry=@{Cluster=4};Images=@($parent)}
    $absent=[pscustomobject]@{Role='Current';Path=$final;Absent=$true}
    $s=[pscustomobject]@{Status='OK';Phase='FlushedHandleHeld';Sequence=1;Captures=@(@{Images=@($parent,$absent)});
        C01Readers=@(@{Status='ERROR';NativeCode=2;Unbuffered=$false},@{Status='ERROR';NativeCode=2;Unbuffered=$true})}
    Check (@(Test-CachedSample $s $base $false $imageA | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C01 raw/index plus both missing-name opens prove held absence.'
    $bad=Clone $s;$bad.C01Readers[1].NativeCode=5
    Check (@(Test-CachedSample $bad $base $false $imageA | ForEach-Object {$_} | Where-Object Verdict -ceq 'INCONCLUSIVE').Count -gt 0) 'C01 access-denied read cannot substitute for raw final absence.'
    $bad=Clone $s;$bad.Captures[0].Images[1].Absent=$false
    Check (@(Test-CachedSample $bad $base $false $imageA | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'C01 final appearance while held fails.'
    $releasedParent=Clone $parent;$releasedParent.DirectoryEntries+= [pscustomobject]@{Name='cached.txt';Reference=5;Eof=12;Attributes=32}
    $released=[pscustomobject]@{Role='Current';Path=$final;Absent=$false;Length=12;Sha256=$hash;LogicalArtifact=$artifact;
        Runs=@(@{Vcn=0;Lcn=10;Clusters=3});Containers=@(@{Kind='DATA';Offset=40;Length=12;Artifact=$artifact})}
    $s.Phase='FinalQuiescence';$s.Captures=@(@{Images=@($releasedParent,$released)});$s.C01Readers=@(@{Status='OK';NativeCode=0;Unbuffered=$false;Result=@{Digest=$hash;Length=12}},@{Status='OK';NativeCode=0;Unbuffered=$true;Result=@{Digest=$hash;Length=12}})
    Check (@(Test-CachedSample $s $base $true $imageA | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C01 approved whole raw image/extents/readers and final-only listing pass.'
    $wrong=[byte[]]$imageA.Clone();$wrong[5]=[byte][char]'X';[IO.File]::WriteAllBytes($artifactPath,$wrong)
    $released.Containers[0].Artifact=@{Path=$artifactPath;Length=12;Sha256=[StagedInvariant.Native]::Hash($wrong)}
    $extent=@(Test-CachedSample $s $base $true $imageA | ForEach-Object {$_} | Where-Object Name -ceq 'C01ReleasedRawExtent')
    Check ($extent.Count -eq 1 -and $extent[0].Verdict -ceq 'FAIL' -and $extent[0].ForbiddenByteCount -eq 1) 'C01 raw extent comparator counts exactly one changed byte.'
    $releasedParent.DirectoryEntries+= [pscustomobject]@{Name='.safeupload-left.pending';Reference=6;Eof=12;Attributes=32}
    Check (@(Test-CachedSample $s $base $true $imageA | ForEach-Object {$_} | Where-Object { $_.Name -ceq 'C01PublicListing' -and $_.Verdict -ceq 'FAIL' }).Count -gt 0) 'C01 lingering publication temporary fails.'
    # C03/C04 compare approved B during the hold and keep the old physical reader
    # after a new target identity becomes A. Different lengths expose EOF mistakes.
    $imageB=[Text.Encoding]::ASCII.GetBytes('approved-base-B!');$bHash=[StagedInvariant.Native]::Hash($imageB)
    $bPath=Join-Path $sampleDirectory 'base.bin';[IO.File]::WriteAllBytes($bPath,$imageB)
    $bArtifact=@{Path=$bPath;Length=$imageB.Length;Sha256=$bHash}
    $bEntry=[pscustomobject]@{Name='cached.txt';Reference=7;Eof=$imageB.Length;Attributes=32}
    $bParent=Clone $parent;$bParent.DirectoryEntries+= $bEntry
    $baseImage=[pscustomobject]@{Role='Current';Path=$final;Absent=$false;Length=$imageB.Length;Sha256=$bHash;Identity=@{FileId='B-id'};LogicalArtifact=$bArtifact;
        Runs=@(@{Vcn=0;Lcn=20;Clusters=4});Containers=@(@{Kind='DATA';Offset=80;Length=$imageB.Length;Artifact=$bArtifact})}
    # Synthetic image uses an exact extent length; the VM fixtures are cluster multiples.
    $retained=Clone $baseImage;$retained.Role='Retained:B-id';$retained.Path=$null
    $base.Images=@($bParent,$baseImage)
    $oldReader=@{Role='Retained';FileId='B-id';Status='OK';Result=@{Digest=$bHash;Length=$imageB.Length}}
    $s.Phase='FlushedHandleHeld';$s.Captures=@(@{Images=@($bParent,$baseImage,$retained);Readers=@($oldReader)})
    $s.C01Readers=@(@{Status='OK';NativeCode=0;Unbuffered=$false;Result=@{Digest=$bHash;Length=$imageB.Length}},@{Status='OK';NativeCode=0;Unbuffered=$true;Result=@{Digest=$bHash;Length=$imageB.Length}})
    Check (@(Test-CachedSample $s $base $false $imageA $imageB | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C03/C04 whole B raw/fresh/uncached and held B reader pass before approval.'
    [IO.File]::WriteAllBytes($artifactPath,$imageA);$released.Containers[0].Artifact=$artifact
    $released | Add-Member NoteProperty Identity @{FileId='A-id'}
    $afterParent=Clone $parent;$afterParent.DirectoryEntries+= [pscustomobject]@{Name='cached.txt';Reference=8;Eof=$imageA.Length;Attributes=32}
    $s.Phase='FinalQuiescence';$s.Captures=@(@{Images=@($afterParent,$released,$retained);Readers=@($oldReader)})
    $s.C01Readers=@(@{Status='OK';NativeCode=0;Unbuffered=$false;Result=@{Digest=$hash;Length=$imageA.Length}},@{Status='OK';NativeCode=0;Unbuffered=$true;Result=@{Digest=$hash;Length=$imageA.Length}})
    Check (@(Test-CachedSample $s $base $true $imageA $imageB | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C03/C04 new target A and retained old physical B pass after POSIX publication.'
    Check (@(Test-CachedSample $s $base $false $imageA $imageB | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'C03/C04 leaked A before approval or on BLOCK fails.'
    $bad=Clone $s;$bad.Captures[0].Readers=@()
    Check (@(Test-CachedSample $bad $base $true $imageA $imageB | ForEach-Object {$_} | Where-Object {$_.Name -ceq 'C01RetainedBaseReader' -and $_.Verdict -ceq 'INCONCLUSIVE'}).Count -eq 1) 'Missing old physical reader is inconclusive.'
    $bad=Clone $s;$bad.Captures[0].Images=@($afterParent,$released)
    Check (@(Test-CachedSample $bad $base $true $imageA $imageB | ForEach-Object {$_} | Where-Object {$_.Name -ceq 'C01RetainedBase' -and $_.Verdict -ceq 'INCONCLUSIVE'}).Count -eq 1) 'Missing retained B raw identity is inconclusive.'
    $bad=Clone $s;$bad.Captures[0].Images[0].DirectoryEntries+= [pscustomobject]@{Name='save.tmp.txt';Reference=9;Eof=12;Attributes=32}
    Check (@(Test-CachedSample $bad $base $true $imageA $imageB | ForEach-Object {$_} | Where-Object {$_.Name -ceq 'C01PublicListing' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1) 'C04 public user temporary fails after publication.'
    # C05 uses the exact same image/listing checks against an explicit outside path.
    $source=Join-Path $sampleDirectory 'source.txt';$sourceImage=Clone $baseImage;$sourceImage.Path=$source
    $sourceParent=Clone $parent;$sourceParent.DirectoryEntries+= [pscustomobject]@{Name='source.txt';Reference=7;Eof=$imageB.Length;Attributes=32}
    $sourceBase=@{Geometry=$base.Geometry;Images=@($sourceParent,$sourceImage)}
    $sourceSample=@{Status='OK';Phase='AfterDeniedRename';Sequence=1;Captures=@(@{Images=@($sourceParent,$sourceImage,$retained);Readers=@($oldReader)});
        C01Readers=@(@{Status='OK';NativeCode=0;Unbuffered=$false;Result=@{Digest=$bHash;Length=$imageB.Length}},@{Status='OK';NativeCode=0;Unbuffered=$true;Result=@{Digest=$bHash;Length=$imageB.Length}})}
    Check (@(Test-CachedSample $sourceSample $sourceBase $false $imageB $imageB $source | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'C05 outside source remains exact image and identity after denied rename.'
    $bad=Clone $sourceSample;$bad.Captures[0].Images[1].Absent=$true
    Check (@(Test-CachedSample $bad $sourceBase $false $imageB $imageB $source | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'C05 source removal despite denial fails.'
}finally{[IO.Directory]::Delete($sampleDirectory,$true)}
# Activation and seed actors use the same Prepare-created writer.ps1 launcher.
# Mock only the OS queries; retain the real actor-identity validation function.
$stateDirectory=Join-Path ([IO.Path]::GetTempPath()) 'activation-identity-fixture'
$actorDirectory=Join-Path $stateDirectory 'actor';$writerTask='fixture-writer-task'
$state=@{ActorSid='S-1-5-21-1-2-3-1001'}
$script:activationIdentity=@{Pid=($PID+100);Sid=$state.ActorSid;Elevated=$false;IsAdministrator=$false;SessionId=0;BootId='fixture-active'}
$script:activationProcess=[pscustomobject]@{ProcessId=($PID+100);SessionId=0;CommandLine=('powershell.exe -File "'+(Join-Path $stateDirectory 'writer.ps1')+'"')}
function Wait-WriterIdentity { return $script:activationIdentity }
function Get-BootId { return 'fixture-active' }
function Get-CimInstance { return $script:activationProcess }
function Invoke-CimMethod { return @{ReturnValue=0;Sid=$state.ActorSid} }
function Get-ScheduledTask { return [pscustomobject]@{TaskName=$writerTask;Principal='standard-user';State='Running'} }
$proof=Get-ActivationActorIdentity
Check ($proof.Pid -eq $script:activationIdentity.Pid -and $proof.OwnerSid -ceq $state.ActorSid) 'Activation actor matches the actual shared writer.ps1 launcher.'
$script:activationProcess.CommandLine='powershell.exe -File unrelated.ps1';$rejected=$false
try{$null=Get-ActivationActorIdentity}catch{$rejected=$_.Exception.Message -like '*OS process provenance mismatch*'}
Check $rejected 'Unrelated process command line must still be rejected.'
$script:activationProcess.CommandLine=('powershell.exe -File "'+(Join-Path $stateDirectory 'writer.ps1')+'"');$script:activationProcess.SessionId=1;$rejected=$false
try{$null=Get-ActivationActorIdentity}catch{$rejected=$_.Exception.Message -like '*OS process provenance mismatch*'}
Check $rejected 'Activation actor session mismatch must still be rejected.'
# Exact-destination journal contradictions from any PID must fail, even when
# that process is neither of the two intended native actors.
function Test-ServiceJournalDelta {return $script:childDeltaFixture}
$script:childDeltaFixture=@{Complete=$true;Findings=@();NewEntries=@(@{Entry=@{Transfer=@{DestinationPath='target';ProcessId=999}};DestinationPaths=@('target')})}
$beforeFixture=@{Status='OK';BootId='fixture';EndQpc=1};$afterFixture=@{Status='OK';BootId='fixture';StartQpc=4};$mutationFixture=@{StartQpc=2;EndQpc=3}
$handBefore=@{Sid='user';Root='root';BootId='fixture';Qpc=1;Files=@()};$handAfter=@{Sid='user';Root='root';BootId='fixture';Qpc=4;Files=@()};$childFixture=@{Pid=124;Sid='user';BootId='fixture'}
$trialFixture=@{Assertions=@()};Test-ActivationChildWindow $trialFixture $beforeFixture $afterFixture $mutationFixture $handBefore $handAfter 'target' @{Pid=123} $childFixture
Check (@($trialFixture.Assertions|Where-Object {$_.Name -ceq 'NoJournalAtChildMutationCheckpoints' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1) 'Other PID exact-destination transfer is contradictory evidence.'
# Pending/committed/tombstoned rename aliases cannot erase a target hit.
foreach($kind in @('PendingRename','LastRenameDestination','NamespaceTombstones')){
 $manifestFixture=[Text.Encoding]::UTF8.GetString((Make-JournalRecord).Bytes)|ConvertFrom-Json
 $manifestFixture.Transfer.DestinationPath='C:\elsewhere\source.txt';$manifestFixture.Transfer.ProcessId=999;$normalizedTarget='C:\fixture\renamed.txt'
 if($kind -ceq 'PendingRename'){$manifestFixture.PendingRename=@{TransactionId=123;SealedVersion=$true;DestinationPath=$normalizedTarget}}
 elseif($kind -ceq 'LastRenameDestination'){$manifestFixture.LastRenameTransactionId=123;$manifestFixture.LastRenameDestination=$normalizedTarget;$manifestFixture.LastRenameCommitted=$true}
 else{$manifestFixture.NamespaceTombstones=@{Generation=1;DestinationPath=$normalizedTarget;Previous=$null}}
 $normalizedFixture=@{Entry=$manifestFixture;DestinationPaths=@(Get-ServiceDestinationPaths $manifestFixture)}
 $script:childDeltaFixture=@{Complete=$true;Findings=@();NewEntries=@($normalizedFixture)};$trialFixture=@{Assertions=@()}
 Test-ActivationChildWindow $trialFixture $beforeFixture $afterFixture $mutationFixture $handBefore $handAfter $normalizedTarget @{Pid=123} $childFixture
 Check (@($trialFixture.Assertions|Where-Object {$_.Name -ceq 'NoJournalAtChildMutationCheckpoints' -and $_.Verdict -ceq 'FAIL'}).Count -eq 1) ('Normalized '+$kind+' target alias must fail journal checkpoint absence.')
}
$script:childDeltaFixture=@{Complete=$false;Findings=@();NewEntries=@()};$trialFixture=@{Assertions=@()};Test-ActivationChildWindow $trialFixture $beforeFixture $afterFixture $mutationFixture $handBefore $handAfter 'target' @{Pid=123} $childFixture
Check (@($trialFixture.Assertions|Where-Object {$_.Name -ceq 'NoJournalAtChildMutationCheckpoints' -and $_.Verdict -ceq 'INCONCLUSIVE'}).Count -eq 1) 'Incomplete journal cannot establish even checkpoint absence.'

# Commands and replies use distinct routes; both sequence counters persist in
# the shared state, and one actor cannot substitute the other actor's receipt.
$routeDirectory=Join-Path ([IO.Path]::GetTempPath()) ('a04-route-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $routeDirectory
function Save-State($Value,[string]$Path){$Value|Export-Clixml -LiteralPath $Path}
try{
 $statePath=Join-Path $routeDirectory 'state.clixml';$state=@{ActivationActors=@{}}
 foreach($key in @('Primary','Duplicate')){
  $replies=Join-Path $routeDirectory ($key+'-replies');$commands=Join-Path $routeDirectory ($key+'-commands');$null=New-Item -ItemType Directory -Path $replies,$commands
  $state.ActivationActors[$key]=@{Directory=$replies;CommandDirectory=$commands;NextSequence=1;ExpectedPid=$(if($key -ceq 'Primary'){123}else{124})}
  Save-State @{Sequence=1;Action='position-holder';BootId='fixture-active';Pid=$state.ActivationActors[$key].ExpectedPid;NativeCode=0} (Join-Path $replies 'reply-0001.clixml')
 }
 $primaryReply=Publish-ActivationActorCommand $state 'position-holder' @{Offset=317}
 Check ($primaryReply.Pid -eq 123 -and $state.ActivationActors.Primary.NextSequence -eq 2 -and $state.ActivationActors.Duplicate.NextSequence -eq 1) 'Primary reply route and independent sequence update.'
 $childReply=Publish-ActivationActorCommand $state 'position-holder' @{Offset=619} 'Duplicate'
 Check ($childReply.Pid -eq 124 -and $state.ActivationActors.Primary.NextSequence -eq 2 -and $state.ActivationActors.Duplicate.NextSequence -eq 2) 'Child reply route and independent sequence update.'
 $persisted=Load-State $statePath
 Check ($persisted.ActivationActors.Primary.NextSequence -eq 2 -and $persisted.ActivationActors.Duplicate.NextSequence -eq 2) 'Shared state preserves both actor counters.'
 Check ((Test-Path (Join-Path $state.ActivationActors.Primary.CommandDirectory 'command-0001.clixml')) -and (Test-Path (Join-Path $state.ActivationActors.Duplicate.CommandDirectory 'command-0001.clixml')) -and -not(Test-Path (Join-Path $state.ActivationActors.Primary.Directory 'command-0001.clixml'))) 'Commands use only trusted read-only command routes.'
 Save-State @{Sequence=2;Action='position-holder';BootId='fixture-active';Pid=123;NativeCode=0} (Join-Path $state.ActivationActors.Duplicate.Directory 'reply-0002.clixml');$rejected=$false
 try{$null=Publish-ActivationActorCommand $state 'position-holder' @{Offset=0} 'Duplicate'}catch{$rejected=$_.Exception.Message -like '*PID mismatch*'}
 Check $rejected 'Other actor PID cannot substitute child reply.'
 Save-State @{Sequence=3;Action='wrong-action';BootId='fixture-active';Pid=124;NativeCode=0} (Join-Path $state.ActivationActors.Duplicate.Directory 'reply-0003.clixml');$rejected=$false
 try{$null=Publish-ActivationActorCommand $state 'position-holder' @{Offset=0} 'Duplicate'}catch{$rejected=$_.Exception.Message -like '*mismatch*'}
 Check $rejected 'Wrong command action cannot substitute child reply.'
}finally{Remove-Item -LiteralPath $routeDirectory -Recurse -Force}

'ProofAdapterEvaluationChecks='+$script:checks+';PASS (host-safe synthetic evaluation, collector mocks and identity publication only)'
}catch{'ScriptError='+$_.Exception.ToString();throw}
