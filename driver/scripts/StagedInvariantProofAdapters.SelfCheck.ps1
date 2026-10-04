# Pure evaluation tests. No Windows APIs, driver, service or guest operations.
# Run on Windows PowerShell 5.1 before qualification; Linux PS7 is authoring QA only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
function Import-EvaluationFunctions([string]$File,[string[]]$Names) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($File,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($name in $Names){
        $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
        if($functions.Count -ne 1){throw ('Missing/ambiguous evaluation function: '+$name)}
        # Define at script scope without importing the module's native decoder.
        $definition=$functions[0].Extent.Text.Replace(('function '+$name+'('),('function script:'+$name+'('))
        Invoke-Expression $definition
    }
}
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') @('New-IORecord','New-IOAssertion','Test-InvariantCadence','Test-InvariantMetadata','Test-InvariantExternalCoverage')
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1') @('Get-ExpectedCheckpoint','Get-ServiceDestinationPaths','Test-ServiceFixtureEntry','ConvertFrom-NotificationRecord','Test-NotificationWindow','Get-ServiceTimeline')
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Clone($Value){return ($Value | ConvertTo-Json -Depth 32 | ConvertFrom-Json)}
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
$policy=[pscustomobject]@{Status='OK';Before=[pscustomobject]@{Value=3;BootId=$boot;VolumeGuid='volume';Qpc=0};After=[pscustomobject]@{Value=3;BootId=$boot;VolumeGuid='volume';Qpc=20000}}
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
$bad=Clone $policy;$bad.After.Value=0
Check (@(Test-InvariantMetadata $image $expect $samples[0] $bad | Where-Object Verdict -eq 'INCONCLUSIVE').Count -gt 0) 'Policy change invalidates tolerance.'
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
$script:evidenceDirectory=$PSScriptRoot;$script:protectedDirectory='C:\fixture'
$script:row.JournalExpectations=@('NoNewTransfer','NoApproved','NoReleased');$script:row.NotificationExpectations=@('NoApproval','NoRelease','NoHandBack')
$before=[pscustomobject]@{Status='OK';BootId=$boot;QpcFrequency=$frequency;StartQpc=0;EndQpc=10;Journal=@();Application=@{Status='OK';OldestRecordId=1;NewestRecordId=5;NewestXml='anchor'}}
$after=Clone $before;$after.StartQpc=3000;$after.EndQpc=3100
$service=Get-ServiceTimeline $before $after $fence
Check (@($service.Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -ne 'PASS'}).Count -eq 0) 'Authenticated empty retained journal supports seed negative journal expectations.'
Check (@($service.Assertions | Where-Object {$_.Name -eq 'NotificationExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 3) 'Empty Application log must not fabricate notification proof.'
$after.Journal=@([pscustomobject]@{Path='manifest';StateName='Released';Entry=@{Transfer=@{DestinationPath='C:\fixture\new.bin'};LastRenameTransactionId=0;LastRenameDestination=$null;LastRenameCommitted=$false}})
$service=Get-ServiceTimeline $before $after $fence
Check (@($service.Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 3) 'New released manifest contradicts all three journal expectations.'
$after.Status='INCONCLUSIVE'
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'FAIL'}).Count -eq 3) 'Partial snapshots must preserve authenticated positive contradictions.'
$after.Journal=@()
Check (@((Get-ServiceTimeline $before $after $fence).Assertions | Where-Object {$_.Name -eq 'JournalExpectation' -and $_.Verdict -eq 'INCONCLUSIVE'}).Count -eq 3) 'Unauthenticated snapshot cannot establish negative journal evidence.'


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
'ProofAdapterEvaluationChecks='+$script:checks+';PASS (synthetic evaluation only)'
