# Host-safe evaluation and temporary identity-publication tests. No Windows APIs,
# driver, service or guest operations.
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
Import-EvaluationFunctions (Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1') @('Wait-WriterIdentity','Get-ExpectedCheckpoint','Test-ServiceJournalStateReachable','Assert-ServiceManifestPath','ConvertFrom-ServiceJournalRecord','Test-ServiceJournalDelta','Get-ServiceDestinationPaths','Test-ServiceFixtureEntry','ConvertFrom-NotificationRecord','Test-NotificationWindow','Get-ServiceTimeline')
$script:checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Clone($Value){return ($Value | ConvertTo-Json -Depth 32 | ConvertFrom-Json)}
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
'ProofAdapterEvaluationChecks='+$script:checks+';PASS (host-safe synthetic evaluation and identity publication only)'
