#requires -Version 5.1
# Synthetic controls only: no service/driver/guest or latency qualification.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
foreach($name in @('Test-LatencyTransientIoError','Invoke-LatencyJournalIo','Get-ErrorChain','Get-LatencyTransferHints',
    'ConvertFrom-LatencyManifestRecord','ConvertFrom-ServiceJournalRecord','Test-ServiceJournalStateReachable','Assert-ServiceManifestPath',
    'Get-ServiceDestinationPaths','Invoke-DedicatedLatencyObservation','Get-LatencyVerdict','Write-DurableFile','Initialize-ServiceEvidenceReader',
    'Remove-LatencyJournalBytes','Assert-CachedAgentExited','Restore-CachedAgent','Complete-CachedAgentQuiescence','Stop-OwnedCachedAgentProcess','Remove-InvariantFixture')){
    $functions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($functions.Count -ne 1){throw ('Missing/ambiguous function: '+$name)}
    Invoke-Expression $functions[0].Extent.Text
}
$checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Refuses([scriptblock]$Body,[string]$Message){$failed=$false;try{$null=& $Body}catch{$failed=$true};Check $failed $Message}
function Clone($Value){return ($Value | ConvertTo-Json -Depth 32 -Compress | ConvertFrom-Json)}
# SCM Stopped and a previous saved restoration flag cannot replace process exit.
$script:processQueries=0
function Get-Process { $script:processQueries++;if($script:processQueries -eq 1){return [pscustomobject]@{Id=123}} }
Assert-CachedAgentExited
Check ($script:processQueries -eq 2) 'Quiescence waits for real process absence after SCM stop'
function Get-Process { return [pscustomobject]@{Id=123} }
Refuses {Assert-CachedAgentExited 0} 'A surviving service process cannot satisfy cleanup'
$state=@{CachedAgent=@{};CachedAgentRestored=$true}
function Assert-CachedAgentExited {throw 'synthetic surviving process'}
Refuses {Restore-CachedAgent} 'Previously saved restoration still checks surviving handles'
$serviceDirectory=Join-Path ([IO.Path]::GetTempPath()) 'owned-test-agent'
$evidenceDirectory=$serviceDirectory
$expectedPath=Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'
$birth=[DateTime]::UtcNow;$script:terminated=0
$fakeProcess=[pscustomobject]@{Id=123;Handle=1;StartTime=$birth;MainModule=@{FileName=$expectedPath}}
$fakeProcess | Add-Member ScriptMethod WaitForExit {param($Milliseconds)return $true}
function Get-Process {return $fakeProcess}
function Stop-Process {param($InputObject,[switch]$Force,$ErrorAction)$script:terminated++;$script:fakeProcess=$null}
function Assert-CachedAgentExited {param($Seconds)if($null -ne $fakeProcess){throw 'synthetic surviving process'}}
function Get-BootId {return 'synthetic/boot'}
function Save-State {}
$state=@{DedicatedUnheldLatency=$true;CachedAgent=@{ProcessId=123;ProcessStartUtcFileTime=$birth.ToUniversalTime().ToFileTimeUtc();ProcessPath=$expectedPath}}
Complete-CachedAgentQuiescence
Check ($script:terminated -eq 1 -and $state.CachedAgentForcedExit.RestorationOnly) 'Only the pinned owned test-agent process is terminated during restoration'
$fakeProcess=[pscustomobject]@{Id=123;Handle=1;StartTime=$birth.AddSeconds(1);MainModule=@{FileName=$expectedPath}}
Refuses {Stop-OwnedCachedAgentProcess} 'A reused PID cannot be terminated'
Check ($script:terminated -eq 1) 'PID reuse rejection happens before termination'
$fakeProcess.StartTime=$birth;$fakeProcess.MainModule.FileName='unrelated.exe'
Refuses {Stop-OwnedCachedAgentProcess} 'An unrelated executable cannot be terminated'
$state.CachedAgent.ProcessId=$null
Refuses {Stop-OwnedCachedAgentProcess} 'Missing process provenance cannot authorize termination'
Remove-Item Function:\Stop-Process,Function:\Get-BootId,Function:\Save-State
Remove-Item Function:\Get-Process,Function:\Assert-CachedAgentExited
$cleanupRoot=Join-Path ([IO.Path]::GetTempPath()) ('latency-cleanup-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $cleanupRoot 'child') -Force
[IO.File]::WriteAllText((Join-Path $cleanupRoot 'child/held.txt'),'fixture')
try{
    function Remove-Item {throw [UnauthorizedAccessException]::new('synthetic access denied')}
    $failure=$null;try{Remove-InvariantFixture $cleanupRoot}catch{$failure=$_.Exception.Message}
    Check ($null -ne $failure -and $failure.Contains('held.txt') -and $failure.Contains('Attributes=')) 'Deletion refusal keeps exact failing leaf and attributes'
    Check (Test-Path -LiteralPath (Join-Path $cleanupRoot 'child/held.txt')) 'Denied cleanup preserves the fixture and cannot report success'
}finally{Microsoft.PowerShell.Management\Remove-Item Function:\Remove-Item}
Remove-InvariantFixture $cleanupRoot
Check (-not (Test-Path -LiteralPath $cleanupRoot)) 'Checked leaf-first cleanup removes the whole disposable fixture'
foreach($code in @(5,32,33)){
    $native=[ComponentModel.Win32Exception]::new($code)
    Check (Test-LatencyTransientIoError $native) ('Native transient '+$code)
    Check (Test-LatencyTransientIoError ([IO.IOException]::new('wrapper',$native))) ('Wrapped transient '+$code)
    Check (Test-LatencyTransientIoError ([IO.IOException]::new('HRESULT',[int](-2147024896+$code)))) ('HRESULT transient '+$code)
}
Check (Test-LatencyTransientIoError ([UnauthorizedAccessException]::new('flush denied'))) 'Flush access denial is retryable'
foreach($code in @(2,3,80,87,112)){
    Check (-not (Test-LatencyTransientIoError ([ComponentModel.Win32Exception]::new($code)))) ('Other native code fails immediately: '+$code)
}
foreach($message in @('Access to the path is denied','sharing violation','Trusted owner and protected DACL required.','Short/unstable product evidence read.')){
    Check (-not (Test-LatencyTransientIoError ([IO.IOException]::new($message)))) 'Text must not classify schema/authentication errors'
}
$retryLog=New-Object 'Collections.Generic.List[object]';$script:attempt=0
$value=Invoke-LatencyJournalIo {$script:attempt++;if($script:attempt -lt 3){throw [ComponentModel.Win32Exception]::new(32)};return 'retained'} 'SyntheticRead' 'fixture' $retryLog -Enabled
Check ($value -ceq 'retained' -and $script:attempt -eq 3 -and $retryLog.Count -eq 2) 'Transient read retries and recovers'
Check (@($retryLog | Where-Object {$_.Outcome -cne 'Recovered' -or $null -eq $_.RecoveryQpc -or -not $_.Retryable}).Count -eq 0) 'Every recovered failure keeps QPC and outcome'
$retryLog=New-Object 'Collections.Generic.List[object]';$script:attempt=0
Refuses {Invoke-LatencyJournalIo {$script:attempt++;throw [ComponentModel.Win32Exception]::new(5)} 'SyntheticCopy' 'fixture' $retryLog ([Diagnostics.Stopwatch]::GetTimestamp()-1) -Enabled} 'Persistent access denial fails at QPC deadline'
Check ($script:attempt -eq 1 -and $retryLog.Count -eq 1 -and $retryLog[0].Outcome -ceq 'Persistent') 'Expired deadline never retries'
$retryLog=New-Object 'Collections.Generic.List[object]';$script:attempt=0
Refuses {Invoke-LatencyJournalIo {$script:attempt++;throw 'Manifest schema invalid'} 'SyntheticRead' 'fixture' $retryLog -Enabled} 'Schema error is fatal'
Check ($script:attempt -eq 1 -and $retryLog[0].Outcome -ceq 'NotRetryable') 'Schema failure cannot be hidden by retry'

$instance=[guid]::NewGuid().ToString('D');$id=[guid]::NewGuid().ToString('D');$boot='synthetic/boot';$frequency=[Diagnostics.Stopwatch]::Frequency
$hint=@{Version=1;Kind='Transfer';Qpc=100;BootId=$boot;InstanceId=$instance;QpcFrequency=$frequency;TargetSessionId=0;TransferId=$id;Phase='Analyzing'}
function Tail($Entry){return @{Bytes=[Text.Encoding]::UTF8.GetBytes(($Entry | ConvertTo-Json -Compress)+"`n");Offset=0}}
$tail=Tail $hint
Check (@(Get-LatencyTransferHints @($tail) $boot $instance 100 $frequency 0).Count -eq 1) 'Session-zero durable emission discovers transfer'
Check (@(Get-LatencyTransferHints @($tail,$tail) $boot $instance 100 $frequency 0).Count -eq 1) 'Rotation overlap deduplicates transfer'
Check (@(Get-LatencyTransferHints @($tail) $boot $instance 101 $frequency 0).Count -eq 0) 'Prior rounds are excluded by native-start QPC'
$excluded=@{};$excluded[$id]=$true
Check (@(Get-LatencyTransferHints @($tail) $boot $instance 100 $frequency 0 $excluded).Count -eq 0) 'A delayed prior-round emission cannot rediscover its completed transfer'
Check (@(Get-LatencyTransferHints @($tail) 'other/boot' $instance 100 $frequency 0).Count -eq 0) 'Historical boot is not current completion'
Check (@(Get-LatencyTransferHints @($tail) $boot $instance 100 $frequency 1).Count -eq 0) 'Other session is not current completion'
$bad=Clone $hint;$bad.TargetSessionId=$null
Check (@(Get-LatencyTransferHints @((Tail $bad)) $boot $instance 100 $frequency 0).Count -eq 0) 'Unbound session is not an actor hint'
foreach($field in @('InstanceId','QpcFrequency','TransferId','Phase','Version','Kind')){
    $bad=Clone $hint
    switch($field){'InstanceId'{$bad.InstanceId=[guid]::NewGuid().ToString('D')}'QpcFrequency'{$bad.QpcFrequency++}'TransferId'{$bad.TransferId=[guid]::Empty.ToString()}'Phase'{$bad.Phase='Approved'}'Version'{$bad.Version=2}'Kind'{$bad.Kind='Unknown'}}
    Refuses {Get-LatencyTransferHints @((Tail $bad)) $boot $instance 100 $frequency 0} ('Malformed/foreign discovery fails: '+$field)
}
$suffix=@{Bytes=[Text.Encoding]::UTF8.GetBytes('cut first line'+"`n"+[Text.Encoding]::UTF8.GetString($tail.Bytes)+'{"partial":');Offset=1}
Check (@(Get-LatencyTransferHints @($suffix) $boot $instance 100 $frequency 0).Count -eq 1) 'Suffix cut and incomplete append boundaries are ignored'
$partial=@{Bytes=[Text.Encoding]::UTF8.GetBytes('{"partial":');Offset=0}
Check (@(Get-LatencyTransferHints @($partial) $boot $instance 100 $frequency 0).Count -eq 0) 'Incomplete append cannot imply completion'
Refuses {Get-LatencyTransferHints @(@{Bytes=[Text.Encoding]::UTF8.GetBytes("malformed`n");Offset=0}) $boot $instance 100 $frequency 0} 'Complete malformed JSON fails'
Refuses {Get-LatencyTransferHints @(@{Bytes=(New-Object byte[] 65537);Offset=0}) $boot $instance 100 $frequency 0} 'Oversized suffix fails'
Refuses {Get-LatencyTransferHints @($tail,$tail,$tail) $boot $instance 100 $frequency 0} 'More than two segment suffixes fail'

$actor=@{Pid=123;SessionId=0;Sid='S-1-5-21-1-2-3-1001';BootId=$boot};$digest='A'*64
function Manifest([string]$Path='C:\fixture\target.txt',[string]$TransferId=$id){
    return @{Transfer=@{TransferId=$TransferId;StagePath='C:\stage\private.bin';DestinationPath=$Path;Destination=2;
        ProcessId=$actor.Pid;ProcessName='powershell.exe';SessionId=$actor.SessionId;RequestorSid=$actor.Sid};
        State=5;Sha256Hex=$digest;UpdatedAtUtc='2026-10-07T00:00:00Z';SealedOnce=$true;DestinationGeneration=1;
        NamespaceTombstones=$null;PendingRename=$null;LastRenameTransactionId=0;LastRenameDestination=$null;LastRenameCommitted=$false;
        StateHistory=@(0..5 | ForEach-Object {@{State=$_}})}
}
function Record($Entry){return [pscustomobject]@{Path=('C:\journal\'+([guid]$Entry.Transfer.TransferId).ToString('N')+'.json');
    Bytes=[Text.Encoding]::UTF8.GetBytes(($Entry | ConvertTo-Json -Depth 32 -Compress));Artifact='synthetic.json';StartQpc=110;EndQpc=111}}
$entry=Manifest;$record=Record $entry
Check ((ConvertFrom-LatencyManifestRecord $record $actor @('C:\fixture\target.txt') $id $digest).StateName -ceq 'Released') 'Exact terminal manifest qualifies completion'
Check ($null -eq (ConvertFrom-LatencyManifestRecord $record $actor @('C:\fixture\other.txt') $id $digest)) 'Unrelated path cannot complete round'
Refuses {ConvertFrom-LatencyManifestRecord $record $actor @('C:\fixture\target.txt') ([guid]::NewGuid().ToString('D')) $digest} 'Exact transfer ID remains required'
foreach($field in @('ProcessId','SessionId','RequestorSid','Sha256Hex','StateHistory','State','SealedOnce')){
    $bad=Clone $entry
    switch($field){'ProcessId'{$bad.Transfer.ProcessId++}'SessionId'{$bad.Transfer.SessionId=1}'RequestorSid'{$bad.Transfer.RequestorSid='foreign'}
        'Sha256Hex'{$bad.Sha256Hex='B'*64}'StateHistory'{$bad.StateHistory=@(@{State=5})}'State'{$bad.State=6}'SealedOnce'{$bad.SealedOnce=$false}}
    Refuses {ConvertFrom-LatencyManifestRecord (Record $bad) $actor @('C:\fixture\target.txt') $id $digest} ('Terminal provenance/history remains required: '+$field)
}
$entry.State=2;$entry.StateHistory=@(0..2 | ForEach-Object {@{State=$_}})
Check ((ConvertFrom-LatencyManifestRecord (Record $entry) $actor @('C:\fixture\target.txt') $id $digest).StateName -ceq 'Inspecting') 'Nonterminal exact manifest is observable but not complete'
$entry.State=7;$entry.StateHistory=@(@{State=0},@{State=1},@{State=2},@{State=3},@{State=4},@{State=7})
Refuses {ConvertFrom-LatencyManifestRecord (Record $entry) $actor @('C:\fixture\target.txt') $id $digest} 'Publication Retained cannot release the next latency round'
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){
    Write-Output ('LatencyLitePureSelfCheck='+$checks+';PASS;WindowsCoordinatorControl=NotRun;Qualification=False')
    exit 0
}

# Coordinator control uses synthetic native/public receipts and actual durable
# barriers. It verifies all 101 snapshots precede admission of the next round.
Add-Type -TypeDefinition @'
namespace StagedInvariant {
 public sealed class LiteReader { public string Status="OK",Digest; public int Length; }
 public static class Native {
  public static string Digest=new string('A',64);
  public static LiteReader Fresh(string p,bool raw,int alignment){return new LiteReader{Digest=Digest,Length=12288};}
 }
}
'@
$actorDirectory=Join-Path ([IO.Path]::GetTempPath()) ('latency-lite-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $actorDirectory
try{
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        Initialize-ServiceEvidenceReader
        $tailPath=Join-Path $actorDirectory 'tail.bin';$bytes=New-Object byte[] 100000
        $bytes[99999]=42;[IO.File]::WriteAllBytes($tailPath,$bytes)
        $proof=[SUProofFile]::Open($tailPath,$false,$false,$true,$false)
        try{$read=[SUProofFile]::ReadTail($proof,65536)}finally{$proof.Dispose()}
        Check ($read.Offset -eq 34464 -and $read.Bytes.Length -eq 65536 -and $read.Bytes[65535] -eq 42) 'Native same-handle tail reader seeks instead of reading historical prefix'
        Remove-Item -LiteralPath $tailPath -Force
    }
    foreach($kind in @('cached','replacement')){
    Get-ChildItem -LiteralPath $actorDirectory -File | Remove-Item -Force
    $protectedDirectory=$actorDirectory;$cachedKind=$kind;$RunName='synthetic-latency';$writerTask='synthetic';$state=@{WriterToken='a'*32}
    $classes=if($kind -ceq 'replacement'){@('writer-open','cached-write','flush','rename-ex','close')}else{@('writer-open','cached-write','flush','close')}
    $row=@{LatencyClasses=$classes};$script:closedRound=-1;$script:snapshots=0;$script:aggregate=@();$script:completionPolls=@{};$script:rejectCompletion=$false
    $trial=@{Operations=@();JournalSnapshots=@();ServiceBefore=@{Status='OK';Notifications=@{LocationStatus='OK';Entries=@(@{Entry=@{BootId=$boot;InstanceId=$instance;QpcFrequency=$frequency}})}}}
    function Wait-WriterIdentity([string]$Path,[int]$Seconds){
        $round=[int]([regex]::Match($Path,'round-(\d{3})-').Groups[1].Value);$closed=$Path.EndsWith('closed.clixml')
        if($closed){
            $script:closedRound=$round;$barrier=if($round -eq 0){'go'}else{'round-'+($round-1).ToString('D3')+'-next'}
            Check (Test-Path -LiteralPath (Join-Path $actorDirectory $barrier)) 'Actor cannot start before published barrier'
            Check ($script:snapshots -eq $round) 'Only the previous rounds have snapshots at native admission'
            $calls=@($row.LatencyClasses | ForEach-Object {$qpc=[Diagnostics.Stopwatch]::GetTimestamp();[pscustomobject]@{Class=$_;Trial=$round;Cold=($round -eq 0);NativeCode=0;StartQpc=$qpc;EndQpc=$qpc}})
            $script:aggregate+= $calls
        }else{$calls=@()}
        $target=Join-Path $actorDirectory $(if($cachedKind -ceq 'replacement'){'cached.txt'}else{'latency-'+$round.ToString('D3')+'.txt'})
        $openPath=if($cachedKind -ceq 'replacement'){Join-Path $actorDirectory 'save.tmp.txt'}else{$target}
        return @{Pid=$actor.Pid;Sid=$actor.Sid;BootId=$boot;Token=$state.WriterToken;Trial=$round;Held=$false;
            Target=$target;OpenPath=$openPath;WriterKind=$cachedKind;PrivateSha256=$digest;Calls=$calls;Qpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    }
    function Get-LatencyCompletionObservation($Probe,$Actor,$Paths,$Digest,$Deadline,$ExcludedIds){
        Check ($script:snapshots -eq $script:closedRound) 'Completion polling does not take full snapshots'
        Check ($ExcludedIds.Count -eq $script:closedRound) 'Completed transfer IDs have constant-time discovery exclusions'
        Check (-not(Test-Path -LiteralPath (Join-Path $actorDirectory ('round-'+$script:closedRound.ToString('D3')+'-next')))) 'Next native round stays closed while service completion is pending'
        if($script:rejectCompletion){throw 'Synthetic Retained publication'}
        $script:completionPolls[$script:closedRound]++
        if(-not $Probe.TransferId){$Probe.TransferId=([guid]::NewGuid().ToString('D'))}
        return @{StateName=$(if($script:completionPolls[$script:closedRound] -eq 1){'Inspecting'}else{'Released'})}
    }
    function Get-CachedJournalObservation($Tag,$Actor,$Paths,$ExcludedIds,[switch]$RetryTransientJournal){
        Check $RetryTransientJournal 'Terminal snapshot enables bounded retry'
        $script:snapshots++;$qpc=[Diagnostics.Stopwatch]::GetTimestamp()
        $transferId=$trial.DedicatedLatency.Rounds[-1].CompletionProbe.TransferId
        $record=Record (Manifest $Paths[0] $transferId)
        return @{Status='OK';Entries=@(@{Record=$record});Errors=@();Snapshot=@{Status='OK';Journal=@($record);StartQpc=$qpc;EndQpc=[Diagnostics.Stopwatch]::GetTimestamp()}}
    }
    function Wait-TaskCompletion {return @{ExitCode=0;Value=@{Held=$false;Actor=$actor;Calls=$script:aggregate;QpcFrequency=$frequency}}}
    $null=Invoke-DedicatedLatencyObservation $trial $actor @{Qpc=0} @{BootId=$boot;Geometry=@{Alignment=4096}} $digest 12288
    Check ($trial.DedicatedLatency.Complete -and $script:snapshots -eq 101 -and $trial.JournalSnapshots.Count -eq 101) 'Exactly one retained snapshot per cold/warm round'
    Check (@($trial.Latency | Where-Object {$_.Samples.Count -ne 101 -or $_.UnheldCount -ne 100 -or $_.Verdict -cne 'PASS'}).Count -eq 0) 'Classes/sample counts/budget computation unchanged'
    $previous=$trial.DedicatedLatency.InitialIoCompletedQpc
    foreach($round in $trial.DedicatedLatency.Rounds){
        Check ($round.NativeNotBeforeQpc -eq $previous -and $round.Receipt.Calls[0].StartQpc -ge $previous) 'Native calls follow previous round I/O boundary'
        Check ($round.SnapshotCompletedQpc -le $round.PublicationVerifiedQpc -and $round.PublicationVerifiedQpc -le $round.IoCompletedQpc) 'Snapshot and public-image work finish before next barrier'
        $previous=$round.IoCompletedQpc
    }
    if($kind -ceq 'replacement'){
        Check (@($trial.DedicatedLatency.Rounds | Where-Object {$_.Receipt.OpenPath -cne (Join-Path $actorDirectory 'save.tmp.txt')}).Count -eq 0) 'All C04 rounds use the exact functional sibling temp'
    }
    Get-ChildItem -LiteralPath $actorDirectory -File | Remove-Item -Force
    $script:closedRound=-1;$script:snapshots=0;$script:aggregate=@();$script:rejectCompletion=$true
    $trial=@{Operations=@();JournalSnapshots=@();ServiceBefore=@{Status='OK';Notifications=@{LocationStatus='OK';Entries=@(@{Entry=@{BootId=$boot;InstanceId=$instance;QpcFrequency=$frequency}})}}}
    Refuses {Invoke-DedicatedLatencyObservation $trial $actor @{Qpc=0} @{BootId=$boot;Geometry=@{Alignment=4096}} $digest 12288} 'A rejected completion stops the coordinator before the next round'
    Check ($trial.DedicatedLatency.Rounds.Count -eq 1 -and -not $trial.DedicatedLatency.Complete -and
        -not(Test-Path -LiteralPath (Join-Path $actorDirectory 'round-000-next'))) 'Failed completion retains partial evidence and no admission barrier'
    }
}finally{Remove-Item -LiteralPath $actorDirectory -Recurse -Force}
# Finalize serialization drops raw journal Bytes from snapshots but keeps each round's terminal record whole.
$termRecord=[pscustomobject]@{Path='t';Artifact='a\\terminal.json';Length=3;Sha256='AA';Bytes=[byte[]](1,2,3)}
$otherRecord=[pscustomobject]@{Path='o';Artifact='a\\other.json';Length=2;Sha256='BB';Bytes=[byte[]](4,5)}
$bytesSnapshot=[ordered]@{Status='OK';Journal=@($termRecord,$otherRecord)}
$bytesTrial=@{DedicatedLatency=@{Rounds=@(@{Terminal=@{Record=$termRecord};Snapshot=$bytesSnapshot})};JournalSnapshots=@($bytesSnapshot)}
Remove-LatencyJournalBytes $bytesTrial
Check ($bytesSnapshot.Journal.Count -eq 2 -and $bytesSnapshot.JournalBytesOmitted -eq $true) 'Snapshot keeps every record and is marked'
Check (($bytesSnapshot.Journal | Where-Object Artifact -ceq 'a\\other.json').PSObject.Properties.Name -cnotcontains 'Bytes') 'Non-terminal journal Bytes are omitted'
Check (($bytesSnapshot.Journal | Where-Object Artifact -ceq 'a\\other.json').Sha256 -ceq 'BB' -and ($bytesSnapshot.Journal | Where-Object Artifact -ceq 'a\\other.json').Length -eq 2) 'Omitted record keeps its authenticated hash and length'
Check ($bytesTrial.DedicatedLatency.Rounds[0].Terminal.Record.Bytes.Length -eq 3) 'Terminal record keeps Bytes for the host decoder'
$functional=@{DedicatedLatency=$null;JournalSnapshots=@([ordered]@{Journal=@([pscustomobject]@{Artifact='x';Bytes=[byte[]](9)})})}
Remove-LatencyJournalBytes $functional
Check ($functional.JournalSnapshots[0].Journal[0].Bytes.Length -eq 1 -and -not $functional.JournalSnapshots[0].Contains('JournalBytesOmitted')) 'Functional trials are untouched'
Write-Output ('LatencyLiteSelfCheck='+$checks+';PASS;Qualification=False')
