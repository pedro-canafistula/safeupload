#requires -Version 5.1
# Pure adversarial controls for expiry/cleanup receipts and the sole permitted
# restart boundary. No service or protected write; never product qualification.
$ErrorActionPreference='Stop'
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$t,[ref]$e)
if($e.Count){throw 'Suite parse failed'}
foreach($name in @('Test-CachedBlockCase','Set-CachedAssertionFamily','Get-CachedBlockTiming','Test-CachedBlockManifest','Test-CachedBlockNotificationWindow','Test-CachedBlockNoRelease','Test-NotificationWindow')){
    $fn=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($fn.Count -ne 1){throw ('Unique function unavailable: '+$name)};Invoke-Expression $fn[0].Extent.Text
}
$count=0
function Check([bool]$Good,[string]$Label){if(-not $Good){throw ('BLOCK window control failed: '+$Label)};$script:count++}
function Copy-Fixture($Value){return [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($Value,32))}
$sid='S-1-5-21-1-2-3-1001';$actor=@{Pid=123;SessionId=2;Sid=$sid};$digest='A'*64
$open=@{TransferId='11111111-1111-1111-1111-111111111111';StateName='Blocked';SealedOnce=$true;Sha256Hex=$digest;History=@('Allocated','Sealed','Inspecting','Blocked');Manifest=@{
    Transfer=@{ProcessId=123;SessionId=2;RequestorSid=$sid;StagePath='C:\ProgramData\SafeUpload\staging\11111111111111111111111111111111.txt';DestinationPath='C:\fixture\cached.txt'};
    StateHistory=@(@{State=6;OccurredAtUtc='2026-10-07T12:00:00Z'});DestinationGeneration=2;BlockedPolicyVersion=3;HandbackState=2;HandbackLength=12288;HandbackPath='C:\Users\su\SafeUpload\_bloqueados\v1.txt';Sha256Hex=$digest;
    JustificationExpiresAtUtc='2026-10-07T12:03:00Z';JustificationWindowClosed=$false;StageDeleted=$false;StageCleanupStarted=$false;UpdatedAtUtc='2026-10-07T12:00:01Z'}}
Check ((Test-CachedBlockManifest $open $open $actor $digest).Verdict -ceq 'PASS') 'verified open window'
$timing=Get-CachedBlockTiming $open ([DateTimeOffset]::Parse('2026-10-07T12:00:20Z')) 1000 100
Check ($timing.WindowSeconds -eq 180 -and $timing.RemainingSeconds -eq 160 -and $timing.RuntimeDeadlineQpc -eq 18500 -and $timing.DeadlineQpc -eq 29000 -and $timing.ActorDeadlineQpc -eq 35000) 'expiry-derived QPC deadlines and margins'
foreach($seconds in @(25,420)){
    $other=Copy-Fixture $open;$other.Manifest.JustificationExpiresAtUtc=([DateTimeOffset]::Parse('2026-10-07T12:00:00Z')).AddSeconds($seconds).ToString('o')
    $plan=Get-CachedBlockTiming $other ([DateTimeOffset]::Parse('2026-10-07T12:00:01Z')) 1000 100
    Check ($plan.WindowSeconds -eq $seconds -and $plan.DeadlineQpc -eq 1000+100*($seconds-1+120)) ('real window '+$seconds+' seconds, no three-minute assumption')
}
foreach($field in @('missingExpiry','expired','missingBlocked','doubleBlocked','badFrequency','badQpc','nonUtc')){
    $bad=Copy-Fixture $open;$freq=100;$qpc=1000;$now=[DateTimeOffset]::Parse('2026-10-07T12:00:20Z')
    switch($field){'missingExpiry'{$bad.Manifest.Remove('JustificationExpiresAtUtc')}'expired'{$now=[DateTimeOffset]::Parse('2026-10-07T12:03:00Z')}'missingBlocked'{$bad.Manifest.StateHistory=@()}'doubleBlocked'{$bad.Manifest.StateHistory+=@($bad.Manifest.StateHistory[0])}'badFrequency'{$freq=0}'badQpc'{$qpc=-1}'nonUtc'{$now=[DateTimeOffset]::Parse('2026-10-07T09:00:20-03:00')}}
    $rejected=$false;try{$null=Get-CachedBlockTiming $bad $now $qpc $freq}catch{$rejected=$true};Check $rejected ('reject timing '+$field)
}
$closed=Copy-Fixture $open;$closed.Manifest.JustificationWindowClosed=$true;$closed.Manifest.UpdatedAtUtc='2026-10-07T12:03:00Z'
Check ((Test-CachedBlockManifest $closed $open $actor $digest -RequireClosed).Verdict -ceq 'PASS') 'non-forced equality at expiry'
$clean=Copy-Fixture $closed;$clean.Manifest.StageDeleted=$true;$clean.Manifest.UpdatedAtUtc='2026-10-07T12:03:01Z'
Check ((Test-CachedBlockManifest $clean $open $actor $digest -RequireClosed -RequireDeleted).Verdict -ceq 'PASS') 'product completed cleanup receipt'
foreach($field in @('closed','deleted','cleanupStarted','missingClosed','missingDeleted','badHandback')){
    $bad=Copy-Fixture $open
    switch($field){'closed'{$bad.Manifest.JustificationWindowClosed=$true}'deleted'{$bad.Manifest.StageDeleted=$true}'cleanupStarted'{$bad.Manifest.StageCleanupStarted=$true}'missingClosed'{$bad.Manifest.Remove('JustificationWindowClosed')}'missingDeleted'{$bad.Manifest.Remove('StageDeleted')}'badHandback'{$bad.Manifest.HandbackState=3}}
    Check ((Test-CachedBlockManifest $bad $open $actor $digest).Verdict -ceq 'FAIL') ('reject open '+$field)
}
foreach($field in @('early','open','notDeleted','cleanupStillStarted','badHandback','changedExpiry','missingExpiry','changedDigest','changedPath','changedLength','changedGeneration','changedPolicy','changedPid','changedSid','changedSession','changedStage','changedDestination','wrongTransfer','releasedState','releaseHistory','emptyHistory','missingDeleted','stringClosed','nonUtcReceipt')){
    $bad=Copy-Fixture $clean
    switch($field){
        'early'{$bad.Manifest.UpdatedAtUtc='2026-10-07T12:02:59Z'} 'open'{$bad.Manifest.JustificationWindowClosed=$false} 'notDeleted'{$bad.Manifest.StageDeleted=$false} 'cleanupStillStarted'{$bad.Manifest.StageCleanupStarted=$true}
        'badHandback'{$bad.Manifest.HandbackState=3} 'changedExpiry'{$bad.Manifest.JustificationExpiresAtUtc='2026-10-07T12:04:00Z'} 'missingExpiry'{$bad.Manifest.Remove('JustificationExpiresAtUtc')}
        'changedDigest'{$bad.Sha256Hex='B'*64} 'changedPath'{$bad.Manifest.HandbackPath='C:\wrong.txt'} 'changedLength'{$bad.Manifest.HandbackLength=1} 'changedGeneration'{$bad.Manifest.DestinationGeneration=3} 'changedPolicy'{$bad.Manifest.BlockedPolicyVersion=4}
        'changedPid'{$bad.Manifest.Transfer.ProcessId=456} 'changedSid'{$bad.Manifest.Transfer.RequestorSid='wrong'} 'changedSession'{$bad.Manifest.Transfer.SessionId=0} 'changedStage'{$bad.Manifest.Transfer.StagePath='C:\wrong.txt'} 'changedDestination'{$bad.Manifest.Transfer.DestinationPath='C:\wrong.txt'}
        'wrongTransfer'{$bad.TransferId='22222222-2222-2222-2222-222222222222'} 'releasedState'{$bad.StateName='Released'} 'releaseHistory'{$bad.History+=@('Released')} 'emptyHistory'{$bad.History=@()}
        'missingDeleted'{$bad.Manifest.Remove('StageDeleted')} 'stringClosed'{$bad.Manifest.JustificationWindowClosed='true'} 'nonUtcReceipt'{$bad.Manifest.UpdatedAtUtc='2026-10-07T09:03:01-03:00'}
    }
    Check ((Test-CachedBlockManifest $bad $open $actor $digest -RequireClosed -RequireDeleted).Verdict -ceq 'FAIL') ('reject cleanup '+$field)
}
$entries=@();$previous='0'*64
foreach($row in @(@(1,'Heartbeat','old',1000),@(2,'Transfer','old',1200),@(3,'Stop','old',1500),@(4,'Start','new',2500),@(5,'Heartbeat','new',2700),@(6,'Transfer','new',2900),@(7,'Heartbeat','new',3100))){
    $hash=([string]$row[0]).PadLeft(64,'0');$entry=@{Sequence=$row[0];Kind=$row[1];InstanceId=$row[2];Qpc=$row[3];BootId='boot';QpcFrequency=100;PreviousSha256=$previous;Phase=$(if($row[1] -ceq 'Transfer'){'Blocked'}else{$null})}
    $entries+=@{Entry=$entry;Hash=$hash};$previous=$hash
}
$before=@{Status='OK';BootId='boot';QpcFrequency=100;Head=@{Sequence=1;Sha256=$entries[0].Hash}}
$after=@{Status='OK';BootId='boot';QpcFrequency=100;Head=@{Sequence=7;Sha256=$entries[-1].Hash};Entries=$entries}
$fence=@{BootId='boot';QpcFrequency=100;ReleasedQpc=1100;CompletedQpc=3000}
$restart=@{Before=@{Pid=123;OwnerSid='S-1-5-18'};After=@{Pid=456;OwnerSid='S-1-5-18'};StopRequestedQpc=1400;StoppedQpc=1600;StartRequestedQpc=2400;ReadyQpc=2600}
Check ((Test-CachedBlockNotificationWindow $before $after $fence $restart).Complete) 'exact SCM Stop->Start permits only the stopped heartbeat gap'
Check (-not (Test-NotificationWindow $before $after $fence $true).Complete) 'original single-instance validator still rejects restarts'
foreach($field in @('lostAnchor','lostFinal','sequenceGap','hashGap','liveGap','wrongBoot','wrongFrequency','wrongInstance','missingStop','missingStart','extraStart','wrongStopFence','wrongStartFence','samePid','wrongOwner','badScmOrder','postStopEmission','startSameInstance')){
    $a=Copy-Fixture $after;$r=Copy-Fixture $restart
    switch($field){
        'lostAnchor'{$a.Entries[0].Hash='bad'} 'lostFinal'{$a.Head.Sha256='bad'} 'sequenceGap'{$a.Entries[5].Entry.Sequence=99} 'hashGap'{$a.Entries[5].Entry.PreviousSha256='bad'} 'liveGap'{$a.Entries[6].Entry.Qpc=3500}
        'wrongBoot'{$a.Entries[5].Entry.BootId='other'} 'wrongFrequency'{$a.Entries[5].Entry.QpcFrequency=1000} 'wrongInstance'{$a.Entries[5].Entry.InstanceId='other'} 'missingStop'{$a.Entries[2].Entry.Kind='Heartbeat'} 'missingStart'{$a.Entries[3].Entry.Kind='Heartbeat'}
        'extraStart'{$a.Entries[4].Entry.Kind='Start'} 'wrongStopFence'{$r.StoppedQpc=1499} 'wrongStartFence'{$r.StartRequestedQpc=2501} 'samePid'{$r.After.Pid=$r.Before.Pid} 'wrongOwner'{$r.After.OwnerSid='wrong'} 'badScmOrder'{$r.StoppedQpc=2700}
        'postStopEmission'{$a.Entries[3].Entry.Kind='Transfer';$a.Entries[3].Entry.InstanceId='old'} 'startSameInstance'{$a.Entries[3].Entry.InstanceId='old'}
    }
    Check (-not (Test-CachedBlockNotificationWindow $before $a $fence $r).Complete) ('reject restart coverage '+$field)
}
$noReleaseProof=Test-CachedBlockNotificationWindow $before $after $fence $restart
Check ((Test-CachedBlockNoRelease $noReleaseProof $open.TransferId).Verdict -ceq 'PASS') 'complete chained no-release fence'
$incomplete=@{Complete=$false;Emissions=@();Reason='Lost head'}
Check ((Test-CachedBlockNoRelease $incomplete $open.TransferId).Verdict -ceq 'INCONCLUSIVE') 'no emissions cannot conceal missing coverage'
foreach($kind in @('Transfer','Event')){
    $release=@{Complete=$true;Emissions=@(@{Entry=@{Kind=$kind;Phase='Released';TransferId=$open.TransferId}})}
    Check ((Test-CachedBlockNoRelease $release $open.TransferId).Verdict -ceq 'FAIL') ('no '+$kind+' Released')
    $release.Complete=$false
    Check ((Test-CachedBlockNoRelease $release $open.TransferId).Verdict -ceq 'FAIL') ('coverage loss cannot conceal '+$kind+' Released')
}
foreach($id in @('C01-block-absent','C02-block-absent','C03-block-existing','C04-block')){
    Check (Test-CachedBlockCase $id) ('shared BLOCK dispatch includes '+$id)
}
foreach($id in @('C02-approve-absent','C01-approve-absent','C03-approve-existing','C04-approve','C05-denied-external-rename','B01','C02','c02-block-absent','C02-block-absent-extra')){
    Check (-not (Test-CachedBlockCase $id)) ('shared BLOCK dispatch excludes '+$id)
}
foreach($family in @('C01','C02','C03','C04')){
    $export=@(@{Name='C01HandBackWindowClosureAndRestart';Verdict='PASS';Evidence=$clean},@{Name='C01BlockedAuditedStageCleanup';Verdict='FAIL'},@{Name='LiveTaintFlags';Verdict='PASS'})
    Set-CachedAssertionFamily $export $family
    $umbrella=if($family -ceq 'C02'){'C02HandBackWindowClosureAndRestart'}else{'C01HandBackWindowClosureAndRestart'}
    Check ($export[0].Name -ceq $umbrella -and $export[0].Verdict -ceq 'PASS' -and $export[0].Evidence.Manifest.StageDeleted -eq $true) ('family umbrella retains verdict/evidence '+$family)
    Check ($export[1].Name -ceq ($family+'BlockedAuditedStageCleanup') -and $export[1].Verdict -ceq 'FAIL') ('family export cannot conceal failed cleanup '+$family)
    Check ($export[2].Name -ceq 'LiveTaintFlags') ('family export leaves unrelated check '+$family)
    Set-CachedAssertionFamily $export $family
    Check ($export[0].Name -ceq $umbrella -and $export[1].Verdict -ceq 'FAIL') ('family export is idempotent '+$family)
}
$safe=@{Name='C01HandBackSafeRelativeCreation';Verdict='INCONCLUSIVE';Reason='Receipt unavailable'}
Set-CachedAssertionFamily @($safe) 'C02'
Check ($safe.Name -ceq 'C02HandBackSafeRelativeCreation' -and $safe.Verdict -ceq 'INCONCLUSIVE' -and $safe.Reason -ceq 'Receipt unavailable') 'C02 naming cannot manufacture a safe-creation receipt'
Check ($ast.Extent.Text.Contains('$cachedBlockCase=Test-CachedBlockCase $CaseId')) 'single shared BLOCK selector'
$routes=@('if($cachedBlockCase){Initialize-CachedSecondUser}', 'BlockWindowClosure=$cachedBlockCase;', '$interactiveActorCase=$coreJustificationCase -or $cachedBlockCase')
$routes+=('if($cachedBlockCase){' + "`n" + '            try{Invoke-CachedBlockWindow')
$routes+=('if($cachedBlockCase){' + "`n" + '                $trial.Assertions+=Invoke-CachedSecondUserDenial')
foreach($route in $routes){
    Check ($ast.Extent.Text.Contains($route)) 'preparation, actor configuration and collection use shared BLOCK selector'
}
Check ($ast.Extent.Text.Contains('Set-CachedAssertionFamily $trial.Assertions $cachedFamily')) 'final export uses tested family adapter'
$table=Import-PowerShellDataFile (Join-Path $PSScriptRoot 'StagedInvariantCases.psd1')
foreach($id in @('C01-block-absent','C02-block-absent','C03-block-existing','C04-block')){
    $row=@($table.Cases | Where-Object CaseId -ceq $id)[0]
    Check ($row.Status -ceq 'Ready' -and $row.Actions -contains 'QpcWaitToExpiryPlusMargin' -and $row.Actions -contains 'RequireProductCompleteStageCleanupJournalReceiptStageDeleted' -and $row.ExtraDuration) ('row expiry contract '+$id)
}
$mapped=@($table.Cases | Where-Object CaseId -ceq 'C02-block-absent')[0]
Check ($mapped.Revision -ge 4 -and $table.TableRevision -ge 13 -and $mapped.Setup -contains 'SecondStandardUserTaskAndRegisteredProfile' -and $mapped.Cleanup -contains 'RemoveSecondUserTaskBatchRightAccountAndProfileIncludingAfterRestorationReboot') 'C02 revised second-user setup/restoration contract'
Check ($mapped.Actions -contains 'CloseSourceHandleBeforeStore' -and $mapped.Actions -contains 'WholeImageMappedStoreA' -and $mapped.Actions -contains 'UnmapView' -and $mapped.Actions -contains 'CloseSection') 'C02 retains mapped-path stimulus'
'BlockWindowSelfCheck=PASS;Controls='+$count+';Qualification=False'
