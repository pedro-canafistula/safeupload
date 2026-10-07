#requires -Version 5.1
# Pure R01/B01/second-user controls and generated actor syntax, run by the existing Windows gate.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
try {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($name in @('Get-WriterBody','Get-R01WriterBody','Get-B01WriterBody','Get-CachedSecondUserBody','Test-R01OfflineCalls','Test-R01OfflineAbsent','Test-R01HeldRecovery','Test-R01HeldNotifications',
        'Test-R01JournalSequence','Test-R01ActorCalls','Test-R01OutcomeSample','Test-R01ReleasedOnce','Test-B01JunctionReceipt','Test-B01FailedHandBack','Test-B01FailureNotification',
        'Test-B01SentinelSample','Test-B01FailureAudit','Test-AgentLogContinuity','ConvertFrom-AgentEventXml','Test-CachedSecondUserDenial','Test-CachedActorCalls','Test-CachedSample','Test-CachedImage')){
        $defs=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
        if($defs.Count -ne 1){throw ('Missing/ambiguous function: '+$name)}
        Invoke-Expression ($defs[0].Extent.Text.Replace(('function '+$name),('function script:'+$name)))
    }
    $checks=0
    function Check([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason};$script:checks++}
    function Clone($Value){return ($Value | ConvertTo-Json -Depth 32 | ConvertFrom-Json)}
    function Passed($Value){return @($Value | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0}
    function Rejected($Value){return @($Value | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0}
    $actor=@{Pid=101;Sid='S-1-5-21-1-2-3-1001';BootId='fixture';Profile='C:\Users\owner'}
    $calls=@();$i=30
    foreach($name in @('writer-open','cached-write','flush','cached-write','flush','close')){
        $calls+=@{Class=$name;NativeCode=0;StartQpc=$i;EndQpc=($i+1)};$i+=10
    }
    $receipt=@{Pid=101;Sid=$actor.Sid;BootId='fixture';Token='token';Target='N';OfflineTarget='offline-new';Held=$true;PrivateSha256='A';Calls=$calls[0..4];Qpc=72;
        OfflineCalls=@(@{Class='writer-open-deny';NativeCode=5;StartQpc=55;EndQpc=56})}
    Check (Passed (Test-R01OfflineCalls $receipt $actor 'token' 'N' 50 'A' 'offline-new')) 'R01 distinct-name Win32:5 denial followed by private write/flush passes.'
    foreach($code in @(80,0,2,32,87,$null)){
        $bad=Clone $receipt;$bad.OfflineCalls[0].NativeCode=$code
        Check (Rejected (Test-R01OfflineCalls $bad $actor 'token' 'N' 50 'A' 'offline-new')) ('R01 rejects offline native code '+$code+'.')
    }
    $bad=Clone $receipt;$bad.OfflineTarget='N'
    Check (Rejected (Test-R01OfflineCalls $bad $actor 'token' 'N' 50 'A' 'N')) 'R01 rejects probing the held private name even with Win32:5.'
    foreach($change in @('admitted','early','digest','sid','token','path','offline-path','missing-offline-path','closed','write-failed','extra-denial')){
        $bad=Clone $receipt
        switch($change){
            'admitted'{$bad.OfflineCalls[0].NativeCode=0}
            'early'{$bad.OfflineCalls[0].StartQpc=49}
            'digest'{$bad.PrivateSha256='other'}
            'sid'{$bad.Sid='other'}
            'token'{$bad.Token='stale'}
            'path'{$bad.Target='other'}
            'offline-path'{$bad.OfflineTarget='other'}
            'missing-offline-path'{$bad.OfflineTarget=$null}
            'closed'{$bad.Held=$false}
            'write-failed'{$bad.Calls[3].NativeCode=5}
            'extra-denial'{$bad.OfflineCalls+=@{Class='close';NativeCode=0;StartQpc=57;EndQpc=58}}
        }
        Check (Rejected (Test-R01OfflineCalls $bad $actor 'token' 'N' 50 'A' 'offline-new')) ('R01 rejects offline '+$change+'.')
    }
    $initial=@{StateName='Allocated';SealedOnce=$false;TransferId='id';DestinationGeneration=1;History=@('Allocated')}
    $unsealed=@{StateName='Unsealed';SealedOnce=$false;TransferId='id';DestinationGeneration=1;Sha256Hex=$null;History=@('Allocated','Unsealed')}
    Check (Passed (Test-R01HeldRecovery $initial $unsealed)) 'R01 same mutable transfer Unsealed passes.'
    foreach($change in @('approved','sealed','id','generation','history')){
        $bad=Clone $unsealed
        switch($change){'approved'{$bad.StateName='Approved'}'sealed'{$bad.SealedOnce=$true}'id'{$bad.TransferId='other'}'generation'{$bad.DestinationGeneration=2}'history'{$bad.History+= 'Inspecting'}}
        Check (Rejected (Test-R01HeldRecovery $initial $bad)) ('R01 rejects recovery '+$change+'.')
    }
    $proof=@{Complete=$true;Reason='fixture';Emissions=@()}
    Check (Passed (Test-R01HeldNotifications $proof 'id')) 'R01 no held outcome emission passes.'
    $bad=Clone $proof;$bad.Emissions=@(@{Entry=@{TransferId='id';Kind='Transfer';Phase='Analyzing'}})
    Check (Rejected (Test-R01HeldNotifications $bad 'id')) 'R01 rejects inspection while held.'
    $terminal=@{StateName='Released';TransferId='id';DestinationGeneration=1;SealedOnce=$true;Sha256Hex='A';History=@('Allocated','Unsealed','Sealed','Inspecting','Approved','Publishing','Released')}
    $transitions=@($initial,$unsealed,$terminal)
    Check (Passed (Test-R01JournalSequence $transitions 'A')) 'R01 exact recovered/fresh inspected history and digest passes.'
    foreach($change in @('history','digest','identity','double-release')){
        $bad=Clone $terminal
        switch($change){'history'{$bad.History=@('Allocated','Approved','Released')}'digest'{$bad.Sha256Hex='other'}'identity'{$bad.TransferId='other'}'double-release'{$bad.History+= 'Released'}}
        Check (Rejected (Test-R01JournalSequence @($initial,$unsealed,$bad) 'A')) ('R01 rejects terminal '+$change+'.')
    }
    Check (Passed (Test-R01ActorCalls $calls 10 75)) 'R01 six native calls and close fence pass.'
    $bad=Clone $calls;$bad[5].StartQpc=74
    Check (Rejected (Test-R01ActorCalls $bad 10 75)) 'R01 rejects early close.'
    $releaseProof=@{Complete=$true;Emissions=@(@{Entry=@{Kind='Transfer';TransferId='id';Phase='Released';TargetSessionId=0;Sha256Hex='A'}})}
    Check (Passed (Test-R01ReleasedOnce $terminal $releaseProof 0 'A')) 'R01 one exact Released journal and emission passes.'
    $bad=Clone $releaseProof;$bad.Emissions+= $bad.Emissions[0]
    Check (Rejected (Test-R01ReleasedOnce $terminal $bad 0 'A')) 'R01 rejects duplicate Released emission.'
    $junction=@{Pid=101;Sid=$actor.Sid;BootId='fixture';Token='token';Root=(Join-Path $actor.Profile 'SafeUpload\_bloqueados');Sentinel='C:\sentinel';Leaf='id.txt';ExitCode=0;Reparse=$true;Held=$true;Target=@('C:\sentinel');Qpc=100}
    Check (Passed (Test-B01JunctionReceipt $junction $actor 'token' 'C:\sentinel' 'id.txt' 90)) 'B01 exact actor junction receipt passes.'
    $bad=Clone $junction;$bad.Target=@('C:\other')
    Check (Rejected (Test-B01JunctionReceipt $bad $actor 'token' 'C:\sentinel' 'id.txt' 90)) 'B01 rejects wrong junction target.'
    $blocked=@{State=6;SealedOnce=$true;Sha256Hex='A';Transfer=@{RequestorSid=$actor.Sid};HandbackState=3;HandbackFailureReason='handback_failed';HandbackPath=$null;StageDeleted=$false;StageCleanupStarted=$false;
        StateHistory=@(@{State=0},@{State=1},@{State=2},@{State=6})}
    Check (Passed (Test-B01FailedHandBack $blocked 'A' $actor.Sid)) 'B01 Blocked/Failed retained exact image passes.'
    foreach($change in @('verified','deleted','digest','history','path','failure')){
        $bad=Clone $blocked
        switch($change){'verified'{$bad.HandbackState=2}'deleted'{$bad.StageDeleted=$true}'digest'{$bad.Sha256Hex='other'}'history'{$bad.StateHistory+=@{State=5}}'path'{$bad.HandbackPath='unexpected'}'failure'{$bad.HandbackFailureReason=$null}}
        Check (Rejected (Test-B01FailedHandBack $bad 'A' $actor.Sid)) ('B01 rejects '+$change+'.')
    }
    $blockProof=@{Complete=$true;Reason='fixture';Emissions=@(@{Entry=@{Kind='Transfer';TransferId='id';Phase='Blocked';TargetSessionId=0;Sha256Hex='A';HandBackPath=$null}})}
    Check (Passed (Test-B01FailureNotification $blockProof 'id' 0 'A')) 'B01 Blocked digest/session with no hand-back path passes.'
    foreach($change in @('released','path','session','digest','missing')){
        $bad=Clone $blockProof
        switch($change){'released'{$bad.Emissions+=@{Entry=@{Kind='Transfer';TransferId='id';Phase='Released';TargetSessionId=0}}}'path'{$bad.Emissions[0].Entry.HandBackPath='unexpected'}'session'{$bad.Emissions[0].Entry.TargetSessionId=1}'digest'{$bad.Emissions[0].Entry.Sha256Hex='other'}'missing'{$bad.Emissions=@()}}
        Check (Rejected (Test-B01FailureNotification $bad 'id' 0 'A')) ('B01 rejects notification '+$change+'.')
    }
    $id='11111111-2222-3333-4444-555555555555'
    $startXml='<Event><System><Provider Name="fixture"/><EventID>1</EventID><EventRecordID>1</EventRecordID><Channel>Application</Channel></System><EventData><Data>anchor</Data></EventData></Event>'
    $failXml='<Event><System><Provider Name="SafeUpload.Agent.Service"/><EventID>0</EventID><EventRecordID>2</EventRecordID><Channel>Application</Channel></System><EventData><Data>Staged hand-back failed for '+$id+'.</Data></EventData></Event>'
    $parsed=ConvertFrom-AgentEventXml $failXml 'Application'
    Check ($parsed.Values.Count -eq 1 -and $parsed.Values[0] -ceq ('Staged hand-back failed for '+$id+'.') -and $parsed.Data.Count -eq 0) 'Application warning text is preserved for unnamed EventData without inventing a field name.'
    $namedXml=$failXml.Replace('<Event>','<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">').Replace('<Data>','<Data Name="Message">')
    $parsed=ConvertFrom-AgentEventXml $namedXml 'Application'
    Check ($parsed.Values.Count -eq 1 -and $parsed.Values[0] -ceq ('Staged hand-back failed for '+$id+'.') -and $parsed.Data.Count -eq 1 -and $parsed.Data.Message -ceq $parsed.Values[0]) 'Namespaced named EventData preserves both its text and field name.'
    $log=@{Status='OK';Before=@{Status='OK';NewestRecordId=1;NewestXml=$startXml};After=@{Status='OK';OldestRecordId=1;NewestRecordId=2;NewestXml=$failXml};Xmls=@($startXml,$failXml)}
    Check (Passed (Test-B01FailureAudit $log $id)) 'B01 exact-transfer product failure warning passes.'
    Check (Rejected (Test-B01FailureAudit $log 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')) 'B01 rejects unrelated transfer warning.'
    $second=@{Pid=102;Sid='S-1-5-21-1-2-3-1002';BootId='fixture';Elevated=$false;IsAdministrator=$false}
    $probe=@{Pid=102;Sid=$second.Sid;BootId='fixture';Token='probe';Calls=@()}
    $i=100
    foreach($kind in @('read','write','list')){$probe.Calls+=@{Class=$kind;Path=$(if($kind -ceq 'list'){'folder'}else{'H'});NativeCode=5;StartQpc=$i;EndQpc=($i+1)};$i+=10}
    Check (Passed (Test-CachedSecondUserDenial $probe $second $actor.Sid 'probe' 'H' 'folder' 90)) 'Second standard user read/write/list access-denied passes.'
    foreach($change in @('read','write','list','wrong-code','path','early','sid','token','missing')){
        $bad=Clone $probe
        switch($change){'read'{$bad.Calls[0].NativeCode=0}'write'{$bad.Calls[1].NativeCode=0}'list'{$bad.Calls[2].NativeCode=0}'wrong-code'{$bad.Calls[0].NativeCode=2}'path'{$bad.Calls[0].Path='other'}'early'{$bad.Calls[0].StartQpc=89}'sid'{$bad.Sid=$actor.Sid}'token'{$bad.Token='stale'}'missing'{$bad.Calls=@($bad.Calls[0],$bad.Calls[1])}}
        Check (Rejected (Test-CachedSecondUserDenial $bad $second $actor.Sid 'probe' 'H' 'folder' 90)) ('Second-user probe rejects '+$change+'.')
    }
    $badActor=Clone $second;$badActor.Elevated=$true
    Check (Rejected (Test-CachedSecondUserDenial $probe $badActor $actor.Sid 'probe' 'H' 'folder' 90)) 'Second-user probe rejects elevated actor.'
    foreach($name in @('Get-R01WriterBody','Get-B01WriterBody','Get-CachedSecondUserBody')){
        $body=& $name;$t=$null;$e=$null;$generated=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
        Check ($e.Count -eq 0) ($name+' generated actor parses.')
        if($name -ceq 'Get-R01WriterBody'){
            $attempts=@($generated.FindAll({param($node)$node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Extent.Text -clike '[[]SUWriter]::Attempt(*'},$true))
            Check (@($attempts | Where-Object {$_.Extent.Text -ceq '[SUWriter]::Attempt($config.R01OfflineTarget,$finalBytes,$true,0)'}).Count -eq 1) 'R01 generated actor uses the separate configured name with CREATE_NEW and the native write-access helper.'
        }
        if($name -cne 'Get-B01WriterBody'){
            $native=@($generated.FindAll({param($node)$node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -like '*public static class SU*'},$true))
            Check ($native.Count -eq 1) ($name+' has one native helper.')
            Add-Type -TypeDefinition $native[0].Value
        }
    }
    Import-Module (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') -Force -DisableNameChecking
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('rows-a-selfcheck-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($temp)
    try{
        $script:protectedDirectory=$temp;$path=Join-Path $temp 'cached.txt';$bytes=[Text.Encoding]::ASCII.GetBytes('AAAAAAAAAAAA');$digest=[StagedInvariant.Native]::Hash($bytes)
        [IO.File]::WriteAllBytes($path,$bytes);$artifact=@{Path=$path;Length=12;Sha256=$digest}
        $meta=@{Attributes=32;Creation=100;Modified=100;Changed=100;Accessed=100;Links=1}
        $identity=Clone $meta;$identity | Add-Member NoteProperty FileId 'id'
        $image=@{Role='Current';Path=$path;Absent=$false;Length=12;Sha256=$digest;LogicalArtifact=$artifact;Identity=$identity;RawMetadata=(Clone $meta);SecurityId=1;Sddl='fixture';
            Runs=@(@{Vcn=0;Lcn=10;Clusters=3});Containers=@(@{Kind='DATA';Offset=40;Length=12;Artifact=$artifact})}
        $parent=@{Role='Parent';Path=$temp;DirectoryEntries=@(@{Name='cached.txt';Reference=1;Eof=12;Attributes=32})}
        $baseline=@{Geometry=@{Cluster=4;Guid='volume'};Images=@($image,$parent)}
        $sample=@{Status='OK';Phase='OutcomeWait';Sequence=1;Captures=@(@{Images=@($image,$parent);Readers=@(@{Path=$path;Status='OK';Unbuffered=$false;Result=@{Digest=$digest;Length=12}},@{Path=$path;Status='OK';Unbuffered=$true;Result=@{Digest=$digest;Length=12}})});
            C01Readers=@(@{Status='OK';Unbuffered=$false;Result=@{Digest=$digest;Length=12}},@{Status='OK';Unbuffered=$true;Result=@{Digest=$digest;Length=12}})}
        Check (Passed (Test-R01OutcomeSample $sample $baseline $bytes)) 'R01 outcome exact whole A passes.'
        $bad=Clone $sample;$bad.Captures[0].Images[0].Sha256='other'
        Check (Rejected (Test-R01OutcomeSample $bad $baseline $bytes)) 'R01 outcome rejects raw different image.'
        $bad=Clone $sample;$bad.C01Readers[1].Result.Digest='other'
        Check (Rejected (Test-R01OutcomeSample $bad $baseline $bytes)) 'R01 outcome rejects uncached different image.'
        $absent=Clone $sample;$absent.Captures[0].Images[0].Absent=$true;$absent.C01Readers=@(@{Status='ERROR';NativeCode=2;Unbuffered=$false},@{Status='ERROR';NativeCode=2;Unbuffered=$true})
        Check (Passed (Test-R01OutcomeSample $absent $baseline $bytes)) 'R01 outcome absence passes.'
        $offlinePath=Join-Path $temp 'offline-new.txt'
        $offlineSample=Clone $sample;$offlineSample.Captures[0].Images+=@{Role='Current';Path=$offlinePath;Absent=$true}
        $offlineSample | Add-Member NoteProperty R01OfflineReaders @(@{Status='ERROR';NativeCode=2;Unbuffered=$false},@{Status='ERROR';NativeCode=2;Unbuffered=$true})
        $offlineBaseline=Clone $baseline;$offlineBaseline.Images[1].DirectoryEntries=@()
        Check (Passed (Test-R01OfflineAbsent $offlineSample $offlineBaseline $offlinePath)) 'R01 offline create-name raw/fresh/uncached absence passes even after cached.txt publication.'
        foreach($change in @('raw-present','raw-name-present','fresh-present','uncached-present','raw-missing','parent-missing','fresh-missing','uncached-wrong-code','capture-error')){
            $bad=Clone $offlineSample
            switch($change){
                'raw-present'{$bad.Captures[0].Images[2].Absent=$false}
                'raw-name-present'{$bad.Captures[0].Images[1].DirectoryEntries+=@{Name='offline-new.txt';Reference=2;Eof=12;Attributes=32}}
                'fresh-present'{$bad.R01OfflineReaders[0].Status='OK';$bad.R01OfflineReaders[0].NativeCode=0}
                'uncached-present'{$bad.R01OfflineReaders[1].Status='OK';$bad.R01OfflineReaders[1].NativeCode=0}
                'raw-missing'{$bad.Captures[0].Images=$bad.Captures[0].Images[0..1]}
                'parent-missing'{$bad.Captures[0].Images=@($bad.Captures[0].Images | Where-Object Role -cne 'Parent')}
                'fresh-missing'{$bad.R01OfflineReaders=@($bad.R01OfflineReaders[1])}
                'uncached-wrong-code'{$bad.R01OfflineReaders[1].NativeCode=5}
                'capture-error'{$bad.Status='ERROR'}
            }
            $result=Test-R01OfflineAbsent $bad $offlineBaseline $offlinePath
            Check (-not (Passed $result)) ('R01 offline create-name absence rejects '+$change+'.')
            if($change -clike '*present'){Check (Rejected $result) ('R01 offline created name present is FAIL: '+$change+'.')}
        }
        Check (Passed (Test-B01SentinelSample $sample $baseline $bytes)) 'B01 unchanged raw sentinel and independent readers pass.'
        foreach($change in @('raw','id','metadata','reader','new-temp')){
            $bad=Clone $sample
            switch($change){'raw'{$bad.Captures[0].Images[0].Sha256='other'}'id'{$bad.Captures[0].Images[0].Identity.FileId='other'}'metadata'{$bad.Captures[0].Images[0].RawMetadata.Modified=101}'reader'{$bad.Captures[0].Readers[0].Result.Digest='other'}'new-temp'{$bad.Captures[0].Images[1].DirectoryEntries+=@{Name='.safeupload.tmp';Reference=2;Eof=12;Attributes=32}}}
            Check (Rejected (Test-B01SentinelSample $bad $baseline $bytes)) ('B01 sentinel rejects '+$change+'.')
        }
    }finally{Remove-Item -LiteralPath $temp -Recurse -Force}
    'StagedInvariantRowsASelfCheck: checks='+$checks+'; PASS'
    exit 0
}catch{Write-Error $_;exit 1}
