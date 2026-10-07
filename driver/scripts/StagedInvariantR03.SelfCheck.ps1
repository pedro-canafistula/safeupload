# Pure R03 receipt/evaluation controls; no guest, service, driver or protected I/O.
# Included automatically by Invoke-HarnessWindowsGate.sh on Windows PowerShell 5.1.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
try {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($name in @('Test-R03OfflineCalls','Test-R03ServiceReady','Test-R03HandBackAbsent','Test-R03BaseSample','Test-R03OutcomeSample','Get-R03WriterBody','Get-B02JustificationClientBody','Get-WriterBody','Get-ExpectedCheckpoint','Test-CachedImage')){
        $defs=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
        if($defs.Count -ne 1){throw ('Missing/ambiguous R03 function: '+$name)}
        Invoke-Expression ($defs[0].Extent.Text.Replace(('function '+$name),('function script:'+$name)))
    }
    $checks=0
    function Check([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason};$script:checks++}
    function Clone($Value){return ($Value | ConvertTo-Json -Depth 32 | ConvertFrom-Json)}
    $actor=@{Pid=101;Sid='S-1-5-21-1-2-3-1001';BootId='fixture';HandBackBefore=@()}
    $ready=@{BootId='fixture';Qpc=10;QpcFrequency=1000}
    $recorded=@{Pid=101;Sid=$actor.Sid;BootId='fixture';Token='token';Readiness=$ready;RecordedQpc=20;Qpc=21;AgentStart=4}
    $receipt=@{Pid=101;Sid=$actor.Sid;BootId='fixture';Token='token';Readiness=$ready;ReadinessRecordedQpc=20;AgentStart=4;CompletedQpc=60;HandBackAfter=@();
        Attempts=@(@{Action='overwrite-B';Path='B';Calls=@(@{Class='writer-open';NativeCode=5;StartQpc=30;EndQpc=40})},@{Action='create-N';Path='N';Calls=@(@{Class='writer-open';NativeCode=5;StartQpc=50;EndQpc=60})})}
    $result=Test-R03OfflineCalls $receipt $actor $ready 'token' 'B' 'N' $recorded
    Check (@($result | Where-Object Verdict -cne 'PASS').Count -eq 0) 'R03 exact two denials after durable readiness pass.'
    foreach($change in @('admitted','write','wrong-path','wrong-sid','early','overlap','wrong-token','missing-readiness','enabled-agent')){
        $bad=Clone $receipt;$badRecorded=Clone $recorded
        switch($change){
            'admitted' {$bad.Attempts[0].Calls[0].NativeCode=0}
            'write' {$bad.Attempts[1].Calls+=@{Class='cached-write';NativeCode=0;StartQpc=61;EndQpc=62}}
            'wrong-path' {$bad.Attempts[1].Path='other'}
            'wrong-sid' {$bad.Sid='S-1-5-21-1-2-3-1002'}
            'early' {$bad.Attempts[0].Calls[0].StartQpc=19}
            'overlap' {$bad.Attempts[1].Calls[0].StartQpc=39}
            'wrong-token' {$bad.Token='stale'}
            'missing-readiness' {$badRecorded=$null}
            'enabled-agent' {$badRecorded.AgentStart=3}
        }
        Check (@(Test-R03OfflineCalls $bad $actor $ready 'token' 'B' 'N' $badRecorded | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) ('R03 rejects '+$change+'.')
    }
    $status=@{Status='OK';ServerPid=202;ServerSid='S-1-5-18';Value=@{protectionActive=$true;admissionCoverage='Ready';nativePolicyGeneration=3}}
    Check ((Test-R03ServiceReady $status 202).Verdict -ceq 'PASS') 'R03 actual SYSTEM agent Ready receipt passes.'
    foreach($change in @('pending','wrong-pid','wrong-sid','inactive','no-generation')){
        $bad=Clone $status
        switch($change){'pending'{$bad.Value.admissionCoverage='Pending'}'wrong-pid'{$bad.ServerPid=203}'wrong-sid'{$bad.ServerSid=$actor.Sid}'inactive'{$bad.Value.protectionActive=$false}'no-generation'{$bad.Value.nativePolicyGeneration=0}}
        Check ((Test-R03ServiceReady $bad 202).Verdict -ceq 'FAIL') ('R03 rejects Ready receipt '+$change+'.')
    }
    Check ((Test-R03HandBackAbsent $actor $receipt).Verdict -ceq 'PASS') 'R03 empty before/after hand-back inventories pass.'
    $bad=Clone $receipt;$bad.HandBackAfter=@(@{Path='unexpected-H'})
    Check ((Test-R03HandBackAbsent $actor $bad).Verdict -ceq 'FAIL') 'R03 rejects offline hand-back.'
    $body=Get-R03WriterBody
    $writerTokens=$null;$writerErrors=$null
    [void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$writerTokens,[ref]$writerErrors)
    Check ($writerErrors.Count -eq 0) 'R03 generated standard-user writer parses.'
    $readinessBeforeMutations=$body.IndexOf("Save-ActorReceipt 'r03-readiness-recorded.clixml'") -lt $body.IndexOf('foreach($mutation')
    $offlineClosedBeforeGo=$body.IndexOf("Save-ActorReceipt 'r03-offline-closed.clixml'") -lt $body.IndexOf("while(-not(Test-Path -LiteralPath '__GO__'))")
    Check ($readinessBeforeMutations -and $offlineClosedBeforeGo) 'R03 durably records readiness, denies offline writes, then waits for fresh-save go.'
    Import-Module (Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1') -Force -DisableNameChecking
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('r03-selfcheck-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($temp)
    try{
        $script:protectedDirectory=$temp;$path=Join-Path $temp 'marker.bin';$bytes=[Text.Encoding]::ASCII.GetBytes('BBBBBBBBBBBB');$digest=[StagedInvariant.Native]::Hash($bytes)
        [IO.File]::WriteAllBytes($path,$bytes);$artifact=@{Path=$path;Length=12;Sha256=$digest}
        $meta=@{Attributes=32;Creation=100;Modified=100;Changed=100;Accessed=100;Links=1}
        $identity=Clone $meta;$identity | Add-Member NoteProperty FileId 'B-id'
        $image=[pscustomobject]@{Role='Current';Path=$path;Absent=$false;Length=12;Sha256=$digest;LogicalArtifact=$artifact;Identity=$identity;RawMetadata=(Clone $meta);SecurityId=1;Sddl='fixture';
            Runs=@(@{Vcn=0;Lcn=10;Clusters=3});Containers=@(@{Kind='DATA';Offset=40;Length=12;Artifact=$artifact})}
        $baseline=@{Geometry=@{Cluster=4;Guid='volume'};Images=@($image);CaptureStartedFileTime=1}
        $script:row=@{ExpectedTimeline=@('setup','boot','ProtectedAgentAbsent');MetadataExpectations=@{Accessed='Exact';AccessReason='fixture'}}
        $sample=@{Status='OK';Phase='FinalQuiescence';Sequence=1;Captures=@(@{Images=@($image);Readers=@(@{Path=$path;Status='OK';Unbuffered=$false;Result=@{Digest=$digest;Length=12}},@{Path=$path;Status='OK';Unbuffered=$true;Result=@{Digest=$digest;Length=12}})})}
        Check (@(Test-R03BaseSample $sample $baseline $bytes @{} | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'R03 raw extents, B identity/metadata and both independent readers pass.'
        foreach($change in @('identity','metadata','reader','bytes')){
            $bad=Clone $sample
            switch($change){'identity'{$bad.Captures[0].Images[0].Identity.FileId='different'}'metadata'{$bad.Captures[0].Images[0].RawMetadata.Modified=101}'reader'{$bad.Captures[0].Readers[0].Result.Digest='wrong'}'bytes'{$bad.Captures[0].Images[0].Sha256='wrong'}}
            Check (@(Test-R03BaseSample $bad $baseline $bytes @{} | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) ('R03 rejects B '+$change+'.')
        }
        $n=Clone $image;$n.Path=Join-Path $temp 'cached.txt'
        $outcome=@{Status='OK';Captures=@(@{Images=@($n)});C01Readers=@(@{Status='OK';Unbuffered=$false;Result=@{Digest=$digest;Length=12}},@{Status='OK';Unbuffered=$true;Result=@{Digest=$digest;Length=12}})}
        Check (@(Test-R03OutcomeSample $outcome $baseline $bytes | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'R03 outcome raw/fresh/uncached whole A passes.'
        $absent=Clone $outcome;$absent.Captures[0].Images[0].Absent=$true;$absent.C01Readers=@(@{Status='ERROR';NativeCode=2;Unbuffered=$false},@{Status='ERROR';NativeCode=2;Unbuffered=$true})
        Check (@(Test-R03OutcomeSample $absent $baseline $bytes | ForEach-Object {$_} | Where-Object Verdict -cne 'PASS').Count -eq 0) 'R03 outcome absence passes before release.'
        $bad=Clone $outcome;$bad.C01Readers[1].Result.Digest='wrong'
        Check (@(Test-R03OutcomeSample $bad $baseline $bytes | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'R03 rejects a different outcome reader image.'
        $bad=Clone $outcome;$bad.Captures[0].Images[0].Sha256='wrong'
        Check (@(Test-R03OutcomeSample $bad $baseline $bytes | ForEach-Object {$_} | Where-Object Verdict -ceq 'FAIL').Count -gt 0) 'R03 rejects a different raw outcome image.'
    }finally{Remove-Item -LiteralPath $temp -Recurse -Force}
    'StagedInvariantR03SelfCheck: checks='+$checks+'; PASS'
    exit 0
}catch{Write-Error $_;exit 1}
