#requires -Version 5.1
# Pure evaluator negative controls and generated actor syntax/native declarations.
# No product service, autologon mutation, protected write or qualification.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
foreach($name in @('Load-State','Get-ActivatingWriterBody','Get-R02WriterBody','Get-B02WriterBody','Initialize-InvariantWts','Test-R02Held','Test-R02Protected','Test-R02Pending','Test-InvariantInteractiveActor','Test-B02Window','Test-B02Versions','Test-B02Notifications')){
    $fn=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($fn.Count -ne 1){throw ('Unique function unavailable: '+$name)};Invoke-Expression $fn[0].Extent.Text
}
$count=0
function Assert-Control([bool]$Good,[string]$Label){if(-not $Good){throw ('Restart/justification control failed: '+$Label)};$script:count++}
function Copy-Fixture($Value){return [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($Value,32))}
$id='0000000000000000000000000000002a';$nt='\Device\HarddiskVolume3\Y\marker.txt'
$held=@{Entries=@(@{fileId=$id;path=$nt;state='Activating';generation=3;H=1;W=0;unknownReasons='0x00000000';openerPids=@(123)});Snapshot=@{Record=@{policyGeneration=9}}}
Assert-Control ((Test-R02Held $held $id $nt 123 9).Verdict -ceq 'PASS') 'exact held Y'
foreach($field in @('fileId','path','state','H','W','unknownReasons','openerPids','policyGeneration','missingW','duplicate')){
    $bad=Copy-Fixture $held
    switch($field){
        'fileId' {$bad.Entries[0].fileId='wrong'} 'path' {$bad.Entries[0].path='wrong'} 'state' {$bad.Entries[0].state='Protected'}
        'H' {$bad.Entries[0].H=0} 'W' {$bad.Entries[0].W=1} 'unknownReasons' {$bad.Entries[0].unknownReasons='0x00000001'}
        'openerPids' {$bad.Entries[0].openerPids=@(456)} 'policyGeneration' {$bad.Snapshot.Record.policyGeneration=8}
        'missingW' {$bad.Entries[0].Remove('W')} 'duplicate' {$bad.Entries+=@($bad.Entries[0])}
    }
    Assert-Control ((Test-R02Held $bad $id $nt 123 9).Verdict -ceq 'FAIL') ('reject held '+$field)
}
$protected=@{registryEntry=$true;historyPresent=$true;nameMatches=$true;fileId=$id;state='Protected';free=$true;H=0;S='NO';C=0;T=0;unknownReasons='0x00000000'}
Assert-Control ((Test-R02Protected $protected $id -RequireFree).Verdict -ceq 'PASS') 'exact Free/Protected'
$bootProtected=Copy-Fixture $protected;$bootProtected.historyPresent=$false
Assert-Control ((Test-R02Protected $bootProtected $id).Verdict -ceq 'PASS') 'protected boot X without manufactured holder history'
Assert-Control ((Test-R02Protected $bootProtected $id -RequireFree).Verdict -ceq 'FAIL') 'Y promotion requires actual holder history'
foreach($field in @('registryEntry','historyPresent','nameMatches','fileId','state','free','H','S','C','T','unknownReasons','missingH')){
    $bad=Copy-Fixture $protected
    switch($field){
        'registryEntry' {$bad.registryEntry=$false} 'historyPresent' {$bad.historyPresent=$false} 'nameMatches' {$bad.nameMatches=$false}
        'fileId' {$bad.fileId='wrong'} 'state' {$bad.state='Activating'} 'free' {$bad.free=$false} 'H' {$bad.H=1} 'S' {$bad.S='Unknown'}
        'C' {$bad.C=1} 'T' {$bad.T=1} 'unknownReasons' {$bad.unknownReasons='0x00000001'} 'missingH' {$bad.Remove('H')}
    }
    Assert-Control ((Test-R02Protected $bad $id -RequireFree).Verdict -ceq 'FAIL') ('reject promotion '+$field)
}
$status=@{Status='OK';ServerSid='S-1-5-18';Value=@{protectionActive=$true;nativePolicyGeneration=9;admissionCoverage='Pending'}}
Assert-Control ((Test-R02Pending $status 9).Verdict -ceq 'PASS') 'authenticated Pending'
foreach($field in @('Status','ServerSid','protectionActive','nativePolicyGeneration','admissionCoverage')){
    $bad=Copy-Fixture $status
    switch($field){'Status' {$bad.Status='INCONCLUSIVE'} 'ServerSid' {$bad.ServerSid='other'} 'protectionActive' {$bad.Value.protectionActive=$false} 'nativePolicyGeneration' {$bad.Value.nativePolicyGeneration=8} 'admissionCoverage' {$bad.Value.admissionCoverage='Ready'}}
    Assert-Control ((Test-R02Pending $bad 9).Verdict -ceq 'FAIL') ('reject status '+$field)
}
$sid='S-1-5-21-1-2-3-1001';$session=@{State=0;SessionId=2;TokenSessionId=2;Sid=$sid}
$actor=@{Pid=123;SessionId=2;Sid=$sid;OwnerSid=$sid;Elevated=$false;IsAdministrator=$false}
Assert-Control ((Test-InvariantInteractiveActor $session $actor).Verdict -ceq 'PASS') 'owning limited interactive token'
foreach($field in @('State','SessionId','TokenSessionId','Sid')){
    $bad=Copy-Fixture $session;switch($field){'State' {$bad.State=4} 'SessionId' {$bad.SessionId=0} 'TokenSessionId' {$bad.TokenSessionId=3} 'Sid' {$bad.Sid='wrong'}}
    Assert-Control ((Test-InvariantInteractiveActor $bad $actor).Verdict -ceq 'FAIL') ('reject WTS '+$field)
}
foreach($field in @('SessionId','Sid','OwnerSid','Elevated','IsAdministrator')){
    $bad=Copy-Fixture $actor;switch($field){'SessionId' {$bad.SessionId=0} 'Sid' {$bad.Sid='wrong'} 'OwnerSid' {$bad.OwnerSid='wrong'} 'Elevated' {$bad.Elevated=$true} 'IsAdministrator' {$bad.IsAdministrator=$true}}
    Assert-Control ((Test-InvariantInteractiveActor $session $bad).Verdict -ceq 'FAIL') ('reject actor '+$field)
}
$d1='A'*64;$d2='B'*64
$window=@{StateName='Blocked';SealedOnce=$true;Sha256Hex=$d1;Manifest=@{JustificationWindowClosed=$false;JustificationExpiresAtUtc='2026-10-07T12:00:00Z';BlockedPolicyVersion=1;HandbackState=2;Sha256Hex=$d1;HandbackPath='C:\Users\su\SafeUpload\_bloqueados\v1.txt';Transfer=@{SessionId=2;RequestorSid=$sid;ProcessId=123}}}
Assert-Control ((Test-B02Window $window $actor $d1).Verdict -ceq 'PASS') 'product open window and verified hand-back'
foreach($field in @('closed','missingExpiry','badHandback','wrongDigest','wrongSid','wrongSession','wrongPid')){
    $bad=Copy-Fixture $window
    switch($field){'closed' {$bad.Manifest.JustificationWindowClosed=$true} 'missingExpiry' {$bad.Manifest.Remove('JustificationExpiresAtUtc')} 'badHandback' {$bad.Manifest.HandbackState=3} 'wrongDigest' {$bad.Sha256Hex=$d2} 'wrongSid' {$bad.Manifest.Transfer.RequestorSid='wrong'} 'wrongSession' {$bad.Manifest.Transfer.SessionId=0} 'wrongPid' {$bad.Manifest.Transfer.ProcessId=456}}
    Assert-Control ((Test-B02Window $bad $actor $d1).Verdict -ceq 'FAIL') ('reject window '+$field)
}
$first=@{StateName='Blocked';TransferId='11111111-1111-1111-1111-111111111111';DestinationGeneration=1;SealedOnce=$true;Sha256Hex=$d1;History=@('Allocated','Sealed','Inspecting','Blocked')}
$latest=@{StateName='Released';TransferId='22222222-2222-2222-2222-222222222222';DestinationGeneration=2;SealedOnce=$true;Sha256Hex=$d2;History=@('Allocated','Sealed','Inspecting','Blocked','Inspecting','Approved','Publishing','Released')}
$checks=Test-B02Versions $first $latest $d1 $d2
Assert-Control (@($checks | Where-Object Verdict -cne 'PASS').Count -eq 0) 'exact two-version histories'
foreach($field in @('sameId','sameGeneration','v1Released','v2WrongDigest','doubleRelease','noBlock')){
    $a=Copy-Fixture $first;$b=Copy-Fixture $latest
    switch($field){'sameId' {$b.TransferId=$a.TransferId} 'sameGeneration' {$b.DestinationGeneration=1} 'v1Released' {$a.History+=@('Released')} 'v2WrongDigest' {$b.Sha256Hex=$d1} 'doubleRelease' {$b.History+=@('Released')} 'noBlock' {$b.History=@('Allocated','Sealed','Inspecting','Approved','Publishing','Released')}}
    $checks=Test-B02Versions $a $b $d1 $d2
    Assert-Control (@($checks | Where-Object Verdict -ceq 'FAIL').Count -gt 0) ('reject versions '+$field)
}
$proof=@{Complete=$true;Emissions=@(@{Entry=@{Kind='Transfer';TransferId=$first.TransferId;Phase='Blocked';TargetSessionId=2;Sha256Hex=$d1;Sequence=10}},@{Entry=@{Kind='Transfer';TransferId=$latest.TransferId;Phase='Blocked';TargetSessionId=2;Sha256Hex=$d2;Sequence=20}},@{Entry=@{Kind='Transfer';TransferId=$latest.TransferId;Phase='Released';TargetSessionId=2;Sha256Hex=$d2;Sequence=30}})}
Assert-Control ((Test-B02Notifications $proof $first.TransferId $latest.TransferId 2 $d1 $d2).Verdict -ceq 'PASS') 'exact owner notifications'
foreach($field in @('gap','wrongSession','wrongDigest','v1Release','doubleRelease','wrongOrder')){
    $bad=Copy-Fixture $proof
    switch($field){'gap' {$bad.Complete=$false} 'wrongSession' {$bad.Emissions[2].Entry.TargetSessionId=3} 'wrongDigest' {$bad.Emissions[2].Entry.Sha256Hex=$d1} 'v1Release' {$bad.Emissions[2].Entry.TransferId=$first.TransferId} 'doubleRelease' {$bad.Emissions+=@($bad.Emissions[2])} 'wrongOrder' {$bad.Emissions[2].Entry.Sequence=15}}
    Assert-Control ((Test-B02Notifications $bad $first.TransferId $latest.TransferId 2 $d1 $d2).Verdict -cne 'PASS') ('reject notification '+$field)
}
foreach($body in @((Get-R02WriterBody),(Get-B02WriterBody))){
    $e=$null;$t=$null;$generated=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$t,[ref]$e)
    Assert-Control ($e.Count -eq 0) 'generated actor parses in PS5.1'
}
# Compile only the declarations from the generated B02 actor, without running it.
$e=$null;$t=$null;$generated=[Management.Automation.Language.Parser]::ParseInput((Get-B02WriterBody),[ref]$t,[ref]$e)
$declaration=@($generated.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Add-Type'},$true))
Assert-Control ($declaration.Count -eq 1) 'one generated native declaration'
Invoke-Expression $declaration[0].Extent.Text
Initialize-InvariantWts
Assert-Control ($null -ne ('SUInvariantWts' -as [type]) -and $null -ne ('SUActivationNative' -as [type])) 'Framework native declarations compile'
'StagedInvariantRestartJustificationControls='+$count
'SelfCheck=PASS'
