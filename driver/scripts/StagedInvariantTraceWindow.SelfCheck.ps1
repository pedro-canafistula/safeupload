#requires -Version 5.1
# Diagnostic collector and task-boundary regression controls. No guest I/O,
# driver, service or real scheduled task; these never qualify a workload.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
foreach($name in @('Register-SystemTask','Invoke-ActivationTraceControlUntilAcknowledged','Get-ActivationQuiescedWriteTrace','ConvertFrom-ActivationTrace','Get-ActivationFileObjectLifetimeEvents','Test-ActivationDuplicateCleanup')){
    $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($definitions.Count -ne 1){throw ('Missing/ambiguous function: '+$name)}
    Invoke-Expression $definitions[0].Extent.Text
}
$checks=0
function Check([bool]$Condition,[string]$Label){if(-not $Condition){throw $Label};$script:checks++}
function Refuses([scriptblock]$Body,[string]$Label){$rejected=$false;try{$null=& $Body}catch{$rejected=$true};Check $rejected $Label}
function Get-ScheduledTask {param($TaskName,$ErrorAction) return $null}
function New-ScheduledTaskAction {param($Execute,$Argument) return @{Execute=$Execute;Argument=$Argument}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) return @{User=$UserId}}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit) return @{Limit=$ExecutionTimeLimit}}
function New-ScheduledTaskTrigger {param([switch]$AtStartup) return @{AtStartup=[bool]$AtStartup}}
function Register-ScheduledTask {param($TaskName,$Action,$Principal,$Settings,$Trigger) $script:registration=@{Name=$TaskName;Settings=$Settings;Trigger=$Trigger}}
foreach($minutes in @(0,15,240)){
    Register-SystemTask 'synthetic' 'synthetic.ps1' -AtStartup -ExecutionMinutes $minutes
    Check ($registration.Settings.Limit.TotalMinutes -eq $minutes -and $registration.Trigger.AtStartup) ('Task duration bound '+$minutes)
}
Refuses {Register-SystemTask 'synthetic' 'synthetic.ps1' -ExecutionMinutes -1} 'Negative task duration must fail'
Refuses {Register-SystemTask 'synthetic' 'synthetic.ps1' -ExecutionMinutes 241} 'Out-of-range task duration must fail'
$evidenceDirectory=[IO.Path]::GetTempPath()
$script:calls=@();$script:disableFailure=$false;$script:disableBusyRemaining=0;$script:ack='admission trace disable: OK';$script:writtenPaths=@()
$fileId='0000000000000000000000000000002a'
$targetFileObject='0xFFFF9989170B10C0'
function New-Trace([long]$Lost=0,[long]$Cursor=3){
    return (@{sequence=1;event='w_begin';fileId=$fileId;ticketSequence=7;writeOffset=64;writeLength=96;targetFileObject=$targetFileObject} | ConvertTo-Json -Compress)+"`n"+
        (@{sequence=2;event='w_end';fileId=$fileId;ticketSequence=7;writeOffset=64;writeLength=96;ioStatus='0x00000000';completionFlags='0x00000001'} | ConvertTo-Json -Compress)+"`n"+
        (@{summary=$true;lostEntries=$Lost;cursor=$Cursor;snapshotSequence=2} | ConvertTo-Json -Compress)
}
$script:trace=New-Trace
function Invoke-ActivationInspector([string]$Argument,[string]$Prefix,[int]$Timeout){
    $script:calls+= $Argument
    if($Argument -ceq '--admission-trace-disable'){
        if($script:disableFailure -or $script:disableBusyRemaining -gt 0){
            if($script:disableBusyRemaining -gt 0){$script:disableBusyRemaining--}
            $path=$Prefix+'.out';[IO.File]::WriteAllText($path,'ERRO: trace disable refused (hr = 0x800700AA).');$script:writtenPaths+=@($path)
            throw 'Child process failed: 3; synthetic outstanding W ticket'
        }
        return $script:ack
    }
    if($Argument -ceq '--admission-trace'){return $script:trace}
    throw 'Unexpected diagnostic operation'
}
$tracePrefix=Join-Path $evidenceDirectory ('trace-window-selfcheck-'+[guid]::NewGuid().ToString('N'))
$script:disableBusyRemaining=1
$result=Get-ActivationQuiescedWriteTrace $fileId ($tracePrefix+'-capture')
Check (($calls -join ',') -ceq '--admission-trace-disable,--admission-trace-disable,--admission-trace') 'One busy W-ticket response retries disable, then freezes before reading the snapshot'
Check ($result.CompletedWritePairs.Count -eq 1 -and $result.Summary.lostEntries -eq 0) 'Exact successful lower write pair remains required'
$script:calls=@();$script:disableFailure=$true
Refuses {Get-ActivationQuiescedWriteTrace $fileId ($tracePrefix+'-busy')} 'Persistent outstanding W ticket cannot qualify a frozen trace'
Check ($calls.Count -eq 8 -and @($calls | Where-Object {$_ -ceq '--admission-trace-disable'}).Count -eq 8) 'Busy retries remain bounded and never read a live trace'
$script:disableFailure=$false;$script:ack='unrecognized acknowledgment';$script:calls=@()
Refuses {Get-ActivationQuiescedWriteTrace $fileId ($tracePrefix+'-bad-ack')} 'Missing disable acknowledgment cannot qualify'
Check ($calls.Count -eq 1) 'Missing acknowledgment cannot proceed to snapshot'
$script:ack='admission trace disable: OK';$script:trace=New-Trace 1
Refuses {Get-ActivationQuiescedWriteTrace $fileId ($tracePrefix+'-loss')} 'Trace loss stays fatal'
$script:trace=New-Trace 0 2
$script:calls=@();Refuses {Get-ActivationQuiescedWriteTrace $fileId ($tracePrefix+'-incomplete')} 'Incomplete snapshot stays fatal'
$script:trace='malformed'
Refuses {Get-ActivationQuiescedWriteTrace $fileId ($tracePrefix+'-malformed')} 'Malformed evidence stays fatal'
$lifetime=[pscustomobject]@{Entries=@();AllEntries=@(
    @{sequence=1;event='file_cleanup';targetFileObject=$targetFileObject.ToLowerInvariant();pid=200},
    @{sequence=2;event='file_close';targetFileObject=$targetFileObject;pid=200},
    @{sequence=3;event='file_cleanup';targetFileObject='0xFFFF9989170B10C1';pid=201})}
$targetLifetime=@(Get-ActivationFileObjectLifetimeEvents $lifetime $targetFileObject)
Check ($targetLifetime.Count -eq 2 -and @($targetLifetime | Where-Object event -ceq 'file_cleanup').Count -eq 1) 'Lifetime filter keeps only cleanup/close for the trusted physical file object'
Refuses {Get-ActivationFileObjectLifetimeEvents $lifetime '0x123'} 'Malformed trusted physical file object cannot filter lifetime evidence'
$oldWrites=@{CompletedWritePairs=@(@{Begin=@{targetFileObject=$targetFileObject}})}
$child=@{Pid=200;BootId='synthetic-boot'};$release=@{NativeCode=0;HolderReleased=$true;Pid=200;BootId='synthetic-boot'}
$cleanupProof=Test-ActivationDuplicateCleanup $lifetime $oldWrites $child $release
Check ($cleanupProof.Verdict -ceq 'PASS') 'Unrelated global cleanups do not mask the exact target final cleanup'
$noTargetCleanup=[pscustomobject]@{Entries=@();AllEntries=@(@{event='file_cleanup';targetFileObject='0xFFFF9989170B10C1';pid=200})}
Check ((Test-ActivationDuplicateCleanup $noTargetCleanup $oldWrites $child $release).Verdict -cne 'PASS') 'Missing target physical-object cleanup cannot pass'
$duplicateCleanup=[pscustomobject]@{Entries=@();AllEntries=@(@{event='file_cleanup';targetFileObject=$targetFileObject;pid=200},@{event='file_cleanup';targetFileObject=$targetFileObject;pid=200})}
Check ((Test-ActivationDuplicateCleanup $duplicateCleanup $oldWrites $child $release).Verdict -cne 'PASS') 'Duplicate target cleanup cannot pass'
$wrongPid=[pscustomobject]@{Entries=@();AllEntries=@(@{event='file_cleanup';targetFileObject=$targetFileObject;pid=201})}
Check ((Test-ActivationDuplicateCleanup $wrongPid $oldWrites $child $release).Verdict -cne 'PASS') 'Wrong-process target cleanup cannot pass'
foreach($path in $script:writtenPaths){Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue}
'TraceWindowSelfCheck=PASS;Controls='+$checks+';Qualification=False'
