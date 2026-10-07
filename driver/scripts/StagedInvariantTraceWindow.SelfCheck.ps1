#requires -Version 5.1
# Diagnostic collector and task-boundary regression controls. No guest I/O,
# driver, service or real scheduled task; these never qualify a workload.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
foreach($name in @('Register-SystemTask','Get-ActivationQuiescedWriteTrace','ConvertFrom-ActivationTrace')){
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
$script:calls=@();$script:disableFailure=$false;$script:ack='admission trace disable: OK'
$fileId='0000000000000000000000000000002a'
function New-Trace([long]$Lost=0,[long]$Cursor=3){
    return (@{sequence=1;event='w_begin';fileId=$fileId;ticketSequence=7;writeOffset=64;writeLength=96;targetFileObject='0x123'} | ConvertTo-Json -Compress)+"`n"+
        (@{sequence=2;event='w_end';fileId=$fileId;ticketSequence=7;writeOffset=64;writeLength=96;ioStatus='0x00000000';completionFlags='0x00000001'} | ConvertTo-Json -Compress)+"`n"+
        (@{summary=$true;lostEntries=$Lost;cursor=$Cursor;snapshotSequence=2} | ConvertTo-Json -Compress)
}
$script:trace=New-Trace
function Invoke-ActivationInspector([string]$Argument,[string]$Prefix,[int]$Timeout){
    $script:calls+= $Argument
    if($Argument -ceq '--admission-trace-disable'){
        if($script:disableFailure){throw 'Synthetic outstanding W ticket'}
        return $script:ack
    }
    if($Argument -ceq '--admission-trace'){return $script:trace}
    throw 'Unexpected diagnostic operation'
}
$result=Get-ActivationQuiescedWriteTrace $fileId
Check (($calls -join ',') -ceq '--admission-trace-disable,--admission-trace') 'Disable/drain must precede reading the snapshot'
Check ($result.CompletedWritePairs.Count -eq 1 -and $result.Summary.lostEntries -eq 0) 'Exact successful lower write pair remains required'
$script:calls=@();$script:disableFailure=$true
Refuses {Get-ActivationQuiescedWriteTrace $fileId} 'Outstanding W ticket cannot qualify a frozen trace'
Check (($calls -join ',') -ceq '--admission-trace-disable') 'Failed disable must not read a live trace'
$script:disableFailure=$false;$script:ack='unrecognized acknowledgment';$script:calls=@()
Refuses {Get-ActivationQuiescedWriteTrace $fileId} 'Missing disable acknowledgment cannot qualify'
Check ($calls.Count -eq 1) 'Missing acknowledgment cannot proceed to snapshot'
$script:ack='admission trace disable: OK';$script:trace=New-Trace 1
Refuses {Get-ActivationQuiescedWriteTrace $fileId} 'Trace loss stays fatal'
$script:trace=New-Trace 0 2
Refuses {Get-ActivationQuiescedWriteTrace $fileId} 'Incomplete snapshot stays fatal'
$script:trace='malformed'
Refuses {Get-ActivationQuiescedWriteTrace $fileId} 'Malformed evidence stays fatal'
'TraceWindowSelfCheck=PASS;Controls='+$checks+';Qualification=False'
