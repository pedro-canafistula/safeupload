$ErrorActionPreference='Stop'
function Req([bool]$v,[string]$msg){if(-not $v){throw $msg}}
$guid='ff67c01b990e41ff9af89b5a9959757c'
$run='boot-start-w01-w01-b38b36-20261006c-'+$guid
$statePath='C:\Users\vika\Documents\SafeUpload-w01-state-'+$guid+'\state.clixml'
Req ($env:COMPUTERNAME -eq 'WIN10-DEBUGGED') 'Wrong guest name'
$uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
Req ($uuid -eq '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') 'Wrong guest UUID'
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
Req ($boot -eq '2026-10-06T14:50:37.5000000Z') 'Failed boot changed'
$hash=(Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
Req ($hash -eq '501E79475838293A134C81A2588C937C5EF98D0F2C55BA66FB79602AC721A1BC') 'State hash changed'
$s=Import-Clixml -LiteralPath $statePath
foreach($key in @('RunGuid','RunName','ChildStarted','AgentTouched','Frozen','Restored','RecoveryRequired','Inspectors')){Req ($s.ContainsKey($key)) ('Missing state key '+$key)}
Req ($s['RunGuid'] -eq $guid -and $s['RunName'] -eq $run) 'Wrong state identity'
foreach($key in @('ChildStarted','AgentTouched','Frozen','Restored')){Req ($s[$key] -is [bool] -and $s[$key] -eq $false) ('Unexpected state '+$key)}
Req ($s['RecoveryRequired'] -is [bool] -and $s['RecoveryRequired'] -eq $true) 'Not recovery required'
$task=Get-ScheduledTask -TaskName ('SafeUpload-W01Phase-'+$run+'-AfterBoot')
Req ($task.State.ToString() -eq 'Ready') 'Phase task still running'
Req (@($task.Actions).Count -eq 1) 'Unexpected phase task actions'
$action=$task.Actions[0]
$launcher='C:\Users\vika\Documents\w01-'+$guid+'-phase-AfterBoot.ps1'
$expectedArguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$launcher+'"'
Req ($action.Execute -eq 'powershell.exe' -and $action.Arguments -ceq $expectedArguments) 'Phase action mismatch'
Req ((Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash -eq 'DA6B3AC6886121FDB7C2898023F61C9BD944933159F03CB72DF97E83DA3B6CCA') 'Launcher hash mismatch'
Req ($task.Principal.UserId -in @('SYSTEM','S-1-5-18')) 'Task principal mismatch' 
$taskInfo=$task|Get-ScheduledTaskInfo
$all=@(Get-CimInstance Win32_Process)
$actors=@($all|Where-Object {$_.Name -eq 'SafeUpload.Agent.Service.exe' -or $_.Name -like '*w01*' -or ($_.CommandLine -and $_.CommandLine.Contains($guid))})
Req ($actors.Count -eq 0) 'W01 actors remain'
$inspectors=@($s['Inspectors']); Req ($inspectors.Count -eq 2) 'Inspector count differs'
$exits=@()
foreach($i in $inspectors){
 Req ($i.Status -eq 'Exited' -and $i.TimedOut -eq $false -and $null -ne $i.CreationDate -and $i.ParentProcessId -eq 4212) 'Inspector exit proof incomplete'
 Req ($i.Executable -eq ('C:\Users\vika\Documents\w01-'+$guid+'-inspector-feature-release.exe') -and $i.ObservedCommandLine.Contains($i.ArgumentList)) 'Inspector executable or command mismatch'
 $current=@($all|Where-Object {$_.ProcessId -eq $i.ProcessId})
 $same=@($current|Where-Object {$_.CreationDate.ToUniversalTime() -eq $i.CreationDate.ToUniversalTime()})
 Req ($same.Count -eq 0) 'Original inspector still running'
 $exits+= [ordered]@{PID=$i.ProcessId;Birth=$i.CreationDate.ToUniversalTime().ToString('o');Executable=$i.Executable;CommandLine=$i.ObservedCommandLine;ExitCode=$i.ExitCode;Status=$i.Status;SameInstanceStillRunning=$false;CurrentPidInstances=@($current|Select-Object ProcessId,CreationDate,Name,CommandLine)}
}
Req (@($all|Where-Object {$_.ProcessId -eq 4212}).Count -eq 0) 'Recorded phase process remains'
$services=@(Get-CimInstance Win32_SystemDriver|Where-Object {$_.Name -in @('SafeUpload','SafeUploadSectionFault')}|Select-Object Name,State,StartMode)
Req ($services.Count -eq 2) 'Missing upper/lower'
Req (@($services|Where-Object {$_.Name -eq 'SafeUpload' -and $_.State -eq 'Running' -and $_.StartMode -eq 'Boot'}).Count -eq 1) 'Upper differs'
Req (@($services|Where-Object {$_.Name -eq 'SafeUploadSectionFault' -and $_.State -eq 'Running' -and $_.StartMode -eq 'Manual'}).Count -eq 1) 'Lower differs'
[ordered]@{UTC=[DateTime]::UtcNow.ToString('o');GuestUUID=$uuid;BootId=$boot;RunGuid=$guid;StateSHA256=$hash;TaskName=$task.TaskName;TaskState=$task.State.ToString();TaskAction=$action|Select-Object Execute,Arguments;TaskLastRunTime=$taskInfo.LastRunTime;TaskLastTaskResult=$taskInfo.LastTaskResult;W01Actors=$actors.Count;Inspectors=$exits;RecordedPhaseParentPID=4212;RecordedPhaseParentStillPresent=$false;Services=$services;KernelGlobalPortEnumeration=$false;PreRecoveryGuestGuardsPassed=$true}|ConvertTo-Json -Depth 10
Write-Output 'Run3PreRecoveryGuestGuards=True'
