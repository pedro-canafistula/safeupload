<# Start the real approval harness in the already signed-in disposable VM session.
   SSH runs in Session 0; use an InteractiveToken task and redirected child output.
   After completion, collect the logs and unregister the exact task below. #>
param([int] $ExpectedSession=1)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$documents='C:\Users\vika\Documents'
$taskName='SafeUpload-StagedTest-InteractiveApproval'
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash C:\Windows\System32\drivers\SafeUpload.sys).Hash -ne
    'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
if(@(Get-Process SafeUpload.Agent.App -ErrorAction SilentlyContinue).Count){throw 'Existing app must not be disturbed.'}
if(-not @(Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $ExpectedSession).Count){throw 'Expected signed-in desktop is absent.'}
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Previous approval task must be inspected first.'}
if(Test-Path (Join-Path $documents 'wpf-interactive-approval-result.json')){throw 'Collect and archive the previous approval result before starting another run.'}
$launcher=Join-Path $documents 'wpf-interactive-approval-launcher.ps1'
$text=@'
param([int] $ExpectedSession)
$ErrorActionPreference='Stop'
$documents='C:\Users\vika\Documents'
$exitCode=1
$process=$null
$childId=$null
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
$env:SAFEUPLOAD_STAGED_VERIFIER_LOG=Join-Path $documents 'wpf-interactive-approval-verifier.txt'
try {
    if($session -ne $ExpectedSession -or $session -eq 0){throw "Wrong interactive session: $session"}
    $process=Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\vika\Documents\Test-StagedApprovalFlow.ps1 -Verifier' -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $documents 'wpf-interactive-approval.txt') -RedirectStandardError (Join-Path $documents 'wpf-interactive-approval-error.txt')
    $childId=$process.Id
    if($null -eq $process.ExitCode){throw 'Child exit status is unavailable.'}
    $exitCode=$process.ExitCode
}
catch {$exitCode=1; $_ | Out-String | Set-Content (Join-Path $documents 'wpf-interactive-approval-launcher-error.txt')}
finally {
    $result=[ordered]@{LauncherSession=$session; ExpectedSession=$ExpectedSession; ChildPid=$childId; ExitCode=$exitCode; CompletedUtc=[DateTime]::UtcNow.ToString('o')}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
    $stream=[IO.FileStream]::new((Join-Path $documents 'wpf-interactive-approval-result.json'),[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)}finally{$stream.Dispose()}
}
exit $exitCode
'@
[IO.File]::WriteAllText($launcher,$text,[Text.UTF8Encoding]::new($false))
$principal=New-ScheduledTaskPrincipal -UserId 'WIN10-DEBUGGED\vika' -LogonType Interactive -RunLevel Highest
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $launcher -ExpectedSession $ExpectedSession"
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(10))
Register-ScheduledTask -TaskName $taskName -Principal $principal -Action $action -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $taskName
"StartedTask=$taskName; ExpectedSession=$ExpectedSession"
