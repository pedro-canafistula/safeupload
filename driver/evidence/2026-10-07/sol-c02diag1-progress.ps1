$ErrorActionPreference='Stop'
$n='boot-start-invariant-C02-approve-absent-runtime-verifier-sol-c02diag1'
$d='C:\Users\vika\Documents\'+$n+'-artifacts'
$a='C:\Users\vika\Documents\SafeUpload-invariant-state-'+$n+'\actor'
$p=Join-Path $d 'stack-diagnostic-ready.clixml'
if(Test-Path -LiteralPath $p){
 $x=Import-Clixml -LiteralPath $p
 'DiagnosticReady=True'
 'RunName='+$x.RunName
 'ActorPid='+$x.Actor.Pid
 'ActorSid='+$x.Actor.Sid
 'BootId='+$x.Actor.BootId
 'StartedQpc='+$x.StartedQpc
 'CurrentQpc='+[Diagnostics.Stopwatch]::GetTimestamp()
 'WaitSeconds='+$x.WaitSeconds
 'SuiteSha256='+$x.SuiteSha256
 foreach($f in @(Get-ChildItem -LiteralPath $a -Filter 'native-*-start.clixml' | Sort-Object LastWriteTime)){
  try{$r=Import-Clixml -LiteralPath $f.FullName;'NativePhase='+$r.Phase+';Pid='+$r.Pid+';Qpc='+$r.Qpc+';CompletedClasses='+($r.Calls.Class -join ',')}catch{'ReceiptError='+$_.Exception.Message}
 }
 'HeldReceiptPresent='+(Test-Path -LiteralPath (Join-Path $a 'held.clixml'))
 $proc=Get-Process -Id $x.Actor.Pid -ErrorAction SilentlyContinue
 'ActorLive='+($null -ne $proc)
}else{'DiagnosticReady=False'}
Get-ScheduledTask | Where-Object TaskName -like ('*'+$n) | Select-Object TaskName,State | Format-Table -AutoSize
