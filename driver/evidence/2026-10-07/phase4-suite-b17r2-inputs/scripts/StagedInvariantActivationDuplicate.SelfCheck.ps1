#requires -Version 5.1
# Builder-only native two-process API control. No product qualification claim.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-StagedInvariantSuite.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Suite parse failed'}
$fn=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-ActivatingWriterBody'},$false))
if($fn.Count -ne 1){throw 'Unique activation body unavailable'}
Invoke-Expression $fn[0].Extent.Text
$proofFunction=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-ActivationPhysicalObjectProof'},$false));if($proofFunction.Count -ne 1){throw 'Unique trusted physical object helper unavailable'};Invoke-Expression $proofFunction[0].Extent.Text
function Get-BootId {return $env:COMPUTERNAME+'/'+(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
$body=Get-ActivatingWriterBody;$tokens=$null;$errors=$null
$actorAst=[Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Activation actor parse failed'}
$native=@($actorAst.FindAll({param($n)$n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -like '*public static class SUActivationNative*'},$true))
if($native.Count -ne 1){throw 'Unique native helper unavailable'}
Add-Type -TypeDefinition $native[0].Value
$directory=Join-Path ([IO.Path]::GetTempPath()) ('sol-duplicate-native-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $directory
[IO.File]::WriteAllText((Join-Path $directory 'native.cs'),$native[0].Value)
$childBody=@'
param([string]$Directory)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $Directory 'native.cs')))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$identityPath=Join-Path $Directory 'identity.clixml';@{Pid=$PID;Sid=$identity.User.Value;SessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId}|Export-Clixml ($identityPath+'.tmp');Move-Item ($identityPath+'.tmp') $identityPath
try{
 for($sequence=1;;$sequence++){
  $commandPath=Join-Path $Directory ('command-'+$sequence+'.clixml')
  $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](30*[Diagnostics.Stopwatch]::Frequency)
  while(-not(Test-Path -LiteralPath $commandPath)){if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Child command timeout'};Start-Sleep -Milliseconds 10}
  $command=Import-Clixml -LiteralPath $commandPath;$reply=@{Pid=$PID;StartQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
  switch($command.Action){
   'adopt' {$reply.NativeCode=[SUActivationNative]::AdoptHolder([long]$command.Handle)}
   'query' {$position=[long]0;$reply.NativeCode=[SUActivationNative]::Position(0,$true,[ref]$position);$reply.Position=$position}
   'set' {$position=[long]0;$reply.NativeCode=[SUActivationNative]::Position([long]$command.Offset,$false,[ref]$position);$reply.Position=$position}
   'write' {$reply.NativeCode=[SUActivationNative]::WriteFileAt([long]$command.Offset,[byte[]]$command.Bytes);$reply.FlushCode=[SUActivationNative]::FlushHolderFile()}
   'reopen' {$written=[long]0;$reply.NativeCode=[SUActivationNative]::StageWriteHeld($command.Target,0,[byte[]]@(),[ref]$written);$reply.Handle=[SUActivationNative]::FileHandle.ToInt64()}
   'close' {$reply.NativeCode=[SUActivationNative]::ReleaseHolder()}
   'exit' {$reply.NativeCode=[SUActivationNative]::ReleaseHolder()}
   default {throw 'Unknown native control action'}
  }
  $reply.EndQpc=[Diagnostics.Stopwatch]::GetTimestamp();$replyPath=Join-Path $Directory ('reply-'+$sequence+'.clixml');$reply|Export-Clixml ($replyPath+'.tmp');Move-Item ($replyPath+'.tmp') $replyPath
  if($command.Action -ceq 'exit'){break}
 }
}finally{[void][SUActivationNative]::ReleaseHolder();$identity.Dispose()}
'@
$childScript=Join-Path $directory 'child.ps1';[IO.File]::WriteAllText($childScript,$childBody)
$process=$null;$sequence=0
function Wait-ControlFile([string]$Path){
 $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](30*[Diagnostics.Stopwatch]::Frequency)
 while(-not(Test-Path -LiteralPath $Path)){if([Diagnostics.Stopwatch]::GetTimestamp() -gt $deadline){throw 'Parent control timeout'};Start-Sleep -Milliseconds 10}
 # Publish using a rename so readers never deserialize an incomplete file.
 return Import-Clixml -LiteralPath $Path
}
function Send-Control([string]$Action,$Fields){
 $script:sequence++;$command=@{Action=$Action};if($Fields){foreach($key in $Fields.Keys){$command[$key]=$Fields[$key]}}
 $path=Join-Path $directory ('command-'+$script:sequence+'.clixml');$temp=$path+'.tmp';$command|Export-Clixml $temp;Move-Item $temp $path
 $reply=Wait-ControlFile (Join-Path $directory ('reply-'+$script:sequence+'.clixml'))
 if($reply.Pid -ne $process.Id -or $reply.NativeCode -ne 0 -or $reply.EndQpc -lt $reply.StartQpc){throw 'Native child receipt failed'}
 return $reply
}
try{
 $seed=[Text.Encoding]::ASCII.GetBytes(('Benign duplicate control').PadRight(12288,'P'));$target=Join-Path $directory 'control.txt';[IO.File]::WriteAllBytes($target,$seed)
 $closed=$false;if([SUActivationNative]::CreateHolder($target,$seed,'handle',[ref]$closed) -ne 0 -or $closed){throw 'Native parent holder failed'}
 $process=Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"'+$childScript+'"'),'-Directory',('"'+$directory+'"')) -PassThru -WindowStyle Hidden
 $identity=Wait-ControlFile (Join-Path $directory 'identity.clixml');$owner=[Security.Principal.WindowsIdentity]::GetCurrent()
 try{if($identity.Pid -ne $process.Id -or $identity.Pid -eq $PID -or $identity.Sid -cne $owner.User.Value -or $identity.SessionId -ne [Diagnostics.Process]::GetCurrentProcess().SessionId){throw 'Actual distinct same-SID process identity failed'}}finally{$owner.Dispose()}
 $source=[long]0;$remote=[long]0;if([SUActivationNative]::DuplicateHolder($process.Id,[ref]$source,[ref]$remote) -ne 0 -or $source -le 0 -or $remote -le 0){throw 'Native DuplicateHandle failed'}
 $null=Send-Control 'adopt' @{Handle=$remote}
 $position=[long]0;if([SUActivationNative]::Position(317,$false,[ref]$position) -ne 0 -or $position -ne 317){throw 'Parent position set failed'}
 if((Send-Control 'query' $null).Position -ne 317){throw 'Child did not share parent current position'}
 if((Send-Control 'set' @{Offset=[long]619}).Position -ne 619){throw 'Child position set failed'}
 if([SUActivationNative]::Position(0,$true,[ref]$position) -ne 0 -or $position -ne 619){throw 'Parent did not share child current position'}
 $physical=Get-ActivationPhysicalObjectProof $PID $source $process.Id $remote
 if($physical.Status -cne 'OK' -or $physical.Object -ceq '0x0000000000000000'){throw 'Trusted physical object control failed'}
 $null=Send-Control 'close' $null;$separate=Send-Control 'reopen' @{Target=$target};$rejected=$false
 try{$null=Get-ActivationPhysicalObjectProof $PID $source $process.Id $separate.Handle}catch{$rejected=$_.Exception.ToString() -like '*do not identify one nonzero kernel object*'}
 if(-not $rejected){throw 'Independent opens of one path were accepted as one file object'}
 $null=Send-Control 'close' $null
 if([SUActivationNative]::DuplicateHolder($process.Id,[ref]$source,[ref]$remote) -ne 0){throw 'Repeat native duplicate failed'};$null=Send-Control 'adopt' @{Handle=$remote}
 $null=Get-ActivationPhysicalObjectProof $PID $source $process.Id $remote
 if([SUActivationNative]::ReleaseHolder() -ne 0){throw 'Parent close failed'}
 $bytes=[Text.Encoding]::ASCII.GetBytes('Child remains writable after parent close');$receipt=Send-Control 'write' @{Offset=[long]1024;Bytes=$bytes}
 if($receipt.FlushCode -ne 0){throw 'Child flush failed'}
 $expected=[byte[]]$seed.Clone();[Array]::Copy($bytes,0,$expected,1024,$bytes.Length)
 $hash=[Security.Cryptography.SHA256]::Create()
 try{
  $digest=[BitConverter]::ToString($hash.ComputeHash($expected)).Replace('-','')
  $read=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete);try{$actual=[byte[]]::new([int]$read.Length);$count=0;while($count -lt $actual.Length){$n=$read.Read($actual,$count,$actual.Length-$count);if($n -le 0){throw 'Short whole control read'};$count+=$n}}finally{$read.Dispose()};if([BitConverter]::ToString($hash.ComputeHash($actual)).Replace('-','') -cne $digest){throw 'Whole image mismatch after parent close/child write'}
  $null=Send-Control 'close' $null;$null=Send-Control 'exit' $null
  if(-not $process.WaitForExit(30000) -or $process.ExitCode -ne 0){throw 'Child exit failed'}
  $written=[long]0;if([SUActivationNative]::StageWriteHeld($target,1024,$bytes,[ref]$written) -ne 0 -or $written -ne $bytes.Length -or [SUActivationNative]::HolderDigest($expected.Length) -cne $digest){throw 'Held owned-write native helper failed'}
 }finally{$hash.Dispose()}
 Write-Output ('NativeDuplicateControl=PASS;ParentPid='+$PID+';ChildPid='+$process.Id+';TrustedPhysicalObject=PASS;SeparateOpensRejected=PASS;SameFileObjectTwoWayPosition=PASS;ParentCloseChildWrite=PASS;WholeImage=PASS;OwnedHeldWrite=PASS;Qualification=False')
}finally{
 [void][SUActivationNative]::ReleaseHolder()
 if($process -and -not $process.HasExited){$process.Kill();$process.WaitForExit()}
 Remove-Item -LiteralPath $directory -Recurse -Force
}
