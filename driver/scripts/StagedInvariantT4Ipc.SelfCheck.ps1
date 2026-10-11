#requires -Version 5.1
# Exercise the actual control readers against Windows sharing rules. No driver
# or product service is loaded, and no protected file is opened.
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
public static class T4IpcControl {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 public static SafeFileHandle DeleteShared(string path) {
  var handle=CreateFileW(path,0x10000,7,IntPtr.Zero,3,0x80,IntPtr.Zero);
  if(handle.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return handle;
 }
 public static Thread Exclusive(string path,int milliseconds) {
  var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.None);
  var thread=new Thread(()=>{try{Thread.Sleep(milliseconds);}finally{file.Dispose();}});
  thread.IsBackground=true;thread.Start();return thread;
 }
 public static Thread AgentFrame(string name,bool silent) {
  var server=new NamedPipeServerStream(name,PipeDirection.Out,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
  var thread=new Thread(()=>{try{
   server.WaitForConnection();
   if(silent)Thread.Sleep(500);
   else{var b=System.Text.Encoding.UTF8.GetBytes("{\"admissionCoverage\":\"Ready\"}\n");server.Write(b,0,b.Length);server.Flush();}
  }finally{server.Dispose();}});
  thread.IsBackground=true;thread.Start();return thread;
 }
}
'@
$count=0
function Assert-Control([bool]$Good,[string]$Label){if(-not $Good){throw ('T4 IPC control failed: '+$Label)};$script:count++}
$root=Join-Path ([IO.Path]::GetTempPath()) ('safeupload-t4-ipc-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
try {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\agent-readiness.ps1'),[ref]$tokens,[ref]$errors)
    Assert-Control ($errors.Count -eq 0) 'actual agent readiness script parses'
    $frame=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-T4AgentFrame'},$false))
    Assert-Control ($frame.Count -eq 1) 'actual agent frame reader available'
    Invoke-Expression $frame[0].Extent.Text
    $pipeName='safeupload-t4-frame-'+[guid]::NewGuid().ToString('N')
    $thread=[T4IpcControl]::AgentFrame($pipeName,$false)
    try{Assert-Control ((Read-T4AgentFrame $pipeName 2000) -ceq '{"admissionCoverage":"Ready"}') 'ready frame is read intact'}finally{$thread.Join()}
    $pipeName='safeupload-t4-silent-'+[guid]::NewGuid().ToString('N')
    $thread=[T4IpcControl]::AgentFrame($pipeName,$true)
    $watch=[Diagnostics.Stopwatch]::StartNew();$timedOut=$false
    try{try{$null=Read-T4AgentFrame $pipeName 100}catch [TimeoutException]{$timedOut=$true}}
    finally{$elapsed=$watch.ElapsedMilliseconds;$thread.Join()}
    Assert-Control ($timedOut -and $elapsed -lt 2000) 'a connected silent server cannot hang readiness'
    $timedOut=$false
    try{$null=Read-T4AgentFrame ('safeupload-t4-absent-'+[guid]::NewGuid().ToString('N')) 100}catch [TimeoutException]{$timedOut=$true}
    Assert-Control $timedOut 'an absent server has a bounded connect timeout'
    foreach($leaf in @('cycles-actor.ps1','cycles-coordinator.ps1')){
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot ('t4\'+$leaf)),[ref]$tokens,[ref]$errors)
        Assert-Control ($errors.Count -eq 0) ($leaf+' parses')
        $fn=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Read-T4ControlText'},$false))
        Assert-Control ($fn.Count -eq 1) ($leaf+' actual control reader available')
        Invoke-Expression $fn[0].Extent.Text
        $file=Join-Path $root $leaf
        [IO.File]::WriteAllText($file,"107 new target payload`r`n")
        $handle=[T4IpcControl]::DeleteShared($file)
        try{
            $refused=$false;try{$null=[IO.File]::ReadAllText($file)}catch [IO.IOException]{$ioFailure=$_.Exception;while($ioFailure.InnerException){$ioFailure=$ioFailure.InnerException};$refused=($ioFailure.HResult -band 0xffff) -eq 32}
            Assert-Control $refused 'control reproduces missing FILE_SHARE_DELETE refusal'
            Assert-Control ((Read-T4ControlText $file) -ceq "107 new target payload`r`n") ($leaf+' reads while producer has DELETE access')
        }finally{$handle.Dispose()}
        $thread=[T4IpcControl]::Exclusive($file,250)
        try{Assert-Control ((Read-T4ControlText $file) -ceq "107 new target payload`r`n") ($leaf+' bounded retry survives temporary exclusive producer')}
        finally{$thread.Join()}
        $missing=$false;try{$null=Read-T4ControlText (Join-Path $root 'absent')}catch [IO.FileNotFoundException]{$missing=$true}
        Assert-Control $missing ($leaf+' never hides a missing command')
    }
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'),[ref]$tokens,[ref]$errors)
    $writer=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Write-T4ResultLine'},$false))
    Assert-Control ($writer.Count -eq 1) 'actual shared append writer available'
    Invoke-Expression $writer[0].Extent.Text
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-progress.ps1'),[ref]$tokens,[ref]$errors)
    Assert-Control ($errors.Count -eq 0) 'actual progress script parses'
    $progress=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-T4Progress'},$false))
    Assert-Control ($progress.Count -eq 1) 'actual progress reader available'
    Invoke-Expression $progress[0].Extent.Text
    $file=Join-Path $root 'cycles.jsonl'
    Write-T4ResultLine $file '{"i":1}'
    $reader=[IO.FileStream]::new($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]'ReadWrite, Delete')
    try{
        $refused=$false
        try{Add-Content -LiteralPath $file -Value '{"i":2}'}catch [IO.IOException]{$cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException};$refused=($cause.HResult -band 0xffff) -eq 32}
        Assert-Control $refused 'PS5.1 Add-Content reproduces refusal with an already-open share-all reader'
        Write-T4ResultLine $file '{"i":2}'
        Assert-Control ((Read-T4ControlText $file) -ceq "{`"i`":1}`r`n{`"i`":2}`r`n") 'actual shared writer appends each outcome exactly once'
    }finally{$reader.Dispose()}
    $writer=[IO.FileStream]::new($file,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]'ReadWrite, Delete')
    try{Assert-Control ((Get-T4Progress $root) -ceq 'RUNNING 2') 'actual progress reader works while the producer holds write access'}
    finally{$writer.Dispose()}
    $unicode='{"text":"'+[char]0xE7+[char]0xE3+'"}'
    Write-T4ResultLine $file $unicode
    $expected="{`"i`":1}`r`n{`"i`":2}`r`n"+$unicode+"`r`n"
    Assert-Control ((Read-T4ControlText $file) -ceq $expected) 'UTF-8 outcome text round-trips without replacement or BOM bytes'
    $exclusive=[IO.FileStream]::new($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try{
        $failed=$false;try{Write-T4ResultLine $file 'must not appear'}catch [IO.IOException]{$failed=$true}
        Assert-Control $failed 'writer does not hide or retry a real exclusive-lock failure'
    }finally{$exclusive.Dispose()}
    Assert-Control ((Read-T4ControlText $file) -ceq $expected) 'failed append creates no duplicate or partial outcome'
    [IO.File]::WriteAllText((Join-Path $root 'result.part'),'{partial')
    Assert-Control ((Get-T4Progress $root) -ceq 'RUNNING 3') 'partial result does not release the host completion barrier'
    [IO.File]::Move((Join-Path $root 'result.part'),(Join-Path $root 'result.json'))
    Assert-Control ((Get-T4Progress $root) -ceq 'DONE') 'atomic result publication releases the host completion barrier'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
'T4IpcSelfCheck=PASS;Controls='+$count+';Qualification=False'
