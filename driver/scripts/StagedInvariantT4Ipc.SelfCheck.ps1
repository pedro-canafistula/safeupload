#requires -Version 5.1
# Exercise the actual control readers against Windows sharing rules. No driver
# or product service is loaded, and no protected file is opened.
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
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
}
'@
$count=0
function Assert-Control([bool]$Good,[string]$Label){if(-not $Good){throw ('T4 IPC control failed: '+$Label)};$script:count++}
$root=Join-Path ([IO.Path]::GetTempPath()) ('safeupload-t4-ipc-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
try {
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
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
'T4IpcSelfCheck=PASS;Controls='+$count+';Qualification=False'
