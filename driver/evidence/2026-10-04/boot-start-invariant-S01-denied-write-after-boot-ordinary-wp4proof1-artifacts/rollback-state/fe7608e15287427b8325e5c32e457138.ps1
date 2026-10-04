function Write-DurableFile { param([string]$Path, [string]$Text, [switch]$New)

    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($Text)
    $fm=if($New){[IO.FileMode]::CreateNew}else{[IO.FileMode]::Create}
    $stream=[IO.FileStream]::new($Path,$fm,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try {$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
 }
function Get-BootId {  $env:COMPUTERNAME+'/'+(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')  }
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$code=0;$chain=@();$value=$null
try {
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class SUDevice{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern uint QueryDosDevice(string n,StringBuilder b,int c);}'
$b=[Text.StringBuilder]::new(1024);if([SUDevice]::QueryDosDevice('C:',$b,1024) -eq 0){throw 'QueryDosDevice failed'}
$value=$b.ToString().Split([char]0)[0]
} catch {
    $code=1;for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){$chain+=@{Type=$ex.GetType().FullName;Message=$ex.Message;HResult=$ex.HResult;Stack=$ex.StackTrace}}
} finally {
    $record=@{Token='fe7608e15287427b8325e5c32e457138';BootId=(Get-BootId);ExitCode=$code;Errors=$chain;Value=$value;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    Write-DurableFile 'C:\Users\vika\Documents\boot-start-invariant-S01-denied-write-after-boot-ordinary-wp4proof1-artifacts\fe7608e15287427b8325e5c32e457138.completion.clixml' ([Management.Automation.PSSerializer]::Serialize($record,32)) -New
}
exit $code