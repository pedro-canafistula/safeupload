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
$boot='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters\BootPolicy'
$parent='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload\Parameters'
if(Test-Path -LiteralPath $boot){Remove-Item -LiteralPath $boot -Recurse -Force}
if(Test-Path -LiteralPath $parent){
    $key=Get-Item -LiteralPath $parent
    if(@(Get-ChildItem -LiteralPath $parent -Force).Count -ne 0 -or $key.GetValueNames().Count -ne 0){throw 'Unexpected registry residue; preserve'}
    Remove-Item -LiteralPath $parent -Force
}
$value='Removed'
} catch {
    $code=1;for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){$chain+=@{Type=$ex.GetType().FullName;Message=$ex.Message;HResult=$ex.HResult;Stack=$ex.StackTrace}}
} finally {
    $record=@{Token='2c8e1d81e12743019c4f088575e2a2a4';BootId=(Get-BootId);ExitCode=$code;Errors=$chain;Value=$value;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    Write-DurableFile 'C:\Users\vika\Documents\boot-start-invariant-S01-denied-write-after-boot-ordinary-wp4proof2-artifacts\2c8e1d81e12743019c4f088575e2a2a4.completion.clixml' ([Management.Automation.PSSerializer]::Serialize($record,32)) -New
}
exit $code