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
function Invoke-CapturedProcess { param([string]$Exe, [string]$Arguments, [string]$Prefix, [int]$Timeout=45000, [string]$WorkingDirectory)

    $p=$null
    try {
        $start=@{FilePath=$Exe;ArgumentList=$Arguments;PassThru=$true;WindowStyle='Hidden';RedirectStandardOutput=($Prefix+'.out');RedirectStandardError=($Prefix+'.err')}
        if(-not [string]::IsNullOrWhiteSpace($WorkingDirectory)){$start.WorkingDirectory=$WorkingDirectory}
        $p=Start-Process @start
        $null=$p.Handle
        if(-not $p.WaitForExit($Timeout)){throw 'Child process timed out'}
        $p.WaitForExit();if($null -eq $p.ExitCode){throw 'Child process exit code absent'}
        if($p.ExitCode -ne 0){throw "Child process failed: $($p.ExitCode); $([IO.File]::ReadAllText($Prefix+'.err'))"}
        return [IO.File]::ReadAllText($Prefix+'.out')
    }finally {if($null -ne $p){if(-not $p.HasExited){$p.Kill();$p.WaitForExit()};$p.Dispose()}}
 }
$value=Invoke-CapturedProcess 'C:\Users\vika\Documents\SafeUpload-invariant-state-boot-start-invariant-S01-denied-write-after-boot-ordinary-wp4proof1\service\SafeUpload.Agent.Service.exe' '--seed-boot-policy' 'C:\Users\vika\Documents\boot-start-invariant-S01-denied-write-after-boot-ordinary-wp4proof1-artifacts\product-seed' -WorkingDirectory 'C:\Users\vika\Documents\SafeUpload-invariant-state-boot-start-invariant-S01-denied-write-after-boot-ordinary-wp4proof1\service'
} catch {
    $code=1;for($ex=$_.Exception;$null -ne $ex;$ex=$ex.InnerException){$chain+=@{Type=$ex.GetType().FullName;Message=$ex.Message;HResult=$ex.HResult;Stack=$ex.StackTrace}}
} finally {
    $record=@{Token='3fc0b0878d0c4c728f95f49347f3170e';BootId=(Get-BootId);ExitCode=$code;Errors=$chain;Value=$value;CompletedQpc=[Diagnostics.Stopwatch]::GetTimestamp()}
    Write-DurableFile 'C:\Users\vika\Documents\boot-start-invariant-S01-denied-write-after-boot-ordinary-wp4proof1-artifacts\3fc0b0878d0c4c728f95f49347f3170e.completion.clixml' ([Management.Automation.PSSerializer]::Serialize($record,32)) -New
}
exit $code