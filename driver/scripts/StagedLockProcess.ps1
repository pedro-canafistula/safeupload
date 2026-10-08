# A physical/owned comparison, using a duplicate whose locking process exits.
function Test-StagedLockProcess([string] $Path) {
    $control=Join-Path $env:TEMP ('lock-process-'+[guid]::NewGuid().ToString('N'))
    $child=$null; $first=$null; $second=$null
    $script=@'
$ErrorActionPreference='Stop'
Add-Type -Path '__HELPER__'
$control='__CONTROL__'
for($i=0;$i -lt 100 -and -not (Test-Path ($control+'.handle'));$i++){Start-Sleep -Milliseconds 100}
$raw=[long](Get-Content -LiteralPath ($control+'.handle'))
$handle=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]$raw,$true)
try {
    $errorCode=[StagedLockProbe]::Lock($handle,64,3)
    if($errorCode -ne 0){throw "Child lock failed: $errorCode"}
    [IO.File]::WriteAllText($control+'.ready','ready')
    for($i=0;$i -lt 100 -and -not (Test-Path ($control+'.finish'));$i++){Start-Sleep -Milliseconds 100}
    if(-not (Test-Path ($control+'.finish'))){throw 'Finish timed out.'}
} finally {$handle.Dispose()}
'@
    try {
        $first=[StagedLockProbe]::Open($Path,$false)
        $second=[StagedLockProbe]::Open($Path,$false)
        [IO.File]::WriteAllText($control+'.ps1',$script.Replace('__HELPER__',(Join-Path $PSScriptRoot 'StagedLockProbe.cs')).Replace('__CONTROL__',$control))
        $child=Start-Process powershell.exe -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',($control+'.ps1')) `
            -RedirectStandardOutput ($control+'.out') -RedirectStandardError ($control+'.err')
        $null=$child.Handle
        $remote=[StagedLockProbe]::Send($first,$child.Id)
        [IO.File]::WriteAllText($control+'.handle',$remote.ToString())
        for($i=0;$i -lt 100 -and -not (Test-Path ($control+'.ready'));$i++){Start-Sleep -Milliseconds 100}
        if(-not (Test-Path ($control+'.ready'))){Get-Content ($control+'.err') | Out-Host; throw 'Child did not lock.'}
        $before=[StagedLockProbe]::Write($first,64)
        [IO.File]::WriteAllText($control+'.finish','finish')
        if(-not $child.WaitForExit(10000) -or $child.ExitCode -ne 0){throw 'Child did not exit successfully.'}
        Start-Sleep -Seconds 1
        $afterExit=[StagedLockProbe]::Write($first,64)
        $first.Dispose(); $first=$null
        $afterClose=[StagedLockProbe]::Write($second,64)
        return "$before,$afterExit,$afterClose"
    }
    finally {
        if($null -ne $child -and -not $child.HasExited){Stop-Process -Id $child.Id -Force; [void]$child.WaitForExit(10000)}
        if($null -ne $first){$first.Dispose()}
        if($null -ne $second){$second.Dispose()}
        Get-ChildItem -LiteralPath (Split-Path $control) -Filter ((Split-Path $control -Leaf)+'.*') | Remove-Item -Force
    }
}
