param([string]$Worker = (Join-Path $PSScriptRoot 'reopen-after-publication.ps1'))
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Requires Windows PowerShell 5.1' }
foreach ($script in @($Worker, (Join-Path $PSScriptRoot 'cycles-actor.ps1'), (Join-Path $PSScriptRoot 'cycles-coordinator.ps1'))) {
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($script, [ref]$tokens, [ref]$errors)
    if (@($errors).Count) { throw ($errors | Out-String) }
}
$root=Join-Path $env:TEMP ('safeupload-reopen-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    $path=Join-Path $root 'public.txt'; $expected=Join-Path $root 'expected.bin'
    [IO.File]::WriteAllText($path, 'approved control bytes')
    [IO.File]::Copy($path, $expected)
    foreach ($exclusive in @($false,$true)) {
        $prefix=Join-Path $root ([string]$exclusive)
        $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Worker +
            '" -Path "' + $path + '" -ExpectedPath "' + $expected + '" -SignalPrefix "' + $prefix + '" -WriterPid ' + $PID
        $child=Start-Process (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
        $held=$null
        try {
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+30*[Diagnostics.Stopwatch]::Frequency
            while (-not [IO.File]::Exists($prefix+'.ready')) {
                if ($child.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'ready timeout' }
                Start-Sleep -Milliseconds 2
            }
            if ($exclusive) { $held=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
            [IO.File]::WriteAllText(($prefix+'.go'),'go')
            while (-not [IO.File]::Exists($prefix+'.result.json')) {
                if ($child.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'result timeout' }
                Start-Sleep -Milliseconds 2
            }
            $receipt=[IO.File]::ReadAllText($prefix+'.result.json')|ConvertFrom-Json
            if ($receipt.Error -or $receipt.WriterPid -ne $PID -or $receipt.ObserverPid -eq $PID) { throw 'invalid observer receipt' }
            foreach ($attempt in @($receipt.Read,$receipt.ReadWrite)) {
                if ($exclusive) { if ($attempt.OpenError -ne 32) { throw 'exclusive negative control did not preserve sharing refusal' } }
                elseif ($attempt.OpenError -ne 0 -or $attempt.CloseError -ne 0 -or $attempt.Error -or -not $attempt.BytesMatch -or -not $attempt.Identity) { throw 'compatible positive control failed' }
            }
        } finally {
            if ($null -ne $held) { $held.Dispose() }
            if (-not $child.HasExited) { if (-not $child.WaitForExit(5000)) { $child.Kill(); if (-not $child.WaitForExit(5000)) { throw 'observer termination not confirmed' } } }
            $child.Dispose()
        }
    }
    # Sequential order (-AfterOwner): the child may not open anything until the saving process reports its own opens are done.
    foreach ($abortInstead in @($false,$true)) {
        $prefix=Join-Path $root ('sequential-' + [string]$abortInstead)
        $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Worker +
            '" -Path "' + $path + '" -ExpectedPath "' + $expected + '" -SignalPrefix "' + $prefix + '" -WriterPid ' + $PID + ' -AfterOwner'
        $child=Start-Process (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -PassThru -WindowStyle Hidden
        try {
            $deadline=[Diagnostics.Stopwatch]::GetTimestamp()+30*[Diagnostics.Stopwatch]::Frequency
            while (-not [IO.File]::Exists($prefix+'.ready')) {
                if ($child.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'sequential ready timeout' }
                Start-Sleep -Milliseconds 2
            }
            [IO.File]::WriteAllText(($prefix+'.go'),'go')
            Start-Sleep -Milliseconds 500
            if ([IO.File]::Exists($prefix+'.result.json')) { throw 'sequential observer probed before the owner was done' }
            if ($abortInstead) { [IO.File]::WriteAllText(($prefix+'.abort'),'abort') } else { [IO.File]::WriteAllText(($prefix+'.owner-done'),'done') }
            while (-not [IO.File]::Exists($prefix+'.result.json')) {
                if ($child.HasExited -or [Diagnostics.Stopwatch]::GetTimestamp() -ge $deadline) { throw 'sequential result timeout' }
                Start-Sleep -Milliseconds 2
            }
            $receipt=[IO.File]::ReadAllText($prefix+'.result.json')|ConvertFrom-Json
            if (-not $receipt.Sequential) { throw 'sequential receipt not marked' }
            if ($abortInstead) {
                if (-not $receipt.Error -or $null -ne $receipt.Read -or $null -ne $receipt.ReadWrite) { throw 'aborted sequential observer must not open anything' }
            } else {
                if ($receipt.Error -or $receipt.OwnerDoneSeenQpc -lt $receipt.SignalSeenQpc) { throw 'sequential receipt invalid' }
                foreach ($attempt in @($receipt.Read,$receipt.ReadWrite)) {
                    if ($attempt.OpenError -ne 0 -or $attempt.CloseError -ne 0 -or $attempt.Error -or -not $attempt.BytesMatch -or -not $attempt.Identity) { throw 'sequential positive control failed' }
                }
            }
        } finally {
            if (-not $child.HasExited) { if (-not $child.WaitForExit(5000)) { $child.Kill(); if (-not $child.WaitForExit(5000)) { throw 'observer termination not confirmed' } } }
            $child.Dispose()
        }
    }
    'PowerShell51ParseAndCrossProcessReopenNativeControls=PASS'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
