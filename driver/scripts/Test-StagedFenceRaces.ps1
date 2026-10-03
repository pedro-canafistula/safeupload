<# Open/map/attach race test for the mapped-writable stream fence. Run only on the recorded isolated WIN10-DEBUGGED VM from
   the experiment wrapper, normally under the volatile Verifier (-Verifier). Per iteration an in-scope fixture is held
   open through a read/write handle opened BEFORE the driver loads, a worker thread creates writable mappings through
   that handle at random moments around `fltmc load`, and after the load has settled:
     - every writable view that exists must REFUSE a write+flush (the fence or the section refusal engaged), and
     - every writable mapping created after the filter attached must have been REFUSED at creation.
   A write+flush that succeeds after the load settled is a leak. Mappings written BEFORE the load are pre-policy
   writes and are not counted. The driver is then unloaded (the unload guard purges and releases). #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)] [string] $ExpectedInspectorSha256,
    [int] $Iterations = 15,
    [switch] $Verifier
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-races-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-races-' + $id + '.sys')
$marker = [Text.Encoding]::UTF8.GetBytes('RACE WRITE ' + $id)
$loaded = $false; $replaced = $false; $scopeCreated = $false; $verifierEnabled = $false

function Invoke-Inspector([string] $Argument) {
    $cmdFile = Join-Path $documents ('fence-races-' + $id + '.cmd'); $cmdOut = Join-Path $documents ('fence-races-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', ('"' + $inspector + '" ' + $Argument))
    $taskName = 'SafeUpload-StagedTest-FenceRaces-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        if (Test-Path -LiteralPath $cmdOut) { return ((Get-Content -LiteralPath $cmdOut -Raw) -replace '\s+', ' ').Trim() } else { return '(no output)' }
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
}
function Get-Counter-Value([string] $Json, [string] $Name) { if ($Json -match ('"' + $Name + '":(\d+)')) { [int64]$Matches[1] } else { -1 } }

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=fence-races'
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
'Iterations=' + $Iterations
$totals = [ordered]@{ ViewsCreatedBeforeLoad = 0; ViewsCreatedAfterLoad = 0; CreationsRefusedAfterLoad = 0; WritesRefused = 0; WritesSucceeded = 0; UnloadRefused = 0; LoadFailures = 0 }
$worker = {
    param($Stream, $Bag, $Stop, $Log, $Id)
    $n = 0
    while (-not $Stop.Value) {
        try {
            $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($Stream, ('Local\SafeUpload-Races-' + $Id + '-' + $n), [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
            $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
            $Bag.Add([pscustomobject]@{ Mapping = $mapping; View = $view; At = [DateTime]::UtcNow.Ticks })
            $Log.Add('C' + [DateTime]::UtcNow.Ticks)
        }
        catch { $Log.Add('R' + [DateTime]::UtcNow.Ticks) }
        $n++
        Start-Sleep -Milliseconds 4
    }
}
try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B'
    }
    $random = New-Object Random 20261002
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $path = Join-Path $scopeDirectory ('race-' + $iteration + '.maptest')
        $bytes = New-Object byte[] 4096; [Text.Encoding]::UTF8.GetBytes('BASELINE ' + $iteration).CopyTo($bytes, 0)
        [IO.File]::WriteAllBytes($path, $bytes)
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $bag = New-Object 'System.Collections.Concurrent.ConcurrentBag[object]'
        $log = New-Object 'System.Collections.Concurrent.ConcurrentBag[string]'
        $stop = [ref]$false
        $pool = [powershell]::Create().AddScript($worker).AddArgument($stream).AddArgument($bag).AddArgument($stop).AddArgument($log).AddArgument($id + '-' + $iteration)
        $async = $pool.BeginInvoke()
        Start-Sleep -Milliseconds $random.Next(0, 120)
        $watch = [Diagnostics.Stopwatch]::StartNew()
        & fltmc.exe load SafeUpload 2>&1 | Out-Null
        $loadExit = $LASTEXITCODE
        $loadedTicks = [DateTime]::UtcNow.Ticks
        $loadMs = [int]$watch.Elapsed.TotalMilliseconds
        if ($loadExit -ne 0) { $totals.LoadFailures++; $stop.Value = $true; [void]$pool.EndInvoke($async); $pool.Dispose(); $stream.Dispose(); 'Iteration_' + $iteration + '_LoadFailed exit=' + $loadExit; continue }
        $loaded = $true
        Start-Sleep -Milliseconds 1500                           # the post-start scan and any late creation settle
        $stop.Value = $true
        [void]$pool.EndInvoke($async); $pool.Dispose()
        $views = @($bag.ToArray())
        $before = @($views | Where-Object { $_.At -lt $loadedTicks }).Count
        $after = @($views | Where-Object { $_.At -ge $loadedTicks }).Count
        $refusedAfter = @($log.ToArray() | Where-Object { $_.StartsWith('R') -and [int64]$_.Substring(1) -ge $loadedTicks }).Count
        $refused = 0; $succeeded = 0
        foreach ($entry in $views) {
            try { $entry.View.WriteArray(0, $marker, 0, $marker.Length); $entry.View.Flush(); $succeeded++ } catch { $refused++ }
        }
        $totals.ViewsCreatedBeforeLoad += $before; $totals.ViewsCreatedAfterLoad += $after; $totals.CreationsRefusedAfterLoad += $refusedAfter
        $totals.WritesRefused += $refused; $totals.WritesSucceeded += $succeeded
        'Iteration_{0} loadMs={1} viewsBefore={2} viewsAfterLoad={3} creationRefusedAfterLoad={4} writeRefused={5} writeSucceeded={6}' -f $iteration, $loadMs, $before, $after, $refusedAfter, $refused, $succeeded
        foreach ($entry in $views) { try { $entry.View.Dispose() } catch { }; try { $entry.Mapping.Dispose() } catch { } }
        $stream.Dispose()
        $unloaded = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $unloaded; $attempt++) {
            & fltmc.exe unload SafeUpload 2>&1 | Out-Null
            $unloaded = ($LASTEXITCODE -eq 0)
            if (-not $unloaded) { if ($attempt -eq 0) { Invoke-Inspector '--admission-fence-refresh' | Out-Null }; Start-Sleep -Milliseconds 500 }
        }
        if (-not $unloaded) { $totals.UnloadRefused++; 'Iteration_' + $iteration + '_UnloadRefused'; break }
        $loaded = $false
    }
    foreach ($key in $totals.Keys) { 'Total_' + $key + '=' + $totals[$key] }
    'Verdict_NoWriteSucceededAfterLoad=' + ($totals.WritesSucceeded -eq 0)
}
catch { 'ScriptError=' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')' }
finally {
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) { try { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message } }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    'RacesRestoration=OriginalDriverRestored; FilterUnloaded=' + (-not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'))
    'VariantComplete=fence-races'
}
