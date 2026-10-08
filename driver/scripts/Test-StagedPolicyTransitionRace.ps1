<# Policy-transition race for the mapped-writable stream fence. Run only on the recorded isolated WIN10-DEBUGGED VM from the
   experiment wrapper, normally under the volatile Verifier (-Verifier).
   The window under test is the one between the fence's pre-swap scan of a file and the policy swap: a stream whose FIRST
   writable mapping is created there is unknown to the scan and, in a driver that classifies sections against the current
   policy only, is allowed. To make the window long, the fixture directory holds the target (sorted first, so it is probed
   first) followed by thousands of filler files the scan must still walk. Per iteration: the feature driver is freshly loaded
   (no policy), the target is held open through a read/write handle, a worker thread creates its FIRST writable mapping at a
   random delay after the real agent is started and then keeps creating them, and the agent's first policy push brings the
   fixture directory into scope. After the push settles every view that exists must refuse a write+flush and no mapping may
   be created any more. A write+flush that succeeds is a leak. The delay and the agent's ready time are printed so the
   iterations that hit the window can be told apart. #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [int] $Iterations = 8,
    [int] $MaxViews = 4000,
    [int] $FillerFiles = 6000,
    [int] $DelayMinMs = 0,
    [int] $DelayMaxMs = 1800,   # the real agent signals policy acceptance about 1.4 to 1.8 s after it is launched
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
$serviceDirectory = Join-Path $documents 'stage-service-publish'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$backup = Join-Path $documents ('SafeUpload-original-before-policy-race-' + $id + '.sys')
$marker = [Text.Encoding]::UTF8.GetBytes('POLICY RACE WRITE ' + $id)
$loaded = $false; $replaced = $false; $verifierEnabled = $false; $policyBytes = $null; $agent = $null
$fixtureDirectories = @()

function Start-TestAgentAndWaitForPolicy([string] $LogPrefix) {
    $ready = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, 'Global\SafeUploadServiceReady')
    $newAgent = $null
    try {
        [void]$ready.Reset()
        $newAgent = Start-StagedTestAgent $serviceDirectory $LogPrefix
        if (-not $ready.WaitOne([TimeSpan]::FromSeconds(60))) { throw 'Agent did not signal policy acceptance within 60 seconds.' }
        return $newAgent
    }
    catch { if ($null -ne $newAgent) { Stop-StagedTestAgent $newAgent }; throw }
    finally { $ready.Dispose() }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
$policyBytes = [IO.File]::ReadAllBytes($policy)
$baselinePolicy = [Text.Encoding]::UTF8.GetString($policyBytes) | ConvertFrom-Json
'Variant=policy-transition-race'
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
'Iterations=' + $Iterations
$totals = [ordered]@{ ViewsBeforePolicyReady = 0; ViewsAfterPolicyReady = 0; CreationsRefusedAfterReady = 0; WritesRefused = 0; WritesSucceeded = 0; IterationsWithLeak = 0; UnloadRefused = 0 }
$worker = {
    param($Stream, $Bag, $Stop, $Log, $Id, $Max, $DelayMs)
    Start-Sleep -Milliseconds $DelayMs
    $n = 0
    while (-not $Stop.Value -and $n -lt $Max) {
        try {
            $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($Stream, ('Local\SafeUpload-PolicyRace-' + $Id + '-' + $n), [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
            $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
            $Bag.Add([pscustomobject]@{ Mapping = $mapping; View = $view; At = [DateTime]::UtcNow.Ticks })
        }
        catch { $Log.Add([DateTime]::UtcNow.Ticks) }
        $n++
        Start-Sleep -Milliseconds 3
    }
}
try {
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
    $fixtureDirectory = Join-Path $documents ('SafeUpload-policy-race-' + $id)
    $fixtureDirectories += $fixtureDirectory
    [void][IO.Directory]::CreateDirectory($fixtureDirectory)
    $filler = New-Object byte[] 16
    for ($f = 0; $f -lt $FillerFiles; $f++) { [IO.File]::WriteAllBytes((Join-Path $fixtureDirectory ('z-filler-{0:D5}.dat' -f $f)), $filler) }
    'FillerFiles=' + $FillerFiles
    $random = New-Object Random 20261003
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $target = Join-Path $fixtureDirectory 'a-target.maptest'
        $bytes = New-Object byte[] 4096; [Text.Encoding]::UTF8.GetBytes('BASELINE ' + $iteration).CopyTo($bytes, 0)
        [IO.File]::WriteAllBytes($target, $bytes)
        $stream = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        & fltmc.exe load SafeUpload 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Feature filter load failed in iteration $iteration." }
        $loaded = $true
        $bag = New-Object 'System.Collections.Concurrent.ConcurrentBag[object]'
        $log = New-Object 'System.Collections.Concurrent.ConcurrentBag[int64]'
        $stop = [ref]$false
        $delayMs = $random.Next($DelayMinMs, $DelayMaxMs)
        $pool = [powershell]::Create().AddScript($worker).AddArgument($stream).AddArgument($bag).AddArgument($stop).AddArgument($log).AddArgument($id + '-' + $iteration).AddArgument($MaxViews).AddArgument($delayMs)
        $agentWatch = [Diagnostics.Stopwatch]::StartNew()
        $async = $pool.BeginInvoke()
        # Bring the fixture directory into scope: the real agent's FIRST policy push happens while the worker runs.
        $expanded = $baselinePolicy | ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $expanded.monitoredScopes.destinationPaths = @($baselinePolicy.monitoredScopes.destinationPaths) + @($fixtureDirectory)
        [IO.File]::WriteAllBytes($policy, [Text.Encoding]::UTF8.GetBytes(($expanded | ConvertTo-Json -Depth 10)))
        $agent = Start-TestAgentAndWaitForPolicy (Join-Path $documents ('policy-race-' + $id + '-' + $iteration))
        $readyTicks = [DateTime]::UtcNow.Ticks
        $readyMs = [int]$agentWatch.Elapsed.TotalMilliseconds
        Start-Sleep -Milliseconds 1500
        $stop.Value = $true
        [void]$pool.EndInvoke($async); $pool.Dispose()
        $views = @($bag.ToArray())
        $before = @($views | Where-Object { $_.At -lt $readyTicks }).Count
        $after = $views.Count - $before
        $refusedAfter = @($log.ToArray() | Where-Object { $_ -ge $readyTicks }).Count
        $refused = 0; $succeeded = 0
        foreach ($entry in $views) {
            try { $entry.View.WriteArray(0, $marker, 0, $marker.Length); $entry.View.Flush(); $succeeded++ } catch { $refused++ }
        }
        $totals.ViewsBeforePolicyReady += $before; $totals.ViewsAfterPolicyReady += $after; $totals.CreationsRefusedAfterReady += $refusedAfter
        $totals.WritesRefused += $refused; $totals.WritesSucceeded += $succeeded
        if ($succeeded -gt 0) { $totals.IterationsWithLeak++ }
        'Iteration_{0} firstMappingDelayMs={1} agentReadyMs={2} viewsBeforeReady={3} viewsAfterReady={4} creationRefusedAfterReady={5} writeRefused={6} writeSucceeded={7}' -f $iteration, $delayMs, $readyMs, $before, $after, $refusedAfter, $refused, $succeeded
        Stop-StagedTestAgent $agent; $agent = $null
        foreach ($entry in $views) { try { $entry.View.Dispose() } catch { }; try { $entry.Mapping.Dispose() } catch { } }
        $stream.Dispose()
        [IO.File]::WriteAllBytes($policy, $policyBytes)
        $unloaded = $false
        for ($attempt = 0; $attempt -lt 60 -and -not $unloaded; $attempt++) {
            & fltmc.exe unload SafeUpload 2>&1 | Out-Null
            $unloaded = ($LASTEXITCODE -eq 0)
            if (-not $unloaded) { Start-Sleep -Milliseconds 500 }
        }
        if (-not $unloaded) { $totals.UnloadRefused++; 'Iteration_' + $iteration + '_UnloadRefused'; break }
        $loaded = $false
    }
    foreach ($key in $totals.Keys) { 'Total_' + $key + '=' + $totals[$key] }
    'Verdict_NoWriteSucceeded=' + ($totals.WritesSucceeded -eq 0)
}
catch { 'ScriptError=' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')' }
finally {
    if ($null -ne $agent) { try { Stop-StagedTestAgent $agent } catch { } }
    if ($null -ne $policyBytes) { [IO.File]::WriteAllBytes($policy, $policyBytes) }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    foreach ($directory in $fixtureDirectories) { if (Test-Path -LiteralPath $directory) { try { Remove-Item -LiteralPath $directory -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message } } }
    Get-ChildItem $documents -Filter ('policy-race-' + $id + '-*') -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { 'PolicyRestoreError=hash mismatch' }
    'RaceRestoration=OriginalDriverAndPolicyRestored; FilterUnloaded=' + (-not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'))
    'VariantComplete=policy-transition-race'
}
