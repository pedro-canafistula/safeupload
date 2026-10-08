<# Local NTFS measurement, not a production latency qualification. Run through
   Invoke-DebuggeeExperiment.sh on the recorded isolated VM. No live stage or
   journal data is removed. A separate child process records foreground samples
   continuously while load-time and explicit fence scans visit synthetic files.
   Explicit refresh elapsed time is measured inside the SYSTEM task, excluding
   scheduled-task startup/polling. Raw CSV/JSONL files are retained in Documents.
   Limits are declared before driver replacement and must not be tuned post-run. #>
param(
    [string] $ExpectedFeatureSha256,
    [string] $ExpectedInspectorSha256,
    [ValidateRange(6000,7500)] [int] $FileCount = 6500,
    [ValidateRange(3,20)] [int] $Iterations = 5,
    [ValidateRange(1,60000)] [int] $MaxScanMs = 10000,
    [ValidateRange(1,60000)] [int] $MaxForegroundMs = 1000,
    [ValidateRange(1,60000)] [int] $P95ForegroundMs = 250,
    [switch] $Verifier,
    [switch] $Worker,
    [string] $ScopeFile,
    [string] $OutsideDirectory,
    [string] $ResultsPath,
    [string] $StopPath
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$culture = [Globalization.CultureInfo]::InvariantCulture

if ($Worker) {
    $writer = [IO.StreamWriter]::new($ResultsPath, $false, [Text.Encoding]::ASCII)
    $writer.AutoFlush = $true
    $writer.WriteLine('operation,startUtcTicks,endUtcTicks,elapsedMs,success')
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $payload = New-Object byte[] 4096
    try {
        while (-not (Test-Path -LiteralPath $StopPath) -and $deadline.Elapsed.TotalSeconds -lt 180) {
            foreach ($operation in 'scopeRead','outsideCreateReadDelete') {
                $started = [DateTime]::UtcNow.Ticks
                $timer = [Diagnostics.Stopwatch]::StartNew()
                $success = $false
                try {
                    if ($operation -eq 'scopeRead') {
                        $stream = [IO.FileStream]::new($ScopeFile, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                        try { $success = ($stream.ReadByte() -eq 83) } finally { $stream.Dispose() }
                    } else {
                        $target = Join-Path $OutsideDirectory 'foreground.bin'
                        [IO.File]::WriteAllBytes($target, $payload)
                        $success = ([IO.File]::ReadAllBytes($target).Length -eq 4096)
                        [IO.File]::Delete($target)
                    }
                } catch { $success = $false }
                $timer.Stop()
                $writer.WriteLine('{0},{1},{2},{3},{4}', $operation, $started, [DateTime]::UtcNow.Ticks,
                    $timer.Elapsed.TotalMilliseconds.ToString('F4', $culture), $success)
            }
            Start-Sleep -Milliseconds 10
        }
    } finally { $writer.Dispose() }
    exit 0
}

if ($ExpectedFeatureSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $ExpectedInspectorSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'Explicit feature and Inspector SHA256 hashes are required.'
}
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-latency-' + $id)
$outsideRoot = Join-Path $documents ('SafeUpload-fence-latency-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-latency-' + $id + '.sys')
$samplesPath = Join-Path $documents ('fence-latency-' + $id + '.csv')
$phasesPath = Join-Path $documents ('fence-latency-' + $id + '-phases.jsonl')
$taskPath = Join-Path $documents ('fence-latency-' + $id + '-system.ps1')
$stopFile = Join-Path $documents ('fence-latency-' + $id + '.stop')
$taskName = 'SafeUpload-StagedTest-FenceLatency-' + $id
$loaded = $false; $replaced = $false; $verifierEnabled = $false
$workerProcess = $null; $taskRegistered = $false; $measurementPassed = $false
$phases = [Collections.Generic.List[object]]::new()

function Get-Distribution($Values) {
    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) { throw 'No latency samples.' }
    [pscustomobject]@{
        count = $ordered.Count
        p50Ms = $ordered[[Math]::Ceiling($ordered.Count * 0.50) - 1]
        p95Ms = $ordered[[Math]::Ceiling($ordered.Count * 0.95) - 1]
        maxMs = $ordered[-1]
    }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'Filter must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy).Hash -ne $expectedPolicy) { throw 'Policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=fence-latency'
'GuestUTC=' + [DateTime]::UtcNow.ToString('o')
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
'InspectorSHA256=' + $ExpectedInspectorSha256.ToUpperInvariant()
'DeclaredLimits=' + (@{ maxScanMs=$MaxScanMs; maxForegroundMs=$MaxForegroundMs; p95ForegroundMs=$P95ForegroundMs; fileCount=$FileCount; iterations=$Iterations; verifier=[bool]$Verifier; qualification='synthetic-local-NTFS-only' } | ConvertTo-Json -Compress)

try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory)
    [void][IO.Directory]::CreateDirectory($outsideRoot)
    $sentinel = Join-Path $scopeDirectory 'sentinel.maptest'
    [IO.File]::WriteAllText($sentinel, 'SENTINEL ' + $id, [Text.Encoding]::ASCII)
    $sentinelHash = (Get-FileHash -LiteralPath $sentinel).Hash
    $payload = New-Object byte[] 4096
    $setupWatch = [Diagnostics.Stopwatch]::StartNew()
    for ($index = 0; $index -lt $FileCount; $index++) {
        [IO.File]::WriteAllBytes((Join-Path $scopeDirectory ('filler-{0:D5}.maptest' -f $index)), $payload)
    }
    'FixtureSetupMs=' + $setupWatch.Elapsed.TotalMilliseconds.ToString('F3', $culture)
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup).Hash -ne $expectedOriginal) { throw 'Restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        & verifier.exe /query | Out-Host
    }

    $workerArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Worker -ScopeFile "' + $sentinel + '" -OutsideDirectory "' + $outsideRoot + '" -ResultsPath "' + $samplesPath + '" -StopPath "' + $stopFile + '"'
    $workerProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $workerArguments -PassThru
    for ($attempt = 0; $attempt -lt 100 -and -not (Test-Path -LiteralPath $samplesPath); $attempt++) {
        if ($workerProcess.HasExited) { throw 'Sampling child exited before readiness.' }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $samplesPath)) { throw 'Sampling child was not ready.' }
    Start-Sleep -Milliseconds 500

    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $started = [DateTime]::UtcNow.Ticks
        $timer = [Diagnostics.Stopwatch]::StartNew()
        & fltmc.exe load SafeUpload | Out-Null
        $timer.Stop()
        $exitCode = $LASTEXITCODE
        $ended = [DateTime]::UtcNow.Ticks
        $loaded = ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s')
        $phase = [pscustomobject]@{ operation='load'; iteration=$iteration; startUtcTicks=$started; endUtcTicks=$ended; elapsedMs=$timer.Elapsed.TotalMilliseconds; exitCode=$exitCode }
        $phases.Add($phase)
        'Phase=' + ($phase | ConvertTo-Json -Compress)
        if ($exitCode -ne 0 -or -not $loaded) { throw 'Feature load failed.' }
        if ($iteration -lt $Iterations) {
            & fltmc.exe unload SafeUpload | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Intermediate unload failed.' }
            $loaded = $false
        }
    }

    # Measure the synchronous refresh call in SYSTEM, with exact before/after status.
    # All interpolated values here are generated paths/numbers, never policy content.
    $taskSource = @"
`$ErrorActionPreference = 'Stop'
try {
    for (`$iteration = 1; `$iteration -le $Iterations; `$iteration++) {
        `$before = & '$inspector' --admission-fence-status
        if (`$LASTEXITCODE -ne 0) { throw 'Before status failed.' }
        `$started = [DateTime]::UtcNow.Ticks
        `$timer = [Diagnostics.Stopwatch]::StartNew()
        `$reply = & '$inspector' --admission-fence-refresh
        `$timer.Stop()
        `$exitCode = `$LASTEXITCODE
        `$ended = [DateTime]::UtcNow.Ticks
        `$after = & '$inspector' --admission-fence-status
        if (`$LASTEXITCODE -ne 0) { throw 'After status failed.' }
        @{ operation='refresh'; iteration=`$iteration; startUtcTicks=`$started; endUtcTicks=`$ended; elapsedMs=`$timer.Elapsed.TotalMilliseconds; exitCode=`$exitCode; before=(`$before | ConvertFrom-Json); after=(`$after | ConvertFrom-Json); reply=(`$reply -join ' ') } | ConvertTo-Json -Depth 4 -Compress | Add-Content -LiteralPath '$phasesPath' -Encoding ASCII
        if (`$exitCode -ne 0) { throw 'Explicit refresh failed.' }
    }
    exit 0
} catch {
    @{ error=`$_.Exception.Message } | ConvertTo-Json -Compress | Add-Content -LiteralPath '$phasesPath' -Encoding ASCII
    exit 1
}
"@
    Set-Content -LiteralPath $taskPath -Value $taskSource -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $taskPath + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(120))) | Out-Null
    $taskRegistered = $true
    Start-ScheduledTask -TaskName $taskName
    for ($attempt = 0; $attempt -lt 240; $attempt++) {
        Start-Sleep -Milliseconds 500
        if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break }
        if ($workerProcess.HasExited) { throw 'Sampling child exited during refreshes.' }
    }
    if ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -or (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult -ne 0) { throw 'SYSTEM refresh task failed or timed out.' }
    foreach ($line in Get-Content -LiteralPath $phasesPath) {
        $phase = $line | ConvertFrom-Json
        'Phase=' + $line
        if ($null -ne $phase.error) { throw $phase.error }
        if ($phase.after.complete -ne $true -or $phase.after.filesScanned -lt $FileCount -or $phase.after.refreshFailed -ne 0 -or $phase.after.refreshCompleted -le $phase.before.refreshCompleted) { throw 'Scan coverage or status failed.' }
        $phases.Add($phase)
    }
    if (@($phases | Where-Object operation -eq 'refresh').Count -ne $Iterations) { throw 'Missing refresh phases.' }
    [IO.File]::WriteAllText($stopFile, 'stop')
    if (-not $workerProcess.WaitForExit(10000)) { throw 'Sampling child did not stop.' }
    if ($workerProcess.ExitCode -ne 0) { throw 'Sampling child failed.' }
    $samples = @(Import-Csv -LiteralPath $samplesPath)
    if (@($samples | Where-Object success -ne 'True').Count -ne 0) { throw 'Foreground operations failed.' }
    $scanSamples = @($samples | Where-Object {
        $sample = $_
        @($phases | Where-Object { [long]$sample.startUtcTicks -le [long]$_.endUtcTicks -and [long]$sample.endUtcTicks -ge [long]$_.startUtcTicks }).Count -gt 0
    })
    $measurementPassed = $true
    foreach ($operation in 'load','refresh') {
        $distribution = Get-Distribution @($phases | Where-Object operation -eq $operation | ForEach-Object { [double]$_.elapsedMs })
        'Distribution_' + $operation + '=' + ($distribution | ConvertTo-Json -Compress)
        if ($distribution.maxMs -gt $MaxScanMs) { $measurementPassed = $false }
    }
    foreach ($operation in 'scopeRead','outsideCreateReadDelete') {
        $selected = @($scanSamples | Where-Object operation -eq $operation)
        $distribution = Get-Distribution @($selected | ForEach-Object { [double]::Parse($_.elapsedMs, $culture) })
        'Distribution_DuringScan_' + $operation + '=' + ($distribution | ConvertTo-Json -Compress)
        $failures = @($selected | Where-Object success -ne 'True').Count
        'Failures_DuringScan_' + $operation + '=' + $failures
        if ($distribution.count -lt 5 -or $failures -ne 0 -or $distribution.maxMs -gt $MaxForegroundMs -or $distribution.p95Ms -gt $P95ForegroundMs) { $measurementPassed = $false }
    }
    'RawSamples=' + $samplesPath
    'RawRefreshPhases=' + $phasesPath
    'LatencyMeasurementPass=' + $measurementPassed
} finally {
    if ($taskRegistered) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($null -ne $workerProcess -and -not $workerProcess.HasExited) {
        [IO.File]::WriteAllText($stopFile, 'stop')
        if (-not $workerProcess.WaitForExit(10000)) { Stop-Process -Id $workerProcess.Id -Force }
    }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if (Test-Path -LiteralPath $sentinel) {
        if ((Get-FileHash -LiteralPath $sentinel).Hash -ne $sentinelHash) { throw 'Scope sentinel changed.' }
    }
    foreach ($directory in $scopeDirectory, $outsideRoot) {
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
    }
    foreach ($file in $taskPath, $stopFile, $backup) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
    if ((Get-FileHash -LiteralPath $installed).Hash -ne $expectedOriginal) { throw 'Original driver not restored.' }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'Filter remains loaded.' }
    if ((Get-FileHash -LiteralPath $policy).Hash -ne $expectedPolicy) { throw 'Policy changed.' }
    'LatencyRestoration=OriginalDriverAndPolicyRestored; FilterUnloaded; SyntheticFixturesRemoved'
}
if (-not $measurementPassed) { throw 'Declared synthetic latency limits did not pass.' }
'VariantComplete=fence-latency'
