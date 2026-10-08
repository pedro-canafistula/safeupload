<# Debug aid: load the feature driver, start the real test agent once with the baseline policy, print the agent
   logs and the policy-ready result, then restore. Run only on the recorded debuggee, from the experiment wrapper. #>
param([Parameter(Mandatory)] [string] $ExpectedFeatureSha256, [switch] $Verifier, [int] $HoldSeconds = 0)
$ErrorActionPreference = 'Stop'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$serviceDirectory = Join-Path $documents 'stage-service-publish'
$id = [guid]::NewGuid().ToString('N')
$backup = Join-Path $documents ('SafeUpload-original-before-fence-debug-' + $id + '.sys')
$log = Join-Path $documents ('fence-debug-agent-' + $id)
$loaded = $false; $agent = $null; $replaced = $false; $verifierEnabled = $false
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'Filter must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature hash mismatch.' }
try {
    Backup-StagedTestDriver $backup
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B'
    }
    $loadWatch = [Diagnostics.Stopwatch]::StartNew()
    $loadOutput = & fltmc.exe load SafeUpload 2>&1 | Out-String
    'FltmcLoadSeconds=' + [math]::Round($loadWatch.Elapsed.TotalSeconds, 2)
    'FltmcLoadExit=' + $LASTEXITCODE
    'FltmcLoadOutput=' + ($loadOutput -replace '\s+', ' ').Trim()
    $loaded = ($LASTEXITCODE -eq 0)
    $ready = New-Object System.Threading.EventWaitHandle($false, [System.Threading.EventResetMode]::ManualReset, 'Global\SafeUploadServiceReady')
    [void]$ready.Reset()
    # Diagnostic replica of Start-StagedTestAgent: a marker is written first thing, and task state is sampled.
    $launchWatch = [Diagnostics.Stopwatch]::StartNew()
    $taskName = 'SafeUpload-StagedTest-DiagLaunch-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-agent-diag-' + $id + '.ps1')
    $marker = $launcher + '.marker'
    $pidFile = $launcher + '.pid'
    $exe = Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'
    Set-Content -LiteralPath $launcher -Encoding UTF8 -Value @(
        "[IO.File]::WriteAllText('$marker', 'launcher-started ' + [DateTime]::UtcNow.ToString('o'))",
        '$env:Interception__Mode = ''Minifilter''',
        '$env:Interception__StagingPrototype = ''true''',
        '$ErrorActionPreference = ''Stop''',
        'try {',
        "  `$p = Start-Process -FilePath '$exe' -PassThru -WindowStyle Hidden -RedirectStandardOutput '$log-out.log' -RedirectStandardError '$log-err.log'",
        "  [IO.File]::WriteAllText('$pidFile', [string]`$p.Id)",
        '  $p.WaitForExit()',
        '} catch {',
        "  [IO.File]::WriteAllText('$marker.err', (`$_ | Out-String) + ' HRESULT=0x' + ('{0:X}' -f `$_.Exception.HResult))",
        "  [IO.File]::WriteAllText('$pidFile', 'failed')",
        '}')
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 12; $i++) {
            Start-Sleep -Seconds 5
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            $state = (Get-ScheduledTask -TaskName $taskName).State
            $elapsed = ($i + 1) * 5
            ('DiagLaunch t+{0}s state={1} lastRun={2} lastResult=0x{3:X} marker={4} pid={5} powershell={6}' -f $elapsed, $state,
                $info.LastRunTime.ToString('HH:mm:ss'), $info.LastTaskResult, (Test-Path $marker), (Test-Path $pidFile),
                @(Get-Process powershell -ErrorAction SilentlyContinue).Count)
            if (Test-Path $pidFile) { break }
        }
        'AgentLaunchSeconds=' + [math]::Round($launchWatch.Elapsed.TotalSeconds, 2)
        if (Test-Path $marker) { 'Marker=' + (Get-Content -LiteralPath $marker -Raw) }
        if (Test-Path "$marker.err") { 'LauncherError=' + ((Get-Content -LiteralPath "$marker.err" -Raw) -replace '\s+', ' ') }
        if ((Test-Path $pidFile) -and ((Get-Content -LiteralPath $pidFile -Raw) -match '^\s*\d+\s*$')) { $agentPid = [int](Get-Content -LiteralPath $pidFile); $agent = [pscustomobject]@{ TaskName = $taskName; Launcher = $launcher; PidFile = $pidFile; Process = (Get-Process -Id $agentPid) } }
    }
    catch { 'DiagLaunchError=' + $_.Exception.Message }
    if ($null -eq $agent) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue; Remove-Item $launcher, $marker, "$marker.err", $pidFile -Force -ErrorAction SilentlyContinue }
    'PolicyReadyWithin20s=' + $ready.WaitOne([TimeSpan]::FromSeconds(20))
    if ($HoldSeconds -gt 0 -and $null -ne $agent) {
        # Hold the guest in this state so the host can capture memory while the agent is (not) running.
        try {
            $ap = Get-Process -Id $agent.Process.Id -ErrorAction Stop
            'AgentState pid={0} cpuSeconds={1} threads={2} handles={3} hasExited={4}' -f $ap.Id, [math]::Round($ap.CPU, 2), $ap.Threads.Count, $ap.HandleCount, $ap.HasExited
            foreach ($g in ($ap.Threads | Group-Object { [string]$_.ThreadState + '/' + [string]$_.WaitReason })) { 'AgentThreads ' + $g.Name + ' x' + $g.Count }
        }
        catch { 'AgentStateError=' + $_.Exception.Message }
        'HOLD_START ' + [DateTime]::UtcNow.ToString('o')
        Start-Sleep -Seconds $HoldSeconds
        'HOLD_END ' + [DateTime]::UtcNow.ToString('o') + ' readyAfterHold=' + $ready.WaitOne(0)
    }
    Start-Sleep -Seconds 2
    if ($null -ne $agent) {
        try { Stop-StagedTestAgent $agent } catch { 'StopAgentError=' + $_.Exception.Message; & taskkill.exe /F /PID $agent.Process.Id 2>&1 | Out-String }
    }
    $agent = $null
    # Fence status and a forced refresh through the Inspector as SYSTEM (one client, so only after the agent stops).
    $inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
    $cmdFile = Join-Path $documents ('fence-debug-' + $id + '.cmd')
    $cmdOut = Join-Path $documents ('fence-debug-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @(
        '@echo off',
        ('"' + $inspector + '" --admission-fence-status'),
        ('"' + $inspector + '" --admission-fence-refresh'),
        ('"' + $inspector + '" --admission-fence-status'))
    $taskName = 'SafeUpload-StagedTest-DebugCmd-' + $id
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 60; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        '--- inspector (status, refresh, status)'
        if (Test-Path -LiteralPath $cmdOut) { Get-Content -LiteralPath $cmdOut } else { '(no output)' }
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
    foreach ($suffix in '-out.log', '-err.log') {
        $path = $log + $suffix
        '--- ' + $suffix
        if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Tail 40 } else { '(absent)' }
    }
}
finally {
    if ($null -ne $agent) { try { Stop-StagedTestAgent $agent } catch { & taskkill.exe /F /PID $agent.Process.Id 2>&1 | Out-Null } }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    Remove-Item -LiteralPath $backup, ($log + '-out.log'), ($log + '-err.log') -Force -ErrorAction SilentlyContinue
}
