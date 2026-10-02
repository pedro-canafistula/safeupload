# Shared test helpers. The agent runs as LocalSystem so its private backing
# files never grant the writing user's SID independent access.
function Save-StagedVerifierEvidence {
    if ([string]::IsNullOrEmpty($env:SAFEUPLOAD_STAGED_VERIFIER_LOG)) { return }
    $result = & verifier.exe /query 2>&1
    $result | Set-Content -LiteralPath $env:SAFEUPLOAD_STAGED_VERIFIER_LOG -Encoding UTF8
}

function Start-StagedTestAgent([string] $ServiceDir, [string] $LogPrefix) {
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedTest-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-agent-' + $id + '.ps1')
    $pidFile = $launcher + '.pid'
    $exe = Join-Path $ServiceDir 'SafeUpload.Agent.Service.exe'
    $script = @'
$ErrorActionPreference = 'Stop'
$env:Interception__Mode = 'Minifilter'
$env:Interception__StagingPrototype = 'true'
$process = Start-Process -FilePath '__EXE__' -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput '__LOG__-out.log' -RedirectStandardError '__LOG__-err.log'
Set-Content -LiteralPath '__PID__' -Value $process.Id
$process.WaitForExit()
'@
    $script = $script.Replace('__EXE__', $exe).Replace('__LOG__', $LogPrefix).Replace('__PID__', $pidFile)
    Set-Content -LiteralPath $launcher -Value $script -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 40 -and -not (Test-Path $pidFile); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path $pidFile)) { throw 'LocalSystem test agent did not launch.' }
        $process = Get-Process -Id ([int](Get-Content -LiteralPath $pidFile)) -ErrorAction Stop
        return [pscustomobject]@{ TaskName = $taskName; Launcher = $launcher; PidFile = $pidFile; Process = $process }
    }
    catch {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $launcher,$pidFile -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Stop-StagedTestAgent($Agent) {
    if ($null -eq $Agent) { return }
    Stop-ScheduledTask -TaskName $Agent.TaskName -ErrorAction SilentlyContinue
    if (-not $Agent.Process.HasExited) {
        Stop-Process -Id $Agent.Process.Id -Force -ErrorAction SilentlyContinue
        [void]$Agent.Process.WaitForExit(10000)
    }
    Unregister-ScheduledTask -TaskName $Agent.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Agent.Launcher,$Agent.PidFile -Force -ErrorAction SilentlyContinue
}

function Remove-StagedTestFiles([string[]] $Paths) {
    $pathsToDelete = @($Paths | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)
    if ($pathsToDelete.Count -eq 0) { return }
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedCleanup-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-cleanup-' + $id + '.ps1')
    $manifest = $launcher + '.json'
    $done = $launcher + '.done'
    ConvertTo-Json -InputObject $pathsToDelete | Set-Content -LiteralPath $manifest -Encoding UTF8
    $script = @'
$ErrorActionPreference = 'Stop'
$cleanupDoneFile = '__DONE__'
try {
    $paths = Get-Content -LiteralPath '__MANIFEST__' -Raw | ConvertFrom-Json
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    [IO.File]::WriteAllText($cleanupDoneFile, 'removed')
}
catch {
    [IO.File]::WriteAllText($cleanupDoneFile, 'failed: ' + $_.Exception.Message)
    exit 1
}
'@
    Set-Content -LiteralPath $launcher -Value ($script.Replace('__MANIFEST__', $manifest).Replace('__DONE__', $done)) -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path $done); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path $done)) {
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            throw "LocalSystem test cleanup did not complete; task result $($info.LastTaskResult)."
        }
        $result = Get-Content -LiteralPath $done -Raw
        if ($result -ne 'removed') { throw $result }
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $launcher,$manifest,$done -Force -ErrorAction SilentlyContinue
    }
}

function Copy-StagedOriginalDriver([string] $Source, [string] $Destination) {
    $expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
    if ((Get-FileHash -LiteralPath $Source).Hash -ne $expected) { throw 'Original driver source mismatch.' }
    $sourceStream = [IO.FileStream]::new($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $output = [IO.FileStream]::new($Destination,[IO.FileMode]::Create,[IO.FileAccess]::Write,
            [IO.FileShare]::Read,65536,[IO.FileOptions]::WriteThrough)
        try { $sourceStream.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
    } finally { $sourceStream.Dispose() }
    if ((Get-FileHash -LiteralPath $Destination).Hash -ne $expected) { throw 'Durable original copy mismatch.' }
}

function Backup-StagedTestDriver([string] $Backup) {
    Copy-StagedOriginalDriver 'C:\Windows\System32\drivers\SafeUpload.sys' $Backup
}

# Unload refusal must never leave experimental installed bytes behind. If a
# live kernel object prevents unloading, preserve fixtures and require reboot.
function Restore-StagedTestDriver([string] $Backup, [bool] $Loaded, [bool] $VerifierEnabled = $false) {
    $installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
    $expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
    if ((Get-FileHash -LiteralPath $Backup).Hash -ne $expected) {
        throw 'Restoration backup is not the recorded original. Recover the preserved VM snapshot.'
    }
    $unloaded = -not $Loaded
    if ($Loaded) {
        for ($attempt = 0; $attempt -lt 80 -and -not $unloaded; $attempt++) {
            $result = & fltmc.exe unload SafeUpload 2>&1
            $unloaded = $LASTEXITCODE -eq 0
            if (-not $unloaded) { Start-Sleep -Milliseconds 250 }
        }
        $result | Out-Host
    }
    if ($VerifierEnabled) {
        & verifier.exe /volatile /removedriver SafeUpload.sys | Out-Host
        & verifier.exe /reset | Out-Host
    }
    if (-not $unloaded) {
        Move-Item -LiteralPath $installed -Destination ($installed + '.owned-' + [guid]::NewGuid().ToString('N') + '.loaded')
    }
    Copy-StagedOriginalDriver $Backup $installed
    $hash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
    if ($hash -ne $expected) { throw "Original driver restoration failed: $hash" }
    Write-Output "OriginalDriverRestored=$hash"
    if (-not $unloaded) { throw 'Live owned objects prevented unload. Original installed bytes restored; reboot before cleaning retained fixtures.' }
    $filters = & fltmc.exe filters
    if ($filters -match '^SafeUpload\s') { throw 'SafeUpload remained loaded after restoration.' }
    Write-Output 'ExperimentalDriverUnloaded=True'
}
