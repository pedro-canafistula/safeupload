#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string]$Label)
$ErrorActionPreference = 'Stop'
$taskName = 'SafeUpload-SecurityRoundTrip-' + $Label
$output = Join-Path $PSScriptRoot ('security-roundtrip-' + $Label + '.txt')
$complete = Join-Path $PSScriptRoot ('security-roundtrip-' + $Label + '.exit')
$worker = Join-Path $PSScriptRoot ('security-roundtrip-' + $Label + '.worker.ps1')
$pidRecord = Join-Path $PSScriptRoot ('security-roundtrip-' + $Label + '.pid')
if ((Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $complete) -or
    (Test-Path -LiteralPath $worker) -or (Test-Path -LiteralPath $pidRecord)) { throw 'Native control destination already exists.' }
$control = Join-Path $PSScriptRoot 'security-roundtrip-native-control.ps1'
$body = @"
`$ErrorActionPreference='Stop'
([string]`$PID + ';' + (Get-Process -Id `$PID).StartTime.ToUniversalTime().Ticks) | Set-Content -LiteralPath '$pidRecord' -Encoding Ascii
try {
    & '$control' *> '$output'
    0 | Set-Content -LiteralPath '$complete' -Encoding Ascii
} catch {
    (`$_ | Out-String) | Add-Content -LiteralPath '$output'
    1 | Set-Content -LiteralPath '$complete' -Encoding Ascii
    exit 1
}
"@
$body | Set-Content -LiteralPath $worker -Encoding UTF8
$timer = [Diagnostics.Stopwatch]::StartNew()
$registered = $false
try {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $worker + '"')
    [void](Register-ScheduledTask -TaskName $taskName -Action $action -User 'SYSTEM' -RunLevel Highest)
    $registered = $true
    Start-ScheduledTask -TaskName $taskName
    while (-not (Test-Path -LiteralPath $complete)) {
        if ($timer.Elapsed.TotalSeconds -ge 180) { throw 'Native control exceeded its monotonic deadline.' }
        Start-Sleep -Milliseconds 200
    }
    Get-Content -LiteralPath $output
    $code = [int](Get-Content -LiteralPath $complete -Raw).Trim()
    if ($code -ne 0) { throw ('Native control failed: exit=' + $code) }
} finally {
    $cleanupFailure = $null
    try {
      # Kill the recorded tree before stopping its task, so a compiler child
      # cannot escape after its parent disappears. Never stop a reused PID.
      if (Test-Path -LiteralPath $pidRecord) {
        $parts = (Get-Content -LiteralPath $pidRecord -Raw).Trim().Split(';')
        $process = Get-Process -Id ([int]$parts[0]) -ErrorAction SilentlyContinue
        if ($null -ne $process -and $process.StartTime.ToUniversalTime().Ticks -eq [long]$parts[1]) {
            & taskkill.exe /PID $parts[0] /T /F *> $null
            if ($LASTEXITCODE -ne 0) { throw 'Native control worker cleanup failed.' }
            $process.WaitForExit(10000) | Out-Null
            if (-not $process.HasExited) { throw 'Native control worker remains live.' }
        }
      }
    } catch { $cleanupFailure = $_ }
    try {
      if ($registered) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
      }
      Remove-Item -LiteralPath $worker -Force
      if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Native control task cleanup failed.' }
    } catch { $cleanupFailure = $_ }
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
    Write-Output 'NativeControlTaskRestored=PASS TaskAbsent=True WorkerStopped=True'
}
