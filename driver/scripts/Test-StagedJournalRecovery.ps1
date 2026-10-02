<# Production journal class under real LocalSystem, with original driver unloaded.
   Publish StagedJournalProbe and take a fresh frozen checkpoint first. This does
   not replace the real service + kernel integration gate. #>
param([string] $ProbeDir = 'C:\Users\vika\Documents\stage-journal-probe',
      [string] $EvidencePrefix = 'C:\Users\vika\Documents\journal-recovery')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
function Assert-JournalBaseline {
    if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
        (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
    if ((Get-FileHash 'C:\Windows\System32\drivers\SafeUpload.sys').Hash -ne $expected) { throw 'Original driver mismatch.' }
    if ((& fltmc.exe filters) -match '^SafeUpload\s') { throw 'Journal-only gate requires the filter unloaded.' }
    if ((& verifier.exe /query | Out-String) -notmatch 'No drivers are currently verified') { throw 'Active Verifier must be off.' }
    if ((& verifier.exe /querysettings | Out-String) -notmatch 'Verifier Flags: 0x00000000') { throw 'Configured Verifier must be off.' }
    $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
    if ($svc.StartMode -ne 'Manual' -or $svc.State -ne 'Stopped') { throw 'Original service state mismatch.' }
}
Assert-JournalBaseline
if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count) { throw 'An agent is already running.' }
$id = [guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData ('SafeUpload-JournalProbe-' + $id)
$prefix = $EvidencePrefix + '-' + $id
$result = $prefix + '.json'
$ready = $prefix + '.ready'
$agent = $null
try {
    $arguments = '"' + $root + '" "' + $result + '" "' + $ready + '"'
    $agent = Start-StagedTestAgent -ServiceDir $ProbeDir -LogPrefix $prefix -ExecutableName 'StagedJournalProbe.exe' -Arguments $arguments
    # Get-Process attaches by PID. Retain its public process handle BEFORE the
    # ready signal so ExitCode remains available after the child disappears.
    # The unfiltered control exits 7: uncached gives null, cached gives 7.
    [void]$agent.Process.Handle
    [IO.File]::WriteAllText($ready, 'go')
    if (-not $agent.Process.WaitForExit(60000)) { throw 'Journal probe is still running after 60 seconds.' }
    if (-not (Test-Path -LiteralPath $result)) { throw 'Journal probe did not persist its result.' }
    $summary = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
    Get-Content -LiteralPath ($prefix + '-out.log') | Out-Host
    if ($agent.Process.ExitCode -ne 0 -or $summary.ExitCode -ne 0 -or @($summary.Passed).Count -ne 28) {
        Get-Content -LiteralPath ($prefix + '-err.log') | Out-Host
        throw ('LocalSystem journal gate failed: ' + $summary.Failure)
    }
    Write-Output ('JournalRecoveryCases=' + @($summary.Passed).Count + '; LocalSystem=True; PASS')
    Write-Output ('RetainedFixtureRoot=' + $summary.FixtureRoot)
    Write-Output ('Result=' + $result)
}
finally {
    Stop-StagedTestAgent $agent
    if ($null -ne $agent) { $agent.Process.Dispose() }
    Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
    Assert-JournalBaseline
    Write-Output ('OriginalDriverUnchanged=' + $expected)
}
