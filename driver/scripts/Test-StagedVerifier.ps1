<# Volatile Driver Verifier gate on the isolated VM. No persistent flags. #>
$ErrorActionPreference = 'Stop'
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver hash mismatch.' }
$current = (& verifier.exe /query 2>&1) -join [Environment]::NewLine
if ($current -notmatch 'No drivers are currently verified') {
    throw 'The isolated verifier harness requires an initially idle Verifier.'
}
$active = $false
try {
    # Special Pool, Force IRQL, Pool Tracking, I/O Verification, Deadlock
    # Detection and Security Checks. Full DDI/filter verification needs boot.
    & verifier.exe /volatile /flags 0x13b /adddriver SafeUpload.sys | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Volatile verification could not be enabled.' }
    $active = $true
    foreach ($test in @('Test-StagedRename','Test-StagedDirectory','Test-StagedPrivateStorage')) {
        $log = 'C:\Users\vika\Documents\stage-verifier-' + $test + '.log'
        $env:SAFEUPLOAD_STAGED_VERIFIER_LOG = $log
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot ($test + '.ps1'))
        if ($LASTEXITCODE -ne 0) { throw "Verifier test failed: $test" }
        if (-not (Test-Path $log)) { throw "No live Verifier statistics: $test" }
        $statistics = Get-Content -LiteralPath $log -Raw
        if ($statistics -notmatch 'SafeUpload.sys') { throw "The driver was not verified: $test" }
        Write-Output "VolatileVerifierPassed=$test Flags=0x13B Evidence=$log"
    }
}
finally {
    Remove-Item Env:\SAFEUPLOAD_STAGED_VERIFIER_LOG -ErrorAction SilentlyContinue
    if ($active) {
        & verifier.exe /volatile /removedriver SafeUpload.sys | Out-Host
        & verifier.exe /volatile /flags 0 | Out-Host
    }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) {
        throw 'Original driver restoration failed; inspect the harness backup before another experiment.'
    }
    Write-Output 'OriginalDriverRestored=True'
}
