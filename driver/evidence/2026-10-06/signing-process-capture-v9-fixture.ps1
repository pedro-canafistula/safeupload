[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$capturePath = Join-Path $PSScriptRoot 'signing-process-capture-v9.ps1'
$captureExpectedSha256 = '6cac6f59c640c6fb045f61b87be1bb4deeeea451c80cd067ae022180a0a01a9f'
if (-not (Test-Path -LiteralPath $capturePath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $capturePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $captureExpectedSha256) {
    throw 'Pinned V9 process-capture helper is missing or changed.'
}
. $capturePath
$cmdPath = Join-Path $env:SystemRoot 'System32\cmd.exe'
if (-not (Test-Path -LiteralPath $cmdPath -PathType Leaf)) { throw 'Fixture cmd.exe is unavailable.' }
$success = Invoke-SafeUploadCapturedProcess -FilePath $cmdPath -Arguments '/d /c "echo fixture-stdout"'
if ($success.ExitCode -ne 0 -or $success.Stdout -notmatch 'fixture-stdout' -or $success.Stderr.Length -ne 0) {
    throw 'Captured process success case failed.'
}
$failure = Invoke-SafeUploadCapturedProcess -FilePath $cmdPath -Arguments '/d /c "echo fixture-stderr 1>&2 & exit /b 7"'
if ($failure.ExitCode -ne 7 -or $failure.Stderr -notmatch 'fixture-stderr') {
    throw 'Captured process stderr/nonzero case failed.'
}
$launchFailurePreserved = $false
$launchFailureType = ''
$launchFailureMessage = ''
$missingExecutablePath = Join-Path $env:TEMP ('safeupload-v9-no-such-process-' + [Guid]::NewGuid().ToString('N') + '.exe')
if (Test-Path -LiteralPath $missingExecutablePath) { throw 'Randomized launch-failure fixture path already exists.' }
try {
    [void](Invoke-SafeUploadCapturedProcess -FilePath $missingExecutablePath -Arguments '')
} catch {
    $launchFailureType = $_.Exception.GetType().FullName
    $launchFailureMessage = $_.Exception.Message
    $launchFailurePreserved = -not [string]::IsNullOrWhiteSpace($launchFailureType) -and -not [string]::IsNullOrWhiteSpace($launchFailureMessage)
}
if (-not $launchFailurePreserved) { throw 'Captured process launch-failure case failed.' }
[ordered]@{
    Status = 'V9_PROCESS_CAPTURE_FIXTURE_PASS'
    HelperSha256 = $captureExpectedSha256
    SuccessExitCode = $success.ExitCode
    SuccessStdoutCaptured = $true
    FailureExitCode = $failure.ExitCode
    FailureStderrCaptured = $true
    LaunchFailurePreserved = $launchFailurePreserved
    LaunchFailureType = $launchFailureType
    TrustOrStoreOperationsPerformed = $false
    KeyOrAclOperationsPerformed = $false
} | ConvertTo-Json -Compress
