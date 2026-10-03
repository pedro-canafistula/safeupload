<#
Independent, read-only check of the isolated WIN10-DEBUGGED baseline. Run it in a
separate call before creating a checkpoint and again after every experiment,
including failures. It never changes state; BaselineClean=False names the
first failing field instead of throwing so every field is always recorded.
#>
param(
    [string] $ExpectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE',
    [string] $ExpectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
$checks = [ordered]@{}

$uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$checks['DebuggeeIdentity'] = ($env:COMPUTERNAME -eq 'WIN10-DEBUGGED' -and $uuid -eq '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D')
$installedHash = (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\SafeUpload.sys' -Algorithm SHA256).Hash
$checks['OriginalDriverHash'] = ($installedHash -eq $ExpectedOriginal)
$checks['FilterUnloaded'] = -not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s')
$verifierQuery = & verifier.exe /query 2>&1 | Out-String
$verifierSettings = & verifier.exe /querysettings 2>&1 | Out-String
$checks['VerifierOff'] = ($verifierQuery -match 'No drivers are currently verified' -and
    $verifierSettings -match 'Verifier Flags:\s+0x00000000')
$memory = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$checks['VerifierNotConfigured'] = (-not $memory.VerifyDriverLevel -and -not $memory.VerifyDrivers)
$service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
$checks['ServiceManualStopped'] = ($service.StartMode -eq 'Manual' -and $service.State -eq 'Stopped')
$policyHash = (Get-FileHash -LiteralPath 'C:\ProgramData\SafeUpload\policy.json' -Algorithm SHA256).Hash
$checks['OriginalPolicyHash'] = ($policyHash -eq $ExpectedPolicy)
$checks['ZeroAgentProcesses'] = (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -eq 0)
$checks['ZeroTestTasks'] = (@(Get-ScheduledTask | Where-Object { $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)' }).Count -eq 0)
$checks['NoOwnedVhdx'] = -not ((Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx')) -or
    (Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx.txt')))
$fixtures = @(Get-ChildItem -LiteralPath $documents -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^SafeUpload-.*[0-9a-f]{32}$' })
$checks['NoGuidFixtureDirectories'] = ($fixtures.Count -eq 0)
$checks['NoSyntheticVolume'] = -not (Test-Path -LiteralPath 'S:\')
$canaries = @()
$canaryRootsRead = $true
$canaryVolumes = @()
try {
    $canaryVolumes = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop |
        Where-Object FileSystem -eq 'NTFS')
    if ($canaryVolumes.Count -eq 0) { throw 'No fixed NTFS volume was enumerated.' }
    foreach ($volume in $canaryVolumes) {
        try { $canaries += @(Get-ChildItem -LiteralPath $volume.DeviceID -Filter 'SafeUpload-canary-*.tmp' -Force -ErrorAction Stop) }
        catch { $canaryRootsRead = $false; 'CanaryRootReadError=' + $_.Exception.Message }
    }
} catch { $canaryRootsRead = $false; 'CanaryVolumeEnumerationError=' + $_.Exception.Message }
$checks['CanaryRootsEnumerated'] = $canaryRootsRead
$checks['NoVolumeCanaryFiles'] = ($canaries.Count -eq 0 -and $canaryRootsRead)

'UTC=' + [DateTime]::UtcNow.ToString('o')
'Host=' + $env:COMPUTERNAME
'UUID=' + $uuid
'OriginalInstalledSHA256=' + $installedHash
'PolicySHA256=' + $policyHash
'Service=' + $service.StartMode + '/' + $service.State
'CanaryVolumeCount=' + $canaryVolumes.Count
'CanaryVolumeRoots=' + (($canaryVolumes | ForEach-Object DeviceID | Sort-Object) -join ';')
foreach ($name in $checks.Keys) { $name + '=' + $checks[$name] }
if ($fixtures.Count -ne 0) { 'FixtureDirectories=' + (($fixtures | ForEach-Object Name) -join ';') }
if ($canaries.Count -ne 0) { 'VolumeCanaryFiles=' + (($canaries | ForEach-Object FullName) -join ';') }
'BaselineClean=' + (-not ($checks.Values -contains $false))
