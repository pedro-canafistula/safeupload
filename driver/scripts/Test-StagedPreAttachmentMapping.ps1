<#
Small reproduction for a writable mapping created before SafeUpload attaches.
Run only on the recorded, isolated WIN10-DEBUGGED VM from its preserved clean
checkpoint. Uses a new synthetic child under the existing protected test root.
#>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')

$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedFeature = 'ACED8226913E062E5D3EE6FD0CF96963C3FD2C1FB2242EDBEDBB00768CCD44F8'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$id = [guid]::NewGuid().ToString('N')
$fixtureDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('premap-' + $id)
$target = Join-Path $fixtureDirectory 'synthetic.txt'
$backup = Join-Path $documents ('SafeUpload-original-before-premap-' + $id + '.sys')
$originalText = 'PUBLIC SYNTHETIC BASELINE ' + $id
$changedText = 'MAPPED AFTER FILTER ATTACH ' + $id
$originalBytes = [Text.Encoding]::UTF8.GetBytes($originalText)
$changedBytes = [Text.Encoding]::UTF8.GetBytes($changedText)
$file = $null
$mapping = $null
$view = $null
$loaded = $false
$replaced = $false
$verified = $false
$fixtureCreated = $false

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
$verifierQuery = & verifier.exe /query 2>&1 | Out-String
$verifierSettings = & verifier.exe /querysettings 2>&1 | Out-String
if ($verifierQuery -notmatch 'No drivers are currently verified' -or
    $verifierSettings -notmatch 'Verifier Flags:\s+0x00000000') { throw 'Verifier must be off at baseline.' }
$service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
if ($service.StartMode -ne 'Manual' -or $service.State -ne 'Stopped') { throw 'Original service baseline mismatch.' }
if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) { throw 'A SafeUpload service process is already running.' }
if (@(Get-ScheduledTask | Where-Object { $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)' }).Count -ne 0) { throw 'A SafeUpload experiment task is already active.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $expectedFeature) { throw 'Feature driver hash mismatch.' }
if (Test-Path -LiteralPath $fixtureDirectory) { throw 'GUID fixture collision.' }
'TestTimestampUTC='+[DateTime]::UtcNow.ToString('o')
'Host='+$env:COMPUTERNAME
'UUID='+(Get-CimInstance Win32_ComputerSystemProduct).UUID
'OriginalInstalledSHA256='+$expectedOriginal
'FeatureDriverSHA256='+$expectedFeature
'ServicePackageSHA256='+((Get-FileHash (Join-Path $documents 'stage-service-publish.zip') -Algorithm SHA256).Hash)
'OriginalPolicySHA256='+$expectedPolicy
'FilterUnloaded=True; VerifierFlags=0; VerifiedDrivers=None; Service=Manual/Stopped'
'ConcurrentAgentProcesses=0; SafeUploadTestTasks=0'

try {
    [void][IO.Directory]::CreateDirectory($fixtureDirectory)
    $fixtureCreated = $true
    [IO.File]::WriteAllBytes($target, $originalBytes)
    $file = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $mappingName = 'Local\SafeUpload-Premap-' + $id
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($file, $mappingName,
        [long][Math]::Max(4096, $file.Length), [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $initial = New-Object byte[] $originalBytes.Length
    $view.ReadArray(0, $initial, 0, $initial.Length)
    if ([Text.Encoding]::UTF8.GetString($initial) -ne $originalText) { throw 'Unfiltered mapping baseline mismatch.' }
    'PreAttachmentFileHandle=True; PreAttachmentWritableSection=True'
    "SyntheticProtectedPath=$target"

    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedFeature) { throw 'Feature driver install hash mismatch.' }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
    $loaded = $true
    'FeatureAttachedWhileOriginalWritableSectionRemained=True'

    $mapped = New-Object byte[] 4096
    [Array]::Copy($changedBytes, $mapped, $changedBytes.Length)
    $view.WriteArray(0, $mapped, 0, $mapped.Length)
    $view.Flush()
    $file.Flush($true)

    # This opens a new file object after attachment. It does not reuse the
    # pre-attachment stream or mapped section used by the writer.
    $fresh = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $observed = New-Object byte[] $changedBytes.Length
        $read = $fresh.Read($observed, 0, $observed.Length)
        if ($read -ne $observed.Length) { throw "Short independent read: $read" }
        $observedText = [Text.Encoding]::UTF8.GetString($observed)
        "FreshFileObjectBytes=$observedText"
        if ($observedText -ne $changedText) { throw 'Pre-attachment mapped mutation did not reach the independent destination view.' }
        'UnauthenticatedMappedWriteAfterAttach=REPRODUCED'
    }
    finally { $fresh.Dispose() }
}
finally {
    if ($null -ne $view) { $view.Dispose() }
    if ($null -ne $mapping) { $mapping.Dispose() }
    if ($null -ne $file) { $file.Dispose() }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verified }
    if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Policy changed during probe.' }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver was not restored.' }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload filter remained loaded.' }
    $finalSettings = & verifier.exe /querysettings 2>&1 | Out-String
    if ($finalSettings -notmatch 'Verifier Flags:\s+0x00000000') { throw 'Verifier settings changed during probe.' }
    'OriginalDriverAndPolicyRestored=True; VerifierOff=True; FilterUnloaded=True'
    if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) {
        Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
    }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) { throw 'Synthetic fixture cleanup failed.' }
    'SyntheticFixtureRemoved=True'
}
