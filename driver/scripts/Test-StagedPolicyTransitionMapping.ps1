<#
Reproduce a writable mapping that predates the agent's first policy push and a
later live policy scope expansion. Run only on the recorded isolated
WIN10-DEBUGGED VM. With the feature filter attached and no agent or policy, a
GUID-scoped file pre-sized to the mapping capacity is opened, mapped writable and
its source handle closed while the section stays alive. The real agent then
pushes the baseline policy (fixture out of scope). The real policy file is
extended with the fixture directory and pushed by restarting the real agent. The
mapping is mutated after that update; no publication permit runs.

Revised 2 October 2026 for the fence slice (first version: commit 3b3bfa0): the feature driver hash is a
parameter (default: the original tested build); a refused flush through the old view is caught and
classified instead of aborting the run; a second independent observer reads with
FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH so cache and stored bytes are told apart; the verdict line is
REPRODUCED when either independent observer reads the unapproved bytes, otherwise BLOCKED with the reasons.
Disposal of the old view is allowed to fail (a fenced stream refuses its final flush) without skipping
restoration. The setup, ordering, policies and baseline checks are unchanged.
#>
param([string] $ExpectedFeatureSha256 = 'ACED8226913E062E5D3EE6FD0CF96963C3FD2C1FB2242EDBEDBB00768CCD44F8', [switch] $Verifier)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
Add-Type -Namespace SafeUploadRepro -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytes, out uint read, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
'@
# Uncached, write-through read of the first Length bytes through a NEW file object (sector-aligned buffer).
function Read-UncachedText([string] $Path, [int] $Length) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3,
        [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return 'OBSERVED_REFUSED: CreateFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = [SafeUploadRepro.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]4096), [uint32]12288, [uint32]4)
    try {
        [uint32] $read = 0
        if (-not [SafeUploadRepro.Native]::ReadFile($handle, $buffer, 4096, [ref]$read, [IntPtr]::Zero)) {
            return 'OBSERVED_REFUSED: ReadFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $bytes = New-Object byte[] $Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
        return [Text.Encoding]::UTF8.GetString($bytes)
    }
    finally {
        [void][SafeUploadRepro.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
    }
}

$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedFeature = $ExpectedFeatureSha256.ToUpperInvariant()
$expectedServicePackage = 'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$serviceDirectory = Join-Path $documents 'stage-service-publish'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$id = [guid]::NewGuid().ToString('N')
$fixtureDirectory = Join-Path $documents ('SafeUpload-policy-transition-' + $id)
$fixtureExtension = '.maptest'
$target = Join-Path $fixtureDirectory ('synthetic' + $fixtureExtension)
$backup = Join-Path $documents ('SafeUpload-original-before-policy-transition-' + $id + '.sys')
$policyBackup = Join-Path $documents ('SafeUpload-policy-before-transition-' + $id + '.bin')
$baseLog = Join-Path $documents ('policy-transition-base-' + $id)
$updatedLog = Join-Path $documents ('policy-transition-updated-' + $id)
$mappingName = 'Local\SafeUpload-PolicyTransition-' + $id
$originalText = 'PUBLIC BASELINE BEFORE POLICY CHANGE ' + $id
$changedText = 'MAPPED AFTER POLICY CHANGE ' + $id
$originalBytes = [Text.Encoding]::UTF8.GetBytes($originalText)
$changedBytes = [Text.Encoding]::UTF8.GetBytes($changedText)
$mappingLength = 4096
$fixtureBytes = New-Object byte[] $mappingLength
[Array]::Copy($originalBytes, $fixtureBytes, $originalBytes.Length)
$agent = $null
$file = $null
$mapping = $null
$view = $null
$policyBytes = $null
$replaced = $false
$loaded = $false
$fixtureCreated = $false
$verifierEnabled = $false

function Start-TestAgentAndWaitForPolicy([string] $LogPrefix) {
    # ReadySignal is emitted only after SetPolicy succeeds. Waiting on the
    # named event avoids reading a live redirected log that the child process
    # owns exclusively and that is itself subject to the file filter.
    $ready = New-Object System.Threading.EventWaitHandle(
        $false,
        [System.Threading.EventResetMode]::ManualReset,
        'Global\SafeUploadServiceReady')
    $newAgent = $null
    try {
        [void]$ready.Reset()
        $newAgent = Start-StagedTestAgent $serviceDirectory $LogPrefix
        if (-not $ready.WaitOne([TimeSpan]::FromSeconds(45))) {
            throw 'Agent did not signal policy acceptance within 45 seconds.'
        }
        return $newAgent
    }
    catch {
        if ($null -ne $newAgent) { Stop-StagedTestAgent $newAgent }
        throw
    }
    finally { $ready.Dispose() }
}

function Assert-OutsideBaselineScopes([string] $Path, $PolicyDocument) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    foreach ($configured in @($PolicyDocument.monitoredScopes.destinationPaths)) {
        if ([string]::IsNullOrWhiteSpace($configured)) { continue }
        $scope = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($configured)).TrimEnd('\')
        if ($candidate.Equals($scope, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith($scope + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $scope.StartsWith($candidate + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "The GUID fixture intersects an existing monitored scope: $scope"
        }
    }
}

function Read-FreshDestinationBytes {
    $fresh = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $observed = New-Object byte[] $changedBytes.Length
        $count = $fresh.Read($observed, 0, $observed.Length)
        if ($count -ne $observed.Length) { throw "Short fresh-file-object read: $count" }
        return [Text.Encoding]::UTF8.GetString($observed)
    }
    finally { $fresh.Dispose() }
}

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
if ((Get-FileHash -LiteralPath $servicePackage -Algorithm SHA256).Hash -ne $expectedServicePackage) { throw 'Service package hash mismatch.' }
if (Test-Path -LiteralPath $fixtureDirectory) { throw 'GUID fixture collision.' }
if ((Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx')) -or
    (Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx.txt'))) { throw 'An owned-stream VHDX is already present.' }

$policyBytes = [IO.File]::ReadAllBytes($policy)
$baselinePolicy = [Text.Encoding]::UTF8.GetString($policyBytes) | ConvertFrom-Json
Assert-OutsideBaselineScopes $fixtureDirectory $baselinePolicy
$monitoredExtensions = @($baselinePolicy.monitoredScopes.extensions | ForEach-Object {
    $extension = [string]$_
    if (-not $extension.StartsWith('.')) { $extension = '.' + $extension }
    $extension.ToLowerInvariant()
})
if ($monitoredExtensions -contains $fixtureExtension.ToLowerInvariant()) {
    throw "Fixture extension is inspected by the baseline policy: $fixtureExtension"
}

'TestTimestampUTC=' + [DateTime]::UtcNow.ToString('o')
'Host=' + $env:COMPUTERNAME
'UUID=' + (Get-CimInstance Win32_ComputerSystemProduct).UUID
'OriginalInstalledSHA256=' + $expectedOriginal
'FeatureDriverSHA256=' + $expectedFeature
'ServicePackageSHA256=' + $expectedServicePackage
'OriginalPolicySHA256=' + $expectedPolicy
'FilterUnloaded=True; VerifierFlags=0; VerifiedDrivers=None; Service=Manual/Stopped'
'ConcurrentAgentProcesses=0; SafeUploadTestTasks=0'
'OwnedVhdxPresent=False'
"FixtureOutsideBaselinePolicy=True; Path=$fixtureDirectory"
"FixtureExtension=$fixtureExtension; BaselineSourceExtensionMonitored=False"

try {
    [void][IO.Directory]::CreateDirectory($fixtureDirectory)
    $fixtureCreated = $true
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedFeature) { throw 'Feature driver install hash mismatch.' }
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B (special pool, IRQL, pool tracking, I/O, deadlock, DDI)'
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
    $loaded = $true

    [IO.File]::WriteAllBytes($target, $fixtureBytes)
    $file = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    if ($file.Length -ne $mappingLength) { throw "Fixture EOF $($file.Length) does not match mapping size $mappingLength." }
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($file, $mappingName,
        [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, $mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $initial = New-Object byte[] $originalBytes.Length
    $view.ReadArray(0, $initial, 0, $initial.Length)
    if ([Text.Encoding]::UTF8.GetString($initial) -ne $originalText) { throw 'Baseline mapping bytes mismatch.' }
    $file.Dispose()
    $file = $null
    'FilterAttached=True; MappingCreatedBeforeFirstPolicyPush=True; MappingCapacityEqualsFileEOF=True; PreChangeFileHandleClosed=True; WritableSectionRetained=True'

    $agent = Start-TestAgentAndWaitForPolicy $baseLog
    'BaselinePolicyAcceptedByRealAgentAndDriver=True; MappingPredatesBaselinePolicy=True'

    Stop-StagedTestAgent $agent
    $agent = $null
    [IO.File]::WriteAllBytes($policyBackup, $policyBytes)
    $updatedPolicy = $baselinePolicy
    $updatedPolicy.monitoredScopes.destinationPaths = @($baselinePolicy.monitoredScopes.destinationPaths) + @($fixtureDirectory)
    $updatedPolicyBytes = [Text.Encoding]::UTF8.GetBytes(($updatedPolicy | ConvertTo-Json -Depth 10))
    [IO.File]::WriteAllBytes($policy, $updatedPolicyBytes)
    $updatedPolicyHash = (Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash
    "ExpandedPolicySHA256=$updatedPolicyHash"
    'ExpandedPolicyIncludesFixture=True'

    $agent = Start-TestAgentAndWaitForPolicy $updatedLog
    'ExpandedPolicyAcceptedByRealAgentAndDriver=True'

    $mapped = New-Object byte[] 4096
    [Array]::Copy($changedBytes, $mapped, $changedBytes.Length)
    $writeResult = 'SUCCESS'
    try {
        $view.WriteArray(0, $mapped, 0, $mapped.Length)
        $view.Flush()
    }
    catch {
        $writeResult = 'OBSERVED_REFUSED: ' + $_.Exception.Message
    }
    "MappedWriteResult=$writeResult"

    # Independent observers: each opens a NEW file object after the policy change.
    $observedText = ''
    try { $observedText = Read-FreshDestinationBytes }
    catch { $observedText = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    $uncachedText = Read-UncachedText $target $changedBytes.Length
    "FreshFileObjectBytes=$observedText"
    "FreshUncachedObserver=$uncachedText"
    if ($observedText -eq $changedText -or $uncachedText -eq $changedText) {
        'UnauthenticatedMappedWriteAfterPolicyExpansion=REPRODUCED'
    }
    else {
        'UnauthenticatedMappedWriteAfterPolicyExpansion=BLOCKED'
    }
}
finally {
    if ($null -ne $agent) { Stop-StagedTestAgent $agent }
    if ($null -ne $view) { try { $view.Dispose() } catch { 'ViewDisposeObserved=' + $_.Exception.Message } }
    if ($null -ne $mapping) { try { $mapping.Dispose() } catch { 'MappingDisposeObserved=' + $_.Exception.Message } }
    if ($null -ne $file) { try { $file.Dispose() } catch { 'FileDisposeObserved=' + $_.Exception.Message } }
    if ($null -ne $policyBytes) {
        $restorePolicy = $policyBytes
        if (Test-Path -LiteralPath $policyBackup) { $restorePolicy = [IO.File]::ReadAllBytes($policyBackup) }
        [IO.File]::WriteAllBytes($policy, $restorePolicy)
    }
    if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy was not restored.' }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    if (Test-Path -LiteralPath $policyBackup) { Remove-Item -LiteralPath $policyBackup -Force }
    if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) { throw 'Policy-transition fixture cleanup failed.' }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver was not restored.' }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload filter remained loaded.' }
    $finalSettings = & verifier.exe /querysettings 2>&1 | Out-String
    if ($finalSettings -notmatch 'Verifier Flags:\s+0x00000000') { throw 'Verifier settings changed during probe.' }
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Test agent process remained active.' }
    if (@(Get-ScheduledTask | Where-Object { $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)' }).Count -ne 0) { throw 'SafeUpload experiment task remained active.' }
    'OriginalDriverAndPolicyRestored=True; VerifierOff=True; FilterUnloaded=True'
    'AgentProcesses=0; AgentTasks=0; PolicyTransitionFixtureRemoved=True'
}
