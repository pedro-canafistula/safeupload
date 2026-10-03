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
FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH, and an unbuffered raw-volume observer checks the allocated
extent against a raw baseline of the complete 4096-byte fixture. Any byte difference from that baseline is
reported as exposure, not just a matching marker. Expansion is BLOCKED only after a successful mapped write
and view flush, successful file-buffer flush, successful disposal of that expansion-only view, and a successful
raw comparison showing the complete fixture unchanged. Filtered file-reader refusals do not replace or
invalidate the raw observer; missing flush, disposal, baseline, or raw evidence is INCONCLUSIVE.
Disposal/agent-stop errors are recorded without skipping policy or driver restoration.

The current source candidate extends this case with a policy shrink while the
old writable view and a second pre-shrink file handle remain alive. Fresh-open
refusal is recognized only for the expected sharing-violation result; other
errors are unclassified failures. A failed writable-section creation is
reported by its exact Win32 error, and only ERROR_ACCESS_DENIED is labeled as
the driver's observed denial. That section-callback status is not a valid pass:
the documented contract does not support STATUS_ACCESS_DENIED as a policy
denial, and no documented policy-denial alternative is known. The script thus
keeps the shrink gate non-passing even when it observes that status. It checks
the fixture's physical NTFS extent through an aligned unbuffered raw-volume
read; an unobservable raw read or an unconfirmed mapping disposal is a failed
measurement. This is source-only until a reviewed Windows build is available.
The test does not force the exact kernel callback interleaving between policy
snapshots; a user-mode policy push cannot deterministically pause the callback.
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
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode, ExactSpelling=true)]
public static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protect, uint maxSizeHigh, uint maxSizeLow, string name);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint offsetHigh, uint offsetLow, UIntPtr size);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool UnmapViewOfFile(IntPtr address);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushViewOfFile(IntPtr address, UIntPtr size);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushFileBuffers(IntPtr file);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint method);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
'@
# Uncached, write-through read of the first Length bytes through a NEW file object (sector-aligned buffer).
function Read-UncachedText([string] $Path, [int] $Length) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3,
        [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return 'OBSERVED_REFUSED: CreateFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = [SafeUploadRepro.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]4096), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) {
        $allocationError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
        return 'OBSERVED_REFUSED: VirtualAlloc error ' + $allocationError
    }
    try {
        [uint32] $read = 0
        if (-not [SafeUploadRepro.Native]::ReadFile($handle, $buffer, 4096, [ref]$read, [IntPtr]::Zero) -or $read -ne 4096) {
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

function Get-FirstLcn([string] $Path) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]128, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'extent query open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $input = [Runtime.InteropServices.Marshal]::AllocHGlobal(8); $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($input, 0)
        [uint32] $returned = 0
        if (-not [SafeUploadRepro.Native]::DeviceIoControl($handle, [uint32]0x00090073, $input, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
            throw 'FSCTL_GET_RETRIEVAL_POINTERS failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if ([Runtime.InteropServices.Marshal]::ReadInt32($output, 0) -lt 1) { throw 'No allocated extent for raw-byte observer.' }
        return [Runtime.InteropServices.Marshal]::ReadInt64($output, 24)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($input); [Runtime.InteropServices.Marshal]::FreeHGlobal($output)
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
    }
}

function Read-RawFixtureBytes([long] $Lcn, [int] $ClusterSize, [int] $Length) {
    if ($ClusterSize -lt 4096 -or ($ClusterSize % 4096) -ne 0) { throw 'Unsupported NTFS cluster size for aligned raw observation.' }
    if ($Length -le 0 -or $Length -gt $ClusterSize) { throw 'Fixture extent does not fit in one allocated cluster.' }
    $handle = [SafeUploadRepro.Native]::CreateFileW('\\.\C:', [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'raw volume open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = [SafeUploadRepro.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]$ClusterSize), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) { [void][SafeUploadRepro.Native]::CloseHandle($handle); throw 'raw read VirtualAlloc failed' }
    try {
        [long] $position = 0
        if (-not [SafeUploadRepro.Native]::SetFilePointerEx($handle, $Lcn * $ClusterSize, [ref]$position, 0)) {
            throw 'raw seek failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        [uint32] $read = 0
        if (-not [SafeUploadRepro.Native]::ReadFile($handle, $buffer, [uint32]$ClusterSize, [ref]$read, [IntPtr]::Zero) -or $read -lt $Length) {
            throw 'raw read failed/short: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $bytes = New-Object byte[] $Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
        return ,$bytes
    }
    finally {
        [void][SafeUploadRepro.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadRepro.Native]::CloseHandle($handle)
    }
}

function Compare-RawFixtureToBaseline([long] $Lcn, [int] $ClusterSize, [byte[]] $Baseline) {
    $current = Read-RawFixtureBytes $Lcn $ClusterSize $Baseline.Length
    $differentBytes = 0
    $firstDifferentOffset = -1
    for ($index = 0; $index -lt $Baseline.Length; $index++) {
        if ($current[$index] -ne $Baseline[$index]) {
            $differentBytes++
            if ($firstDifferentOffset -lt 0) { $firstDifferentOffset = $index }
        }
    }
    $state = if ($differentBytes -eq 0) { 'IDENTICAL_TO_BASELINE' } else { 'UNEXPECTED_BYTES_CHANGED' }
    return [pscustomobject]@{
        State = $state
        ByteCount = $Baseline.Length
        DifferentBytes = $differentBytes
        FirstDifferentOffset = $firstDifferentOffset
    }
}

function Flush-TestFileBuffers($Stream) {
    if ($null -eq $Stream) { return 'UNAVAILABLE: file handle absent' }
    try {
        if ([SafeUploadRepro.Native]::FlushFileBuffers($Stream.SafeFileHandle.DangerousGetHandle())) { return 'SUCCESS' }
        return 'OBSERVED_REFUSED: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } catch { return 'OBSERVED_REFUSED: ' + $_.Exception.Message }
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
$shrinkMarker = [Text.Encoding]::ASCII.GetBytes(('SHRINK-' + $id).Substring(0, 32))
$mappingLength = 4096
$fixtureBytes = New-Object byte[] $mappingLength
[Array]::Copy($originalBytes, $fixtureBytes, $originalBytes.Length)
$agent = $null
$activeTestAgents = New-Object System.Collections.ArrayList
$file = $null
$sectionFile = $null
$shrinkFile = $null
$mapping = $null
$view = $null
$shrinkMapping = $null
$shrinkView = $null
$sectionMappingHandle = [IntPtr]::Zero
$sectionView = [IntPtr]::Zero
$rawCluster = -1L
$rawClusterSize = 0
$rawBaseline = $null
$rawBaselineFileBuffersOutcome = 'NOT_ATTEMPTED'
$expansionFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$shrinkSectionFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$oldViewShrinkFileBuffersFlushOutcome = 'NOT_ATTEMPTED'
$expansionRawComparison = 'UNOBSERVABLE'
$finalRawComparison = $null
$allMappingsReleased = $true
$expansionMappingsReleased = $false
$expansionPrivacyVerdict = 'NOT_RUN'
$policyBytes = $null
$replaced = $false
$loaded = $false
$fixtureCreated = $false
$verifierEnabled = $false
$expansionWriteOutcome = 'NOT_RUN'
$expansionFlushOutcome = 'NOT_RUN'
$shrinkSectionWriteOutcome = 'NOT_ATTEMPTED'
$shrinkSectionFlushOutcome = 'NOT_ATTEMPTED'
$shrinkSectionMeasurementOutcome = 'NOT_RUN'
$shrinkSectionMeasurementUnknown = $false
$oldViewShrinkWriteOutcome = 'NOT_ATTEMPTED'
$oldViewShrinkFlushOutcome = 'NOT_ATTEMPTED'
$shrinkSectionWriteAttempted = $false

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
        if ($null -ne $newAgent) { [void]$script:activeTestAgents.Add($newAgent) }
        if (-not $ready.WaitOne([TimeSpan]::FromSeconds(45))) {
            throw 'Agent did not signal policy acceptance within 45 seconds.'
        }
        return $newAgent
    }
    catch {
        # Keep a successfully returned process in activeTestAgents. The outer
        # finally retries stop independently of policy and driver restoration.
        throw
    }
    finally { $ready.Dispose() }
}

function Stop-TestAgentTracked($Target) {
    if ($null -eq $Target) { return }
    Stop-StagedTestAgent $Target
    [void]$script:activeTestAgents.Remove($Target)
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
'PolicyShrinkAtomicRace=NOT_RUN_NO_DETERMINISTIC_KERNEL_BARRIER'
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
    $rawClusterSize = [int](Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'").BlockSize
    $rawCluster = Get-FirstLcn $target
    "RawObserverFixtureCluster=$rawCluster; ClusterSize=$rawClusterSize"
    # Keep a second FILE_OBJECT opened before the policy expands. It has no writable section yet;
    # after shrink, CreateFileMapping on this old handle must be refused by section-object identity.
    $sectionFile = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $shrinkFile = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $file = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    if ($file.Length -ne $mappingLength) { throw "Fixture EOF $($file.Length) does not match mapping size $mappingLength." }
    $rawBaselineFileBuffersOutcome = Flush-TestFileBuffers $file
    "RawBaselineFlushFileBuffers=$rawBaselineFileBuffersOutcome"
    if ($rawBaselineFileBuffersOutcome -ne 'SUCCESS') { throw 'Could not flush fixture baseline before raw capture.' }
    $rawBaseline = Read-RawFixtureBytes $rawCluster $rawClusterSize $fixtureBytes.Length
    $baselineDifferenceCount = 0
    for ($baselineIndex = 0; $baselineIndex -lt $fixtureBytes.Length; $baselineIndex++) {
        if ($rawBaseline[$baselineIndex] -ne $fixtureBytes[$baselineIndex]) { $baselineDifferenceCount++ }
    }
    "RawBaselineExtent=IDENTICAL_TO_FIXTURE; Bytes=$($fixtureBytes.Length); DifferentBytes=$baselineDifferenceCount"
    if ($baselineDifferenceCount -ne 0) { throw 'Raw baseline did not match the complete fixture contents.' }
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($file, $mappingName,
        [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, $mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $shrinkMapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($shrinkFile,
        ('Local\SafeUpload-PolicyShrinkOriginal-' + $id), [long]$mappingLength,
        [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $shrinkView = $shrinkMapping.CreateViewAccessor(0, $mappingLength,
        [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $initial = New-Object byte[] $originalBytes.Length
    $view.ReadArray(0, $initial, 0, $initial.Length)
    if ([Text.Encoding]::UTF8.GetString($initial) -ne $originalText) { throw 'Baseline mapping bytes mismatch.' }
    $shrinkInitial = New-Object byte[] $originalBytes.Length
    $shrinkView.ReadArray(0, $shrinkInitial, 0, $shrinkInitial.Length)
    if ([Text.Encoding]::UTF8.GetString($shrinkInitial) -ne $originalText) { throw 'Baseline shrink mapping bytes mismatch.' }
    $file.Dispose()
    $file = $null
    'FilterAttached=True; ExpansionAndShrinkMappingsCreatedBeforeFirstPolicyPush=True; MappingCapacityEqualsFileEOF=True; PreChangeFileHandleClosed=True; TwoWritableSectionsRetained=True'

    $agent = Start-TestAgentAndWaitForPolicy $baseLog
    'BaselinePolicyAcceptedByRealAgentAndDriver=True; MappingPredatesBaselinePolicy=True'

    Stop-TestAgentTracked $agent
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
    $expansionWriteOutcome = 'SUCCESS'
    try {
        $view.WriteArray(0, $mapped, 0, $mapped.Length)
    }
    catch {
        $expansionWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message
    }
    if ($expansionWriteOutcome -eq 'SUCCESS') {
        try {
            $view.Flush()
            $expansionFlushOutcome = 'SUCCESS'
        }
        catch {
            $expansionFlushOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message
        }
    }
    "MappedWriteResult=$expansionWriteOutcome; MappedFlushResult=$expansionFlushOutcome"

    # Independent observers: each opens a NEW file object after the policy change.
    $observedText = 'UNOBSERVABLE'
    $freshReadSucceeded = $false
    try { $observedText = Read-FreshDestinationBytes; $freshReadSucceeded = $true }
    catch { $observedText = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    $uncachedText = Read-UncachedText $target $changedBytes.Length
    $uncachedReadSucceeded = $uncachedText -notlike 'OBSERVED_REFUSED:*'
    "FreshFileObjectBytes=$observedText"
    "FreshUncachedObserver=$uncachedText; ReadSucceeded=$uncachedReadSucceeded"

    # Release the expansion-only mapping before observing raw bytes. A separate
    # untouched preexisting view remains alive for the shrink scenario below.
    $expansionMappingsReleased = $true
    if ($null -ne $view) {
        try { $view.Dispose(); $view = $null }
        catch { $expansionMappingsReleased = $false; $allMappingsReleased = $false; 'ExpansionViewDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $mapping) {
        try { $mapping.Dispose(); $mapping = $null }
        catch { $expansionMappingsReleased = $false; $allMappingsReleased = $false; 'ExpansionMappingDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $file) {
        try { $file.Dispose(); $file = $null }
        catch { $expansionMappingsReleased = $false; $allMappingsReleased = $false; 'ExpansionFileDisposeObserved=' + $_.Exception.Message }
    }
    "ExpansionMappingDisposalConfirmed=$expansionMappingsReleased"
    if ($expansionFlushOutcome -eq 'SUCCESS') {
        $expansionFileBuffersFlushOutcome = Flush-TestFileBuffers $shrinkFile
    }
    "ExpansionFlushFileBuffers=$expansionFileBuffersFlushOutcome"

    $expansionRawComparison = 'UNOBSERVABLE'
    try {
        for ($rawTry = 0; $rawTry -lt 20; $rawTry++) {
            $expansionRawComparison = Compare-RawFixtureToBaseline $rawCluster $rawClusterSize $rawBaseline
            if ($expansionRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        $expansionRawComparison = 'UNOBSERVABLE: ' + $_.Exception.Message
        "ExpansionRawObserverError=$($_.Exception.Message)"
    }
    if ($expansionRawComparison -is [string]) { "ExpansionRawExtentComparison=$expansionRawComparison" }
    else { "ExpansionRawExtentComparison=$($expansionRawComparison.State); Bytes=$($expansionRawComparison.ByteCount); DifferentBytes=$($expansionRawComparison.DifferentBytes); FirstDifferentOffset=$($expansionRawComparison.FirstDifferentOffset)" }
    $expansionRawReadSucceeded = $expansionRawComparison -isnot [string]
    $expansionExposureObserved = $observedText -eq $changedText -or $uncachedText -eq $changedText -or
        ($expansionRawReadSucceeded -and $expansionRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED')
    "ExpansionObserverState=FreshRead:$freshReadSucceeded; UncachedRead:$uncachedReadSucceeded; RawRead:$expansionRawReadSucceeded"
    $expansionMeasurementComplete = $expansionWriteOutcome -eq 'SUCCESS' -and
        $expansionFlushOutcome -eq 'SUCCESS' -and $expansionMappingsReleased -and
        $expansionFileBuffersFlushOutcome -eq 'SUCCESS' -and $expansionRawReadSucceeded
    if ($expansionExposureObserved) { $expansionPrivacyVerdict = 'REPRODUCED' }
    elseif ($expansionMeasurementComplete -and $expansionRawComparison.State -eq 'IDENTICAL_TO_BASELINE') { $expansionPrivacyVerdict = 'BLOCKED' }
    else { $expansionPrivacyVerdict = 'INCONCLUSIVE' }
    "ExpansionPrivacyVerdict=$expansionPrivacyVerdict; MeasurementComplete=$expansionMeasurementComplete"

    # Shrink back to the original policy while both the old writable view and a separate, pre-shrink
    # file handle remain alive. Then exercise both the fresh-reader name gate and the new-section SOP gate.
    Stop-TestAgentTracked $agent
    $agent = $null
    [IO.File]::WriteAllBytes($policy, $policyBytes)
    $agent = Start-TestAgentAndWaitForPolicy (Join-Path $documents ('policy-transition-shrunk-' + $id))
    'PolicyShrinkAcceptedByRealAgentAndDriver=True'

    $freshOpenHandle = [SafeUploadRepro.Native]::CreateFileW($target, [uint32]2147483648,
        [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($freshOpenHandle -ne [IntPtr](-1)) {
        $freshOpenOutcome = 'ALLOWED'
        [void][SafeUploadRepro.Native]::CloseHandle($freshOpenHandle)
        $freshOpenError = 0
    } else {
        $freshOpenError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($freshOpenError -eq 32) { $freshOpenOutcome = 'PROTECTED_REFUSAL_SHARING_VIOLATION' }
        else { $freshOpenOutcome = 'UNCLASSIFIED_FAILURE' }
    }
    "PolicyShrinkFreshReaderOpen=$freshOpenOutcome; Win32Error=$freshOpenError"

    $sectionMappingHandle = [SafeUploadRepro.Native]::CreateFileMappingW(
        $sectionFile.SafeFileHandle.DangerousGetHandle(), [IntPtr]::Zero, [uint32]4, [uint32]0,
        [uint32]4096, ('Local\SafeUpload-PolicyShrink-' + $id))
    $sectionCreateError = if ($sectionMappingHandle -eq [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } else { 0 }
    if ($sectionMappingHandle -ne [IntPtr]::Zero) {
        $sectionCreateOutcome = 'ALLOWED'
        $shrinkSectionMeasurementOutcome = 'SECTION_CREATED'
    } elseif ($sectionCreateError -eq 5) {
        $sectionCreateOutcome = 'ACCESS_DENIED_OBSERVED_CONTRACT_UNSUPPORTED'
        $shrinkSectionMeasurementOutcome = 'ACCESS_DENIED_CONTRACT_UNSUPPORTED'
    } else {
        $sectionCreateOutcome = 'UNCLASSIFIED_FAILURE'
        $shrinkSectionMeasurementOutcome = 'UNOBSERVABLE_UNCLASSIFIED_CREATE_ERROR'
        $shrinkSectionMeasurementUnknown = $true
    }
    "PolicyShrinkWritableSectionCreate=$sectionCreateOutcome; Win32Error=$sectionCreateError"
    if ($sectionMappingHandle -ne [IntPtr]::Zero) {
        $sectionView = [SafeUploadRepro.Native]::MapViewOfFile($sectionMappingHandle, [uint32]2, [uint32]0, [uint32]0,
            [UIntPtr]::new([uint64]4096))
        if ($sectionView -ne [IntPtr]::Zero) {
            $shrinkSectionMeasurementOutcome = 'WRITABLE_VIEW_ACQUIRED'
            $sectionData = New-Object byte[] 4096
            [Array]::Copy($shrinkMarker, $sectionData, $shrinkMarker.Length)
            $shrinkSectionWriteAttempted = $true
            try {
                [Runtime.InteropServices.Marshal]::Copy($sectionData, 0, $sectionView, $sectionData.Length)
                $shrinkSectionWriteOutcome = 'SUCCESS'
            }
            catch { $shrinkSectionWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
            if ($shrinkSectionWriteOutcome -eq 'SUCCESS') {
                if ([SafeUploadRepro.Native]::FlushViewOfFile($sectionView, [UIntPtr]::new([uint64]4096))) {
                    $shrinkSectionFlushOutcome = 'SUCCESS'
                    $shrinkSectionFileBuffersFlushOutcome = Flush-TestFileBuffers $sectionFile
                } else {
                    $shrinkSectionFlushOutcome = 'OBSERVED_REFUSED: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                }
            }
            "PolicyShrinkWritableSectionMappedWrite=$shrinkSectionWriteOutcome; FlushViewOfFile=$shrinkSectionFlushOutcome; FlushFileBuffers=$shrinkSectionFileBuffersFlushOutcome"
            if ([SafeUploadRepro.Native]::UnmapViewOfFile($sectionView)) {
                $sectionView = [IntPtr]::Zero
            } else {
                $allMappingsReleased = $false
                'PolicyShrinkWritableSectionUnmap=FAILED; LastError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            }
        } else {
            $mapViewError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $shrinkSectionMeasurementOutcome = 'UNOBSERVABLE_MAP_VIEW_FAILURE'
            $shrinkSectionMeasurementUnknown = $true
            "PolicyShrinkWritableSectionMapView=UNOBSERVABLE; Win32Error=$mapViewError"
        }
        if ([SafeUploadRepro.Native]::CloseHandle($sectionMappingHandle)) {
            $sectionMappingHandle = [IntPtr]::Zero
        } else {
            $allMappingsReleased = $false
            'PolicyShrinkSectionHandleClose=FAILED; LastError=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
    }
    "PolicyShrinkSectionMeasurement=$shrinkSectionMeasurementOutcome; Unknown=$shrinkSectionMeasurementUnknown"

    $shrinkData = New-Object byte[] 4096
    [Array]::Copy($shrinkMarker, $shrinkData, $shrinkMarker.Length)
    $oldViewShrinkWriteOutcome = 'SUCCESS'
    try {
        $shrinkView.WriteArray(0, $shrinkData, 0, $shrinkData.Length)
    }
    catch { $oldViewShrinkWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    if ($oldViewShrinkWriteOutcome -eq 'SUCCESS') {
        try {
            $shrinkView.Flush()
            $oldViewShrinkFlushOutcome = 'SUCCESS'
            $oldViewShrinkFileBuffersFlushOutcome = Flush-TestFileBuffers $shrinkFile
        }
        catch { $oldViewShrinkFlushOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    }
    "PreShrinkMappedViewWriteAfterShrink=$oldViewShrinkWriteOutcome; Flush=$oldViewShrinkFlushOutcome; FlushFileBuffers=$oldViewShrinkFileBuffersFlushOutcome"

    if ($null -ne $shrinkView) {
        try { $shrinkView.Dispose(); $shrinkView = $null }
        catch { $allMappingsReleased = $false; 'ViewDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $shrinkMapping) {
        try { $shrinkMapping.Dispose(); $shrinkMapping = $null }
        catch { $allMappingsReleased = $false; 'MappingDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $shrinkFile) { $shrinkFile.Dispose(); $shrinkFile = $null }
    if ($null -ne $sectionFile) { $sectionFile.Dispose(); $sectionFile = $null }

    # Compare the complete fixture data extent against the saved raw baseline.
    # Any byte change is unexpected exposure; a failed file-buffer flush or raw
    # read is unknown, never evidence of physical absence.
    $finalRawComparison = 'UNOBSERVABLE'
    try {
        for ($rawTry = 0; $rawTry -lt 60; $rawTry++) {
            $finalRawComparison = Compare-RawFixtureToBaseline $rawCluster $rawClusterSize $rawBaseline
            if ($finalRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    catch {
        $finalRawComparison = 'UNOBSERVABLE: ' + $_.Exception.Message
        "RawDestinationObservationError=$($_.Exception.Message)"
    }
    if ($finalRawComparison -is [string]) { "RawDestinationExtentComparison=$finalRawComparison" }
    else { "RawDestinationExtentComparison=$($finalRawComparison.State); Bytes=$($finalRawComparison.ByteCount); DifferentBytes=$($finalRawComparison.DifferentBytes); FirstDifferentOffset=$($finalRawComparison.FirstDifferentOffset)" }
    "MappingDisposalConfirmed=$allMappingsReleased"
    $privacyGap = $expansionPrivacyVerdict -eq 'REPRODUCED' -or
        ($finalRawComparison -isnot [string] -and $finalRawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED')
    $privacyUnknown = $expansionPrivacyVerdict -eq 'INCONCLUSIVE' -or -not $allMappingsReleased -or
        ($shrinkSectionWriteAttempted -and
            ($shrinkSectionWriteOutcome -ne 'SUCCESS' -or $shrinkSectionFlushOutcome -ne 'SUCCESS' -or
             $shrinkSectionFileBuffersFlushOutcome -ne 'SUCCESS')) -or
        $shrinkSectionMeasurementUnknown -or
        ($oldViewShrinkWriteOutcome -ne 'SUCCESS' -or $oldViewShrinkFlushOutcome -ne 'SUCCESS' -or
         $oldViewShrinkFileBuffersFlushOutcome -ne 'SUCCESS') -or
        $expansionFileBuffersFlushOutcome -ne 'SUCCESS' -or $finalRawComparison -is [string]
    "ExpansionPrivacyMeasurement=$expansionPrivacyVerdict"
    "PrivacyExposure=$(if ($privacyGap) { 'OBSERVED_UNEXPECTED_BYTES' } else { 'NOT_OBSERVED' })"
    $privacyObservation = if ($privacyGap) {
        'UNEXPECTED_BYTES_EXPOSED'
    } elseif ($oldViewShrinkWriteOutcome -ne 'SUCCESS' -or
        $oldViewShrinkFlushOutcome -ne 'SUCCESS' -or $oldViewShrinkFileBuffersFlushOutcome -ne 'SUCCESS') {
        'UNOBSERVABLE'
    } elseif ($privacyUnknown) { 'UNOBSERVABLE' }
    else { 'NO_UNEXPECTED_BYTES_OBSERVED' }
    "PrivacyObservation=$privacyObservation"
    $freshReaderRefusedByFence = $freshOpenOutcome -eq 'PROTECTED_REFUSAL_SHARING_VIOLATION'
    # No documented STATUS value presently authorizes a policy-denied section callback, so this cannot pass.
    $sectionCreateRefusedBySupportedContract = $false
    if ($privacyGap -or $privacyUnknown -or -not $freshReaderRefusedByFence -or
        -not $sectionCreateRefusedBySupportedContract) {
        'PolicyShrinkProtection=FAIL'
        'PolicyShrinkSectionCallbackStatus=BLOCKED_UNSUPPORTED_STATUS_CONTRACT'
        throw 'Policy-shrink protection is not a pass: see raw-byte outcome, exact refusal errors, and unsupported section-callback status contract.'
    }
}
finally {
    $cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
    $policyRestoreSucceeded = $false
    $policyHashVerified = $false
    $driverRestoreSucceeded = $false
    $driverHashVerified = $false
    $filterUnloadedVerified = $false
    $agentQuiescenceVerified = $false

    # Stop every process returned by the helper, including a process whose
    # startup wait failed before assignment to $agent. Continue on stop errors.
    foreach ($trackedAgent in @($activeTestAgents)) {
        try {
            Stop-StagedTestAgent $trackedAgent
            [void]$activeTestAgents.Remove($trackedAgent)
        } catch { [void]$cleanupFailures.Add('Stop agent: ' + $_.Exception.Message) }
    }

    if ($sectionView -ne [IntPtr]::Zero) {
        try {
            if ([SafeUploadRepro.Native]::UnmapViewOfFile($sectionView)) { $sectionView = [IntPtr]::Zero }
            else { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Unmap section view: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        } catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Unmap section view: ' + $_.Exception.Message) }
    }
    if ($sectionMappingHandle -ne [IntPtr]::Zero) {
        try {
            if ([SafeUploadRepro.Native]::CloseHandle($sectionMappingHandle)) { $sectionMappingHandle = [IntPtr]::Zero }
            else { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Close section mapping handle: Win32Error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        } catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Close section mapping handle: ' + $_.Exception.Message) }
    }
    foreach ($item in @(
        @{ Name = 'view'; Value = $view }, @{ Name = 'mapping'; Value = $mapping },
        @{ Name = 'shrink view'; Value = $shrinkView }, @{ Name = 'shrink mapping'; Value = $shrinkMapping },
        @{ Name = 'file'; Value = $file }, @{ Name = 'section file'; Value = $sectionFile },
        @{ Name = 'shrink file'; Value = $shrinkFile }
    )) {
        if ($null -ne $item.Value) {
            try { $item.Value.Dispose() }
            catch { $allMappingsReleased = $false; [void]$cleanupFailures.Add('Dispose ' + $item.Name + ': ' + $_.Exception.Message) }
        }
    }

    # Restoration actions are independent: a failed agent stop or handle close
    # must not skip policy restoration, driver restoration, or final checks.
    if ($null -ne $policyBytes) {
        try {
            $restorePolicy = $policyBytes
            if (Test-Path -LiteralPath $policyBackup) {
                try {
                    $backupPolicyHash = (Get-FileHash -LiteralPath $policyBackup -Algorithm SHA256).Hash
                    if ($backupPolicyHash -eq $expectedPolicy) { $restorePolicy = [IO.File]::ReadAllBytes($policyBackup) }
                    else { [void]$cleanupFailures.Add('Policy backup hash mismatch; falling back to in-memory baseline') }
                } catch { [void]$cleanupFailures.Add('Read/verify policy backup: ' + $_.Exception.Message) }
            }
            [IO.File]::WriteAllBytes($policy, $restorePolicy)
            $policyRestoreSucceeded = $true
        } catch { [void]$cleanupFailures.Add('Restore policy: ' + $_.Exception.Message) }
    }
    try {
        if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) {
            [void]$cleanupFailures.Add('Original policy hash mismatch after restoration')
        } else { $policyHashVerified = $true }
    } catch { [void]$cleanupFailures.Add('Verify policy restoration: ' + $_.Exception.Message) }

    if ($replaced) {
        try { Restore-StagedTestDriver $backup $loaded $verifierEnabled; $driverRestoreSucceeded = $true }
        catch { [void]$cleanupFailures.Add('Restore driver: ' + $_.Exception.Message) }
    }
    if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) {
        try { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force }
        catch { [void]$cleanupFailures.Add('Remove fixture: ' + $_.Exception.Message) }
    }
    try {
        if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) { [void]$cleanupFailures.Add('Policy-transition fixture remains') }
    } catch { [void]$cleanupFailures.Add('Verify fixture cleanup: ' + $_.Exception.Message) }
    try {
        if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
            [void]$cleanupFailures.Add('Original driver hash mismatch after restoration')
        } else { $driverHashVerified = $true }
    } catch { [void]$cleanupFailures.Add('Verify driver restoration: ' + $_.Exception.Message) }
    try {
        if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { [void]$cleanupFailures.Add('SafeUpload filter remained loaded') }
        else { $filterUnloadedVerified = $true }
    } catch { [void]$cleanupFailures.Add('Verify filter unload: ' + $_.Exception.Message) }

    try {
        $activeAgentCount = @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count
        $activeTaskCount = @(Get-ScheduledTask | Where-Object { $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)' }).Count
        if ($activeAgentCount -eq 0 -and $activeTaskCount -eq 0) { $agentQuiescenceVerified = $true }
        else {
            [void]$cleanupFailures.Add("Agent/task cleanup incomplete: processes=$activeAgentCount tasks=$activeTaskCount")
        }
    } catch { [void]$cleanupFailures.Add('Verify agent/task cleanup: ' + $_.Exception.Message) }

    if ($agentQuiescenceVerified) {
        try {
            if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -eq $expectedPolicy) { $policyHashVerified = $true }
            else { $policyHashVerified = $false; [void]$cleanupFailures.Add('Policy changed after initial restoration verification') }
        } catch { $policyHashVerified = $false; [void]$cleanupFailures.Add('Final policy restoration verification: ' + $_.Exception.Message) }
    } else { $policyHashVerified = $false }

    # Remove recovery copies independently, and only after the corresponding
    # restore and verification succeeded. Failed recovery keeps a named copy.
    try {
        if ($policyRestoreSucceeded -and $policyHashVerified -and $agentQuiescenceVerified) {
            if (Test-Path -LiteralPath $policyBackup) {
                try { Remove-Item -LiteralPath $policyBackup -Force }
                catch { [void]$cleanupFailures.Add('Remove verified policy backup: ' + $_.Exception.Message); 'RetainedPolicyBackup=' + $policyBackup }
            }
        } elseif (Test-Path -LiteralPath $policyBackup) {
            'RetainedPolicyBackup=' + $policyBackup + '; Reason=policy restore/hash/agent verification incomplete'
        } elseif ($null -ne $policyBytes) {
            'RequiredPolicyBackupUnavailable=' + $policyBackup
        }
    } catch { [void]$cleanupFailures.Add('Verify/remove policy backup: ' + $_.Exception.Message); 'RetainedPolicyBackup=' + $policyBackup }
    try {
        if ($driverRestoreSucceeded -and $driverHashVerified -and $filterUnloadedVerified) {
            if (Test-Path -LiteralPath $backup) {
                try { Remove-Item -LiteralPath $backup -Force }
                catch { [void]$cleanupFailures.Add('Remove verified driver backup: ' + $_.Exception.Message); 'RetainedDriverBackup=' + $backup }
            }
        } elseif (Test-Path -LiteralPath $backup) {
            'RetainedDriverBackup=' + $backup + '; Reason=driver restore/hash/filter verification incomplete'
        } elseif ($replaced) {
            'RequiredDriverBackupUnavailable=' + $backup
        }
    } catch { [void]$cleanupFailures.Add('Verify/remove driver backup: ' + $_.Exception.Message); 'RetainedDriverBackup=' + $backup }
    try {
        $finalSettings = & verifier.exe /querysettings 2>&1 | Out-String
        if ($finalSettings -notmatch 'Verifier Flags:\s+0x00000000') { [void]$cleanupFailures.Add('Verifier settings changed during probe') }
    } catch { [void]$cleanupFailures.Add('Verify verifier settings: ' + $_.Exception.Message) }
    'MappingDisposalConfirmed=' + $allMappingsReleased
    if ($cleanupFailures.Count -eq 0) {
        'OriginalDriverAndPolicyRestored=True; VerifierOff=True; FilterUnloaded=True'
        'AgentProcesses=0; AgentTasks=0; PolicyTransitionFixtureRemoved=True'
    } else {
        foreach ($cleanupFailure in $cleanupFailures) { 'CleanupFailure=' + $cleanupFailure }
        throw ('Cleanup incomplete after all restoration attempts: ' + ($cleanupFailures -join '; '))
    }
}
