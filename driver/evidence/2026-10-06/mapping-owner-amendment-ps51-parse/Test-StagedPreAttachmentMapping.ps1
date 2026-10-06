<#
Small reproduction for a writable mapping created before SafeUpload attaches.
Run only on the recorded, isolated WIN10-DEBUGGED VM from its preserved clean
checkpoint. Uses a new synthetic child under the existing protected test root.

Revised 5 October 2026: the verdict is REPRODUCED if any independent observer sees any changed
fixture byte or if a full raw-volume extent differs from its pinned baseline. BLOCKED requires a
successful mapped write and view flush, successful post-write FlushFileBuffers, successful disposal,
successful independent buffered and uncached reads, and 20 unchanged full raw-volume extent samples.
A refused write/flush, failed disposal, denied observer, or missing raw evidence is INCONCLUSIVE.
Historical fence15 results that reported
BLOCKED after the flush and both readers were refused are not accepted as privacy evidence.

This frozen legacy ordering is currently fail-closed before fixture/product mutation
with OWNER_SETUP_API_TODO. M1 needs owner-ready proof before the writer open/section and
must delay its fixed-NTFS-only test-policy activation until the private mapping and flush;
it must preserve and later byte-verify the pinned production policy. Do not claim USB,
UNC, or sync DOD qualification from this NTFS mapping probe.
Post-write buffered, uncached, and raw observations use the separately pinned
StagedMappingByteObserver.ps1 child process and the original public NTFS path.
#>
param([string] $ExpectedFeatureSha256 = 'ACED8226913E062E5D3EE6FD0CF96963C3FD2C1FB2242EDBEDBB00768CCD44F8', [switch] $Verifier)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
$observerHelper = Join-Path $documents 'StagedMappingByteObserver.ps1'
$expectedObserverHelperSha256 = '76d3b9f6ef90880fbb748b4d194f42ef16a52403bdf4824eedb9271531ddeb91'
$observerHelperItem = Get-Item -LiteralPath $observerHelper -Force -ErrorAction Stop
if ($observerHelperItem.PSIsContainer -or
    (($observerHelperItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    ([IO.Path]::GetFullPath($observerHelperItem.FullName) -ine [IO.Path]::GetFullPath($observerHelper)) -or
    (Get-FileHash -LiteralPath $observerHelper -Algorithm SHA256).Hash -ine $expectedObserverHelperSha256) {
    throw 'Separate-process byte observer helper is not the pinned regular Documents input.'
}
. $observerHelper
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
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushFileBuffers(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint method);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
'@
function Get-FirstLcn([string] $Path) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]128, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'extent query open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $retrievalInput = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($retrievalInput, 0)
        [uint32] $returned = 0
        if (-not [SafeUploadRepro.Native]::DeviceIoControl($handle, [uint32]0x00090073, $retrievalInput, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
            throw 'FSCTL_GET_RETRIEVAL_POINTERS failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if ($returned -lt 32) { throw "FSCTL_GET_RETRIEVAL_POINTERS returned only $returned bytes." }
        $extentCount = [Runtime.InteropServices.Marshal]::ReadInt32($output, 0)
        $startingVcn = [Runtime.InteropServices.Marshal]::ReadInt64($output, 8)
        $nextVcn = [Runtime.InteropServices.Marshal]::ReadInt64($output, 16)
        $lcn = [Runtime.InteropServices.Marshal]::ReadInt64($output, 24)
        if ($extentCount -ne 1 -or $startingVcn -ne 0 -or $nextVcn -lt 1 -or $lcn -lt 0) {
            throw "Fixture extent is not one allocated run covering VCN 0: count=$extentCount start=$startingVcn next=$nextVcn lcn=$lcn"
        }
        return $lcn
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($retrievalInput)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($output)
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
        if (-not [SafeUploadRepro.Native]::ReadFile($handle, $buffer, [uint32]$ClusterSize, [ref]$read, [IntPtr]::Zero) -or $read -ne $ClusterSize) {
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

function Test-BytesEqual([byte[]] $Left, [byte[]] $Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) { if ($Left[$index] -ne $Right[$index]) { return $false } }
    return $true
}

function Flush-IndependentFileBuffers([string] $Path) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]1073741824, [uint32]7, [IntPtr]::Zero,
        [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) {
        return [pscustomobject]@{ Succeeded = $false; Error = 'CreateFile(GENERIC_WRITE) error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    }
    try {
        if (-not [SafeUploadRepro.Native]::FlushFileBuffers($handle)) {
            return [pscustomobject]@{ Succeeded = $false; Error = 'FlushFileBuffers error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        }
        return [pscustomobject]@{ Succeeded = $true; Error = '' }
    }
    catch { return [pscustomobject]@{ Succeeded = $false; Error = $_.Exception.Message } }
    finally { [void][SafeUploadRepro.Native]::CloseHandle($handle) }
}

$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedFeature = $ExpectedFeatureSha256.ToUpperInvariant()
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
$mappingLength = 4096
$fixtureBytes = New-Object byte[] $mappingLength
[Array]::Copy($originalBytes, $fixtureBytes, $originalBytes.Length)
$rawCluster = -1L
$rawClusterSize = 0
$rawBaseline = $null
$file = $null
$mapping = $null
$view = $null
$mappingWriteOutcome = 'NOT_ATTEMPTED'
$viewFlushOutcome = 'NOT_ATTEMPTED'
$viewReleased = $false
$mappingReleased = $false
$sourceFileReleased = $false
$postWriteFlush = [pscustomobject]@{ Succeeded = $false; Error = 'NOT_ATTEMPTED' }
$loaded = $false
$replaced = $false
$verified = $false
$verifierEnabled = $false
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

throw 'OWNER_SETUP_API_TODO: M1 is disabled until the authenticated owner endpoint and owned-stream allocator protect the trusted baseline before the first writable open/section. Only after the private mapping and file flush may a fixed-NTFS-only test policy be activated; preserve and verify the exact production policy bytes and do not claim USB/UNC/sync DOD qualification.'

try {
    [void][IO.Directory]::CreateDirectory($fixtureDirectory)
    $fixtureCreated = $true
    [IO.File]::WriteAllBytes($target, $fixtureBytes)
    $rawClusterSize = [int](Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'").BlockSize
    $rawCluster = Get-FirstLcn $target
    "RawObserverFixtureCluster=$rawCluster; ClusterSize=$rawClusterSize"
    $file = [IO.FileStream]::new($target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    if ($file.Length -ne $mappingLength) { throw "Fixture EOF $($file.Length) does not match mapping size $mappingLength." }
    if (-not [SafeUploadRepro.Native]::FlushFileBuffers($file.SafeFileHandle.DangerousGetHandle())) {
        throw 'Could not flush fixture baseline before raw capture: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    $rawBaseline = Read-RawFixtureBytes $rawCluster $rawClusterSize $mappingLength
    if (-not (Test-BytesEqual $rawBaseline $fixtureBytes)) { throw 'Raw baseline did not match the complete fixture contents.' }
    'RawBaselineExtent=IDENTICAL_TO_FIXTURE; Bytes=4096; DifferentBytes=0'
    $mappingName = 'Local\SafeUpload-Premap-' + $id
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($file, $mappingName,
        [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, $mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $initial = New-Object byte[] $mappingLength
    $view.ReadArray(0, $initial, 0, $initial.Length)
    if (-not (Test-BytesEqual $initial $fixtureBytes)) { throw 'Unfiltered mapping baseline mismatch.' }
    $file.Dispose()
    $file = $null
    $sourceFileReleased = $true
    'PreAttachmentFileHandleClosed=True; PreAttachmentWritableSectionRetained=True'
    "SyntheticProtectedPath=$target"

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
    'FeatureAttachedWhileOriginalWritableSectionRemained=True'

    $mapped = New-Object byte[] $mappingLength
    [Array]::Copy($changedBytes, $mapped, $changedBytes.Length)
    try {
        $view.WriteArray(0, $mapped, 0, $mapped.Length)
        $mappingWriteOutcome = 'SUCCESS'
    }
    catch {
        $mappingWriteOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message
    }
    if ($mappingWriteOutcome -eq 'SUCCESS') {
        try { $view.Flush(); $viewFlushOutcome = 'SUCCESS' }
        catch { $viewFlushOutcome = 'OBSERVED_REFUSED: ' + $_.Exception.Message }
    }
    "MappedWriteResult=$mappingWriteOutcome"
    "MappedViewFlushResult=$viewFlushOutcome"

    if ($null -ne $view) {
        try { $view.Dispose(); $view = $null; $viewReleased = $true }
        catch { 'ViewDisposeObserved=' + $_.Exception.Message }
    }
    if ($null -ne $mapping) {
        try { $mapping.Dispose(); $mapping = $null; $mappingReleased = $true }
        catch { 'MappingDisposeObserved=' + $_.Exception.Message }
    }
    "PreAttachmentViewAndSectionReleased=$($viewReleased -and $mappingReleased)"

    $postWriteFlush = Flush-IndependentFileBuffers $target
    $postWriteFlushState = if ($postWriteFlush.Succeeded) { 'SUCCESS' } else { 'OBSERVED_REFUSED: ' + $postWriteFlush.Error }
    "PostWriteFlushFileBuffers=$postWriteFlushState"

    # Both readers and the physical extent read run in a distinct PowerShell
    # process. The helper is a separately pinned Documents input; it opens the
    # original public NTFS path directly and reports complete byte arrays.
    $observer = Invoke-StagedMappingByteObserver -HelperPath $observerHelper `
        -ExpectedHelperSha256 $expectedObserverHelperSha256 -TargetPath $target `
        -BaselineBytes $fixtureBytes -ExpectedLcn $rawCluster -ClusterSize $rawClusterSize `
        -ReadBuffered -ReadUncached -RawSamples 20 -RawSampleDelayMilliseconds 500
    "SeparateProcessByteObserver=Transport:$($observer.TransportSucceeded); ParentPID:$PID; ChildPID:$($observer.ChildProcessId); HelperSHA256:$($observer.HelperSha256)"
    $bufferedRecord = if ($observer.TransportSucceeded) { $observer.Result.Buffered } else { $null }
    $uncachedRecord = if ($observer.TransportSucceeded) { $observer.Result.Uncached } else { $null }
    $bufferedObservation = ConvertFrom-StagedObserverByteRead $observer $bufferedRecord $fixtureBytes
    $uncachedObservation = ConvertFrom-StagedObserverByteRead $observer $uncachedRecord $fixtureBytes
    $bufferedChanged = $bufferedObservation.Succeeded -and $bufferedObservation.State -eq 'UNEXPECTED_BYTES_CHANGED'
    $uncachedChanged = $uncachedObservation.Succeeded -and $uncachedObservation.State -eq 'UNEXPECTED_BYTES_CHANGED'
    $bufferedState = if (-not $bufferedObservation.Succeeded) { 'OBSERVED_REFUSED: ' + $bufferedObservation.Error } elseif ($bufferedChanged) { 'UNAPPROVED_BYTES_OBSERVED' } else { 'IDENTICAL_TO_BASELINE' }
    $uncachedState = if (-not $uncachedObservation.Succeeded) { 'OBSERVED_REFUSED: ' + $uncachedObservation.Error } elseif ($uncachedChanged) { 'UNAPPROVED_BYTES_OBSERVED' } else { 'IDENTICAL_TO_BASELINE' }
    "FreshBufferedObserver=$bufferedState; ReadSucceeded=$($bufferedObservation.Succeeded)"
    "FreshUncachedObserver=$uncachedState; ReadSucceeded=$($uncachedObservation.Succeeded)"

    $rawObservation = ConvertFrom-StagedObserverRawRead $observer $rawBaseline 20
    $rawComparison = $rawObservation.Comparison
    $rawComparisonAttempts = $rawObservation.Samples
    $rawComparisonError = $rawObservation.Error
    $rawLocationStable = $rawObservation.LcnStable
    if ($rawComparisonError) {
        "RawExtentComparison=INCOMPLETE: $rawComparisonError; SuccessfulSamples=$rawComparisonAttempts"
    }
    elseif ($null -ne $rawComparison) {
        "RawExtentComparison=$($rawComparison.State); Bytes=$($rawComparison.ByteCount); DifferentBytes=$($rawComparison.DifferentBytes); FirstDifferentOffset=$($rawComparison.FirstDifferentOffset); SuccessfulSamples=$rawComparisonAttempts"
    }
    else { 'RawExtentComparison=UNOBSERVABLE: no successful raw sample' }

    $rawChanged = $null -ne $rawComparison -and $rawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED'
    $exposureObserved = $bufferedChanged -or $uncachedChanged -or $rawChanged
    $measurementComplete = $mappingWriteOutcome -eq 'SUCCESS' -and $viewFlushOutcome -eq 'SUCCESS' -and $postWriteFlush.Succeeded -and
        $sourceFileReleased -and $viewReleased -and $mappingReleased -and
        $bufferedObservation.Succeeded -and $uncachedObservation.Succeeded -and
        $null -ne $rawComparison -and $rawComparison.State -eq 'IDENTICAL_TO_BASELINE' -and
        $rawLocationStable -and $rawComparisonAttempts -eq 20 -and -not $rawComparisonError
    "MappingMeasurementComplete=$measurementComplete; PostWriteFlushSucceeded=$($postWriteFlush.Succeeded); RawObserverAvailable=$($rawComparisonAttempts -gt 0); RawLcnStable=$rawLocationStable; RawSamples=$rawComparisonAttempts"
    if ($exposureObserved) { 'UnauthenticatedMappedWriteAfterAttach=REPRODUCED' }
    elseif ($measurementComplete) { 'UnauthenticatedMappedWriteAfterAttach=BLOCKED' }
    else { 'UnauthenticatedMappedWriteAfterAttach=INCONCLUSIVE' }
}
finally {
    if ($null -ne $view) { try { $view.Dispose(); $view = $null } catch { 'FinalViewDisposeObserved=' + $_.Exception.Message } }
    if ($null -ne $mapping) { try { $mapping.Dispose(); $mapping = $null } catch { 'FinalMappingDisposeObserved=' + $_.Exception.Message } }
    if ($null -ne $file) { try { $file.Dispose(); $file = $null } catch { 'FinalFileDisposeObserved=' + $_.Exception.Message } }
    $finalHandlesReleased = $null -eq $view -and $null -eq $mapping -and $null -eq $file
    "FinalMappedHandleRelease=$finalHandlesReleased"
    if (-not $finalHandlesReleased) {
        'GUEST_RECOVERY_REQUIRED=True'
        "PreservedSyntheticFixture=$fixtureDirectory"
        if (Test-Path -LiteralPath $backup) { 'OriginalDriverBackupPreserved=True'; "PreservedOriginalDriverBackup=$backup" }
        else { 'OriginalDriverBackupPreserved=False; OriginalDriverBackupPresent=False' }
        throw 'Cleanup refused to restore or delete files while a mapped view/section/file handle may remain. Preserve this VM for operator recovery.'
    }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
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
