<#
Focused A/B for the late-attach unload race. Run only on the recorded isolated WIN10-DEBUGGED VM.
The ordinary race mode fills (but does not exceed) the 8192-file bound. FailurePath instead creates
65 writable mappings against the 64-stream fence limit to force a bounded scan failure. That mode
tests quarantine visibility and recovery while still attached, and measures the known paging-write
privacy residual; it is not a privacy pass. An old-build leak is counted only when unload succeeds
while the mapping is live and an independent unbuffered read observes the public marker.
#>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)] [string] $ExpectedInspectorSha256,
    [ValidateSet('old','fixed')] [string] $ExpectedBehavior = 'old',
    [ValidateRange(1, 24)] [int] $Attempts = 12,
    [ValidateRange(6000, 7500)] [int] $Fillers = 6500,
    [switch] $FailurePath,
    [int] $SettleMs = 0,
    [switch] $Verifier
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
Add-Type -Namespace SafeUploadLateUnload -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytes, out uint read, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint method);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
[DllImport("kernel32.dll", SetLastError=true)] public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
'@
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('zzzz-fence-late-unload-' + $id)
$availabilityFixture = Join-Path $env:TEMP ('SafeUpload-LateUnload-Availability-' + $id + '.map')
$backup = Join-Path $documents ('SafeUpload-original-before-late-unload-' + $id + '.sys')
$loaded = $false; $replaced = $false; $verifierEnabled = $false; $scopeCreated = $false
$observedOldRace = $false; $fixedDiscriminatingPass = 0; $unexpectedFixedUnload = $false
$manualDetachBlocked = $false
$failurePathRecovered = $false; $privacyExposureObserved = $false; $runFailed = $false; $runFailure = ''
function Invoke-Inspector([string] $Argument) {
    $cmdFile = Join-Path $documents ('late-unload-' + $id + '.cmd'); $cmdOut = Join-Path $documents ('late-unload-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', ('"' + $inspector + '" ' + $Argument), 'echo InspectorExit=%errorlevel%')
    $taskName = 'SafeUpload-StagedTest-LateUnload-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        if (Test-Path -LiteralPath $cmdOut) { return ((Get-Content -LiteralPath $cmdOut -Raw) -replace '\s+', ' ').Trim() } else { return '(no output)' }
    } finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
}
function Get-Counter-Value([string] $Json, [string] $Name) { if ($Json -match ('"' + $Name + '":(\d+)')) { [int64]$Matches[1] } else { -1 } }
function Test-AttachedToC {
    return (@(& fltmc.exe instances -f SafeUpload 2>&1 | Where-Object { $_ -match 'C:' }).Count -gt 0)
}
function Wait-StartupRefresh {
    $until = [DateTime]::UtcNow.AddSeconds(90)
    $stable = 0; $lastStarted = -1; $lastDone = -1
    do {
        $current = Invoke-Inspector '--admission-fence-status'
        $started = Get-Counter-Value $current 'refreshStarted'
        $done = (Get-Counter-Value $current 'refreshCompleted') + (Get-Counter-Value $current 'refreshFailed')
        $flags = Get-Counter-Value $current 'stateFlags'
        $entries = Get-Counter-Value $current 'entries'
        if ($started -ge 0 -and $started -eq $done -and $current -match '"complete":true' -and
            ($flags -lt 0 -or (($flags -band 5) -eq 0)) -and $entries -eq 0) {
            if ($started -eq $lastStarted -and $done -eq $lastDone) { $stable++ } else { $stable = 1 }
            if ($stable -ge 2) { return $current }
            $lastStarted = $started; $lastDone = $done
        } else { $stable = 0 }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Timed out waiting for load-time and automatic-attach fence scans to settle before detaching C:.'
}
function Read-UncachedMarker([string] $Path, [byte[]] $Marker) {
    # Fresh file object, NO_BUFFERING|WRITE_THROUGH, and a VirtualAlloc-aligned 4 KiB buffer.
    $handle = [SafeUploadLateUnload.Native]::CreateFileW($Path, [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return ('REFUSED: CreateFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    $buffer = [SafeUploadLateUnload.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]4096), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) { [void][SafeUploadLateUnload.Native]::CloseHandle($handle); return 'ERROR: VirtualAlloc failed' }
    try {
        [uint32] $read = 0
        if (-not [SafeUploadLateUnload.Native]::ReadFile($handle, $buffer, 4096, [ref]$read, [IntPtr]::Zero)) { return ('REFUSED: ReadFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        $bytes = New-Object byte[] $Marker.Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Marker.Length)
        for ($i = 0; $i -lt $Marker.Length; $i++) { if ($bytes[$i] -ne $Marker[$i]) { return 'MARKER_ABSENT' } }
        return 'MARKER_PRESENT'
    } finally {
        [void][SafeUploadLateUnload.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadLateUnload.Native]::CloseHandle($handle)
    }
}
function Get-FirstLcn([string] $Path) {
    # Capture the fixture's first allocated cluster before reattaching the filter. This gives the
    # failure-path observer an independent raw-volume view that cannot be hidden by file cache.
    $handle = [SafeUploadLateUnload.Native]::CreateFileW($Path, [uint32]128, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'extent query open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $input = [Runtime.InteropServices.Marshal]::AllocHGlobal(8); $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($input, 0)
        [uint32] $returned = 0
        if (-not [SafeUploadLateUnload.Native]::DeviceIoControl($handle, [uint32]0x00090073, $input, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
            throw 'FSCTL_GET_RETRIEVAL_POINTERS failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if ([Runtime.InteropServices.Marshal]::ReadInt32($output, 0) -lt 1) { throw 'No extent (resident file).' }
        return [Runtime.InteropServices.Marshal]::ReadInt64($output, 24)
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($input); [Runtime.InteropServices.Marshal]::FreeHGlobal($output)
        [void][SafeUploadLateUnload.Native]::CloseHandle($handle)
    }
}
function Read-RawDiskMarker([long] $Lcn, [int] $ClusterSize, [byte[]] $Marker) {
    # Aligned, unbuffered read from \Device\HarddiskVolume through the volume handle. An inability
    # to observe raw bytes invalidates the measurement instead of being reported as privacy success.
    if ($ClusterSize -lt 4096 -or ($ClusterSize % 4096) -ne 0) { throw 'Unsupported NTFS cluster size for aligned raw observation.' }
    $handle = [SafeUploadLateUnload.Native]::CreateFileW('\\.\C:', [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]536870912, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'raw volume open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = [SafeUploadLateUnload.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]$ClusterSize), [uint32]12288, [uint32]4)
    if ($buffer -eq [IntPtr]::Zero) { [void][SafeUploadLateUnload.Native]::CloseHandle($handle); throw 'raw read VirtualAlloc failed' }
    try {
        [long] $position = 0
        if (-not [SafeUploadLateUnload.Native]::SetFilePointerEx($handle, $Lcn * $ClusterSize, [ref]$position, 0)) {
            throw 'raw seek failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        [uint32] $read = 0
        if (-not [SafeUploadLateUnload.Native]::ReadFile($handle, $buffer, [uint32]$ClusterSize, [ref]$read, [IntPtr]::Zero) -or $read -lt $Marker.Length) {
            throw 'raw read failed/short: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        $bytes = New-Object byte[] $Marker.Length
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Marker.Length)
        for ($i = 0; $i -lt $Marker.Length; $i++) { if ($bytes[$i] -ne $Marker[$i]) { return 'MARKER_ABSENT' } }
        return 'MARKER_PRESENT'
    } finally {
        [void][SafeUploadLateUnload.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        [void][SafeUploadLateUnload.Native]::CloseHandle($handle)
    }
}
function New-Marker([string] $Text) { return [Text.Encoding]::ASCII.GetBytes($Text.PadRight(32, '!')) }
function Wait-QueuedRefresh([string] $BeforeJson) {
    $beforeQueued = Get-Counter-Value $BeforeJson 'lateRefreshesQueued'
    $beforeDone = (Get-Counter-Value $BeforeJson 'refreshCompleted') + (Get-Counter-Value $BeforeJson 'refreshFailed')
    $until = [DateTime]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 250
        $current = Invoke-Inspector '--admission-fence-status'
        $queued = Get-Counter-Value $current 'lateRefreshesQueued'
        $done = (Get-Counter-Value $current 'refreshCompleted') + (Get-Counter-Value $current 'refreshFailed')
        $flags = Get-Counter-Value $current 'stateFlags'
        if ($queued -gt $beforeQueued -and $done -gt $beforeDone -and ($flags -lt 0 -or (($flags -band 5) -eq 0))) { return $current }
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Timed out waiting for the queued refresh to complete.'
}
function Wait-QuarantineRecovery {
    # Backoff is exponential and caps at 60 seconds; allow one capped wait plus a scan margin.
    $until = [DateTime]::UtcNow.AddSeconds(180)
    do {
        Start-Sleep -Seconds 1
        $current = Invoke-Inspector '--admission-fence-status'
        $entries = Get-Counter-Value $current 'entries'
        $flags = Get-Counter-Value $current 'stateFlags'
        if ($entries -eq 0 -and $flags -eq 0 -and $current -match '"complete":true' -and
            $current -match '(?m)InspectorExit=0\s*$' -and (Test-AttachedToC)) { return $current }
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Timed out waiting for automatic quarantine retry while the volume remained attached.'
}
function Test-OutsideScopeWritableMapping([string] $Path, [byte[]] $Marker, [string] $MappingName) {
    [IO.File]::WriteAllBytes($Path, (New-Object byte[] 4096))
    $stream = $null; $mapping = $null; $view = $null
    try {
        $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($stream, $MappingName,
            [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
            [IO.HandleInheritability]::None, $true)
        $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
        $view.WriteArray(0, $Marker, 0, $Marker.Length)
        $view.Flush()
        $view.Dispose(); $view = $null
        $mapping.Dispose(); $mapping = $null
        $stream.Dispose(); $stream = $null
        $onDisk = [IO.File]::ReadAllBytes($Path)
        for ($i = 0; $i -lt $Marker.Length; $i++) { if ($onDisk[$i] -ne $Marker[$i]) { return $false } }
        return $true
    } finally {
        if ($null -ne $view) { try { $view.Dispose() } catch { } }
        if ($null -ne $mapping) { try { $mapping.Dispose() } catch { } }
        if ($null -ne $stream) { try { $stream.Dispose() } catch { } }
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
    }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=late-attach-unload'
'ExpectedBehavior=' + $ExpectedBehavior
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
'Fillers=' + $(if ($FailurePath) { 0 } else { $Fillers }) + '; Attempts=' + $(if ($FailurePath) { 1 } else { $Attempts }) + '; FailurePath=' + [bool]$FailurePath + '; SettleMs=' + $SettleMs
try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    if ($FailurePath) { $Attempts = 1 } else { for ($i = 0; $i -lt $Fillers; $i++) {
        $filler = Join-Path $scopeDirectory ('000000-filler-{0:D5}.dat' -f $i)
        [IO.File]::WriteAllBytes($filler, [byte[]](0x41))
    } }
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B'
    }
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        if (-not $loaded) {
            & fltmc.exe load SafeUpload | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
            $loaded = $true
        }
        $startupStatus = Wait-StartupRefresh
        'Attempt=' + $attempt + '; StatusBeforeTestDetach=' + $startupStatus
        $beforeAttach = if ($FailurePath) { Invoke-Inspector '--admission-fence-status' } else { '' }
        if (Test-AttachedToC) {
            $detach = (& fltmc.exe detach SafeUpload C: 2>&1 | Out-String) -replace '\s+', ' '
            if (Test-AttachedToC) {
                if ($ExpectedBehavior -eq 'fixed') {
                    $manualDetachBlocked = $true
                    'ManualDetachGuard=REFUSED; Output=' + $detach.Trim()
                    'LateAttachPrivacy=NOT_RUN_MANUAL_DETACH_DISABLED'
                    'FailurePathLifecycle=NOT_RUN_MANUAL_DETACH_DISABLED'
                    break
                }
                throw ('Could not detach C: before attempt ' + $attempt + ': ' + $detach.Trim())
            }
        }
        $path = Join-Path $scopeDirectory ('zzzz-target-{0:D2}.map' -f $attempt)
        $marker = New-Marker ('LATE-UNLOAD-' + $id + '-' + $attempt)
        $rawCluster = -1L; $rawClusterSize = 0
        $stream = $null; $mapping = $null; $view = $null; $mappings = @(); $views = @()
        try {
            # The filter is detached: this writable mapping is invisible to its pre-attach scan.
            $mappingCount = if ($FailurePath) { 65 } else { 1 }
            if ($FailurePath) { 'FailurePath=stream-capacity; WritableMappings=65; FenceMaxStreams=64' }
            for ($mapIndex = 0; $mapIndex -lt $mappingCount; $mapIndex++) {
                $mapPath = Join-Path $scopeDirectory ('zzzz-target-{0:D2}-{1:D2}.map' -f $attempt, $mapIndex)
                $baseline = New-Object byte[] 4096
                [Text.Encoding]::ASCII.GetBytes(('BASELINE-' + $id + '-' + $attempt + '-' + $mapIndex)).CopyTo($baseline, 0)
                [IO.File]::WriteAllBytes($mapPath, $baseline)
                if ($FailurePath -and $mapIndex -eq 0) {
                    $rawClusterSize = [int](Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'").BlockSize
                    $rawCluster = Get-FirstLcn $mapPath
                    'FailurePathRawFixtureCluster=' + $rawCluster + '; ClusterSize=' + $rawClusterSize
                }
                $source = [IO.FileStream]::new($mapPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                try {
                    $newMapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($source, ('Local\SafeUpload-LateUnload-' + $id + '-' + $attempt + '-' + $mapIndex), [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
                    $newView = $newMapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
                    $mappings += $newMapping; $views += $newView
                } finally { $source.Dispose() }
            }
            $path = Join-Path $scopeDirectory ('zzzz-target-{0:D2}-00.map' -f $attempt)
            $view = $views[0]; $mapping = $mappings[0]
            $attach = (& fltmc.exe attach SafeUpload C: 2>&1 | Out-String) -replace '\s+', ' '
            if (-not (Test-AttachedToC)) { throw ('Attach failed: ' + $attach.Trim()) }
            'Attempt=' + $attempt + '; AttachExit=' + $LASTEXITCODE + ' output=' + $attach.Trim()
            if ($FailurePath) {
                $failureStatus = Wait-QueuedRefresh $beforeAttach
                'Attempt=' + $attempt + '; StatusAfterQueuedFailureScan=' + $failureStatus
                if ($ExpectedBehavior -eq 'fixed') {
                    $state = Get-Counter-Value $failureStatus 'stateFlags'
                    if (($state -band 8) -eq 0 -or $failureStatus -notmatch '"complete":false') { throw 'Async scan failure did not publish incomplete quarantine status.' }
                }
            } elseif ($SettleMs -gt 0) { Start-Sleep -Milliseconds $SettleMs }
            # No status query or other deliberate delay here: preserve the unload-vs-scan race.
            $unloadOutput = (& fltmc.exe unload SafeUpload 2>&1 | Out-String) -replace '\s+', ' '
            $unloadSucceeded = ($LASTEXITCODE -eq 0)
            'Attempt=' + $attempt + '; UnloadExit=' + $LASTEXITCODE + ' output=' + $unloadOutput.Trim()
            if ($unloadSucceeded) {
                $loaded = $false
                $write = try { $view.WriteArray(0, $marker, 0, $marker.Length); $view.Flush(); 'SUCCESS' } catch { 'REFUSED: ' + $_.Exception.Message }
                if ($null -ne $view) { $view.Dispose(); $view = $null }
                if ($null -ne $mapping) { $mapping.Dispose(); $mapping = $null }
                if ($views.Count -gt 0) { $views[0] = $null }
                if ($mappings.Count -gt 0) { $mappings[0] = $null }
                if ($null -ne $stream) { $stream.Dispose(); $stream = $null }
                $publicMarker = Read-UncachedMarker $path $marker
                'Attempt=' + $attempt + '; WriteAfterUnload=' + $write + '; IndependentUncachedPublicMarker=' + $publicMarker
                if ($publicMarker -eq 'MARKER_PRESENT') {
                    $observedOldRace = $true
                    'RegressionResult=REPRODUCED_OLD_UNLOAD_LEAK'
                    if ($ExpectedBehavior -eq 'fixed') { $unexpectedFixedUnload = $true }
                    break
                }
                if ($ExpectedBehavior -eq 'fixed') { $unexpectedFixedUnload = $true; break }
                continue
            }

            if ($FailurePath -and $ExpectedBehavior -eq 'fixed') {
                if (-not $loaded) { throw 'Unload refusal returned but filter is no longer loaded.' }
                $quarantineStatus = Invoke-Inspector '--admission-fence-status'
                $quarantineFlags = Get-Counter-Value $quarantineStatus 'stateFlags'
                if (($quarantineFlags -band 8) -eq 0 -or $quarantineStatus -notmatch '"complete":false') {
                    throw 'Quarantine did not remain active after voluntary unload was refused.'
                }
                $protectedOpen = Read-UncachedMarker $path $marker
                'Attempt=' + $attempt + '; ProtectedTargetOpenWhileQuarantined=' + $protectedOpen
                if ($protectedOpen -ne 'REFUSED: CreateFile error 32') {
                    throw 'Quarantined protected target open did not fail with sharing violation 32.'
                }
                $mappedObservation = try {
                    $view.WriteArray(0, $marker, 0, $marker.Length); $view.Flush(); 'SUCCESS'
                } catch { 'REFUSED: ' + $_.Exception.Message }
                'Attempt=' + $attempt + '; QuarantinedMappedWriteObservation=' + $mappedObservation + '; paging-write privacy is not guaranteed by quarantine'

                $availabilityRoot = [IO.Path]::GetPathRoot($availabilityFixture)
                if ($availabilityRoot -ne 'C:\' -or
                    $availabilityFixture.StartsWith('C:\SafeUpload\Escopo Monitorado\', [StringComparison]::OrdinalIgnoreCase) -or
                    $availabilityFixture.StartsWith('C:\safeupload-teste\', [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'The availability fixture is not on C: outside the configured protected scope.'
                }
                $availabilityMarker = New-Marker ('QUARANTINE-AVAILABLE-' + $id)
                $available = Test-OutsideScopeWritableMapping $availabilityFixture $availabilityMarker ('Local\SafeUpload-Availability-' + $id + '-' + $attempt)
                'Attempt=' + $attempt + '; OutsideScopeWritableMappingAndDiskCheck=' + $(if ($available) { 'SUCCESS' } else { 'FAILED' })
                if (-not $available) { throw 'Writable mapping outside the protected scope did not reach disk while quarantined.' }

                for ($disposeIndex = 0; $disposeIndex -lt $views.Count; $disposeIndex++) {
                    if ($null -ne $views[$disposeIndex]) { try { $views[$disposeIndex].Dispose() } catch { }; $views[$disposeIndex] = $null }
                }
                for ($disposeIndex = 0; $disposeIndex -lt $mappings.Count; $disposeIndex++) {
                    if ($null -ne $mappings[$disposeIndex]) { try { $mappings[$disposeIndex].Dispose() } catch { }; $mappings[$disposeIndex] = $null }
                }
                $view = $null; $mapping = $null
                if ($null -ne $stream) { $stream.Dispose(); $stream = $null }
                if (-not (Test-AttachedToC)) { throw 'The volume detached before automatic quarantine recovery.' }
                $rawWhileQuarantined = Read-RawDiskMarker $rawCluster $rawClusterSize $marker
                'Attempt=' + $attempt + '; IndependentRawVolumeMarkerWhileQuarantined=' + $rawWhileQuarantined
                if ($rawWhileQuarantined -eq 'MARKER_PRESENT') { $privacyExposureObserved = $true }
                $recoveryStatus = Wait-QuarantineRecovery
                'Attempt=' + $attempt + '; AutomaticRecoveryWhileAttached=' + $recoveryStatus
                $recoveredEntries = Get-Counter-Value $recoveryStatus 'entries'
                $recoveredFlags = Get-Counter-Value $recoveryStatus 'stateFlags'
                if (-not (Test-AttachedToC) -or $recoveredEntries -ne 0 -or $recoveredFlags -ne 0 -or
                    $recoveryStatus -notmatch '"complete":true') {
                    throw 'Automatic retry did not clear the failure quarantine while still attached.'
                }
                $failurePathRecovered = $true
                'Attempt=' + $attempt + '; QuarantineLifecycle=PASS'
                $rawAfterRecovery = Read-RawDiskMarker $rawCluster $rawClusterSize $marker
                'Attempt=' + $attempt + '; IndependentRawVolumeMarkerAfterAttachedRecovery=' + $rawAfterRecovery
                if ($rawAfterRecovery -eq 'MARKER_PRESENT') { $privacyExposureObserved = $true }
                $publicMarker = Read-UncachedMarker $path $marker
                'Attempt=' + $attempt + '; IndependentUncachedMarkerAfterAttachedRecovery=' + $publicMarker
                if ($publicMarker -eq 'MARKER_PRESENT') {
                    $privacyExposureObserved = $true
                }
                'Attempt=' + $attempt + '; PrivacyExposure=' + $(if ($privacyExposureObserved) { 'OBSERVED' } else { 'NOT_OBSERVED' })
                if ($privacyExposureObserved) { 'KNOWN_PRIVACY_GAP=UNAPPROVED_MAPPED_BYTES_REACHED_PUBLIC_FILE' }
                $postRelease = (& fltmc.exe unload SafeUpload 2>&1 | Out-String) -replace '\s+', ' '
                if ($LASTEXITCODE -ne 0) { throw ('Unload after automatic recovery failed: ' + $postRelease.Trim()) }
                $loaded = $false
                'Attempt=' + $attempt + '; UnloadAfterAttachedRecovery=SUCCESS'
                break
            } else {
                if ($ExpectedBehavior -eq 'fixed') { $fixedDiscriminatingPass++ }
                $write = try { $view.WriteArray(0, $marker, 0, $marker.Length); $view.Flush(); 'SUCCESS' } catch { 'REFUSED: ' + $_.Exception.Message }
                'Attempt=' + $attempt + '; WriteAndFlushWhileAttached=' + $write
                if ($ExpectedBehavior -eq 'fixed' -and -not $write.StartsWith('REFUSED:')) { throw 'Fixed candidate allowed a mapped write/flush while attached.' }
                if ($null -ne $view) { $view.Dispose(); $view = $null }
                if ($null -ne $mapping) { $mapping.Dispose(); $mapping = $null }
                if ($views.Count -gt 0) { $views[0] = $null }
                if ($mappings.Count -gt 0) { $mappings[0] = $null }
                if ($null -ne $stream) { $stream.Dispose(); $stream = $null }
                if (-not $loaded) { throw 'Unload refusal returned but filter is no longer loaded.' }
                $refresh = Invoke-Inspector '--admission-fence-refresh'
                'Attempt=' + $attempt + '; ExplicitRecovery=' + $refresh
                $statusJson = Invoke-Inspector '--admission-fence-status'
                'Attempt=' + $attempt + '; StatusAfterRelease=' + $statusJson
                $entries = Get-Counter-Value $statusJson 'entries'
                $complete = $statusJson -match '"complete":true'
                if (-not $complete -or $entries -ne 0) { throw 'After releasing the view, complete recovery did not clear the fence.' }
                $publicMarker = Read-UncachedMarker $path $marker
                'Attempt=' + $attempt + '; IndependentUncachedMarkerAfterRecovery=' + $publicMarker
                if ($publicMarker -eq 'MARKER_PRESENT') { throw 'Mapped marker reached the public file despite unload refusal.' }
                $postRelease = (& fltmc.exe unload SafeUpload 2>&1 | Out-String) -replace '\s+', ' '
                if ($LASTEXITCODE -ne 0) { throw ('Unload after release/recovery failed: ' + $postRelease.Trim()) }
                $loaded = $false
                'Attempt=' + $attempt + '; UnloadAfterRelease=SUCCESS'
            }
        } finally {
            if ($null -ne $view) { try { $view.Dispose() } catch { } }
            if ($null -ne $mapping) { try { $mapping.Dispose() } catch { } }
            if ($null -ne $stream) { try { $stream.Dispose() } catch { } }
            for ($disposeIndex = 0; $disposeIndex -lt $views.Count; $disposeIndex++) {
                if ($null -ne $views[$disposeIndex]) { try { $views[$disposeIndex].Dispose() } catch { } }
            }
            for ($disposeIndex = 0; $disposeIndex -lt $mappings.Count; $disposeIndex++) {
                if ($null -ne $mappings[$disposeIndex]) { try { $mappings[$disposeIndex].Dispose() } catch { } }
            }
        }
    }
    if (-not $manualDetachBlocked) {
        if ($ExpectedBehavior -eq 'old' -and -not $observedOldRace) { 'RegressionResult=UNOBSERVED_OLD_RACE' }
        if ($ExpectedBehavior -eq 'fixed' -and -not $FailurePath -and -not $unexpectedFixedUnload -and $fixedDiscriminatingPass -eq $Attempts) {
            'RegressionResult=FIXED_UNLOAD_GUARD_PASS'
        }
        if ($ExpectedBehavior -eq 'fixed' -and -not $FailurePath -and ($unexpectedFixedUnload -or $fixedDiscriminatingPass -ne $Attempts)) {
            throw 'Fixed candidate failed the unload-race expectation.'
        }
        if ($ExpectedBehavior -eq 'fixed' -and $FailurePath -and $failurePathRecovered) {
            'FailurePathResult=QUARANTINE_AND_ATTACHED_AUTO_RETRY_LIFECYCLE_COMPLETE'
            'QuarantineLifecycle=PASS'
            'PrivacyExposure=' + $(if ($privacyExposureObserved) { 'OBSERVED' } else { 'NOT_OBSERVED' })
            if ($privacyExposureObserved) { 'KNOWN_PRIVACY_GAP=UNAPPROVED_MAPPED_BYTES_REACHED_PUBLIC_FILE' }
        }
    }
}
catch { $runFailed = $true; $runFailure = $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')'; 'ScriptError=' + $runFailure }
finally {
    if ($null -ne $views) {
        for ($disposeIndex = 0; $disposeIndex -lt $views.Count; $disposeIndex++) {
            if ($null -ne $views[$disposeIndex]) { try { $views[$disposeIndex].Dispose() } catch { } }
        }
    }
    if ($null -ne $mappings) {
        for ($disposeIndex = 0; $disposeIndex -lt $mappings.Count; $disposeIndex++) {
            if ($null -ne $mappings[$disposeIndex]) { try { $mappings[$disposeIndex].Dispose() } catch { } }
        }
    }
    if (Test-Path -LiteralPath $availabilityFixture) {
        Remove-Item -LiteralPath $availabilityFixture -Force -ErrorAction SilentlyContinue
    }
    if ($loaded -and $scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) {
        if (Test-AttachedToC -and $FailurePath -and $ExpectedBehavior -eq 'fixed') {
            try {
                $cleanupStatus = Wait-QuarantineRecovery
                'CleanupAutomaticRecoveryWhileAttached=' + $cleanupStatus
            } catch { 'CleanupAttachedRecoveryError=' + $_.Exception.Message }
        }
        try { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message }
        if (-not (Test-AttachedToC) -and $loaded) { & fltmc.exe attach SafeUpload C: 2>&1 | Out-Null }
        if (-not ($FailurePath -and $ExpectedBehavior -eq 'fixed')) {
            try { [void](Invoke-Inspector '--admission-fence-refresh') } catch { 'CleanupRefreshError=' + $_.Exception.Message }
        }
    }
    if ($loaded) {
        $unloaded = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $unloaded; $attempt++) { & fltmc.exe unload SafeUpload 2>&1 | Out-Null; $unloaded = ($LASTEXITCODE -eq 0); if (-not $unloaded) { Start-Sleep -Milliseconds 500 } }
        $loaded = -not $unloaded
    }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) { try { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message } }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    'LateUnloadRestoration=OriginalDriverRestored; FilterUnloaded=' + (-not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'))
    'VariantComplete=late-attach-unload'
}
if ($runFailed) { [Console]::Error.WriteLine($runFailure); exit 1 }
if ($manualDetachBlocked) { exit 5 }
if ($FailurePath -and $ExpectedBehavior -eq 'fixed') {
    if (-not $failurePathRecovered) { exit 1 }
    if ($privacyExposureObserved) { exit 3 }
    exit 4
}
if ($ExpectedBehavior -eq 'old' -and -not $observedOldRace) { exit 2 }
