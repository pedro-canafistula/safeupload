param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('preattach-immediate', 'preattach-protected-open', 'mmdoes-matrix', 'policy-transition', 'retained-section', 'section-eol', 'writer-count', 'section-inflight', 'section-lower', 'All')]
    [string] $Variant,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedFeatureSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedInspectorSha256,

    [ValidateRange(1, 600)]
    [int] $InspectorTimeoutSeconds = 60,

    # Run-scoped guest file names keep the long-standing inputs (SafeUpload-stage-prototype.sys and
    # SafeUpload.Inspector.input.exe) untouched when a newer build is staged beside them.
    [ValidatePattern('^SafeUpload-stage-prototype[A-Za-z0-9._-]*\.sys$')]
    [string] $FeatureDriverFileName = 'SafeUpload-stage-prototype.sys',

    [ValidatePattern('^SafeUpload\.Inspector\.[A-Za-z0-9_-]+\.exe$')]
    [string] $InspectorInputFileName = 'SafeUpload.Inspector.input.exe',

    # Runtime Driver Verifier (volatile, flags 0x13B) on SafeUpload.sys for variants that support it.
    [switch] $Verifier,
    [switch] $RequireCanary,
    [switch] $RequireAllVolumeCanaries,
    [ValidatePattern('^StagedTestAgent[A-Za-z0-9._-]*\.ps1$')]
    [string] $TestAgentHelperFileName = 'StagedTestAgent.ps1',
    [ValidatePattern('^SafeUploadSectionFault[A-Za-z0-9._-]*\.sys$')]
    [string] $FaultDriverFileName = 'SafeUploadSectionFault.input.sys',
    [ValidatePattern('^StagedSectionFaultClient[A-Za-z0-9._-]*\.cs$')]
    [string] $FaultClientFileName = 'StagedSectionFaultClient.cs',
    [ValidatePattern('^Invoke-StagedSectionFault[A-Za-z0-9._-]*\.ps1$')]
    [string] $FaultExerciseFileName = 'Invoke-StagedSectionFault.ps1',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string] $ExpectedFaultSha256 = '',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string] $ExpectedFaultClientSha256 = '',
    [ValidatePattern('^([0-9A-Fa-f]{64})?$')][string] $ExpectedFaultExerciseSha256 = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($RequireAllVolumeCanaries) { $RequireCanary = $true }
$documents = Join-Path $env:USERPROFILE 'Documents'
$installedDriver = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginalDriver = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedOriginalPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$expectedServicePackage = 'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997'
$featureDriver = Join-Path $documents $FeatureDriverFileName
$inspectorSource = Join-Path $documents $InspectorInputFileName
$inspectorPath = Join-Path $documents 'SafeUpload-admission-inspector.exe'
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$serviceDirectory = Join-Path $documents 'stage-service-publish'
$policyPath = 'C:\ProgramData\SafeUpload\policy.json'
$mappingLength = 4096

. (Join-Path $documents $TestAgentHelperFileName)

if (-not ('SafeUploadAdmissionNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class SafeUploadAdmissionNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
        EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadFile")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadFile(
        SafeFileHandle file, IntPtr buffer, uint bytesToRead, out uint bytesRead,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "SetFilePointerEx")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle file, long distance, out long newPosition, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualAlloc")]
    public static extern IntPtr VirtualAlloc(
        IntPtr address, UIntPtr size, uint allocationType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualFree")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFree(
        IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode,
        EntryPoint = "GetDiskFreeSpaceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpace(
        string rootPathName, out uint sectorsPerCluster, out uint bytesPerSector,
        out uint numberOfFreeClusters, out uint totalNumberOfClusters);
}
'@
}

function Get-Sha256Hex([byte[]] $Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $algorithm.ComputeHash($Bytes)
        return [BitConverter]::ToString($digest).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function Get-ErrorText($ErrorRecord) {
    $message = [string]$ErrorRecord.Exception.Message
    if ([string]::IsNullOrEmpty($message)) {
        $message = [string]$ErrorRecord
    }
    return [regex]::Replace($message, '[\r\n\t]', ' ')
}

function Test-HasReparsePoint($Item) {
    return (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Assert-ReparseFreeFixturePath([string] $Path) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath -notmatch '^[A-Za-z]:\\') {
        throw "Fixture path is not a local drive path: $fullPath"
    }
    if ($fullPath.Length -gt 2 -and $fullPath.Substring(2).Contains(':')) {
        throw "Fixture path contains an alternate-stream colon: $fullPath"
    }

    $root = $fullPath.Substring(0, 3)
    $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (Test-HasReparsePoint $item) {
        throw "Fixture path component is a reparse point: $root"
    }

    $current = $root
    $parts = @($fullPath.Substring(3).Split([char[]]@('\')) | Where-Object { $_.Length -gt 0 })
    foreach ($part in $parts) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (Test-HasReparsePoint $item) {
            throw "Fixture path component is a reparse point: $current"
        }
    }
}

function Get-StagedAdmissionBaseline {
    $uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
    if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
        $uuid -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') {
        throw 'Wrong debuggee host or UUID.'
    }

    $originalHash = (Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash
    if ($originalHash -ne $expectedOriginalDriver) {
        throw "Original driver hash mismatch: $originalHash"
    }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') {
        throw 'SafeUpload must be unloaded at baseline.'
    }

    $verifierQuery = & verifier.exe /query 2>&1 | Out-String
    $verifierSettings = & verifier.exe /querysettings 2>&1 | Out-String
    if ($verifierQuery -notmatch 'No drivers are currently verified' -or
        $verifierSettings -notmatch 'Verifier Flags:\s+0x00000000') {
        throw 'Verifier must be off at baseline.'
    }
    $memory = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    if ($memory.VerifyDriverLevel -or $memory.VerifyDrivers) {
        throw 'Verifier must not be configured at baseline.'
    }

    $service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
    if ($service.StartMode -ne 'Manual' -or $service.State -ne 'Stopped') {
        throw 'Original service baseline mismatch.'
    }

    $policyHash = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash
    if ($policyHash -ne $expectedOriginalPolicy) {
        throw "Original policy hash mismatch: $policyHash"
    }

    $featureHash = (Get-FileHash -LiteralPath $featureDriver -Algorithm SHA256).Hash
    if ($featureHash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
        throw "Feature driver hash mismatch: $featureHash"
    }
    $inspectorSourceHash = (Get-FileHash -LiteralPath $inspectorSource -Algorithm SHA256).Hash
    if ($inspectorSourceHash -ne $ExpectedInspectorSha256.ToUpperInvariant()) {
        throw "Inspector source hash mismatch: $inspectorSourceHash"
    }
    if (Test-Path -LiteralPath $inspectorPath) {
        throw "The fixed Inspector copy path already exists: $inspectorPath"
    }

    $packageHash = (Get-FileHash -LiteralPath $servicePackage -Algorithm SHA256).Hash
    if ($packageHash -ne $expectedServicePackage) {
        throw "Service package hash mismatch: $packageHash"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'))) {
        throw 'Published service executable is missing.'
    }

    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'A SafeUpload agent process is already running.'
    }
    if (@(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'An admission Inspector process is already running.'
    }

    $taskCount = @(Get-ScheduledTask | Where-Object {
        $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)'
    }).Count
    if ($taskCount -ne 0) {
        throw "SafeUpload experiment tasks already exist: $taskCount"
    }

    $fixtureDirectories = @(Get-ChildItem -LiteralPath $documents -Directory -Force |
        Where-Object { $_.Name -match '^SafeUpload-.*[0-9a-f]{32}$' })
    if ($fixtureDirectories.Count -ne 0) {
        throw 'A SafeUpload GUID fixture directory is already present.'
    }
    if (@(Get-ChildItem -LiteralPath $documents -File -Filter 'SafeUpload-admission-driver-*.sys' -Force).Count -ne 0 -or
        @(Get-ChildItem -LiteralPath $documents -File -Filter 'SafeUpload-admission-policy-*.bin' -Force).Count -ne 0) {
        throw 'A SafeUpload admission backup from an earlier run is present.'
    }
    if ((Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx')) -or
        (Test-Path -LiteralPath (Join-Path $documents 'SafeUpload-owned.vhdx.txt'))) {
        throw 'An owned-stream VHDX is present.'
    }
    if (Test-Path -LiteralPath 'S:\') {
        throw 'A synthetic SafeUpload volume is present.'
    }

    return [pscustomobject]@{
        UUID = $uuid
        OriginalHash = $originalHash
        PolicyHash = $policyHash
        FeatureHash = $featureHash
        InspectorSourceHash = $inspectorSourceHash
        ServicePackageHash = $packageHash
        TaskCount = $taskCount
    }
}

function ConvertTo-PowerShellLiteral([string] $Value) {
    return $Value.Replace("'", "''")
}

function ConvertTo-WindowsArgument([string] $Value) {
    if ($Value -match '[\s"]') {
        return '"' + $Value.Replace('"', '\"') + '"'
    }
    return $Value
}

function Invoke-FeatureFilterLoad {
    $output = (& fltmc.exe load SafeUpload 2>&1 | Out-String).Trim()
    $exitCode = $LASTEXITCODE
    Write-Output ('FeatureFilterLoadOutput=' + [regex]::Replace($output, '[\r\n\t]', ' '))
    if ($exitCode -ne 0) {
        throw 'Feature filter load failed.'
    }
}

function Assert-OutsideBaselineScopes([string] $Path, $PolicyDocument) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    foreach ($configured in @($PolicyDocument.monitoredScopes.destinationPaths)) {
        if ([string]::IsNullOrWhiteSpace([string]$configured)) {
            continue
        }
        $scope = [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables([string]$configured)).TrimEnd('\')
        if ($candidate.Equals($scope, [StringComparison]::OrdinalIgnoreCase) -or
            $candidate.StartsWith($scope + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $scope.StartsWith($candidate + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "The GUID fixture intersects an existing monitored scope: $scope"
        }
    }
}

function Assert-MaptestExtensionOutsideBaselinePolicy($PolicyDocument) {
    $monitoredExtensions = @($PolicyDocument.monitoredScopes.extensions | ForEach-Object {
        $extension = [string]$_
        if (-not $extension.StartsWith('.')) {
            $extension = '.' + $extension
        }
        $extension.ToLowerInvariant()
    })
    if ($monitoredExtensions -contains '.maptest') {
        throw 'The .maptest fixture extension is monitored by the baseline policy.'
    }
}

function Assert-NoAgentProcess {
    if (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Inspector call requires zero SafeUpload.Agent.Service processes.'
    }
}

function Assert-NoInspectorProcess {
    if (@(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'A SafeUpload admission Inspector process is already running.'
    }
}

function Invoke-InspectorAsSystem([string[]] $Arguments, [int] $Timeout) {
    Assert-NoAgentProcess
    Assert-NoInspectorProcess

    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedTest-Inspector-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-inspector-' + $id + '.ps1')
    $pidFile = $launcher + '.pid'
    $exitFile = $launcher + '.exit'
    $stdoutFile = $launcher + '.stdout'
    $stderrFile = $launcher + '.stderr'
    $argumentLine = (@($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) })) -join ' '
    $launcherTemplate = @'
$ErrorActionPreference = 'Stop'
$start = @{ FilePath = '__EXE__'; PassThru = $true; WindowStyle = 'Hidden';
    RedirectStandardOutput = '__STDOUT__'; RedirectStandardError = '__STDERR__' }
$start.ArgumentList = '__ARGUMENTS__'
$process = Start-Process @start
[IO.File]::WriteAllText('__PID__', [string]$process.Id)
$process.WaitForExit()
[IO.File]::WriteAllText('__EXIT__', [string]$process.ExitCode)
'@
    $launcherBody = $launcherTemplate.Replace('__EXE__', (ConvertTo-PowerShellLiteral $inspectorPath))
    $launcherBody = $launcherBody.Replace('__STDOUT__', (ConvertTo-PowerShellLiteral $stdoutFile))
    $launcherBody = $launcherBody.Replace('__STDERR__', (ConvertTo-PowerShellLiteral $stderrFile))
    $launcherBody = $launcherBody.Replace('__ARGUMENTS__', (ConvertTo-PowerShellLiteral $argumentLine))
    $launcherBody = $launcherBody.Replace('__PID__', (ConvertTo-PowerShellLiteral $pidFile))
    $launcherBody = $launcherBody.Replace('__EXIT__', (ConvertTo-PowerShellLiteral $exitFile))
    Set-Content -LiteralPath $launcher -Value $launcherBody -Encoding UTF8

    $registered = $false
    $timedOut = $false
    try {
        $taskArgument = '-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $taskArgument
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        $registered = $true
        Start-ScheduledTask -TaskName $taskName

        $deadline = [DateTime]::UtcNow.AddSeconds($Timeout)
        while (-not (Test-Path -LiteralPath $exitFile) -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $exitFile)) {
            $timedOut = $true
            $script:InspectorTimedOut = $true
            $script:InspectorTimeoutCommand = $Arguments -join ' '
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $pidFile) {
                $pidText = [IO.File]::ReadAllText($pidFile)
                $inspectorPid = 0
                if ([int]::TryParse($pidText, [ref]$inspectorPid)) {
                    Stop-Process -Id $inspectorPid -Force -ErrorAction SilentlyContinue
                }
            }
            throw 'Inspector call exceeded its timeout.'
        }

        $taskStopped = $false
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $scheduled = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -eq $scheduled -or $scheduled.State -ne 'Running') {
                $taskStopped = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
        if (-not $taskStopped) {
            $timedOut = $true
            $script:InspectorTimedOut = $true
            $script:InspectorTimeoutCommand = $Arguments -join ' '
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            throw 'Inspector task did not stop after writing its exit code.'
        }

        $capturedPid = [int]([IO.File]::ReadAllText($pidFile))
        $capturedExit = [int]([IO.File]::ReadAllText($exitFile))
        $stdoutBytes = [IO.File]::ReadAllBytes($stdoutFile)
        $stdout = [IO.File]::ReadAllText($stdoutFile)
        $stderr = [IO.File]::ReadAllText($stderrFile)
        return [pscustomobject]@{
            Arguments = $Arguments
            PID = $capturedPid
            ExitCode = $capturedExit
            Stdout = $stdout
            StdoutBytes = $stdoutBytes
            Stderr = $stderr
            StdoutPath = $stdoutFile
            StderrPath = $stderrFile
            TaskName = $taskName
        }
    }
    finally {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $launcher,$pidFile,$exitFile,$stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-InspectorChecked([string[]] $Arguments, [int] $Timeout) {
    if ($script:InspectorTimedOut) {
        throw 'No Inspector call is permitted after an Inspector timeout.'
    }
    $result = Invoke-InspectorAsSystem -Arguments $Arguments -Timeout $Timeout
    if ($result.ExitCode -ne 0) {
        $script:InspectorFailed = $true
        $errorText = [regex]::Replace([string]$result.Stderr, '[\r\n\t]', ' ')
        throw "Inspector command '$($Arguments -join ' ')' returned $($result.ExitCode): $errorText"
    }
    return $result
}

function Start-TestAgentAndWaitForPolicy([string] $LogPrefix) {
    Assert-NoInspectorProcess
    Assert-NoAgentProcess
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
        if ($null -ne $newAgent) {
            Stop-StagedTestAgent $newAgent
        }
        throw
    }
    finally {
        $ready.Dispose()
    }
}

function New-UncachedObserver([string] $Path) {
    $buffer = [IntPtr]::Zero
    $handle = $null
    try {
        $root = [IO.Path]::GetPathRoot($Path)
        [uint32]$sectorsPerCluster = 0
        [uint32]$bytesPerSector = 0
        [uint32]$freeClusters = 0
        [uint32]$totalClusters = 0
        $ok = [SafeUploadAdmissionNative]::GetDiskFreeSpace(
            $root, [ref]$sectorsPerCluster, [ref]$bytesPerSector,
            [ref]$freeClusters, [ref]$totalClusters)
        if (-not $ok) {
            throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
        if ($bytesPerSector -eq 0 -or ($mappingLength % $bytesPerSector) -ne 0) {
            throw "4096 bytes is not a whole number of $bytesPerSector-byte sectors."
        }

        $buffer = [SafeUploadAdmissionNative]::VirtualAlloc(
            [IntPtr]::Zero, [UIntPtr]([uint32]$mappingLength), [uint32]12288, [uint32]4)
        if ($buffer -eq [IntPtr]::Zero) {
            throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
        if (($buffer.ToInt64() % [long]$bytesPerSector) -ne 0) {
            throw 'VirtualAlloc returned a buffer that is not sector aligned.'
        }

        $genericRead = [uint32]2147483648
        $shareReadWriteDelete = [uint32]7
        $openExisting = [uint32]3
        $noBufferingWriteThrough = [uint32]2684354560
        $handle = [SafeUploadAdmissionNative]::CreateFile(
            $Path, $genericRead, $shareReadWriteDelete, [IntPtr]::Zero,
            $openExisting, $noBufferingWriteThrough, [IntPtr]::Zero)
        if ($null -eq $handle -or $handle.IsInvalid) {
            throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }

        return [pscustomobject]@{
            Handle = $handle
            Buffer = $buffer
            SectorSize = [uint32]$bytesPerSector
            Path = $Path
        }
    }
    catch {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        if ($buffer -ne [IntPtr]::Zero) {
            [void][SafeUploadAdmissionNative]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
        }
        throw
    }
}

function New-ObserverPair(
    [string] $Path,
    [System.Collections.ArrayList] $FileHandles,
    [System.Collections.ArrayList] $UncachedReaders
) {
    $buffered = $null
    $bufferedError = ''
    try {
        $buffered = [IO.FileStream]::new(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        [void]$FileHandles.Add($buffered)
    }
    catch {
        $bufferedError = Get-ErrorText $_
    }

    $uncached = $null
    $uncachedError = ''
    try {
        $uncached = New-UncachedObserver $Path
        [void]$UncachedReaders.Add($uncached)
    }
    catch {
        $uncachedError = Get-ErrorText $_
    }

    return [pscustomobject]@{
        R1 = $buffered
        R1Error = $bufferedError
        R2 = $uncached
        R2Error = $uncachedError
    }
}

function New-PaddedFixtureBytes([byte[]] $Prefix) {
    $bytes = New-Object byte[] $mappingLength
    if ($Prefix.Length -gt $bytes.Length) {
        throw 'Fixture prefix is longer than the 4096-byte mapping.'
    }
    [Array]::Copy($Prefix, $bytes, $Prefix.Length)
    return ,$bytes
}

function New-MappedFixture(
    [string] $Path,
    [string] $MappingName,
    [bool] $ReadOnly,
    [bool] $KeepSourceHandle,
    [System.Collections.ArrayList] $FileHandles,
    [System.Collections.ArrayList] $Mappings,
    [System.Collections.ArrayList] $Views
) {
    $fileAccess = [IO.FileAccess]::ReadWrite
    $mappingAccess = [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite
    if ($ReadOnly) {
        $fileAccess = [IO.FileAccess]::Read
        $mappingAccess = [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read
    }

    $file = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, $fileAccess,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    [void]$FileHandles.Add($file)
    if ($file.Length -ne $mappingLength) {
        throw "Fixture EOF $($file.Length) does not equal mapping capacity $mappingLength."
    }

    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
        $file, $MappingName, [long]$mappingLength, $mappingAccess,
        [IO.HandleInheritability]::None, $true)
    [void]$Mappings.Add($mapping)
    $view = $mapping.CreateViewAccessor(
        0, [long]$mappingLength, $mappingAccess)
    [void]$Views.Add($view)
    $initialBytes = New-Object byte[] $mappingLength
    $initialRead = $view.ReadArray(0, $initialBytes, 0, $mappingLength)
    if ($initialRead -ne $mappingLength) {
        throw "Initial mapping read returned $initialRead bytes instead of $mappingLength."
    }

    if (-not $KeepSourceHandle) {
        $file.Dispose()
    }

    return [pscustomobject]@{
        File = $file
        Mapping = $mapping
        View = $view
    }
}

function Get-ExactFileStreamBytes([IO.Stream] $Stream, [int] $Length) {
    $bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $count = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($count -le 0) {
            throw "Short read: $offset of $Length bytes."
        }
        $offset += $count
    }
    return ,$bytes
}

function Get-ObservationFromBytes([byte[]] $Bytes, [byte[]] $Original, [byte[]] $Mapped) {
    if ($Bytes.Length -ne $mappingLength) {
        throw "Observer returned $($Bytes.Length) bytes instead of $mappingLength."
    }
    $hash = Get-Sha256Hex $Bytes
    $originalHash = Get-Sha256Hex $Original
    $mappedHash = Get-Sha256Hex $Mapped
    $equalsOriginal = $hash -eq $originalHash
    $equalsMapped = $hash -eq $mappedHash
    $take = [Math]::Min(80, $Bytes.Length)
    $preview = [Text.Encoding]::UTF8.GetString($Bytes, 0, $take)
    $preview = $preview.Replace([string][char]0, '\0')
    $preview = $preview.Replace([string][char]13, '\r').Replace([string][char]10, '\n')
    $class = 'OBSERVED_CHANGED'
    if ($equalsOriginal) {
        $class = 'OBSERVED_UNCHANGED'
    }
    return [pscustomobject]@{
        Text = $preview
        SHA256 = $hash
        Class = $class
        EqualOriginal = $equalsOriginal
        EqualMapped = $equalsMapped
        Error = ''
    }
}

function New-RefusedObservation([string] $ErrorText) {
    return [pscustomobject]@{
        Text = ''
        SHA256 = 'NONE'
        Class = 'OBSERVED_REFUSED'
        EqualOriginal = 'UNKNOWN'
        EqualMapped = 'UNKNOWN'
        Error = [regex]::Replace($ErrorText, '[\r\n\t]', ' ')
    }
}

function Read-BufferedObservation(
    [IO.FileStream] $Stream,
    [byte[]] $Original,
    [byte[]] $Mapped
) {
    $Stream.Position = 0
    $bytes = Get-ExactFileStreamBytes $Stream $mappingLength
    return (Get-ObservationFromBytes $bytes $Original $Mapped)
}

function Read-UncachedObservation(
    $Reader,
    [byte[]] $Original,
    [byte[]] $Mapped
) {
    $newPosition = [long]0
    $ok = [SafeUploadAdmissionNative]::SetFilePointerEx(
        $Reader.Handle, [long]0, [ref]$newPosition, [uint32]0)
    if (-not $ok) {
        throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
    }

    [uint32]$bytesRead = 0
    $ok = [SafeUploadAdmissionNative]::ReadFile(
        $Reader.Handle, $Reader.Buffer, [uint32]$mappingLength, [ref]$bytesRead, [IntPtr]::Zero)
    if (-not $ok) {
        throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
    }
    if ($bytesRead -ne $mappingLength) {
        throw "Uncached read returned $bytesRead bytes instead of $mappingLength."
    }

    $bytes = New-Object byte[] $mappingLength
    [Runtime.InteropServices.Marshal]::Copy($Reader.Buffer, $bytes, 0, $mappingLength)
    return (Get-ObservationFromBytes $bytes $Original $Mapped)
}

function Read-FreshBufferedObservation(
    [string] $Path,
    [byte[]] $Original,
    [byte[]] $Mapped
) {
    $fresh = $null
    try {
        $fresh = [IO.FileStream]::new(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $bytes = Get-ExactFileStreamBytes $fresh $mappingLength
        return (Get-ObservationFromBytes $bytes $Original $Mapped)
    }
    catch {
        return (New-RefusedObservation (Get-ErrorText $_))
    }
    finally {
        if ($null -ne $fresh) {
            $fresh.Dispose()
        }
    }
}

function Get-ObserverReadResult($Observer, [string] $ReaderName, [byte[]] $Original, [byte[]] $Mapped) {
    try {
        if ($ReaderName -eq 'R1') {
            if ($null -eq $Observer.R1) {
                return (New-RefusedObservation $Observer.R1Error)
            }
            return (Read-BufferedObservation $Observer.R1 $Original $Mapped)
        }
        if ($null -eq $Observer.R2) {
            return (New-RefusedObservation $Observer.R2Error)
        }
        return (Read-UncachedObservation $Observer.R2 $Original $Mapped)
    }
    catch {
        return (New-RefusedObservation (Get-ErrorText $_))
    }
}

function Write-ReaderFacts([string] $Prefix, $Observation) {
    Write-Output ($Prefix + '_Text=' + $Observation.Text)
    Write-Output ($Prefix + '_SHA256=' + $Observation.SHA256)
    Write-Output ($Prefix + '_EqualOriginal=' + $Observation.EqualOriginal)
    Write-Output ($Prefix + '_EqualMapped=' + $Observation.EqualMapped)
    Write-Output ($Prefix + '_Class=' + $Observation.Class)
    if (-not [string]::IsNullOrEmpty([string]$Observation.Error)) {
        Write-Output ($Prefix + '_Error=' + $Observation.Error)
    }
}

function Invoke-MappedWrite($View, [string] $Marker) {
    $prefix = [Text.Encoding]::UTF8.GetBytes($Marker)
    $mappedBytes = New-PaddedFixtureBytes $prefix
    try {
        $View.WriteArray(0, $mappedBytes, 0, $mappedBytes.Length)
        $View.Flush()
        return [pscustomobject]@{ Result = 'SUCCESS'; Error = ''; Bytes = $mappedBytes }
    }
    catch {
        return [pscustomobject]@{
            Result = 'OBSERVED_REFUSED'
            Error = Get-ErrorText $_
            Bytes = $mappedBytes
        }
    }
}

function New-ExpandedPolicyForFixture([string] $FixtureDirectory, [string] $PolicyBackup) {
    $policyBytes = [IO.File]::ReadAllBytes($policyPath)
    [IO.File]::WriteAllBytes($PolicyBackup, $policyBytes)
    $policyDocument = [Text.Encoding]::UTF8.GetString($policyBytes) | ConvertFrom-Json
    $policyDocument.monitoredScopes.destinationPaths =
        @($policyDocument.monitoredScopes.destinationPaths) + @($FixtureDirectory)
    $updatedBytes = [Text.Encoding]::UTF8.GetBytes(($policyDocument | ConvertTo-Json -Depth 10))
    return [pscustomobject]@{
        OriginalBytes = $policyBytes
        UpdatedBytes = $updatedBytes
    }
}

function Invoke-AdmissionProbe([string] $Path, [string] $Name, [int] $Timeout) {
    # The reparse-free precondition was verified before the driver loaded. It is not repeated here: with a
    # fence active the file itself may be quarantined and even a stat of it is refused.
    if ($Path.Length -gt 260) {
        throw "Inspector probe path exceeds the 260-character command limit: $Path"
    }
    $result = Invoke-InspectorChecked -Arguments @('--admission-probe', $Path) -Timeout $Timeout
    # Callers discard the return value, so the facts go to the host stream (stdout), not the pipeline.
    Write-Host ('ProbeCommand_' + $Name + '=SUCCESS')
    Write-Host ('ProbeCommand_' + $Name + '_ExitCode=' + $result.ExitCode)
    Write-Host ('ProbeCommand_' + $Name + '_Stdout=' + ([regex]::Replace([string]$result.Stdout, '[\r\n]+', ' ')).Trim())
    Write-Host ('ProbeCommand_' + $Name + '_Stderr=' + ([regex]::Replace([string]$result.Stderr, '[\r\n]+', ' ')).Trim())
    return $result
}

function Get-TraceDump($InspectorResult, [string] $RawPath) {
    [IO.File]::WriteAllBytes($RawPath, $InspectorResult.StdoutBytes)
    $entries = New-Object System.Collections.ArrayList
    $summary = $null
    foreach ($line in ($InspectorResult.Stdout -split "\r?\n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if (-not $line.TrimStart().StartsWith('{')) {
            throw "Inspector trace output contains a non-JSON line: $line"
        }
        $record = ConvertFrom-Json -InputObject $line -ErrorAction Stop
        if ($record.event) {
            [void]$entries.Add($record)
        }
        elseif ($record.summary -eq $true) {
            $summary = $record
        }
        else {
            throw "Inspector trace JSON line has no event or summary key: $line"
        }
    }
    if ($null -eq $summary) {
        throw 'Inspector trace output did not include its summary JSON object.'
    }
    return [pscustomobject]@{
        Entries = @($entries.ToArray())
        Summary = $summary
        RawFile = $RawPath
    }
}

function Get-PagingWriteEntries($Trace, [UInt64] $AfterSequence = [UInt64]0) {
    $matching = @()
    foreach ($entry in $Trace.Entries) {
        if ([UInt64]$entry.sequence -le $AfterSequence) {
            continue
        }
        $major = [int]$entry.major
        $flagsText = [string]$entry.irpFlags
        $flags = [uint32]0
        if ($flagsText.Length -ge 3) {
            $flags = [Convert]::ToUInt32($flagsText.Substring(2), 16)
        }
        $pagingFlag = (($flags -band [uint32]2) -ne 0)
        if ($major -eq 4 -and
            ($entry.event -eq 'paging_write' -or $pagingFlag) -and
            $entry.ownedStream -eq $false) {
            $matching += $entry
        }
    }
    return $matching
}

function Get-TraceProbeEntries($Trace) {
    $matching = @($Trace.Entries | Where-Object { $_.event -eq 'explicit_probe' })
    return $matching
}

function Get-ProbeProperty($Probe, [string] $PropertyName) {
    if ($null -eq $Probe) {
        return 'AMBIGUOUS'
    }
    $property = $Probe.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return 'AMBIGUOUS'
    }
    return [string]$property.Value
}

function Get-SopEquality([string] $ProbeSop, $PagingEntries, [string] $OtherProbeSop) {
    if ($PagingEntries.Count -eq 0) {
        return 'NoPagingEntry'
    }
    if ([string]::IsNullOrEmpty($ProbeSop) -or $ProbeSop -eq '0x0000000000000000') {
        return 'AMBIGUOUS'
    }
    $sops = @($PagingEntries | ForEach-Object { [string]$_.sectionObjectPointer } | Select-Object -Unique)
    if ($sops.Count -ne 1) {
        return 'AMBIGUOUS'
    }
    if (-not [string]::IsNullOrEmpty($OtherProbeSop) -and $sops[0] -eq $OtherProbeSop) {
        return 'AMBIGUOUS'
    }
    if ($sops[0] -eq $ProbeSop) {
        return 'True'
    }
    return 'False'
}

function Write-TraceFacts($Trace) {
    Write-Output ('Trace_RawFile=' + $Trace.RawFile)
    Write-Output ('Trace_EntryCount=' + $Trace.Entries.Count)
    $pagingWrites = @(Get-PagingWriteEntries $Trace)
    $probeEntries = @(Get-TraceProbeEntries $Trace)
    Write-Output ('Trace_PagingWriteEntries=' + $pagingWrites.Count)
    Write-Output ('Trace_ProbeEntries=' + $probeEntries.Count)
    Write-Output ('Trace_LostEntries=' + $Trace.Summary.lostEntries)

    $counts = @{}
    foreach ($entry in $Trace.Entries) {
        $key = [string]$entry.event + '|' + [string]$entry.irpFlags + '|' +
            [string]$entry.sectionObjectPointer
        if ($counts.ContainsKey($key)) {
            $counts[$key] = [int]$counts[$key] + 1
        }
        else {
            $counts[$key] = 1
        }
    }
    $parts = @()
    foreach ($key in @($counts.Keys | Sort-Object)) {
        $parts += ($key + '=' + $counts[$key])
    }
    if ($parts.Count -eq 0) {
        $parts = @('NONE')
    }
    Write-Output ('Trace_Summary=' + ($parts -join ';'))
}

function Write-ProbeFacts($ProbeEntries, [string[]] $Names) {
    if ($ProbeEntries.Count -ne $Names.Count) {
        Write-Output 'ProbeAttribution=AMBIGUOUS'
        foreach ($name in $Names) {
            Write-Output ('MmDoes_' + $name + '=AMBIGUOUS')
            Write-Output ('ProbeStatus_' + $name + '=AMBIGUOUS')
            Write-Output ('ProbeSOP_' + $name + '=AMBIGUOUS')
        }
        return
    }
    for ($index = 0; $index -lt $Names.Count; $index++) {
        $entry = $ProbeEntries[$index]
        Write-Output ('MmDoes_' + $Names[$index] + '=' + (Get-ProbeProperty $entry 'mmDoes'))
        Write-Output ('ProbeStatus_' + $Names[$index] + '=' + (Get-ProbeProperty $entry 'probeStatus'))
        Write-Output ('ProbeSOP_' + $Names[$index] + '=' + (Get-ProbeProperty $entry 'sectionObjectPointer'))
    }
}

function Dispose-ObserverResources(
    [System.Collections.ArrayList] $Views,
    [System.Collections.ArrayList] $Mappings,
    [System.Collections.ArrayList] $FileHandles,
    [System.Collections.ArrayList] $UncachedReaders,
    [System.Collections.ArrayList] $Errors
) {
    for ($index = $Views.Count - 1; $index -ge 0; $index--) {
        try {
            $Views[$index].Dispose()
        }
        catch {
            $disposeText = Get-ErrorText $_
            if ($disposeText -match 'write protected') {
                # A fenced stream refuses the final flush of its old view: an observation, not a restoration failure.
                Write-Output ('ViewDisposeObserved=' + $disposeText)
            }
            else {
                [void]$Errors.Add('View dispose: ' + $disposeText)
            }
        }
    }
    for ($index = $Mappings.Count - 1; $index -ge 0; $index--) {
        try {
            $Mappings[$index].Dispose()
        }
        catch {
            [void]$Errors.Add('Mapping dispose: ' + (Get-ErrorText $_))
        }
    }
    for ($index = $FileHandles.Count - 1; $index -ge 0; $index--) {
        try {
            $FileHandles[$index].Dispose()
        }
        catch {
            [void]$Errors.Add('File handle dispose: ' + (Get-ErrorText $_))
        }
    }
    for ($index = $UncachedReaders.Count - 1; $index -ge 0; $index--) {
        try {
            $reader = $UncachedReaders[$index]
            $reader.Handle.Dispose()
            [void][SafeUploadAdmissionNative]::VirtualFree(
                $reader.Buffer, [UIntPtr]::Zero, [uint32]32768)
        }
        catch {
            [void]$Errors.Add('Uncached reader dispose: ' + (Get-ErrorText $_))
        }
    }
}

function New-RetainedSection([string] $Path, [string] $MappingName, [System.Collections.ArrayList] $Mappings) {
    # A writable section object with NO view and with the file handle closed again, so the file object
    # stays alive only because the section references it.
    $file = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $mapping = $null
    try {
        if ($file.Length -ne $mappingLength) {
            throw "Fixture EOF $($file.Length) does not equal mapping capacity $mappingLength."
        }
        $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
            $file, $MappingName, [long]$mappingLength,
            [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
            [IO.HandleInheritability]::None, $true)
    }
    finally {
        $file.Dispose()
    }
    [void]$Mappings.Add($mapping)
    return $mapping
}

function Add-RetainedView($Mapping) {
    return $Mapping.CreateViewAccessor(
        0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
}

function ConvertTo-NormalizedHex([string] $Value) {
    return ('0x' + $Value.Substring(2).ToUpperInvariant())
}

$script:LightEntryPattern = [regex]('^\{"sequence":(\d+),"timestamp":(\d+),"event":"(\w+)","pid":(\d+),"irql":(\d+),' +
    '"instance":"[^"]*","targetFileObject":"(0x[0-9A-Fa-f]+)","sectionObjectPointer":"(0x[0-9A-Fa-f]+)",' +
    '"major":(\d+),"minor":(\d+),"irpFlags":"(0x[0-9A-Fa-f]+)","mmDoes":"(\w+)".*"syncType":(\d+),' +
    '"pageProtection":"(0x[0-9A-Fa-f]+)"(?:.*"writeObjects":(\d+),"writersUntracked":(true|false))?(?:,"inFlightSections":(\d+))?')

function Get-LightTrace($InspectorResult, [string] $RawPath) {
    # Cheap parse for dumps of thousands of lines; the raw dump is kept as evidence.
    [IO.File]::WriteAllBytes($RawPath, $InspectorResult.StdoutBytes)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $summary = $null
    foreach ($line in ([string]$InspectorResult.Stdout -split "`n")) {
        $text = $line.TrimEnd("`r")
        if ($text.Length -eq 0) {
            continue
        }
        if ($text.StartsWith('{"summary":true')) {
            $summary = ConvertFrom-Json -InputObject $text
            continue
        }
        $m = $script:LightEntryPattern.Match($text)
        if (-not $m.Success) {
            throw "Unrecognized trace line: $text"
        }
        $g = $m.Groups
        $probe = $null
        $probeValid = $false
        if ($g[3].Value -eq 'explicit_probe') {
            $probe = ConvertFrom-Json -InputObject $text
            $required = @('probeStatus','probeStage','targetFileObject','sectionObjectPointer',
                'writeObjects','writersUntracked','inFlightSections','mmDoes')
            $present = @($probe.PSObject.Properties.Name)
            $missing = @($required | Where-Object { $present -notcontains $_ })
            $probeValid = ($missing.Count -eq 0 -and $probe.probeStatus -eq '0x00000000' -and
                $probe.probeStage -eq 8 -and $probe.targetFileObject -match '^0x[0-9a-fA-F]{16}$' -and
                $probe.targetFileObject -notmatch '^0x0+$' -and
                $probe.sectionObjectPointer -match '^0x[0-9a-fA-F]{16}$' -and
                $probe.sectionObjectPointer -notmatch '^0x0+$' -and
                $probe.mmDoes -in @('yes','no') -and $probe.writersUntracked -is [bool])
        }
        [void]$entries.Add([pscustomobject]@{
            ProbeValid = $probeValid
            ProbeStatus = $(if ($null -ne $probe) { $probe.probeStatus } else { '' })
            ProbeStage = $(if ($null -ne $probe) { $probe.probeStage } else { -1 })
            CanaryOk = ($null -ne $probe -and $probe.canaryState -eq 2 -and
                $probe.canaryStatus -eq '0x00000000' -and $probe.canaryChecks -eq 7 -and
                $probe.canaryCleanupStatus -eq '0x00000000')
            CanaryState = $(if ($null -ne $probe) { $probe.canaryState } else { -1 })
            CanaryStatus = $(if ($null -ne $probe) { $probe.canaryStatus } else { '' })
            CanaryChecks = $(if ($null -ne $probe) { $probe.canaryChecks } else { -1 })
            Seq = [UInt64]$g[1].Value
            Ts = [Int64]$g[2].Value
            Ev = $g[3].Value
            ProcessId = [int]$g[4].Value
            Fo = (ConvertTo-NormalizedHex $g[6].Value)
            Sop = (ConvertTo-NormalizedHex $g[7].Value)
            Major = [int]$g[8].Value
            MmDoes = $g[11].Value
            Sync = [Int64]$g[12].Value   # 4294967295 marks 'sync parameters unavailable'
            Prot = [Convert]::ToUInt32($g[13].Value.Substring(2), 16)
            Writers = $(if ($g[14].Success) { [int]$g[14].Value } else { 0 })
            WritersUntracked = ($g[15].Success -and $g[15].Value -eq 'true')
            InFlightSections = $(if ($g[16].Success) { [Int64]$g[16].Value } else { -1 })
        })
    }
    if ($null -eq $summary) {
        throw 'Trace output did not include its summary object.'
    }
    return [pscustomobject]@{ Entries = $entries; Summary = $summary; RawFile = $RawPath }
}

function Write-DumpQuality([string] $Name, $Trace) {
    $counts = @{}
    foreach ($entry in $Trace.Entries) {
        $counts[$entry.Ev] = 1 + [int]$counts[$entry.Ev]
    }
    $parts = @()
    foreach ($key in @($counts.Keys | Sort-Object)) {
        $parts += ($key + '=' + $counts[$key])
    }
    Write-Output ('Dump_' + $Name + '=entries:' + $Trace.Entries.Count + ';snapshotSequence:' + $Trace.Summary.snapshotSequence +
        ';totalEvents:' + $Trace.Summary.totalEvents + ';lostEntries:' + $Trace.Summary.lostEntries +
        ';ringWrapped:' + ([UInt64]$Trace.Summary.snapshotSequence -gt [UInt64]16384) + ';' + ($parts -join ','))
    Write-Output ('Dump_' + $Name + '_RawFile=' + $Trace.RawFile)
}

function Get-SopEventFacts($Trace, [string] $Sop) {
    $mine = @($Trace.Entries | Where-Object { $_.Sop -eq $Sop })
    return [pscustomobject]@{
        All = $mine
        Acquire = @($mine | Where-Object { $_.Ev -eq 'section_acquire' })
        Release = @($mine | Where-Object { $_.Ev -eq 'section_release' })
        Cleanup = @($mine | Where-Object { $_.Ev -eq 'file_cleanup' })
        Close = @($mine | Where-Object { $_.Ev -eq 'file_close' })
        Paging = @($mine | Where-Object { $_.Ev -eq 'paging_write' })
    }
}

function Format-SopEventFacts($Facts) {
    $acquireText = (@($Facts.Acquire | ForEach-Object { 'sync' + $_.Sync + '/prot0x' + $_.Prot.ToString('X') }) -join ',')
    $pids = (@($Facts.All | ForEach-Object { $_.ProcessId } | Sort-Object -Unique) -join ',')
    return ('acquire=' + $Facts.Acquire.Count + '[' + $acquireText + ']; release=' + $Facts.Release.Count +
        '; cleanup=' + $Facts.Cleanup.Count + '; close=' + $Facts.Close.Count +
        '; pagingWrite=' + $Facts.Paging.Count + '; pids=' + $pids)
}

function Get-ProbeResults($Trace, [string[]] $Labels) {
    $probes = @($Trace.Entries | Where-Object { $_.Ev -eq 'explicit_probe' })
    if ($probes.Count -ne $Labels.Count) {
        Write-Host ('ProbeAttribution=AMBIGUOUS;ProbeEntries=' + $probes.Count + ';Expected=' + $Labels.Count)
        return $null
    }
    $map = @{}
    for ($index = 0; $index -lt $Labels.Count; $index++) {
        $map[$Labels[$index]] = $probes[$index]
    }
    return $map
}

function Write-CompactReader([string] $Name, $Observation) {
    Write-Output ($Name + '=' + $Observation.Class + ';EqualMapped=' + $Observation.EqualMapped +
        ';EqualOriginal=' + $Observation.EqualOriginal + ';Text=' + $Observation.Text)
}

function Initialize-EolNative {
    if (-not ('SafeUploadEolNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SafeUploadEolNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
    }
}

function Initialize-WriterInheritance {
    $script:WriterInheritanceSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class SafeUploadWriterInheritance
{
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO {
        public uint cb; public string reserved, desktop, title;
        public uint x, y, xSize, ySize, xCountChars, yCountChars, fillAttribute, flags;
        public ushort showWindow, reserved2Size; public IntPtr reserved2, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX { public STARTUPINFO startup; public IntPtr attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr process, thread; public uint processId, threadId; }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetHandleInformation(IntPtr handle, out uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processAttributes,
        IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags,
        IntPtr environment, string directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFileAttributesW(string path);
    public static int MissingFileError(string path) {
        uint attributes = GetFileAttributesW(path);
        return attributes == 0xffffffff ? Marshal.GetLastWin32Error() : 0;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(IntPtr file, int informationClass, byte[] information, int size);
    static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public static string Identity(IntPtr file) {
        byte[] info = new byte[24]; Check(GetFileInformationByHandleEx(file, 18, info, info.Length));
        return BitConverter.ToString(info).Replace("-", "");
    }
    public static uint ReparseTag(IntPtr directory) {
        byte[] info = new byte[8]; Check(GetFileInformationByHandleEx(directory, 9, info, info.Length));
        if ((BitConverter.ToUInt32(info, 0) & 0x400) == 0) throw new InvalidOperationException("Not a reparse point");
        return BitConverter.ToUInt32(info, 4);
    }
    // The explicit list contains only the fixture file handle. No DuplicateHandle into the child is used.
    public static Process Start(IntPtr file, string application, string command) {
        uint originalFlags; Check(GetHandleInformation(file, out originalFlags));
        IntPtr size = IntPtr.Zero, list = IntPtr.Zero, handles = IntPtr.Zero;
        bool initialized = false, inheritanceChanged = false; Process managed = null;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try {
            Check(SetHandleInformation(file, 1, 1)); inheritanceChanged = true;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            list = Marshal.AllocHGlobal(size); handles = Marshal.AllocHGlobal(IntPtr.Size);
            Check(InitializeProcThreadAttributeList(list, 1, 0, ref size)); initialized = true;
            Marshal.WriteIntPtr(handles, file);
            Check(UpdateProcThreadAttribute(list, 0, new IntPtr(0x20002), handles, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
            STARTUPINFOEX si = new STARTUPINFOEX(); si.startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOEX)); si.attributes = list;
            Check(CreateProcessW(application, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
                0x08080000, IntPtr.Zero, null, ref si, out pi));
            managed = Process.GetProcessById((int)pi.processId);
            IntPtr managedHandle = managed.Handle; // Acquire managed ownership before releasing the native handle.
            Check(SetHandleInformation(file, 1, originalFlags & 1)); inheritanceChanged = false;
            return managed;
        } catch (Exception error) {
            bool terminated = pi.process == IntPtr.Zero || TerminateProcess(pi.process, 3);
            uint waited = pi.process == IntPtr.Zero ? 0 : WaitForSingleObject(pi.process, 10000);
            if (managed != null) managed.Dispose();
            throw new InvalidOperationException("Inherited child setup failed: " + error.Message +
                "; childPid=" + pi.processId + "; terminated=" + terminated + "; wait=" + waited, error);
        } finally {
            if (inheritanceChanged) SetHandleInformation(file, 1, originalFlags & 1);
            if (pi.thread != IntPtr.Zero) CloseHandle(pi.thread);
            if (pi.process != IntPtr.Zero) CloseHandle(pi.process);
            if (initialized) DeleteProcThreadAttributeList(list);
            if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
            if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
        }
    }
}
'@
    if (-not ('SafeUploadWriterInheritance' -as [type])) { Add-Type -TypeDefinition $script:WriterInheritanceSource }
}

function Initialize-WriterStress {
    if (-not ('SafeUploadWriterStress' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;

public static class SafeUploadWriterStress
{
    // Opens and closes the same file for write from several threads; returns the number of failed opens.
    public static int Run(string path, int threads, int iterations)
    {
        int failures = 0;
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++)
        {
            workers[t] = new Thread(delegate ()
            {
                for (int i = 0; i < iterations; i++)
                {
                    try
                    {
                        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite,
                            FileShare.ReadWrite | FileShare.Delete)) { f.WriteByte(0x41); }
                    }
                    catch (IOException) { Interlocked.Increment(ref failures); }
                }
            });
            workers[t].Start();
        }
        foreach (Thread w in workers) { w.Join(); }
        return failures;
    }
}
'@
    }
}

$script:WriterChecks = New-Object System.Collections.ArrayList

function Add-WriterProbe([string] $Path, [string] $Label, [int] $ExpectedWriters, [string] $ExpectedMmDoes = '') {
    # Probes the stream and remembers what the harness knows to be true at this instant.
    [void]$script:WriterChecks.Add(@{ Label = $Label; Expected = $ExpectedWriters; ExpectedMm = $ExpectedMmDoes })
    [void](Invoke-AdmissionProbe $Path ('WC_' + $Label) $InspectorTimeoutSeconds)
}

function Complete-WriterChecks([string] $GroupName, [string] $RawPath) {
    # One dump per group keeps the ring small; entries are matched to checks by order.
    $trace = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds) $RawPath
    $probes = @($trace.Entries | Where-Object { $_.Ev -eq 'explicit_probe' } | Sort-Object Seq)
    Write-Output ('WC_Group_' + $GroupName + '=probes:' + $probes.Count + ';checks:' + $script:WriterChecks.Count +
        ';lostEntries:' + $trace.Summary.lostEntries + ';snapshotSequence:' + $trace.Summary.snapshotSequence)
    if ($probes.Count -ne $script:WriterChecks.Count) {
        Write-Output ('WC_Group_' + $GroupName + '_Attribution=AMBIGUOUS')
        $script:WriterChecksFailed += $script:WriterChecks.Count
    }
    else {
        for ($index = 0; $index -lt $probes.Count; $index++) {
            $check = $script:WriterChecks[$index]
            $entry = $probes[$index]
            $writersOk = ($entry.Writers -eq $check.Expected) -and (-not $entry.WritersUntracked)
            $mmOk = ([string]::IsNullOrEmpty($check.ExpectedMm) -or $entry.MmDoes -eq $check.ExpectedMm)
            $verdict = if ($entry.ProbeValid -and $writersOk -and $mmOk -and
                (-not $RequireCanary -or $entry.CanaryOk)) { 'PASS' } else { 'FAIL' }
            if ($verdict -ne 'PASS') { $script:WriterChecksFailed++ } else { $script:WriterChecksPassed++ }
            Write-Output ('WC_' + $check.Label + '=expected:' + $check.Expected + ';observed:' + $entry.Writers +
                ';untracked:' + $entry.WritersUntracked + ';mmDoes:' + $entry.MmDoes +
                ';probeStatus:' + $entry.ProbeStatus + ';probeStage:' + $entry.ProbeStage +
                $(if ($check.ExpectedMm) { ';expectedMmDoes:' + $check.ExpectedMm } else { '' }) + ';' + $verdict)
        }
    }
    $script:WriterChecks.Clear()
    [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds)
}

function Get-WriterStateStats {
    $r = Invoke-InspectorChecked -Arguments @('--writer-state-status') -Timeout $InspectorTimeoutSeconds
    return (ConvertFrom-Json -InputObject ([string]$r.Stdout).Trim())
}

function Wait-AdmissionCanary([string] $Path, [string] $RawPath) {
    if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($RawPath + '-volumes.json') }
    if (-not $RequireCanary) { return }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        [void](Invoke-AdmissionProbe $Path ('Canary_' + $attempt) $InspectorTimeoutSeconds)
        $trace = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds) ($RawPath + '-canary-' + $attempt + '.jsonl')
        $probes = @($trace.Entries | Where-Object { $_.Ev -eq 'explicit_probe' })
        if ($probes.Count -ne 1 -or -not $probes[0].ProbeValid) { throw 'Canary probe failed or attribution is ambiguous.' }
        if ($probes[0].CanaryOk) {
            Write-Output 'VolumeCanary=PASS;retained:YES;released:NO;removed:YES'
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds)
            return
        }
        if ($probes[0].CanaryState -ge 3) {
            throw ('Volume canary failed: state=' + $probes[0].CanaryState + ';status=' +
                $probes[0].CanaryStatus + ';checks=' + $probes[0].CanaryChecks)
        }
        [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds)
        Start-Sleep -Milliseconds 100
    }
    throw 'Volume canary did not reach its passed state (inspect retained raw canary probes).'
}

function Wait-AllVolumeCanaries([string] $RawPath) {
    $volumes = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' -ErrorAction Stop |
        Where-Object FileSystem -eq 'NTFS')
    $expected = @($volumes | ForEach-Object {
        if ($_.DeviceID -notmatch '(?i)\{[0-9a-f-]{36}\}') { throw 'Invalid independent volume GUID.' }
        $matches[0].ToLowerInvariant()
    } | Sort-Object)
    if ($expected.Count -eq 0 -or @($expected | Select-Object -Unique).Count -ne $expected.Count) {
        throw 'Independent fixed NTFS volume set is empty or ambiguous.'
    }
    Write-Output ('IndependentFixedNtfsGuids=' + ($expected -join ';'))
    for ($attempt = 0; $attempt -lt 60; ++$attempt) {
        $response = Invoke-InspectorChecked -Arguments @('--admission-volume-status') -Timeout $InspectorTimeoutSeconds
        [IO.File]::WriteAllText(($RawPath + '-' + $attempt), [string]$response.Stdout)
        $status = ConvertFrom-Json -InputObject ([string]$response.Stdout).Trim()
        if ($null -eq $status.admissionVolumes -or $null -eq $status.writerGlobalUnknown) {
            throw 'Missing all-volume status fields.'
        }
        if ($status.writerGlobalUnknown -ne 0) { throw 'Global writer tracking is unknown.' }
        foreach ($entry in $status.admissionVolumes) {
            if ($entry.contextStatus -ne 0 -or $entry.fileSystemStatus -ne 0 -or
                $null -eq $entry.volumeInfoStatus -or $entry.volumeInfoStatus -ne 0 -or $null -eq $entry.volumeFlags) {
                throw 'An attached instance has an unresolved context or filesystem.'
            }
        }
        $detached = @($status.admissionVolumes | Where-Object { ($_.volumeFlags -band 1) -ne 0 })
        Write-Output ('DetachedVolumeEntries=' + $detached.Count)
        $eligible = @($status.admissionVolumes | Where-Object {
            $_.volumeKind -eq 1 -and $_.fileSystemType -eq 2 -and ($_.volumeFlags -band 1) -eq 0 })
        $actual = @($eligible | ForEach-Object {
            if ($_.contextStatus -ne 0 -or $_.fileSystemStatus -ne 0 -or $_.volumeGuidStatus -ne 0 -or
                $_.volumeGuid -notmatch '(?i)\{[0-9a-f-]{36}\}') { throw 'Unresolved eligible volume identity.' }
            $matches[0].ToLowerInvariant()
        } | Sort-Object)
        if (($actual -join ';') -ne ($expected -join ';')) { throw 'Attached fixed NTFS set differs from independent volume set.' }
        $pending = $false
        foreach ($entry in $eligible) {
            if ($entry.instanceWritersUntracked -ne 0) { throw 'Instance writer tracking is unknown.' }
            if ($entry.canaryState -lt 2) { $pending = $true; continue }
            if ($entry.canaryState -ne 2 -or $entry.canaryStatus -ne 0 -or $entry.canaryChecks -ne 7 -or
                $entry.canaryCleanupStatus -ne 0) { throw ('All-volume canary failed for ' + $entry.volumeGuid) }
        }
        if (-not $pending) {
            Write-Output ('AllVolumeCanaries=PASS;count:' + $eligible.Count)
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw 'All-volume canary timeout.'
}

function Initialize-SectionStress {
    if (-not ('SafeUploadSectionStress' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Threading;

public static class SafeUploadSectionStress
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protect, uint maxHigh, uint maxLow, string name);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);

    // Creates and drops writable sections (and, optionally, read-only ones) from several threads; returns failures.
    public static int Run(string[] paths, int threads, int iterations, bool alsoReadOnly)
    {
        int failures = 0;
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++)
        {
            int seed = t;
            workers[t] = new Thread(delegate ()
            {
                for (int i = 0; i < iterations; i++)
                {
                    string path = paths[(seed * iterations + i) % paths.Length];
                    try
                    {
                        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
                        using (MemoryMappedFile m = MemoryMappedFile.CreateFromFile(f, null, 4096, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, true))
                        {
                            using (MemoryMappedViewAccessor v = m.CreateViewAccessor(0, 4096, MemoryMappedFileAccess.ReadWrite)) { v.Write(0, (byte)0x42); }
                        }
                        if (alsoReadOnly)
                        {
                            using (FileStream r = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                            using (MemoryMappedFile m2 = MemoryMappedFile.CreateFromFile(r, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, true))
                            {
                                using (MemoryMappedViewAccessor v2 = m2.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read)) { v2.ReadByte(0); }
                            }
                        }
                    }
                    catch (Exception) { Interlocked.Increment(ref failures); }
                }
            });
            workers[t].Start();
        }
        foreach (Thread w in workers) { w.Join(); }
        return failures;
    }

    // A writable mapping of an empty file with no size fails inside the memory manager. Returns the Win32 error (0 = unexpected success).
    public static int TryEmptyFileMapping(string path)
    {
        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
        {
            IntPtr mapping = CreateFileMappingW(f.SafeFileHandle.DangerousGetHandle(), IntPtr.Zero, 0x04, 0, 0, null);
            if (mapping == IntPtr.Zero) { return Marshal.GetLastWin32Error(); }
            CloseHandle(mapping);
            return 0;
        }
    }

    // All threads map the SAME file object. Mixed protections exercise release pairing without
    // the incidental isolation provided by a separate FileStream for every mapping.
    public static int RunSharedFileObject(string path, int threads, int iterations)
    {
        int failures = 0;
        using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
        using (ManualResetEvent start = new ManualResetEvent(false))
        {
            IntPtr file = f.SafeFileHandle.DangerousGetHandle();
            Thread[] workers = new Thread[threads];
            for (int t = 0; t < threads; t++)
            {
                workers[t] = new Thread(delegate ()
                {
                    start.WaitOne();
                    for (int i = 0; i < iterations; i++)
                    {
                        foreach (uint protection in new uint[] { 0x04, 0x02 })
                        {
                            IntPtr mapping = CreateFileMappingW(file, IntPtr.Zero, protection, 0, 4096, null);
                            if (mapping == IntPtr.Zero) Interlocked.Increment(ref failures);
                            else if (!CloseHandle(mapping)) Interlocked.Increment(ref failures);
                        }
                    }
                });
                workers[t].Start();
            }
            start.Set();
            foreach (Thread w in workers) w.Join();
        }
        return failures;
    }
}
'@
    }
}

function Invoke-Variant([string] $SelectedVariant) {
    $script:LastRestorationVerified = $false
    $script:LastRunSucceeded = $false
    $script:InspectorTimedOut = $false
    $script:InspectorTimeoutCommand = ''
    $script:InspectorFailed = $false

    $baseline = Get-StagedAdmissionBaseline
    $id = [guid]::NewGuid().ToString('N')
    $fixtureDirectory = Join-Path $documents ('SafeUpload-admission-' + $id)
    $backup = Join-Path $documents ('SafeUpload-admission-driver-' + $id + '.sys')
    $policyBackup = Join-Path $documents ('SafeUpload-admission-policy-' + $id + '.bin')
    $policyBytes = $null
    $fixtureCreated = $false
    $inspectorCopyCreated = $false
    $driverReplaced = $false
    $filterLoaded = $false
    $verifierEnabled = $false
    $traceEnabled = $false
    $agent = $null
    $runSucceeded = $false
    $restorationErrors = New-Object System.Collections.ArrayList
    $fileHandles = New-Object System.Collections.ArrayList
    $mappings = New-Object System.Collections.ArrayList
    $views = New-Object System.Collections.ArrayList
    $uncachedReaders = New-Object System.Collections.ArrayList
    $agentLogs = New-Object System.Collections.ArrayList
    $observers = @{}
    $fixturePaths = @()
    $mappingRecords = @{}
    $probeNames = @()
    $trace = $null
    $preWriteTrace = $null
    $afterATrace = $null
    $rawTrace = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '.jsonl')
    $rawPreWriteTrace = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-prewrite.jsonl')
    $rawAfterATrace = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-after-A.jsonl')
    $rawTraceA = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-A.jsonl')
    $rawTraceP1 = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-P1.jsonl')
    $rawTraceB = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-B.jsonl')
    $rawTraceP2 = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-P2.jsonl')
    $rawTraceL = Join-Path $documents ('SafeUpload-admission-trace-' + $SelectedVariant + '-' + $id + '-L.jsonl')
    $originals = @{}
    $mappedExpected = @{}
    $markers = @{}

    Write-Output ('Variant=' + $SelectedVariant)
    Write-Output ('TestTimestampUTC=' + [DateTime]::UtcNow.ToString('o'))
    Write-Output ('Host=' + $env:COMPUTERNAME)
    Write-Output ('UUID=' + $baseline.UUID)
    Write-Output ('OriginalInstalledSHA256=' + $baseline.OriginalHash)
    Write-Output ('FeatureSHA256=' + $baseline.FeatureHash)
    Write-Output ('ExpectedInspectorSHA256=' + $ExpectedInspectorSha256.ToUpperInvariant())
    Write-Output ('OriginalPolicySHA256=' + $baseline.PolicyHash)
    Write-Output ('ServicePackageSHA256=' + $baseline.ServicePackageHash)
    Write-Output 'Baseline=FilterUnloaded;VerifierOffAndUnconfigured;ServiceManualStopped;AgentProcesses0;Tasks0'

    try {
        $baselinePolicyBytes = [IO.File]::ReadAllBytes($policyPath)
        $baselinePolicyDocument = [Text.Encoding]::UTF8.GetString($baselinePolicyBytes) | ConvertFrom-Json
        Assert-OutsideBaselineScopes $fixtureDirectory $baselinePolicyDocument
        Assert-MaptestExtensionOutsideBaselinePolicy $baselinePolicyDocument

        [void][IO.Directory]::CreateDirectory($fixtureDirectory)
        $fixtureCreated = $true
        $inspectorCopyCreated = $true
        Copy-Item -LiteralPath $inspectorSource -Destination $inspectorPath -Force
        $copiedInspectorHash = (Get-FileHash -LiteralPath $inspectorPath -Algorithm SHA256).Hash
        if ($copiedInspectorHash -ne $ExpectedInspectorSha256.ToUpperInvariant()) {
            throw "Copied Inspector hash mismatch: $copiedInspectorHash"
        }
        Write-Output ('InspectorSHA256=' + $copiedInspectorHash)

        if ($SelectedVariant -eq 'mmdoes-matrix') {
            foreach ($name in @('A', 'B', 'C', 'D')) {
                $target = Join-Path $fixtureDirectory ($name + '.maptest')
                $fixturePaths += $target
                $originalText = 'PUBLIC BASELINE ' + $name + ' ' + $id
                $originals[$name] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($originalText))
                [IO.File]::WriteAllBytes($target, $originals[$name])
            }

            $mappingRecords['A'] = New-MappedFixture $fixturePaths[0] ('Local\SafeUpload-Admission-' + $id + '-A') $false $false $fileHandles $mappings $views
            $mappingRecords['B'] = New-MappedFixture $fixturePaths[1] ('Local\SafeUpload-Admission-' + $id + '-B') $true $false $fileHandles $mappings $views
            $mappingRecords['D'] = New-MappedFixture $fixturePaths[3] ('Local\SafeUpload-Admission-' + $id + '-D') $false $true $fileHandles $mappings $views

            $observers['A'] = New-ObserverPair $fixturePaths[0] $fileHandles $uncachedReaders
            $observers['D'] = New-ObserverPair $fixturePaths[3] $fileHandles $uncachedReaders

            foreach ($path in $fixturePaths) {
                Assert-ReparseFreeFixturePath $path
            }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true

            $clear = Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds
            $enable = Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds
            $traceEnabled = $true
            Write-Output 'AdmissionTrace=ClearedAndEnabled'

            $probeNames = @('A', 'B', 'C', 'D')
            foreach ($name in $probeNames) {
                $probePath = Join-Path $fixtureDirectory ($name + '.maptest')
                [void](Invoke-AdmissionProbe $probePath $name $InspectorTimeoutSeconds)
            }

            $preWriteResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
            $preWriteTrace = Get-TraceDump $preWriteResult $rawPreWriteTrace
            Write-Output ('Trace_PreWrite_RawFile=' + $rawPreWriteTrace)
            $preWriteBoundary = [UInt64]$preWriteTrace.Summary.snapshotSequence

            foreach ($name in @('A', 'D')) {
                $markers[$name] = 'MAPPED DIAGNOSTIC ' + $name + ' ' + $id
                $mappedExpected[$name] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers[$name]))
                $write = Invoke-MappedWrite $mappingRecords[$name].View $markers[$name]
                Write-Output ('MappedWrite_' + $name + '_Result=' + $write.Result)
                if (-not [string]::IsNullOrEmpty($write.Error)) {
                    Write-Output ('MappedWrite_' + $name + '_Error=' + $write.Error)
                }
                Write-Output ('WriteMarker_' + $name + '=' + $markers[$name])
                if ($name -eq 'A') {
                    $afterAResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
                    $afterATrace = Get-TraceDump $afterAResult $rawAfterATrace
                    Write-Output ('Trace_AfterA_RawFile=' + $rawAfterATrace)
                    $afterABoundary = [UInt64]$afterATrace.Summary.snapshotSequence
                }
            }

            foreach ($name in @('A', 'D')) {
                $mappedExpected[$name] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers[$name]))
                $r1 = Get-ObserverReadResult $observers[$name] 'R1' $originals[$name] $mappedExpected[$name]
                $r2 = Get-ObserverReadResult $observers[$name] 'R2' $originals[$name] $mappedExpected[$name]
                $pathIndex = 0
                if ($name -eq 'D') {
                    $pathIndex = 3
                }
                $r3 = Read-FreshBufferedObservation $fixturePaths[$pathIndex] $originals[$name] $mappedExpected[$name]
                Write-ReaderFacts ($name + '_R1') $r1
                Write-ReaderFacts ($name + '_R2') $r2
                Write-ReaderFacts ($name + '_R3') $r3
            }

            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $InspectorTimeoutSeconds
            $traceEnabled = $false
            $traceResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
            $trace = Get-TraceDump $traceResult $rawTrace
            Write-TraceFacts $trace
            $fence = Invoke-InspectorChecked -Arguments @('--admission-fence-status') -Timeout $InspectorTimeoutSeconds
            Write-Output ('FenceStatus=' + ([regex]::Replace([string]$fence.Stdout, '[\r\n]+', ' ')).Trim())

            $probes = @(Get-TraceProbeEntries $trace)
            Write-ProbeFacts $probes $probeNames
            if ($probes.Count -eq 4) {
                $probeSopA = Get-ProbeProperty $probes[0] 'sectionObjectPointer'
                $probeSopD = Get-ProbeProperty $probes[3] 'sectionObjectPointer'
                $aWindow = @(Get-PagingWriteEntries $afterATrace $preWriteBoundary)
                $dWindow = @(Get-PagingWriteEntries $trace $afterABoundary)
                if ($probeSopA -eq $probeSopD) {
                    Write-Output 'SOP_Equal_A=AMBIGUOUS'
                    Write-Output 'SOP_Equal_D=AMBIGUOUS'
                }
                else {
                    Write-Output ('SOP_Equal_A=' + (Get-SopEquality $probeSopA $aWindow $probeSopD))
                    Write-Output ('SOP_Equal_D=' + (Get-SopEquality $probeSopD $dWindow $probeSopA))
                }
            }
            else {
                Write-Output 'SOP_Equal_A=AMBIGUOUS'
                Write-Output 'SOP_Equal_D=AMBIGUOUS'
            }
            $runSucceeded = $true
        }
        elseif ($SelectedVariant -eq 'retained-section') {
            # Question under test: can a writable section object that outlives its file handle (and has no view)
            # create a NEW view later without any filter-visible event, and when does the writer's file object
            # finally close? Observe-only: no policy, no agent, fixtures outside every protected scope.
            $copies = 4
            $t = $InspectorTimeoutSeconds
            $labels = @()
            $records = @{}
            foreach ($kind in @('Rpre', 'Rpost', 'S')) {
                for ($i = 0; $i -lt $copies; $i++) {
                    $label = $kind + $i
                    $path = Join-Path $fixtureDirectory ($label + '.maptest')
                    $original = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('PUBLIC BASELINE ' + $label + ' ' + $id))
                    [IO.File]::WriteAllBytes($path, $original)
                    $fixturePaths += $path
                    $labels += $label
                    $records[$label] = [pscustomobject]@{
                        Label = $label; Kind = $kind; Path = $path; Original = $original
                        Mapping = $null; View = $null; Observer = $null; Sop = ''; Expected = $null
                    }
                }
            }
            $lifeLabels = @('Lnv0', 'Lnv1', 'Lv0', 'Lv1', 'Lc0', 'Lc1', 'Lh0', 'Lh1')   # Lc = cached (buffered I/O before mapping)
            $lifePaths = @{}
            foreach ($label in $lifeLabels) {
                $path = Join-Path $fixtureDirectory ($label + '.maptest')
                [IO.File]::WriteAllBytes($path, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('LIFETIME BASELINE ' + $label + ' ' + $id))))
                $fixturePaths += $path
                $lifePaths[$label] = $path
            }
            foreach ($path in $fixturePaths) {
                Assert-ReparseFreeFixturePath $path
            }
            foreach ($label in $labels) {
                $records[$label].Observer = New-ObserverPair $records[$label].Path $fileHandles $uncachedReaders
            }
            foreach ($label in $labels) {
                if ($records[$label].Kind -eq 'Rpre') {
                    $records[$label].Mapping = New-RetainedSection $records[$label].Path ('Local\SafeUpload-Retained-' + $id + '-' + $label) $mappings
                }
            }
            Write-Output ('RetainedSection_Copies=' + $copies)
            Write-Output 'RetainedPreAttachSections=Created;NoViews;FileHandlesClosed'

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)

            # Window A: creation of the post-attach retained sections (section + lifetime events on).
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-sections-lifetime') -Timeout $t)
            $traceEnabled = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                if ($records[$label].Kind -eq 'Rpost') {
                    $records[$label].Mapping = New-RetainedSection $records[$label].Path ('Local\SafeUpload-Retained-' + $id + '-' + $label) $mappings
                }
            }
            $traceA = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceA
            Write-DumpQuality 'A' $traceA

            # Probes before any retained section has a view (lifetime events only, so the ring stays quiet).
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                [void](Invoke-AdmissionProbe $records[$label].Path ('P1_' + $label) $t)
            }
            $traceP1 = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceP1
            Write-DumpQuality 'P1' $traceP1
            $probe1 = Get-ProbeResults $traceP1 $labels
            if ($null -ne $probe1) {
                foreach ($label in $labels) {
                    $records[$label].Sop = ConvertTo-NormalizedHex ([string]$probe1[$label].Sop)
                    Write-Output ('P1_' + $label + '_MmDoes=' + $probe1[$label].MmDoes + ';Sop=' + $records[$label].Sop)
                }
            }

            # Window B: view creation from the retained sections, plus fresh sections as the positive control.
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-sections-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                $record = $records[$label]
                $marker = $record.Kind + ' MARKER ' + $label + ' ' + $id
                if ($record.Kind -eq 'S') {
                    $fixture = New-MappedFixture $record.Path ('Local\SafeUpload-Retained-' + $id + '-' + $label) $false $false $fileHandles $mappings $views
                    $record.Mapping = $fixture.Mapping
                    $record.View = $fixture.View
                }
                else {
                    $record.View = Add-RetainedView $record.Mapping
                    [void]$views.Add($record.View)
                }
                $record.Expected = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($marker))
                $write = Invoke-MappedWrite $record.View $marker
                Write-Output ('B_MappedWrite_' + $label + '=' + $write.Result + $(if ($write.Error) { ';' + $write.Error } else { '' }))
            }
            $traceB = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceB
            Write-DumpQuality 'B' $traceB

            foreach ($label in $labels) {
                $record = $records[$label]
                $r1 = Get-ObserverReadResult $record.Observer 'R1' $record.Original $record.Expected
                $r2 = Get-ObserverReadResult $record.Observer 'R2' $record.Original $record.Expected
                $r3 = Read-FreshBufferedObservation $record.Path $record.Original $record.Expected
                Write-CompactReader ('B_' + $label + '_R1buffered') $r1
                Write-CompactReader ('B_' + $label + '_R2uncached') $r2
                Write-CompactReader ('B_' + $label + '_R3fresh') $r3
            }

            # Probes after every view exists.
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            foreach ($label in $labels) {
                [void](Invoke-AdmissionProbe $records[$label].Path ('P2_' + $label) $t)
            }
            $traceP2 = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceP2
            Write-DumpQuality 'P2' $traceP2
            $probe2 = Get-ProbeResults $traceP2 $labels
            if ($null -ne $probe2) {
                foreach ($label in $labels) {
                    $sop2 = ConvertTo-NormalizedHex ([string]$probe2[$label].Sop)
                    Write-Output ('P2_' + $label + '_MmDoes=' + $probe2[$label].MmDoes + ';Sop=' + $sop2 + ';SopStable=' + ($sop2 -eq $records[$label].Sop))
                }
            }

            # Per-label event facts for windows A and B.
            foreach ($label in $labels) {
                $sop = $records[$label].Sop
                if ([string]::IsNullOrEmpty($sop)) {
                    Write-Output ('A_' + $label + '=AMBIGUOUS_NO_SOP')
                    Write-Output ('B_' + $label + '=AMBIGUOUS_NO_SOP')
                    continue
                }
                Write-Output ('A_' + $label + '=' + (Format-SopEventFacts (Get-SopEventFacts $traceA $sop)))
                Write-Output ('B_' + $label + '=' + (Format-SopEventFacts (Get-SopEventFacts $traceB $sop)))
            }
            foreach ($kind in @('Rpre', 'Rpost', 'S')) {
                $bWithSection = 0
                $aWithAcquire = 0
                foreach ($label in ($labels | Where-Object { $records[$_].Kind -eq $kind })) {
                    $sop = $records[$label].Sop
                    if ([string]::IsNullOrEmpty($sop)) { continue }
                    $bFacts = Get-SopEventFacts $traceB $sop
                    if (($bFacts.Acquire.Count + $bFacts.Release.Count) -gt 0) { $bWithSection++ }
                    if ((Get-SopEventFacts $traceA $sop).Acquire.Count -gt 0) { $aWithAcquire++ }
                }
                Write-Output ('Summary_' + $kind + '_SectionAcquireInWindowA=' + $aWithAcquire + 'of' + $copies)
                Write-Output ('Summary_' + $kind + '_SectionEventsInWindowB=' + $bWithSection + 'of' + $copies)
            }

            # Lifetime window: no observers and no probes on these files, so no other file object touches their streams.
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            $lifeSteps = @{}
            foreach ($label in $lifeLabels) {
                $step = @{ FileClosed = [Int64]0; Unmapped = [Int64]0; MappingClosed = [Int64]0 }
                $lifeSteps[$label] = $step
                $mapPath = $lifePaths[$label]
                $mapName = 'Local\SafeUpload-Life-' + $id + '-' + $label
                if ($label.StartsWith('Lnv')) {
                    $mapping = New-RetainedSection $mapPath $mapName $mappings
                    $step.FileClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                    Start-Sleep -Seconds 3
                    $mapping.Dispose()
                    $step.MappingClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                }
                else {
                    $fileStream = [IO.FileStream]::new($mapPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    if ($label.StartsWith('Lc')) {
                        # Buffered write first, so the Cache Manager has initialized a cache map for this stream.
                        $cachedBytes = [Text.Encoding]::UTF8.GetBytes('CACHED ' + $label)
                        $fileStream.Write($cachedBytes, 0, $cachedBytes.Length)
                        $fileStream.Flush()
                    }
                    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                        $fileStream, $mapName, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
                        [IO.HandleInheritability]::None, $true)
                    $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
                    [void](Invoke-MappedWrite $view ('LIFETIME ' + $label + ' ' + $id))
                    $fileStream.Dispose()
                    $step.FileClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                    if ($label.StartsWith('Lv') -or $label.StartsWith('Lc')) {
                        $view.Dispose()
                        $step.Unmapped = [DateTime]::UtcNow.ToFileTimeUtc()
                        Start-Sleep -Seconds 3
                        $mapping.Dispose()
                        $step.MappingClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                    }
                    else {
                        $mapping.Dispose()
                        $step.MappingClosed = [DateTime]::UtcNow.ToFileTimeUtc()
                        Start-Sleep -Seconds 3
                        $view.Dispose()
                        $step.Unmapped = [DateTime]::UtcNow.ToFileTimeUtc()
                    }
                }
            }
            $lifeEndFt = [DateTime]::UtcNow.ToFileTimeUtc()
            $lifeDumps = @()
            foreach ($wait in @(5, 15, 30)) {
                Start-Sleep -Seconds $wait
                $dump = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) ($rawTraceL + '-after' + $wait)
                Write-DumpQuality ('L_after_' + $wait + 's') $dump
                $lifeDumps += $dump
            }
            $finalLife = $lifeDumps[$lifeDumps.Count - 1]
            $writableMask = [uint32]0xCC
            $creates = @($finalLife.Entries | Where-Object {
                $_.Ev -eq 'section_acquire' -and $_.Sync -eq 1 -and (($_.Prot -band $writableMask) -ne 0) -and $_.ProcessId -eq $PID
            } | Sort-Object Seq)
            Write-Output ('L_OwnWritableCreateSectionEvents=' + $creates.Count + ';Expected=' + $lifeLabels.Count)
            if ($creates.Count -eq $lifeLabels.Count) {
                for ($index = 0; $index -lt $lifeLabels.Count; $index++) {
                    $label = $lifeLabels[$index]
                    $step = $lifeSteps[$label]
                    $sop = $creates[$index].Sop
                    $unmapText = 'n/a'
                    if ($step.Unmapped -ne 0) { $unmapText = [string][Math]::Round(($step.Unmapped - $step.FileClosed) / 10000.0, 1) }
                    Write-Output ('L_' + $label + '=sop:' + $sop + ';unmapMsFromFileClose:' + $unmapText +
                        ';mappingClosedMsFromFileClose:' + [Math]::Round(($step.MappingClosed - $step.FileClosed) / 10000.0, 1))
                    foreach ($event in @($finalLife.Entries | Where-Object { $_.Sop -eq $sop -and $_.Seq -ge $creates[$index].Seq } | Sort-Object Seq)) {
                        Write-Output ('L_' + $label + '_Event=' + $event.Ev + ';fo=' + $event.Fo + ';pid=' + $event.ProcessId +
                            ';msFromFileClose=' + [Math]::Round(($event.Ts - $step.FileClosed) / 10000.0, 1))
                    }
                }
            }
            else {
                Write-Output 'L_Attribution=AMBIGUOUS'
            }
            Write-Output ('L_ObservedMsAfterLastStep=' + [Math]::Round(([DateTime]::UtcNow.ToFileTimeUtc() - $lifeEndFt) / 10000.0, 0))

            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t
            $traceEnabled = $false
            $fence = Invoke-InspectorChecked -Arguments @('--admission-fence-status') -Timeout $t
            Write-Output ('FenceStatus=' + ([regex]::Replace([string]$fence.Stdout, '[\r\n]+', ' ')).Trim())
            $runSucceeded = $true
        }
        elseif ($SelectedVariant -eq 'section-eol') {
            # Question under test: how does MmDoesFileHaveUserWritableReferences (the explicit probe) behave across the
            # life of a writable section, and does it flip back to "no" promptly once the last writable section/view is
            # gone? Observer-free fixtures, one probe per state change, each probe timestamped by the kernel.
            $t = $InspectorTimeoutSeconds
            $caseNames = @('Env', 'Eview', 'Ecache', 'Ehold')
            $copies = 2
            $eolLabels = @()
            $eolPaths = @{}
            foreach ($case in $caseNames) {
                for ($i = 0; $i -lt $copies; $i++) {
                    $label = $case + $i
                    $path = Join-Path $fixtureDirectory ($label + '.maptest')
                    [IO.File]::WriteAllBytes($path, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('EOL BASELINE ' + $label + ' ' + $id))))
                    $fixturePaths += $path
                    $eolPaths[$label] = $path
                    $eolLabels += $label
                }
            }
            $extraLabels = @('Edup0', 'Ecow0', 'Eread0')
            foreach ($label in $extraLabels) {
                $path = Join-Path $fixtureDirectory ($label + '.maptest')
                [IO.File]::WriteAllBytes($path, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('EOL BASELINE ' + $label + ' ' + $id))))
                $fixturePaths += $path
                $eolPaths[$label] = $path
            }
            foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }
            if (-not ('SafeUploadEolNative' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SafeUploadEolNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
            }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-lifetime') -Timeout $t)
            $traceEnabled = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)

            $eolProbes = New-Object System.Collections.ArrayList
            $releaseFt = @{}
            foreach ($label in $eolLabels) {
                $path = $eolPaths[$label]
                $name = 'Local\SafeUpload-Eol-' + $id + '-' + $label
                $mapping = $null; $view = $null
                if ($label.StartsWith('Env')) {
                    $mapping = New-RetainedSection $path $name $mappings
                    [void]$eolProbes.Add(@{ Label = $label; State = 'sectionOpenNoView' })
                    [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_sectionOpenNoView') $t)
                }
                else {
                    $fileStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    if ($label.StartsWith('Ecache')) {
                        $cachedBytes = [Text.Encoding]::UTF8.GetBytes('CACHED ' + $label)
                        $fileStream.Write($cachedBytes, 0, $cachedBytes.Length)
                        $fileStream.Flush()
                    }
                    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                        $fileStream, $name, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
                        [IO.HandleInheritability]::None, $true)
                    [void]$mappings.Add($mapping)
                    $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
                    [void](Invoke-MappedWrite $view ('EOL ' + $label + ' ' + $id))
                    $fileStream.Dispose()
                    [void]$eolProbes.Add(@{ Label = $label; State = 'viewLiveSectionOpen' })
                    [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_viewLiveSectionOpen') $t)
                    if ($label.StartsWith('Ehold')) {
                        $mapping.Dispose()      # section handle gone, view still mapped
                        [void]$eolProbes.Add(@{ Label = $label; State = 'viewOnlySectionHandleClosed' })
                        [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_viewOnlySectionHandleClosed') $t)
                        $view.Dispose()
                        $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
                    }
                    else {
                        $view.Dispose()         # section handle still open, no views
                        [void]$eolProbes.Add(@{ Label = $label; State = 'sectionOpenNoView' })
                        [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_sectionOpenNoView') $t)
                    }
                }
                if (-not $label.StartsWith('Ehold')) {
                    $mapping.Dispose()
                    $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
                }
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)
                Start-Sleep -Seconds 4
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease2' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease2') $t)
                Start-Sleep -Seconds 10
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease3' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease3') $t)
            }
            # Edup: the only writable section handle lives in ANOTHER process after the creator closes its own.
            $child = $null
            try {
                $label = 'Edup0'; $path = $eolPaths[$label]
                $mapping = New-RetainedSection $path ('Local\SafeUpload-Eol-' + $id + '-' + $label) $mappings
                $child = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 300') -PassThru -WindowStyle Hidden
                $duplicate = [IntPtr]::Zero
                $ok = [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(),
                    $mapping.SafeMemoryMappedFileHandle.DangerousGetHandle(), $child.Handle, [ref]$duplicate, [uint32]0, $false, [uint32]2)
                if (-not $ok) { throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error())) }
                Write-Output ('Edup_DuplicatedIntoChildPid=' + $child.Id)
                $mapping.Dispose()
                [void]$eolProbes.Add(@{ Label = $label; State = 'creatorClosedChildHolds' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_creatorClosedChildHolds') $t)
                $child.Kill()
                $child.WaitForExit()
                $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)
                Start-Sleep -Seconds 4
                [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease2' })
                [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease2') $t)
            }
            finally {
                if ($null -ne $child -and -not $child.HasExited) { $child.Kill() }
            }
            # Ecow: a copy-on-write section can never write back to the file, so it must not read as "writable".
            $label = 'Ecow0'; $path = $eolPaths[$label]
            $fileStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                $fileStream, ('Local\SafeUpload-Eol-' + $id + '-' + $label), [long]$mappingLength,
                [IO.MemoryMappedFiles.MemoryMappedFileAccess]::CopyOnWrite, [IO.HandleInheritability]::None, $true)
            [void]$mappings.Add($mapping)
            $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::CopyOnWrite)
            $view.WriteArray(0, [byte[]](1, 2, 3, 4), 0, 4)
            $fileStream.Dispose()
            [void]$eolProbes.Add(@{ Label = $label; State = 'copyOnWriteViewLive' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_copyOnWriteViewLive') $t)
            $view.Dispose(); $mapping.Dispose()
            $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
            [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)
            # Eread: a read-only section and view.
            $label = 'Eread0'; $path = $eolPaths[$label]
            $fileStream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
                $fileStream, ('Local\SafeUpload-Eol-' + $id + '-' + $label), [long]$mappingLength,
                [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read, [IO.HandleInheritability]::None, $true)
            [void]$mappings.Add($mapping)
            $view = $mapping.CreateViewAccessor(0, [long]$mappingLength, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read)
            $fileStream.Dispose()
            [void]$eolProbes.Add(@{ Label = $label; State = 'readOnlyViewLive' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_readOnlyViewLive') $t)
            $view.Dispose(); $mapping.Dispose()
            $releaseFt[$label] = [DateTime]::UtcNow.ToFileTimeUtc()
            [void]$eolProbes.Add(@{ Label = $label; State = 'afterRelease1' })
            [void](Invoke-AdmissionProbe $path ('EOL_' + $label + '_afterRelease1') $t)

            $traceE = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceL
            Write-DumpQuality 'EOL' $traceE
            $probeEntries = @($traceE.Entries | Where-Object { $_.Ev -eq 'explicit_probe' } | Sort-Object Seq)
            Write-Output ('EOL_ProbeEntries=' + $probeEntries.Count + ';Expected=' + $eolProbes.Count)
            if ($probeEntries.Count -eq $eolProbes.Count) {
                for ($index = 0; $index -lt $eolProbes.Count; $index++) {
                    $probe = $eolProbes[$index]
                    $entry = $probeEntries[$index]
                    $msText = 'n/a'
                    if ($releaseFt.ContainsKey($probe.Label)) {
                        $msText = [string][Math]::Round(($entry.Ts - $releaseFt[$probe.Label]) / 10000.0, 0)
                    }
                    Write-Output ('EOL_' + $probe.Label + '_' + $probe.State + '=mmDoes:' + $entry.MmDoes + ';msAfterFinalRelease:' + $msText)
                }
            }
            else {
                Write-Output 'EOL_Attribution=AMBIGUOUS'
            }
            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t
            $traceEnabled = $false
            $runSucceeded = $true
        }
        elseif ($SelectedVariant -eq 'writer-count') {
            # X2: H(F), the per-stream count of write file objects, against what the harness knows to be true.
            $t = $InspectorTimeoutSeconds
            Initialize-EolNative
            Initialize-WriterStress
            Initialize-WriterInheritance
            $script:WriterChecksPassed = 0
            $script:WriterChecksFailed = 0
            $access = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            function Open-WC([string] $p, [IO.FileMode] $mode = [IO.FileMode]::Open, [IO.FileAccess] $acc = [IO.FileAccess]::ReadWrite,
                [IO.FileShare] $share = ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)) {
                return [IO.FileStream]::new($p, $mode, $acc, $share)
            }
            function New-WCFile([string] $name) {
                $p = Join-Path $fixtureDirectory $name
                [IO.File]::WriteAllBytes($p, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('WC BASELINE ' + $name + ' ' + $id))))
                $script:fixturePathsLocal += $p
                return $p
            }
            $script:fixturePathsLocal = @()
            $fa = New-WCFile 'wc_single.maptest'
            $fb = New-WCFile 'wc_two.maptest'
            $fc = New-WCFile 'wc_readonly.maptest'
            $fd = New-WCFile 'wc_dupsame.maptest'
            $fe = New-WCFile 'wc_dupchild.maptest'
            $ff = New-WCFile 'wc_failed.maptest'
            $fg = New-WCFile 'wc_truncate.maptest'
            $fh = New-WCFile 'wc_alias_target.maptest'
            $fi = New-WCFile 'wc_a_rather_long_file_name_for_short_names.maptest'
            $fj = New-WCFile 'wc_many.maptest'
            $fk = New-WCFile 'wc_stress.maptest'
            $fl = New-WCFile 'wc_section.maptest'
            $fm = New-WCFile 'wc_ads_base.maptest'
            $fn = New-WCFile 'wc_delete_only.maptest'
            $fo = New-WCFile 'wc_inherited.maptest'
            $fp = New-WCFile 'wc_delete_on_close.maptest'
            $reparseTargetDirectory = Join-Path $fixtureDirectory 'wc-reparse-target'
            [void][IO.Directory]::CreateDirectory($reparseTargetDirectory)
            $fq = New-WCFile 'wc-reparse-target\wc_reparsed.maptest'
            $fixturePaths += $script:fixturePathsLocal
            foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            if ($Verifier) {
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
                $verifierEnabled = $true
                Write-Output 'VerifierEnabled=volatile flags 0x13B'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $t)
            $traceEnabled = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            $statsBefore = Get-WriterStateStats
            Wait-AdmissionCanary $fa $rawTraceA
            Write-Output ('WC_StatsBefore=counted:' + $statsBefore.writeObjectsCounted + ';released:' + $statsBefore.writeObjectsReleased +
                ';untracked:' + $statsBefore.untrackedCreates + ';unmatched:' + $statsBefore.cleanupUnmatched)

            # Group 1: basic counting
            Add-WriterProbe $fa 'single_beforeOpen' 0
            $s1 = Open-WC $fa
            Add-WriterProbe $fa 'single_open' 1
            $s1.Dispose()
            Add-WriterProbe $fa 'single_closed' 0
            $sa = Open-WC $fb; Add-WriterProbe $fb 'two_firstOpen' 1
            $sb = Open-WC $fb; Add-WriterProbe $fb 'two_secondOpen' 2
            $sa.Dispose(); Add-WriterProbe $fb 'two_firstClosed' 1
            $sb.Dispose(); Add-WriterProbe $fb 'two_allClosed' 0
            $r1 = Open-WC $fc ([IO.FileMode]::Open) ([IO.FileAccess]::Read); Add-WriterProbe $fc 'readOnly_open' 0
            $r1.Dispose()
            $attr = [SafeUploadAdmissionNative]::CreateFile($fc, [uint32]0x100, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
            if ($attr.IsInvalid) { throw 'Attributes-only open failed.' }
            Add-WriterProbe $fc 'attributesOnly_open' 0
            $attr.Dispose(); Add-WriterProbe $fc 'attributesOnly_closed' 0
            $deleteOnly = [SafeUploadAdmissionNative]::CreateFile($fn, [uint32]0x10000, [uint32]7,
                [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
            if ($deleteOnly.IsInvalid) { throw 'Delete-only open failed.' }
            Add-WriterProbe $fn 'deleteOnly_open' 1
            $deleteOnly.Dispose(); Add-WriterProbe $fn 'deleteOnly_closed' 0
            # FILE_FLAG_DELETE_ON_CLOSE takes effect after the final handle to the same file object closes.
            $deleteClose = [SafeUploadAdmissionNative]::CreateFile($fp, [uint32]0x40010000, [uint32]7,
                [IntPtr]::Zero, [uint32]3, [uint32]0x04000080, [IntPtr]::Zero)
            if ($deleteClose.IsInvalid) { throw 'Delete-on-close open failed.' }
            [void]$fileHandles.Add($deleteClose)
            $deleteDup = $null
            try {
                Add-WriterProbe $fp 'deleteOnClose_open' 1
                $deleteDupPtr = [IntPtr]::Zero
                if (-not [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(),
                    $deleteClose.DangerousGetHandle(), [SafeUploadEolNative]::GetCurrentProcess(),
                    [ref]$deleteDupPtr, [uint32]0, $false, [uint32]2)) { throw 'Delete-on-close duplicate failed.' }
                $deleteDup = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($deleteDupPtr, $true)
                [void]$fileHandles.Add($deleteDup)
                $deleteClose.Dispose()
                Add-WriterProbe $fp 'deleteOnClose_originalClosedDuplicateHolds' 1
                $deleteDup.Dispose()
                $deleteError = [SafeUploadWriterInheritance]::MissingFileError($fp)
                $deleted = $deleteError -eq 2
                Write-Output ('WC_DeleteOnClose_FinalHandleDeletedFile=' + $deleted + ';NativeError=' + $deleteError)
                if (-not $deleted) { throw 'Delete-on-close did not delete the fixture after final close.' }
            } finally {
                $deleteClose.Dispose()
                if ($null -ne $deleteDup) { $deleteDup.Dispose() }
            }
            Complete-WriterChecks 'basic_and_deleteOnClose' $rawTraceA

            # Group 2: duplicated handles
            $d1 = Open-WC $fd
            $dupPtr = [IntPtr]::Zero
            $okDup = [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(), $d1.SafeFileHandle.DangerousGetHandle(),
                [SafeUploadEolNative]::GetCurrentProcess(), [ref]$dupPtr, [uint32]0, $false, [uint32]2)
            if (-not $okDup) { throw 'In-process DuplicateHandle failed.' }
            $dup = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($dupPtr, $true)
            Add-WriterProbe $fd 'dupSame_afterDuplicate' 1
            $d1.Dispose(); Add-WriterProbe $fd 'dupSame_originalClosed' 1
            $dup.Dispose(); Add-WriterProbe $fd 'dupSame_allClosed' 0
            $e1 = Open-WC $fe
            $child = $null
            try {
                $child = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 300') -PassThru -WindowStyle Hidden
                $dupChild = [IntPtr]::Zero
                $okChild = [SafeUploadEolNative]::DuplicateHandle([SafeUploadEolNative]::GetCurrentProcess(), $e1.SafeFileHandle.DangerousGetHandle(),
                    $child.Handle, [ref]$dupChild, [uint32]0, $false, [uint32]2)
                if (-not $okChild) { throw 'Cross-process DuplicateHandle failed.' }
                $e1.Dispose()
                Add-WriterProbe $fe 'dupChild_parentClosedChildHolds' 1
                $child.Kill(); $child.WaitForExit()
                Add-WriterProbe $fe 'dupChild_childKilled' 0
            }
            finally { if ($null -ne $child -and -not $child.HasExited) { $child.Kill() } }
            # True CreateProcess inheritance, with child-side FILE_ID_INFO proof of the inherited handle.
            $inheritedFile = Open-WC $fo
            [void]$fileHandles.Add($inheritedFile)
            $nativeSourcePath = Join-Path $fixtureDirectory 'wc-inherit-native.cs'
            $readyPath = Join-Path $fixtureDirectory 'wc-inherit-ready.json'
            [IO.File]::WriteAllText($nativeSourcePath, $script:WriterInheritanceSource)
            $nativeHandle = $inheritedFile.SafeFileHandle.DangerousGetHandle()
            $expectedIdentity = [SafeUploadWriterInheritance]::Identity($nativeHandle)
            $childCode = @"
`$ErrorActionPreference='Stop'
Add-Type -Path '$nativeSourcePath'
`$identity=[SafeUploadWriterInheritance]::Identity([IntPtr]::new($($nativeHandle.ToInt64())))
if (`$identity -ne '$expectedIdentity') { throw 'Inherited file identity mismatch' }
@{ Identity=`$identity; ProcessId=`$PID; Handle=$($nativeHandle.ToInt64()) } | ConvertTo-Json | Set-Content -LiteralPath '$readyPath.next'
Move-Item -LiteralPath '$readyPath.next' -Destination '$readyPath'
Start-Sleep -Seconds 300
"@
            $childScriptPath = Join-Path $fixtureDirectory 'wc-inherit-child.ps1'
            [IO.File]::WriteAllText($childScriptPath, $childCode)
            $application = Join-Path $PSHOME 'powershell.exe'
            $child = $null
            try {
                $child = [SafeUploadWriterInheritance]::Start($nativeHandle, $application,
                    ('"' + $application + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $childScriptPath + '"'))
                $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
                while (-not (Test-Path -LiteralPath $readyPath) -and -not $child.HasExited -and [DateTime]::UtcNow -lt $readyDeadline) {
                    Start-Sleep -Milliseconds 50
                }
                if (-not (Test-Path -LiteralPath $readyPath)) { throw 'Inherited child did not prove its handle.' }
                $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
                if ($ready.Identity -ne $expectedIdentity -or $ready.ProcessId -ne $child.Id -or
                    $ready.Handle -ne $nativeHandle.ToInt64()) { throw 'Inherited child proof mismatch.' }
                Write-Output ('WC_InheritedProof=PID:' + $ready.ProcessId + ';Identity:' + $ready.Identity + ';Handle:' + $ready.Handle)
                Add-WriterProbe $fo 'inherited_parentAndChildHold' 1
                $inheritedFile.Dispose()
                Add-WriterProbe $fo 'inherited_parentClosedChildHolds' 1
                $child.Kill(); $child.WaitForExit()
                Add-WriterProbe $fo 'inherited_childExited' 0
            } finally {
                $inheritedFile.Dispose()
                if ($null -ne $child) {
                    if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
                    $child.Dispose()
                }
            }
            Complete-WriterChecks 'duplicates_and_inheritance' $rawTraceP1

            # Group 3: failed creates, truncation, aliases
            $x1 = Open-WC $ff ([IO.FileMode]::Open) ([IO.FileAccess]::ReadWrite) ([IO.FileShare]::None)
            Add-WriterProbe ($ff) 'failed_exclusiveOpen' 1
            $failedSharing = $false
            try { $x2 = Open-WC $ff; $x2.Dispose() } catch { $failedSharing = $true }
            Write-Output ('WC_Note_SharingViolationRaised=' + $failedSharing)
            if (-not $failedSharing) { throw 'Sharing-violation fixture did not fail its create.' }
            Add-WriterProbe $ff 'failed_afterSharingViolation' 1
            $failedMissing = $false
            try { $x3 = Open-WC (Join-Path $fixtureDirectory 'wc_missing.maptest'); $x3.Dispose() } catch { $failedMissing = $true }
            Write-Output ('WC_Note_MissingOpenRaised=' + $failedMissing)
            if (-not $failedMissing) { throw 'Missing-file fixture did not fail its create.' }
            Add-WriterProbe $ff 'failed_afterMissingOpen' 1
            $x1.Dispose(); Add-WriterProbe $ff 'failed_closed' 0
            $tr = Open-WC $fg ([IO.FileMode]::Create); Add-WriterProbe $fg 'truncate_open' 1
            $tr.Dispose(); Add-WriterProbe $fg 'truncate_closed' 0
            $linkPath = Join-Path $fixtureDirectory 'wc_alias_link.maptest'
            New-Item -ItemType HardLink -Path $linkPath -Target $fh | Out-Null
            $script:fixturePathsLocal += $linkPath; $fixturePaths += $linkPath
            $viaLink = Open-WC $linkPath
            Add-WriterProbe $fh 'hardLink_openedViaLinkProbedViaTarget' 1
            Add-WriterProbe $linkPath 'hardLink_probedViaLink' 1
            $viaLink.Dispose(); Add-WriterProbe $fh 'hardLink_closed' 0
            $shortPath = $null
            try { $shortPath = (New-Object -ComObject Scripting.FileSystemObject).GetFile($fi).ShortPath } catch { }
            if ($shortPath -and $shortPath -ne $fi) {
                $viaShort = Open-WC $shortPath
                Add-WriterProbe $fi 'shortName_openedViaShortProbedViaLong' 1
                $viaShort.Dispose(); Add-WriterProbe $fi 'shortName_closed' 0
                Write-Output ('WC_Note_ShortPath=' + $shortPath)
            }
            else { Write-Output 'WC_Note_ShortPath=NOT_AVAILABLE' }
            $adsPath = $fm + ':side'
            # .NET FileStream rejects stream names; use the Win32 open. GENERIC_WRITE, share all, OPEN_ALWAYS.
            $adsHandle = [SafeUploadAdmissionNative]::CreateFile($adsPath, [uint32]0x40000000, [uint32]7, [IntPtr]::Zero, [uint32]4, [uint32]0x80, [IntPtr]::Zero)
            if ($adsHandle.IsInvalid) { throw 'Alternate stream open failed.' }
            Add-WriterProbe $fm 'ads_sideStreamWriterDoesNotCountForBase' 0
            $adsHandle.Dispose()
            # A same-volume junction causes a real filesystem reparse of the write create.
            $junction = Join-Path $fixtureDirectory 'wc-reparse-junction'
            $reparsedFile = $null
            try {
                New-Item -ItemType Junction -Path $junction -Target $reparseTargetDirectory | Out-Null
                $junctionHandle = [SafeUploadAdmissionNative]::CreateFile($junction, [uint32]0x100, [uint32]7,
                    [IntPtr]::Zero, [uint32]3, [uint32]0x02200000, [IntPtr]::Zero)
                if ($junctionHandle.IsInvalid) { throw 'Junction tag open failed.' }
                try { $tag = [SafeUploadWriterInheritance]::ReparseTag($junctionHandle.DangerousGetHandle()) }
                finally { $junctionHandle.Dispose() }
                if ($tag -ne [uint32]2684354563) { throw 'Fixture is not a mount-point junction.' }
                $direct = [SafeUploadAdmissionNative]::CreateFile($fq, [uint32]0x100, [uint32]7,
                    [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
                if ($direct.IsInvalid) { throw 'Canonical reparse target identity open failed.' }
                try { $canonicalIdentity = [SafeUploadWriterInheritance]::Identity($direct.DangerousGetHandle()) }
                finally { $direct.Dispose() }
                $reparsedFile = [SafeUploadAdmissionNative]::CreateFile((Join-Path $junction 'wc_reparsed.maptest'),
                    [uint32]0x40010000, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0x80, [IntPtr]::Zero)
                if ($reparsedFile.IsInvalid) { throw 'Reparsed write-create failed.' }
                [void]$fileHandles.Add($reparsedFile)
                $redirectedIdentity = [SafeUploadWriterInheritance]::Identity($reparsedFile.DangerousGetHandle())
                if ($redirectedIdentity -ne $canonicalIdentity) { throw 'Reparsed write-create resolved to another file.' }
                Write-Output ('WC_ReparseProof=Tag:' + $tag + ';Identity:' + $redirectedIdentity + ';MatchesCanonical=True')
                Add-WriterProbe $fq 'reparsed_writeOpenCountsCanonicalTarget' 1
                $reparsedFile.Dispose()
                Add-WriterProbe $fq 'reparsed_closed' 0
            } finally {
                if ($null -ne $reparsedFile) { $reparsedFile.Dispose() }
                # Remove only the junction itself; never recurse through the target during cleanup.
                if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction, $false) }
            }
            Complete-WriterChecks 'aliases_and_reparse' $rawTraceP2

            # Group 4: many handles, stress, and a writer whose file handle closed but whose section is retained
            $many = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt 120; $i++) { [void]$many.Add((Open-WC $fj)) }
            Add-WriterProbe $fj 'many_120open' 120
            for ($i = 0; $i -lt 60; $i++) { $many[$i].Dispose() }
            Add-WriterProbe $fj 'many_60closed' 60
            for ($i = 60; $i -lt 120; $i++) { $many[$i].Dispose() }
            Add-WriterProbe $fj 'many_allClosed' 0
            $stressFailures = [SafeUploadWriterStress]::Run($fk, 8, 400)
            Write-Output ('WC_Note_StressOpenFailures=' + $stressFailures)
            if ($stressFailures -ne 0) { throw ('Writer stress open failures: ' + $stressFailures) }
            Add-WriterProbe $fk 'stress_8x400_allClosed' 0
            $secFile = Open-WC $fl
            $secMap = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($secFile, ('Local\SafeUpload-Wc-' + $id), [long]$mappingLength,
                [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
            [void]$mappings.Add($secMap)
            Add-WriterProbe $fl 'section_fileOpenSectionRetained' 1 'yes'
            $secFile.Dispose()
            Add-WriterProbe $fl 'section_fileClosedSectionRetained_HzeroSyes' 0 'yes'
            $secMap.Dispose()
            Add-WriterProbe $fl 'section_released_HzeroSno' 0 'no'
            Complete-WriterChecks 'many_and_sections' $rawTraceB

            $statsAfter = Get-WriterStateStats
            Write-Output ('WC_StatsAfter=counted:' + $statsAfter.writeObjectsCounted + ';released:' + $statsAfter.writeObjectsReleased +
                ';untracked:' + $statsAfter.untrackedCreates + ';unmatched:' + $statsAfter.cleanupUnmatched +
                ';postCreateRuns:' + $statsAfter.postCreateRuns)
            $dCounted = [int64]$statsAfter.writeObjectsCounted - [int64]$statsBefore.writeObjectsCounted
            $dReleased = [int64]$statsAfter.writeObjectsReleased - [int64]$statsBefore.writeObjectsReleased
            Write-Output ('WC_StatsDelta=counted:' + $dCounted + ';released:' + $dReleased + ';liveDelta:' + ($dCounted - $dReleased))
            Write-Output ('WC_Summary=passed:' + $script:WriterChecksPassed + ';failed:' + $script:WriterChecksFailed)
            if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceB + '-final-volumes.json') }
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t)
            $traceEnabled = $false
            $runSucceeded = ($script:WriterChecksFailed -eq 0)
        }
        elseif ($SelectedVariant -eq 'section-lower') {
            $t = $InspectorTimeoutSeconds
            $faultInput=Join-Path $documents $FaultDriverFileName
            $faultClientSource=Join-Path $documents $FaultClientFileName
            $faultExercise=Join-Path $documents $FaultExerciseFileName
            foreach ($lowerInput in @(@($faultInput,$ExpectedFaultSha256),@($faultClientSource,$ExpectedFaultClientSha256),
                @($faultExercise,$ExpectedFaultExerciseSha256))) {
                if ($lowerInput[1].Length -ne 64 -or (Get-FileHash -LiteralPath $lowerInput[0] -Algorithm SHA256).Hash -ne $lowerInput[1]) {
                    throw 'Lower qualification input hash mismatch.'
                }
            }
            $faultInstalled='C:\Windows\System32\drivers\SafeUploadSectionFault.sys'
            $faultKey='HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadSectionFault'
            $faultInventory=& fltmc.exe filters 2>&1|Out-String
            if ($LASTEXITCODE -ne 0) { throw 'Companion baseline filter enumeration failed.' }
            if ((Test-Path $faultInstalled) -or (Test-Path $faultKey) -or
                @(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUploadSectionFault'" -ErrorAction Stop).Count -ne 0 -or
                ($faultInventory -match '(?m)^SafeUploadSectionFault\s')) { throw 'Companion baseline is not empty.' }
            $sig=Get-AuthenticodeSignature -LiteralPath $faultInput
            if ($sig.Status.ToString() -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne '220DD82C37FCF36048D59E4F10113185D81D5DC7') {
                throw 'Companion signature mismatch.'
            }
            $target=Join-Path $fixtureDirectory 'sf_lower.maptest'
            [IO.File]::WriteAllBytes($target,(New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('SECTION LOWER '+$id))))
            $fixturePaths += $target
            Assert-ReparseFreeFixturePath $target
            Backup-StagedTestDriver $backup
            if ((Get-FileHash $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) { throw 'Original backup mismatch.' }
            $driverReplaced=$true
            Copy-Item $featureDriver $installedDriver -Force
            if ((Get-FileHash $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256) { throw 'Upper install mismatch.' }
            if ($Verifier) {
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Upper Verifier enable failed.' }
                $verifierEnabled=$true
            }
            Invoke-FeatureFilterLoad
            $filterLoaded=$true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable-sections') -Timeout $t)
            $traceEnabled=$true
            Wait-AdmissionCanary $target $rawTraceA
            $faultFileOwned=$false; $faultServiceOwned=$false; $faultLoaded=$false; $faultVerified=$false
            $faultCleanupErrors=New-Object System.Collections.Generic.List[string]
            try {
                $faultFileOwned=$true
                Copy-Item -LiteralPath $faultInput -Destination $faultInstalled
                if ((Get-FileHash $faultInstalled -Algorithm SHA256).Hash -ne $ExpectedFaultSha256) { throw 'Companion installed hash mismatch.' }
                & sc.exe create SafeUploadSectionFault type= filesys start= demand binPath= $faultInstalled group= 'FSFilter Anti-Virus' depend= FltMgr|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Companion service creation failed.' }
                $faultServiceOwned=$true
                $instances=Join-Path $faultKey 'Instances'; $instance=Join-Path $instances 'SectionFault Test'
                New-Item $instance -Force|Out-Null
                New-ItemProperty $instances DefaultInstance -PropertyType String -Value 'SectionFault Test' -Force|Out-Null
                New-ItemProperty $instance Altitude -PropertyType String -Value '321409' -Force|Out-Null
                New-ItemProperty $instance Flags -PropertyType DWord -Value 1 -Force|Out-Null
                if ($Verifier) {
                    & verifier.exe /volatile /flags 0x13B /adddriver SafeUploadSectionFault.sys|Out-Host
                    if ($LASTEXITCODE -ne 0) { throw 'Companion Verifier enable failed.' }
                    $faultVerified=$true
                }
                & fltmc.exe load SafeUploadSectionFault|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Companion load failed.' }
                $faultLoaded=$true
                & fltmc.exe attach SafeUploadSectionFault C:|Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Companion manual attachment failed.' }
                Write-Output ('SectionFaultSHA256='+$ExpectedFaultSha256)
                Add-Type -Path $faultClientSource
                if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') { throw 'NonSYSTEM control-denial qualification needs the ordinary harness identity.' }
                $denied=$false; $denialCode=''
                try { $unexpected=[SafeUploadSectionFaultClient]::new(); $unexpected.Dispose() }
                catch {
                    $exception=$_.Exception
                    while ($exception.InnerException) { $exception=$exception.InnerException }
                    $denialCode='0x'+([uint32]([int64]$exception.HResult -band 0xffffffff)).ToString('X8')
                    $denied=$denialCode -eq '0x80070005'
                }
                Write-Output ('SectionFaultNonSystemDenied='+$denied+';HRESULT='+$denialCode)
                if (-not $denied) { throw 'Companion port did not reject the ordinary identity with access denied.' }
                $resultPath=Join-Path $documents ('SafeUpload-section-lower-'+$id+'-result.json')
                $tracePrefix=Join-Path $documents ('SafeUpload-section-lower-'+$id)
                $exerciseArguments=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$faultExercise,
                    '-Fixture',$target,'-Inspector',$inspectorPath,'-ClientSource',$faultClientSource,'-ResultPath',$resultPath,
                    '-TracePrefix',$tracePrefix,'-ExpectedInspectorSha256',$ExpectedInspectorSha256,
                    '-ExpectedClientSha256',$ExpectedFaultClientSha256)
                $argumentLine=(@($exerciseArguments|ForEach-Object { ConvertTo-WindowsArgument ([string]$_) })) -join ' '
                $agent=Start-StagedTestAgent $PSHOME (Join-Path $documents ('SafeUpload-section-lower-'+$id+'-system')) 'powershell.exe' $argumentLine
                if (-not $agent.Process.WaitForExit(60000)) { throw 'SYSTEM lower exercise timed out.' }
                if (-not (Test-Path $resultPath)) { throw 'SYSTEM lower exercise did not write its result.' }
                $lower=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
                Write-Output ('SectionLowerResult='+($lower|ConvertTo-Json -Depth 10 -Compress))
                Write-Output ('SectionLowerResultFile='+$resultPath)
                Write-Output ('SectionLowerTracePrefix='+$tracePrefix)
                if ($agent.Process.ExitCode -ne 0 -or $lower.Passed -ne $true -or $lower.Errors.Count -ne 0 -or
                    $lower.Disarmed.Mode -ne 0 -or $lower.Disarmed.ArmedFileObject -ne 0 -or $lower.Disarmed.CurrentHeld -ne 0) {
                    throw 'Live lower-stack section qualification failed.'
                }
                if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceB+'-final-volumes.json') }
                $runSucceeded=$true
                Write-Output 'SectionLowerQualification=PASS'
            } finally {
                try { Stop-StagedTestAgent $agent; $agent=$null }
                finally {
                    if ($faultLoaded) {
                        & fltmc.exe unload SafeUploadSectionFault|Out-Host
                        if ($LASTEXITCODE -ne 0) { [void]$faultCleanupErrors.Add('Companion unload failed.') }
                    }
                    if ($faultVerified) {
                        & verifier.exe /volatile /removedriver SafeUploadSectionFault.sys|Out-Host
                        if ($LASTEXITCODE -ne 0) { [void]$faultCleanupErrors.Add('Companion Verifier removal failed.') }
                    }
                    if ($faultServiceOwned) {
                        & sc.exe delete SafeUploadSectionFault|Out-Host
                        if ($LASTEXITCODE -ne 0) { [void]$faultCleanupErrors.Add('Companion service delete failed.') }
                    }
                    $faultInventory=& fltmc.exe filters 2>&1|Out-String
                    $faultInventoryExit=$LASTEXITCODE
                    if ($faultInventoryExit -ne 0) { [void]$faultCleanupErrors.Add('Companion filter enumeration failed; binary retained.') }
                    if ($faultFileOwned -and $faultInventoryExit -eq 0 -and $faultInventory -notmatch '(?m)^SafeUploadSectionFault\s') {
                        try { Remove-Item -LiteralPath $faultInstalled -Force }
                        catch { [void]$faultCleanupErrors.Add('Companion file delete: '+$_.Exception.Message) }
                    }
                    $faultServices=@(); $faultServicesRead=$false
                    try {
                        $deleteDeadline=[DateTime]::UtcNow.AddSeconds(5)
                        do {
                            $faultServices=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUploadSectionFault'" -ErrorAction Stop)
                            if ($faultServices.Count -ne 0 -or (Test-Path $faultKey)) { Start-Sleep -Milliseconds 100 }
                        } while (($faultServices.Count -ne 0 -or (Test-Path $faultKey)) -and [DateTime]::UtcNow -lt $deleteDeadline)
                        $faultServicesRead=$true
                    } catch { [void]$faultCleanupErrors.Add('Companion service enumeration: '+$_.Exception.Message) }
                    $clean=$faultInventoryExit -eq 0 -and $faultServicesRead -and
                        -not (Test-Path $faultInstalled) -and -not (Test-Path $faultKey) -and $faultServices.Count -eq 0 -and
                        $faultInventory -notmatch '(?m)^SafeUploadSectionFault\s'
                    Write-Output ('SectionFaultRestored='+$clean)
                    if (-not $clean -or $faultCleanupErrors.Count -ne 0) { throw ('Companion restoration failed: '+($faultCleanupErrors -join '; ')) }
                }
            }
        }
        elseif ($SelectedVariant -eq 'section-inflight') {
            # X3: C(F), writable CreateSections in flight. The window is microseconds, so this checks conservation:
            # every entry inserted is removed again (release, or post-operation on a failed acquire), nothing
            # overflows or sticks, and read-only sections are never tracked.
            $t = $InspectorTimeoutSeconds
            Initialize-SectionStress
            $stormFiles = @()
            for ($i = 0; $i -lt 16; $i++) {
                $p = Join-Path $fixtureDirectory ('sf_{0:D2}.maptest' -f $i)
                [IO.File]::WriteAllBytes($p, (New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes('SF ' + $i + ' ' + $id))))
                $fixturePaths += $p
                $stormFiles += $p
            }
            $emptyFile = Join-Path $fixtureDirectory 'sf_empty.maptest'
            [IO.File]::WriteAllBytes($emptyFile, [byte[]]@())
            $fixturePaths += $emptyFile
            foreach ($path in $fixturePaths) { Assert-ReparseFreeFixturePath $path }

            Backup-StagedTestDriver $backup
            if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                throw 'Durable restoration backup mismatch.'
            }
            $driverReplaced = $true
            Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
            if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                throw 'Feature driver install hash mismatch.'
            }
            if ($Verifier) {
                & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
                if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
                $verifierEnabled = $true
                Write-Output 'VerifierEnabled=volatile flags 0x13B'
            }
            Invoke-FeatureFilterLoad
            $filterLoaded = $true
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $t)
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $t)
            $traceEnabled = $true

            $s0 = Get-WriterStateStats
            Wait-AdmissionCanary $stormFiles[0] $rawTraceA
            Write-Output ('X3_Stats0=inserted:' + $s0.sectionInFlightInserted + ';released:' + $s0.sectionInFlightReleased +
                ';removedOnFailure:' + $s0.sectionInFlightRemovedOnFailure + ';now:' + $s0.sectionInFlightNow +
                ';overflow:' + $s0.sectionInFlightOverflow + ';stuck:' + $s0.sectionInFlightStuck)

            $single = [SafeUploadSectionStress]::Run($stormFiles, 1, 500, $false)
            $s1 = Get-WriterStateStats
            Write-Output ('X3_Single=failures:' + $single + ';insertedDelta:' + ([int64]$s1.sectionInFlightInserted - [int64]$s0.sectionInFlightInserted) +
                ';releasedDelta:' + ([int64]$s1.sectionInFlightReleased - [int64]$s0.sectionInFlightReleased) +
                ';now:' + $s1.sectionInFlightNow)

            $storm = [SafeUploadSectionStress]::Run($stormFiles, 8, 300, $true)
            $s2 = Get-WriterStateStats
            Write-Output ('X3_Storm=failures:' + $storm + ';writableSections:2400;readOnlySections:2400' +
                ';insertedDelta:' + ([int64]$s2.sectionInFlightInserted - [int64]$s1.sectionInFlightInserted) +
                ';releasedDelta:' + ([int64]$s2.sectionInFlightReleased - [int64]$s1.sectionInFlightReleased) +
                ';removedOnFailureDelta:' + ([int64]$s2.sectionInFlightRemovedOnFailure - [int64]$s1.sectionInFlightRemovedOnFailure) +
                ';maxDepth:' + $s2.sectionInFlightMaxDepth + ';overflowDelta:' + ([int64]$s2.sectionInFlightOverflow - [int64]$s1.sectionInFlightOverflow))

            # Failure injection: a writable mapping of an empty file with no size fails inside Mm.
            $failed = 0
            for ($i = 0; $i -lt 20; $i++) {
                if ([SafeUploadSectionStress]::TryEmptyFileMapping($emptyFile) -eq 1006) { $failed++ }
            }
            $s3 = Get-WriterStateStats
            Write-Output ('X3_InjectedFailures=attempts:20;failedAsExpected:' + $failed +
                ';insertedDelta:' + ([int64]$s3.sectionInFlightInserted - [int64]$s2.sectionInFlightInserted) +
                ';releasedDelta:' + ([int64]$s3.sectionInFlightReleased - [int64]$s2.sectionInFlightReleased) +
                ';removedOnFailureDelta:' + ([int64]$s3.sectionInFlightRemovedOnFailure - [int64]$s2.sectionInFlightRemovedOnFailure))
            # A failed CreateFileMapping can still have a successful acquire followed by release.
            # Count the callback path separately so this does not qualify failed-acquire cleanup.
            Write-Output ('X3_FailedAcquireCoverage=' + $(if ([int64]$s3.sectionInFlightRemovedOnFailure -gt [int64]$s2.sectionInFlightRemovedOnFailure) { 'EXERCISED' } else { 'NOT_EXERCISED' }))

            $shared = [SafeUploadSectionStress]::RunSharedFileObject($stormFiles[0], 8, 300)
            $sharedStats = Get-WriterStateStats
            $sharedTracked = [int64]$sharedStats.sectionInFlightInserted - [int64]$s3.sectionInFlightInserted
            Write-Output ('X3_SharedFileObject=failures:' + $shared + ';writableSections:2400;readOnlySections:2400;insertedDelta:' + $sharedTracked +
                ';releasedDelta:' + ([int64]$sharedStats.sectionInFlightReleased - [int64]$s3.sectionInFlightReleased))

            Start-Sleep -Seconds 3
            $s4 = Get-WriterStateStats
            Write-Output ('X3_AtRest=inserted:' + $s4.sectionInFlightInserted + ';released:' + $s4.sectionInFlightReleased +
                ';removedOnFailure:' + $s4.sectionInFlightRemovedOnFailure + ';now:' + $s4.sectionInFlightNow +
                ';overflow:' + $s4.sectionInFlightOverflow + ';stuck:' + $s4.sectionInFlightStuck + ';maxDepth:' + $s4.sectionInFlightMaxDepth)
            [void](Invoke-AdmissionProbe $stormFiles[0] 'X3_Probe' $t)
            $traceX = Get-LightTrace (Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $t) $rawTraceA
            $probeX = @($traceX.Entries | Where-Object { $_.Ev -eq 'explicit_probe' })
            $probeText = if ($probeX.Count -eq 1) { [string]$probeX[0].InFlightSections } else { 'AMBIGUOUS' }
            Write-Output ('X3_Probe=' + $probeText + ';mmDoes:' + $(if ($probeX.Count -eq 1) { $probeX[0].MmDoes } else { 'n/a' }))
            $probeOk = ($probeX.Count -eq 1 -and $probeX[0].ProbeValid -and
                $probeX[0].InFlightSections -eq 0 -and $probeX[0].MmDoes -eq 'no' -and
                (-not $RequireCanary -or $probeX[0].CanaryOk))

            $conserved = ([int64]$s4.sectionInFlightInserted - [int64]$s4.sectionInFlightReleased - [int64]$s4.sectionInFlightRemovedOnFailure - [int64]$s4.sectionInFlightNow)
            $tracked = ([int64]$s2.sectionInFlightInserted - [int64]$s1.sectionInFlightInserted)
            Write-Output ('X3_Verdict=conservationResidual:' + $conserved + ';stormTrackedSections:' + $tracked +
                ';overflow:' + $s4.sectionInFlightOverflow + ';stuck:' + $s4.sectionInFlightStuck + ';now:' + $s4.sectionInFlightNow)
            if ($RequireAllVolumeCanaries) { Wait-AllVolumeCanaries ($rawTraceA + '-final-volumes.json') }
            [void](Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $t)
            $traceEnabled = $false
            # The storm creates 2400 writable sections; other processes may add a few. Read-only sections must not be tracked.
            $ok = ($conserved -eq 0) -and ([int64]$s4.sectionInFlightOverflow -eq 0) -and ([int64]$s4.sectionInFlightStuck -eq 0) -and
                ([int64]$s4.sectionInFlightNow -eq 0) -and ($tracked -ge 2400) -and ($tracked -lt 3000) -and ($storm -eq 0) -and
                ($single -eq 0) -and ($failed -eq 20) -and ($shared -eq 0) -and ($sharedTracked -ge 2400) -and ($sharedTracked -lt 3000) -and $probeOk
            Write-Output ('X3_Result=' + $(if ($ok) { 'PASS' } else { 'FAIL' }))
            $runSucceeded = $ok
        }
        else {
            $target = Join-Path $fixtureDirectory ('synthetic-' + $id + '.maptest')
            $fixturePaths = @($target)
            $originalText = 'PUBLIC BASELINE ' + $SelectedVariant + ' ' + $id
            $originals['Fixture'] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($originalText))
            [IO.File]::WriteAllBytes($target, $originals['Fixture'])

            if ($SelectedVariant -eq 'preattach-immediate' -or
                $SelectedVariant -eq 'preattach-protected-open') {
                $mappingRecords['Fixture'] = New-MappedFixture $target ('Local\SafeUpload-Admission-' + $id) $false $false $fileHandles $mappings $views
                $observers['Fixture'] = New-ObserverPair $target $fileHandles $uncachedReaders
                Assert-ReparseFreeFixturePath $target

                Backup-StagedTestDriver $backup
                if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Durable restoration backup mismatch.'
                }
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                    throw 'Feature driver install hash mismatch.'
                }
                Invoke-FeatureFilterLoad
                $filterLoaded = $true

                $clear = Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds
                $enable = Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds
                $traceEnabled = $true
                Write-Output 'AdmissionTrace=ClearedAndEnabled'

                if ($SelectedVariant -eq 'preattach-protected-open') {
                    $expandedPolicy = New-ExpandedPolicyForFixture $fixtureDirectory $policyBackup
                    $policyBytes = $expandedPolicy.OriginalBytes
                    [IO.File]::WriteAllBytes($policyPath, $expandedPolicy.UpdatedBytes)
                    Write-Output ('ExpandedPolicySHA256=' + (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash)
                    Write-Output 'ExpandedPolicyIncludesFixture=True'

                    $baseLog = Join-Path $documents ('admission-agent-protected-' + $id)
                    [void]$agentLogs.Add($baseLog + '-out.log')
                    [void]$agentLogs.Add($baseLog + '-err.log')
                    $agent = Start-TestAgentAndWaitForPolicy $baseLog
                    Write-Output 'ExpandedPolicyAcceptedByRealAgentAndDriver=True'

                    $protected = $null
                    try {
                        $protected = [IO.FileStream]::new(
                            $target, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                        $protected.Dispose()
                        $protected = $null
                        Write-Output 'ProtectedOpen_Result=SUCCESS'
                    }
                    catch {
                        if ($null -ne $protected) {
                            $protected.Dispose()
                        }
                        Write-Output 'ProtectedOpen_Result=EXCEPTION'
                        Write-Output 'ProtectedOpen_Class=OBSERVED_REFUSED'
                        Write-Output ('ProtectedOpen_Exception=' + (Get-ErrorText $_))
                    }
                    finally {
                        if ($null -ne $agent) {
                            Stop-StagedTestAgent $agent
                            $agent = $null
                        }
                    }
                }

                if ($SelectedVariant -eq 'preattach-immediate') {
                    $markers['Fixture'] = 'MAPPED IMMEDIATE ' + $id
                }
                else {
                    $markers['Fixture'] = 'MAPPED AFTER PROTECTED OPEN ' + $id
                }
                $mappedExpected['Fixture'] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers['Fixture']))
                $write = Invoke-MappedWrite $mappingRecords['Fixture'].View $markers['Fixture']
                Write-Output ('MappedWrite_Result=' + $write.Result)
                if (-not [string]::IsNullOrEmpty($write.Error)) {
                    Write-Output ('MappedWrite_Error=' + $write.Error)
                }
                $r1 = Get-ObserverReadResult $observers['Fixture'] 'R1' $originals['Fixture'] $mappedExpected['Fixture']
                $r2 = Get-ObserverReadResult $observers['Fixture'] 'R2' $originals['Fixture'] $mappedExpected['Fixture']
                $r3 = Read-FreshBufferedObservation $target $originals['Fixture'] $mappedExpected['Fixture']
                Write-ReaderFacts 'R1' $r1
                Write-ReaderFacts 'R2' $r2
                Write-ReaderFacts 'R3' $r3
                [void](Invoke-AdmissionProbe $target 'Fixture' $InspectorTimeoutSeconds)
            }
            else {
                # V4 creates its file and pre-load readers before attachment.
                $observers['Fixture'] = New-ObserverPair $target $fileHandles $uncachedReaders
                Assert-ReparseFreeFixturePath $target

                Backup-StagedTestDriver $backup
                if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Durable restoration backup mismatch.'
                }
                $driverReplaced = $true
                Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
                    throw 'Feature driver install hash mismatch.'
                }
                Invoke-FeatureFilterLoad
                $filterLoaded = $true

                $mappingRecords['Fixture'] = New-MappedFixture $target ('Local\SafeUpload-Admission-' + $id) $false $false $fileHandles $mappings $views
                Write-Output 'FilterAttachedBeforeMapping=True;NoAgentOrPolicyPushedAtMapping=True'

                $clear = Invoke-InspectorChecked -Arguments @('--admission-trace-clear') -Timeout $InspectorTimeoutSeconds
                $enable = Invoke-InspectorChecked -Arguments @('--admission-trace-enable') -Timeout $InspectorTimeoutSeconds
                $traceEnabled = $true
                Write-Output 'AdmissionTrace=ClearedAndEnabled'

                $baseLog = Join-Path $documents ('admission-agent-baseline-' + $id)
                [void]$agentLogs.Add($baseLog + '-out.log')
                [void]$agentLogs.Add($baseLog + '-err.log')
                $agent = Start-TestAgentAndWaitForPolicy $baseLog
                Write-Output 'BaselinePolicyAcceptedByRealAgentAndDriver=True'
                Stop-StagedTestAgent $agent
                $agent = $null

                $expandedPolicy = New-ExpandedPolicyForFixture $fixtureDirectory $policyBackup
                $policyBytes = $expandedPolicy.OriginalBytes
                [IO.File]::WriteAllBytes($policyPath, $expandedPolicy.UpdatedBytes)
                Write-Output ('ExpandedPolicySHA256=' + (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash)
                Write-Output 'ExpandedPolicyIncludesFixture=True'

                $expandedLog = Join-Path $documents ('admission-agent-expanded-' + $id)
                [void]$agentLogs.Add($expandedLog + '-out.log')
                [void]$agentLogs.Add($expandedLog + '-err.log')
                $agent = Start-TestAgentAndWaitForPolicy $expandedLog
                Write-Output 'ExpandedPolicyAcceptedByRealAgentAndDriver=True'

                $markers['Fixture'] = 'MAPPED AFTER POLICY CHANGE ' + $id
                $mappedExpected['Fixture'] = New-PaddedFixtureBytes ([Text.Encoding]::UTF8.GetBytes($markers['Fixture']))
                $write = Invoke-MappedWrite $mappingRecords['Fixture'].View $markers['Fixture']
                Write-Output ('MappedWrite_Result=' + $write.Result)
                if (-not [string]::IsNullOrEmpty($write.Error)) {
                    Write-Output ('MappedWrite_Error=' + $write.Error)
                }

                Stop-StagedTestAgent $agent
                $agent = $null

                $r1 = Get-ObserverReadResult $observers['Fixture'] 'R1' $originals['Fixture'] $mappedExpected['Fixture']
                $r2 = Get-ObserverReadResult $observers['Fixture'] 'R2' $originals['Fixture'] $mappedExpected['Fixture']
                $r3 = Read-FreshBufferedObservation $target $originals['Fixture'] $mappedExpected['Fixture']
                Write-ReaderFacts 'R1' $r1
                Write-ReaderFacts 'R2' $r2
                Write-ReaderFacts 'R3' $r3
                [void](Invoke-AdmissionProbe $target 'Fixture' $InspectorTimeoutSeconds)
            }

            $disable = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $InspectorTimeoutSeconds
            $traceEnabled = $false
            $traceResult = Invoke-InspectorChecked -Arguments @('--admission-trace') -Timeout $InspectorTimeoutSeconds
            $trace = Get-TraceDump $traceResult $rawTrace
            Write-TraceFacts $trace
            $fence = Invoke-InspectorChecked -Arguments @('--admission-fence-status') -Timeout $InspectorTimeoutSeconds
            Write-Output ('FenceStatus=' + ([regex]::Replace([string]$fence.Stdout, '[\r\n]+', ' ')).Trim())
            $probes = @(Get-TraceProbeEntries $trace)
            Write-ProbeFacts $probes @('Fixture')
            $runSucceeded = $true
        }
    }
    catch {
        $runSucceeded = $false
        Write-Output ('RunError=' + (Get-ErrorText $_))
        if ($filterLoaded) {
            foreach ($command in @('--writer-state-status','--admission-fence-status','--admission-volume-status')) {
                try {
                    $diagnostic = Invoke-InspectorChecked -Arguments @($command) -Timeout $InspectorTimeoutSeconds
                    Write-Output ('RunErrorDiagnostic_' + $command + '=' + ([string]$diagnostic.Stdout).Trim())
                } catch { Write-Output ('RunErrorDiagnosticFailed_' + $command + '=' + (Get-ErrorText $_)) }
            }
        }
    }
    finally {
        if ($null -ne $agent) {
            try {
                Stop-StagedTestAgent $agent
                $agent = $null
            }
            catch {
                [void]$restorationErrors.Add('Agent stop: ' + (Get-ErrorText $_))
            }
        }

        Dispose-ObserverResources $views $mappings $fileHandles $uncachedReaders $restorationErrors

        if ($traceEnabled -and -not $script:InspectorTimedOut -and
            -not $script:InspectorFailed -and
            (@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count -eq 0)) {
            try {
                $disableResult = Invoke-InspectorChecked -Arguments @('--admission-trace-disable') -Timeout $InspectorTimeoutSeconds
                $traceEnabled = $false
            }
            catch {
                [void]$restorationErrors.Add('Admission trace disable: ' + (Get-ErrorText $_))
            }
        }

        if ($null -ne $policyBytes) {
            try {
                $restoreBytes = $policyBytes
                if (Test-Path -LiteralPath $policyBackup) {
                    $restoreBytes = [IO.File]::ReadAllBytes($policyBackup)
                }
                [IO.File]::WriteAllBytes($policyPath, $restoreBytes)
            }
            catch {
                [void]$restorationErrors.Add('Policy restore: ' + (Get-ErrorText $_))
            }
        }

        if ($driverReplaced) {
            try {
                Restore-StagedTestDriver $backup $filterLoaded $verifierEnabled
                $filterLoaded = $false
            }
            catch {
                [void]$restorationErrors.Add('Driver restore: ' + (Get-ErrorText $_))
                foreach ($command in @('--writer-state-status','--admission-fence-status')) {
                    try {
                        $diagnostic = Invoke-InspectorChecked -Arguments @($command) -Timeout 15
                        Write-Output ('UnloadRefusalDiagnostic_' + $command + '=' + ([string]$diagnostic.Stdout).Trim())
                    } catch { Write-Output ('UnloadRefusalDiagnosticFailed_' + $command + '=' + (Get-ErrorText $_)) }
                }
            }
        }

        $driverRestored = $false
        $policyRestored = $false
        $filterUnloaded = $false
        $verifierOff = $false
        $serviceRestored = $false
        $agentProcessesZero = $false
        $inspectorProcessesZero = $false
        $tasksZero = $false
        try {
            $driverRestored = (Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -eq $expectedOriginalDriver
        }
        catch {
            [void]$restorationErrors.Add('Original driver verification: ' + (Get-ErrorText $_))
        }
        try {
            $policyRestored = (Get-FileHash -LiteralPath $policyPath -Algorithm SHA256).Hash -eq $expectedOriginalPolicy
        }
        catch {
            [void]$restorationErrors.Add('Original policy verification: ' + (Get-ErrorText $_))
        }
        try {
            $filterUnloaded = -not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s')
        }
        catch {
            [void]$restorationErrors.Add('Filter verification: ' + (Get-ErrorText $_))
        }
        try {
            $query = & verifier.exe /query 2>&1 | Out-String
            $settings = & verifier.exe /querysettings 2>&1 | Out-String
            $memory = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            $verifierOff = ($query -match 'No drivers are currently verified' -and
                $settings -match 'Verifier Flags:\s+0x00000000' -and
                -not $memory.VerifyDriverLevel -and -not $memory.VerifyDrivers)
        }
        catch {
            [void]$restorationErrors.Add('Verifier verification: ' + (Get-ErrorText $_))
        }
        try {
            $service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
            $serviceRestored = ($service.StartMode -eq 'Manual' -and $service.State -eq 'Stopped')
        }
        catch {
            [void]$restorationErrors.Add('Service verification: ' + (Get-ErrorText $_))
        }

        $agentProcessCount = @(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count
        $inspectorProcessCount = @(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count
        $taskCount = @(Get-ScheduledTask | Where-Object {
            $_.TaskName -match '^SafeUpload-(StagedTest-|StagedCleanup-|Owned-)'
        }).Count
        $agentProcessesZero = $agentProcessCount -eq 0
        $inspectorProcessesZero = $inspectorProcessCount -eq 0
        $tasksZero = $taskCount -eq 0

        $coreRestored = ($driverRestored -and $policyRestored -and $filterUnloaded -and
            $verifierOff -and $serviceRestored -and $agentProcessesZero -and
            $inspectorProcessesZero -and $tasksZero)

        if ($coreRestored) {
            if ($fixtureCreated -and (Test-Path -LiteralPath $fixtureDirectory)) {
                try {
                    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
                }
                catch {
                    [void]$restorationErrors.Add('Fixture cleanup: ' + (Get-ErrorText $_))
                }
            }
            if (Test-Path -LiteralPath $backup) {
                try {
                    Remove-Item -LiteralPath $backup -Force
                }
                catch {
                    [void]$restorationErrors.Add('Driver backup cleanup: ' + (Get-ErrorText $_))
                }
            }
            if (Test-Path -LiteralPath $policyBackup) {
                try {
                    Remove-Item -LiteralPath $policyBackup -Force
                }
                catch {
                    [void]$restorationErrors.Add('Policy backup cleanup: ' + (Get-ErrorText $_))
                }
            }
            foreach ($logPath in $agentLogs) {
                if (Test-Path -LiteralPath $logPath) {
                    try {
                        Remove-Item -LiteralPath $logPath -Force
                    }
                    catch {
                        [void]$restorationErrors.Add('Agent log cleanup: ' + (Get-ErrorText $_))
                    }
                }
            }
            if ($inspectorCopyCreated -and (Test-Path -LiteralPath $inspectorPath) -and
                @(Get-Process SafeUpload-admission-inspector -ErrorAction SilentlyContinue).Count -eq 0) {
                try {
                    Remove-Item -LiteralPath $inspectorPath -Force
                }
                catch {
                    [void]$restorationErrors.Add('Inspector copy cleanup: ' + (Get-ErrorText $_))
                }
            }
        }

        $fixtureRemoved = -not (Test-Path -LiteralPath $fixtureDirectory)
        $backupRemoved = (-not (Test-Path -LiteralPath $backup)) -and
            (-not (Test-Path -LiteralPath $policyBackup))
        $agentLogsRemoved = $true
        foreach ($logPath in $agentLogs) {
            if (Test-Path -LiteralPath $logPath) {
                $agentLogsRemoved = $false
            }
        }
        $inspectorCopyRemoved = (-not $inspectorCopyCreated) -or
            (-not (Test-Path -LiteralPath $inspectorPath))
        $restorationVerified = ($coreRestored -and $fixtureRemoved -and $backupRemoved -and
            $agentLogsRemoved -and $inspectorCopyRemoved -and $restorationErrors.Count -eq 0)

        Write-Output ('Restoration_OriginalDriver=' + $driverRestored)
        Write-Output ('Restoration_OriginalPolicy=' + $policyRestored)
        Write-Output ('Restoration_FilterUnloaded=' + $filterUnloaded)
        Write-Output ('Restoration_VerifierOff=' + $verifierOff)
        Write-Output ('Restoration_ServiceManualStopped=' + $serviceRestored)
        Write-Output ('Restoration_AgentProcesses=' + $agentProcessCount)
        Write-Output ('Restoration_InspectorProcesses=' + $inspectorProcessCount)
        Write-Output ('Restoration_Tasks=' + $taskCount)
        Write-Output ('Restoration_FixtureRemoved=' + $fixtureRemoved)
        Write-Output ('Restoration_BackupsRemoved=' + $backupRemoved)
        Write-Output ('Restoration_AgentLogsRemoved=' + $agentLogsRemoved)
        Write-Output ('Restoration_InspectorCopyRemoved=' + $inspectorCopyRemoved)
        if ($script:InspectorTimedOut) {
            Write-Output ('InspectorTimeout=' + $script:InspectorTimeoutCommand)
        }
        foreach ($errorText in $restorationErrors) {
            Write-Output ('RestorationError=' + $errorText)
        }
        Write-Output ('RestorationSucceeded=' + $restorationVerified)
        if ($restorationVerified -and $runSucceeded) {
            Write-Output ('VariantComplete=' + $SelectedVariant)
        }

        $script:LastRestorationVerified = $restorationVerified
        $script:LastRunSucceeded = $runSucceeded
    }
}

$variantsToRun = @()
if ($Variant -eq 'All') {
    $variantsToRun = @('preattach-immediate', 'preattach-protected-open', 'mmdoes-matrix', 'policy-transition')
}
else {
    $variantsToRun = @($Variant)
}

$overallSucceeded = $true
try {
    foreach ($selected in $variantsToRun) {
        Invoke-Variant $selected
        if (-not $script:LastRestorationVerified) {
            $overallSucceeded = $false
            break
        }
        if (-not $script:LastRunSucceeded) {
            $overallSucceeded = $false
            if ($script:InspectorTimedOut) {
                break
            }
        }
    }
}
catch {
    Write-Output ('HarnessError=' + (Get-ErrorText $_))
    $overallSucceeded = $false
}

if ($overallSucceeded) {
    exit 0
}
exit 1
