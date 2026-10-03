param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('preattach-immediate', 'preattach-protected-open', 'mmdoes-matrix', 'policy-transition', 'All')]
    [string] $Variant,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedFeatureSha256,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedInspectorSha256,

    [ValidateRange(1, 600)]
    [int] $InspectorTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
$installedDriver = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginalDriver = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedOriginalPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$expectedServicePackage = 'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997'
$featureDriver = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspectorSource = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$inspectorPath = Join-Path $documents 'SafeUpload-admission-inspector.exe'
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$serviceDirectory = Join-Path $documents 'stage-service-publish'
$policyPath = 'C:\ProgramData\SafeUpload\policy.json'
$mappingLength = 4096

. (Join-Path $documents 'StagedTestAgent.ps1')

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
                Restore-StagedTestDriver $backup $filterLoaded $false
                $filterLoaded = $false
            }
            catch {
                [void]$restorationErrors.Add('Driver restore: ' + (Get-ErrorText $_))
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
