param([string] $ObserverRequestBase64)

# This file is dot-sourced by the mapping harness and launched directly in a
# fresh powershell.exe for every post-write observation. It contains no test
# driver, policy, service, or fixture mutation path.

function Invoke-StagedMappingByteObserver {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $HelperPath,
        [Parameter(Mandatory = $true)][string] $ExpectedHelperSha256,
        [Parameter(Mandatory = $true)][string] $TargetPath,
        [Parameter(Mandatory = $true)][byte[]] $BaselineBytes,
        [Parameter(Mandatory = $true)][long] $ExpectedLcn,
        [Parameter(Mandatory = $true)][int] $ClusterSize,
        [string] $VolumePath = '\\.\C:',
        [switch] $ReadBuffered,
        [switch] $ReadUncached,
        [ValidateRange(0, 60)][int] $RawSamples = 0,
        [ValidateRange(0, 5000)][int] $RawSampleDelayMilliseconds = 500
    )

    $stdoutPath = $null
    $stderrPath = $null
    $startedProcess = $null
    try {
        $expectedHash = $ExpectedHelperSha256.ToUpperInvariant()
        if ($expectedHash -notmatch '^[0-9A-F]{64}$') { throw 'Observer helper hash pin is malformed.' }
        $expectedDocuments = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'Documents'))
        $helperFullPath = [IO.Path]::GetFullPath($HelperPath)
        if (-not [string]::Equals([IO.Path]::GetDirectoryName($helperFullPath), $expectedDocuments,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Observer helper must be a direct child of the canonical Documents folder.'
        }
        $helperItem = Get-Item -LiteralPath $helperFullPath -Force -ErrorAction Stop
        if ($helperItem.PSIsContainer -or
            (($helperItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            ([IO.Path]::GetFullPath($helperItem.FullName) -ine $helperFullPath)) {
            throw 'Observer helper must be a regular, non-reparse file.'
        }
        $actualHash = (Get-FileHash -LiteralPath $helperFullPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actualHash -cne $expectedHash) { throw 'Observer helper SHA-256 mismatch.' }
        if ($BaselineBytes.Length -ne 4096 -or $ClusterSize -lt 4096 -or ($ClusterSize % 4096) -ne 0) {
            throw 'Observer requires a complete 4096-byte fixture and supported NTFS cluster size.'
        }
        if ($ExpectedLcn -lt 0) { throw 'Expected first LCN is invalid.' }

        $requestId = [guid]::NewGuid().ToString('N')
        $request = [ordered]@{
            Protocol = 'SafeUploadMappingObserverV1'
            RequestId = $requestId
            ParentProcessId = $PID
            HelperSha256 = $expectedHash
            TargetPath = [IO.Path]::GetFullPath($TargetPath)
            VolumePath = $VolumePath
            BaselineBase64 = [Convert]::ToBase64String($BaselineBytes)
            ExpectedLcn = $ExpectedLcn
            ClusterSize = $ClusterSize
            ReadBuffered = [bool]$ReadBuffered
            ReadUncached = [bool]$ReadUncached
            RawSamples = $RawSamples
            RawSampleDelayMilliseconds = $RawSampleDelayMilliseconds
        }
        $requestBytes = [Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Compress -Depth 5))
        $requestBase64 = [Convert]::ToBase64String($requestBytes)
        $tempDirectory = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $stdoutPath = Join-Path $tempDirectory ('safeupload-observer-' + $requestId + '.stdout.txt')
        $stderrPath = Join-Path $tempDirectory ('safeupload-observer-' + $requestId + '.stderr.txt')
        $powershellPath = Join-Path $PSHOME 'powershell.exe'
        $argumentLine = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
            $helperFullPath + '" -ObserverRequestBase64 ' + $requestBase64
        $startedProcess = Start-Process -FilePath $powershellPath -ArgumentList $argumentLine -WorkingDirectory $expectedDocuments `
            -PassThru -Wait -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -ErrorAction Stop
        $stdout = if (Test-Path -LiteralPath $stdoutPath) { [IO.File]::ReadAllText($stdoutPath) } else { '' }
        $stderr = if (Test-Path -LiteralPath $stderrPath) { [IO.File]::ReadAllText($stderrPath) } else { '' }
        $lines = @($stdout -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($startedProcess.ExitCode -ne 0) { throw "Observer child exited with code $($startedProcess.ExitCode): $stderr $stdout" }
        if (-not [string]::IsNullOrEmpty($stderr)) { throw 'Observer child wrote to stderr.' }
        if ($lines.Count -ne 1 -or -not $lines[0].StartsWith('SAFEUPLOAD_MAPPING_OBSERVER_V1:', [StringComparison]::Ordinal)) {
            throw 'Observer child did not return exactly one versioned result record.'
        }
        $payloadBase64 = $lines[0].Substring('SAFEUPLOAD_MAPPING_OBSERVER_V1:'.Length)
        $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payloadBase64))
        $result = ConvertFrom-Json -InputObject $payload -ErrorAction Stop
        if ($result.Protocol -cne 'SafeUploadMappingObserverV1' -or
            $result.RequestId -cne $requestId -or
            [int]$result.ParentProcessId -ne $PID -or
            [int]$result.ChildProcessId -ne [int]$startedProcess.Id -or
            $result.HelperSha256 -ine $expectedHash -or
            [IO.Path]::GetFullPath([string]$result.TargetPath) -ine [IO.Path]::GetFullPath($TargetPath)) {
            throw 'Observer child identity, request, helper pin, or target-path receipt mismatch.'
        }
        if (-not [string]::IsNullOrEmpty([string]$result.FatalError)) {
            throw ('Observer child failed before producing measurements: ' + [string]$result.FatalError)
        }
        return [pscustomobject]@{
            TransportSucceeded = $true
            ChildProcessId = [int]$startedProcess.Id
            RequestId = $requestId
            HelperSha256 = $actualHash
            Result = $result
            Error = ''
        }
    }
    catch {
        return [pscustomobject]@{
            TransportSucceeded = $false
            ChildProcessId = if ($null -eq $startedProcess) { 0 } else { [int]$startedProcess.Id }
            RequestId = if ($null -eq $requestId) { '' } else { $requestId }
            HelperSha256 = if ($null -eq $actualHash) { '' } else { $actualHash }
            Result = $null
            Error = $_.Exception.Message
        }
    }
    finally {
        foreach ($temporaryPath in @($stdoutPath, $stderrPath)) {
            if ($temporaryPath -and (Test-Path -LiteralPath $temporaryPath)) {
                try { Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop }
                catch { Write-Warning ('Observer temporary output retained: ' + $temporaryPath + '; ' + $_.Exception.Message) }
            }
        }
    }
}

function ConvertFrom-StagedObserverByteRead {
    param($ObserverTransport, $ReadRecord, [byte[]] $BaselineBytes)
    if (-not $ObserverTransport.TransportSucceeded -or $null -eq $ReadRecord -or -not $ReadRecord.Succeeded) {
        $errorText = if ($null -eq $ReadRecord) { $ObserverTransport.Error } else { $ReadRecord.Error }
        return [pscustomobject]@{ Succeeded = $false; Bytes = $null; Error = [string]$errorText; State = 'UNOBSERVABLE' }
    }
    try {
        $bytes = [Convert]::FromBase64String([string]$ReadRecord.BytesBase64)
        if ($bytes.Length -ne $BaselineBytes.Length) { throw 'Observer byte record has the wrong full-fixture length.' }
        $differentBytes = 0
        $firstDifferentOffset = -1
        for ($index = 0; $index -lt $BaselineBytes.Length; $index++) {
            if ($bytes[$index] -ne $BaselineBytes[$index]) {
                $differentBytes++
                if ($firstDifferentOffset -lt 0) { $firstDifferentOffset = $index }
            }
        }
        return [pscustomobject]@{
            Succeeded = $true
            Bytes = $bytes
            Error = ''
            State = if ($differentBytes -eq 0) { 'IDENTICAL_TO_BASELINE' } else { 'UNEXPECTED_BYTES_CHANGED' }
            DifferentBytes = $differentBytes
            FirstDifferentOffset = $firstDifferentOffset
        }
    }
    catch {
        return [pscustomobject]@{ Succeeded = $false; Bytes = $null; Error = $_.Exception.Message; State = 'UNOBSERVABLE' }
    }
}

function ConvertFrom-StagedObserverRawRead {
    param($ObserverTransport, [byte[]] $BaselineBytes, [int] $RequestedSamples)
    if (-not $ObserverTransport.TransportSucceeded -or $null -eq $ObserverTransport.Result -or $null -eq $ObserverTransport.Result.Raw) {
        return [pscustomobject]@{ Succeeded = $false; Comparison = $null; Samples = 0; LcnStable = $false; Error = [string]$ObserverTransport.Error }
    }
    $raw = $ObserverTransport.Result.Raw
    if (-not $raw.LcnStable) {
        return [pscustomobject]@{ Succeeded = $false; Comparison = $null; Samples = [int]$raw.SuccessfulSamples; LcnStable = $false; Error = [string]$raw.Error }
    }
    $bytesBase64 = if ($raw.State -eq 'UNEXPECTED_BYTES_CHANGED') { $raw.FirstDifferentBytesBase64 } else { $raw.LastBytesBase64 }
    if ([string]::IsNullOrEmpty([string]$bytesBase64)) {
        return [pscustomobject]@{ Succeeded = $false; Comparison = $null; Samples = [int]$raw.SuccessfulSamples; LcnStable = [bool]$raw.LcnStable; Error = [string]$raw.Error }
    }
    try {
        $bytes = [Convert]::FromBase64String([string]$bytesBase64)
        if ($bytes.Length -ne $BaselineBytes.Length) { throw 'Raw observer record has the wrong full-fixture length.' }
        $differentBytes = 0
        $firstDifferentOffset = -1
        for ($index = 0; $index -lt $BaselineBytes.Length; $index++) {
            if ($bytes[$index] -ne $BaselineBytes[$index]) {
                $differentBytes++
                if ($firstDifferentOffset -lt 0) { $firstDifferentOffset = $index }
            }
        }
        $state = if ($differentBytes -eq 0) { 'IDENTICAL_TO_BASELINE' } else { 'UNEXPECTED_BYTES_CHANGED' }
        $comparison = [pscustomobject]@{
            State = $state
            ByteCount = $BaselineBytes.Length
            DifferentBytes = $differentBytes
            FirstDifferentOffset = $firstDifferentOffset
        }
        $complete = [int]$raw.SuccessfulSamples -eq $RequestedSamples -and
            $raw.State -eq 'IDENTICAL_TO_BASELINE' -and $state -eq 'IDENTICAL_TO_BASELINE' -and -not $raw.Error
        return [pscustomobject]@{
            Succeeded = [bool]($complete -or $state -eq 'UNEXPECTED_BYTES_CHANGED')
            Comparison = $comparison
            Samples = [int]$raw.SuccessfulSamples
            LcnStable = [bool]$raw.LcnStable
            Error = [string]$raw.Error
        }
    }
    catch {
        return [pscustomobject]@{ Succeeded = $false; Comparison = $null; Samples = [int]$raw.SuccessfulSamples; LcnStable = [bool]$raw.LcnStable; Error = $_.Exception.Message }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ObserverRequestBase64)) {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $result = [ordered]@{
        Protocol = 'SafeUploadMappingObserverV1'
        RequestId = ''
        ParentProcessId = 0
        ChildProcessId = $PID
        HelperSha256 = ''
        TargetPath = ''
        Buffered = $null
        Uncached = $null
        Raw = $null
        FatalError = ''
    }
    try {
        $requestJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ObserverRequestBase64))
        $request = ConvertFrom-Json -InputObject $requestJson -ErrorAction Stop
        if ($request.Protocol -cne 'SafeUploadMappingObserverV1' -or
            [string]::IsNullOrWhiteSpace([string]$request.RequestId) -or
            [string]::IsNullOrWhiteSpace([string]$request.TargetPath)) {
            throw 'Observer request protocol, request ID, or target path is invalid.'
        }
        $result.RequestId = [string]$request.RequestId
        $result.ParentProcessId = [int]$request.ParentProcessId
        $result.HelperSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToUpperInvariant()
        $result.TargetPath = [IO.Path]::GetFullPath([string]$request.TargetPath)
        if ($result.ParentProcessId -eq $PID) { throw 'Observer child did not receive a distinct process ID.' }
        if ($result.HelperSha256 -cne ([string]$request.HelperSha256).ToUpperInvariant()) { throw 'Observer child helper pin mismatch.' }
        $volumePath = [string]$request.VolumePath
        if ($volumePath -notmatch '^\\\\\.\\[A-Za-z]:$') { throw 'Observer raw-volume path is not an exact local drive device.' }
        $volumeRoot = $volumePath.Substring(4) + '\'
        if ([IO.Path]::GetPathRoot($result.TargetPath) -ine $volumeRoot) {
            throw 'Observer target path and raw-volume device are on different drive roots.'
        }
        $targetItem = Get-Item -LiteralPath $result.TargetPath -Force -ErrorAction Stop
        if ($targetItem.PSIsContainer -or (($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Observer target is not a regular, non-reparse file.'
        }
        $ancestor = $targetItem
        while ($null -ne $ancestor) {
            if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Observer target path contains a reparse-point ancestor.'
            }
            $parent = [IO.Directory]::GetParent($ancestor.FullName)
            if ($null -eq $parent) { break }
            $ancestor = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
        }
        $baseline = [Convert]::FromBase64String([string]$request.BaselineBase64)
        $clusterSize = [int]$request.ClusterSize
        if ($baseline.Length -ne 4096 -or $clusterSize -lt 4096 -or ($clusterSize % 4096) -ne 0) {
            throw 'Observer request does not describe a 4096-byte fixture and aligned NTFS cluster.'
        }
        if ([long]$targetItem.Length -ne [long]$baseline.Length) {
            throw 'Observer target file length differs from the complete pinned fixture baseline.'
        }

        Add-Type -Namespace SafeUploadMappingObserver -Name Native -MemberDefinition @'
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
public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint method);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
'@
        function Get-ObserverFirstLcn([string] $Path) {
            $handle = [SafeUploadMappingObserver.Native]::CreateFileW($Path, [uint32]128, [uint32]7,
                [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
            if ($handle -eq [IntPtr](-1)) { throw 'extent query open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            $retrievalInput = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
            $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
            try {
                [Runtime.InteropServices.Marshal]::WriteInt64($retrievalInput, 0)
                [uint32]$returned = 0
                if (-not [SafeUploadMappingObserver.Native]::DeviceIoControl($handle, [uint32]0x00090073,
                        $retrievalInput, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
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
                [void][SafeUploadMappingObserver.Native]::CloseHandle($handle)
            }
        }
        function Read-ObserverRawBytes([string]$VolumePath, [long]$Lcn, [int]$ClusterSize, [int]$Length) {
            $handle = [SafeUploadMappingObserver.Native]::CreateFileW($VolumePath, [uint32]2147483648,
                [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
            if ($handle -eq [IntPtr](-1)) { throw 'raw volume open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            $buffer = [SafeUploadMappingObserver.Native]::VirtualAlloc([IntPtr]::Zero,
                [UIntPtr]::new([uint64]$ClusterSize), [uint32]12288, [uint32]4)
            if ($buffer -eq [IntPtr]::Zero) {
                $allocationError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                [void][SafeUploadMappingObserver.Native]::CloseHandle($handle)
                throw 'raw read VirtualAlloc failed: ' + $allocationError
            }
            try {
                [long]$position = 0
                if (-not [SafeUploadMappingObserver.Native]::SetFilePointerEx($handle, $Lcn * $ClusterSize,
                        [ref]$position, 0)) { throw 'raw seek failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
                [uint32]$read = 0
                if (-not [SafeUploadMappingObserver.Native]::ReadFile($handle, $buffer, [uint32]$ClusterSize,
                        [ref]$read, [IntPtr]::Zero) -or $read -ne [uint32]$ClusterSize) {
                    throw 'raw read failed/short: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                }
                $bytes = New-Object byte[] $Length
                [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
                return ,$bytes
            }
            finally {
                [void][SafeUploadMappingObserver.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
                [void][SafeUploadMappingObserver.Native]::CloseHandle($handle)
            }
        }
        function Read-ObserverBufferedBytes([string]$Path, [int]$Length) {
            $stream = $null
            try {
                $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                    [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                $bytes = New-Object byte[] $Length
                $offset = 0
                while ($offset -lt $Length) {
                    $count = $stream.Read($bytes, $offset, $Length - $offset)
                    if ($count -le 0) { throw "short buffered read: $offset/$Length" }
                    $offset += $count
                }
                return [pscustomobject]@{ Succeeded = $true; BytesBase64 = [Convert]::ToBase64String($bytes); Error = '' }
            }
            catch { return [pscustomobject]@{ Succeeded = $false; BytesBase64 = ''; Error = $_.Exception.Message } }
            finally { if ($null -ne $stream) { $stream.Dispose() } }
        }
        function Read-ObserverUncachedBytes([string]$Path, [int]$Length, [int]$ClusterSize) {
            $handle = [SafeUploadMappingObserver.Native]::CreateFileW($Path, [uint32]2147483648, [uint32]7,
                [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
            if ($handle -eq [IntPtr](-1)) {
                return [pscustomobject]@{ Succeeded = $false; BytesBase64 = ''; Error = 'CreateFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
            }
            $buffer = [SafeUploadMappingObserver.Native]::VirtualAlloc([IntPtr]::Zero,
                [UIntPtr]::new([uint64]$ClusterSize), [uint32]12288, [uint32]4)
            if ($buffer -eq [IntPtr]::Zero) {
                $allocationError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                [void][SafeUploadMappingObserver.Native]::CloseHandle($handle)
                return [pscustomobject]@{ Succeeded = $false; BytesBase64 = ''; Error = 'VirtualAlloc error ' + $allocationError }
            }
            try {
                [uint32]$read = 0
                if (-not [SafeUploadMappingObserver.Native]::ReadFile($handle, $buffer, [uint32]$ClusterSize,
                        [ref]$read, [IntPtr]::Zero) -or $read -lt $Length) {
                    return [pscustomobject]@{ Succeeded = $false; BytesBase64 = ''; Error = 'ReadFile error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
                }
                $bytes = New-Object byte[] $Length
                [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, $Length)
                return [pscustomobject]@{ Succeeded = $true; BytesBase64 = [Convert]::ToBase64String($bytes); Error = '' }
            }
            catch { return [pscustomobject]@{ Succeeded = $false; BytesBase64 = ''; Error = $_.Exception.Message } }
            finally {
                [void][SafeUploadMappingObserver.Native]::VirtualFree($buffer, [UIntPtr]::Zero, [uint32]32768)
                [void][SafeUploadMappingObserver.Native]::CloseHandle($handle)
            }
        }
        function Compare-ObserverBytes([byte[]]$Left, [byte[]]$Right) {
            $different = 0; $first = -1
            for ($i = 0; $i -lt $Left.Length; $i++) {
                if ($Left[$i] -ne $Right[$i]) { $different++; if ($first -lt 0) { $first = $i } }
            }
            return [pscustomobject]@{ DifferentBytes = $different; FirstDifferentOffset = $first }
        }

        $expectedPath = [IO.Path]::GetFullPath([string]$request.TargetPath)
        if ([long]$request.ExpectedLcn -lt 0) { throw 'Observer expected LCN is invalid.' }
        $length = $baseline.Length
        if ([bool]$request.ReadBuffered) { $result.Buffered = Read-ObserverBufferedBytes $expectedPath $length }
        if ([bool]$request.ReadUncached) { $result.Uncached = Read-ObserverUncachedBytes $expectedPath $length $clusterSize }
        $rawSamples = [int]$request.RawSamples
        if ($rawSamples -lt 0 -or $rawSamples -gt 60) { throw 'Observer raw sample count is outside its bound.' }
        if ($rawSamples -gt 0) {
            $raw = [ordered]@{
                State = 'UNOBSERVABLE'
                RequestedSamples = $rawSamples
                SuccessfulSamples = 0
                LcnStable = $true
                LastBytesBase64 = ''
                FirstDifferentBytesBase64 = ''
                DifferentBytes = 0
                FirstDifferentOffset = -1
                Error = ''
            }
            try {
                $preflightLcn = Get-ObserverFirstLcn $expectedPath
                if ($preflightLcn -ne [long]$request.ExpectedLcn) { throw "Fixture LCN changed before raw samples: expected $($request.ExpectedLcn), observed $preflightLcn." }
                for ($sample = 0; $sample -lt $rawSamples; $sample++) {
                    $sampleLcn = Get-ObserverFirstLcn $expectedPath
                    if ($sampleLcn -ne [long]$request.ExpectedLcn) {
                        $raw.LcnStable = $false
                        throw "Fixture LCN changed before raw sample $($sample + 1): expected $($request.ExpectedLcn), observed $sampleLcn."
                    }
                    $bytes = Read-ObserverRawBytes ([string]$request.VolumePath) ([long]$request.ExpectedLcn) $clusterSize $length
                    $raw.SuccessfulSamples++
                    $raw.LastBytesBase64 = [Convert]::ToBase64String($bytes)
                    $difference = Compare-ObserverBytes $bytes $baseline
                    if ($difference.DifferentBytes -gt 0) {
                        $raw.State = 'UNEXPECTED_BYTES_CHANGED'
                        $raw.FirstDifferentBytesBase64 = $raw.LastBytesBase64
                        $raw.DifferentBytes = $difference.DifferentBytes
                        $raw.FirstDifferentOffset = $difference.FirstDifferentOffset
                        break
                    }
                    $raw.State = 'IDENTICAL_TO_BASELINE'
                    if ($sample -lt ($rawSamples - 1) -and [int]$request.RawSampleDelayMilliseconds -gt 0) {
                        Start-Sleep -Milliseconds ([int]$request.RawSampleDelayMilliseconds)
                    }
                }
                if ($raw.State -eq 'IDENTICAL_TO_BASELINE' -and $raw.SuccessfulSamples -ne $rawSamples) {
                    $raw.State = 'INCOMPLETE'
                }
            }
            catch {
                $raw.Error = $_.Exception.Message
                if (-not $raw.LcnStable) { $raw.State = 'INCOMPLETE' }
                elseif ($raw.SuccessfulSamples -ne $rawSamples -and $raw.State -ne 'UNEXPECTED_BYTES_CHANGED') { $raw.State = 'INCOMPLETE' }
            }
            $result.Raw = [pscustomobject]$raw
        }
    }
    catch { $result.FatalError = $_.Exception.Message }
    $json = ConvertTo-Json -InputObject ([pscustomobject]$result) -Compress -Depth 8
    [Console]::Out.WriteLine('SAFEUPLOAD_MAPPING_OBSERVER_V1:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
    exit 0
}
