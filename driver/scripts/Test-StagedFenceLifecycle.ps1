<# Lifecycle of a fenced stream: does the unapproved mapped write ever reach the DISK, and how does the Memory Manager
   behave while writeback is refused? Run only on the recorded isolated WIN10-DEBUGGED VM from the experiment wrapper.
   Timeline (feature driver, bootstrap scope, no agent, optionally under the volatile Verifier):
     1. in-scope fixture, writable mapping, file handle closed; the file's on-disk cluster is recorded BEFORE the load
     2. load (the scan registers the stream), write a marker through the old view, flush (expected refused)
     3. raw on-disk read after the refused flush
     4. dispose the view and mapping, then sample fence counters every 5 s (retry behaviour of the modified writer)
     5. forced refresh through the Inspector (the entry should be pruned: no user-writable reference remains)
     6. wait, raw read again with the driver still loaded and the entry gone
     7. unload (the guard may refuse), wait, flush through a fresh handle, raw read again
   The on-disk bytes are read from the raw volume (unbuffered), so no cache or filter can hide or fake them. #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)] [string] $ExpectedInspectorSha256,
    [switch] $Verifier
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
Add-Type -Namespace SafeUploadLife -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint bytes, out uint read, IntPtr overlapped);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool SetFilePointerEx(IntPtr handle, long distance, out long newPosition, uint method);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FlushFileBuffers(IntPtr handle);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protect);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr input, uint inputSize, IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);
'@
function New-AlignedBuffer([int] $Size) { [SafeUploadLife.Native]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new([uint64]$Size), [uint32]12288, [uint32]4) }
function Free-AlignedBuffer([IntPtr] $Buffer) { [void][SafeUploadLife.Native]::VirtualFree($Buffer, [UIntPtr]::Zero, [uint32]32768) }
# First extent (VCN 0) of a file as an LCN, through FSCTL_GET_RETRIEVAL_POINTERS. Done BEFORE the driver is loaded.
function Get-FirstLcn([string] $Path) {
    $handle = [SafeUploadLife.Native]::CreateFileW($Path, [uint32]128, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { throw 'extent query open failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $input = [Runtime.InteropServices.Marshal]::AllocHGlobal(8); $output = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
    try {
        [Runtime.InteropServices.Marshal]::WriteInt64($input, 0)
        [uint32] $returned = 0
        if (-not [SafeUploadLife.Native]::DeviceIoControl($handle, [uint32]0x00090073, $input, 8, $output, 64, [ref]$returned, [IntPtr]::Zero)) {
            throw 'FSCTL_GET_RETRIEVAL_POINTERS failed: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if ([Runtime.InteropServices.Marshal]::ReadInt32($output, 0) -lt 1) { throw 'No extent (resident file).' }
        return [Runtime.InteropServices.Marshal]::ReadInt64($output, 24)   # Extents[0].Lcn
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($input); [Runtime.InteropServices.Marshal]::FreeHGlobal($output); [void][SafeUploadLife.Native]::CloseHandle($handle) }
}
# Unbuffered read of the first 64 bytes of the recorded cluster straight from the volume.
function Read-Disk([long] $Lcn, [int] $ClusterSize) {
    $handle = [SafeUploadLife.Native]::CreateFileW('\\.\C:', [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]536870912, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return 'RAW_OPEN_FAILED ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $buffer = New-AlignedBuffer 4096
    try {
        [long] $position = 0
        if (-not [SafeUploadLife.Native]::SetFilePointerEx($handle, $Lcn * $ClusterSize, [ref]$position, 0)) { return 'RAW_SEEK_FAILED ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        [uint32] $read = 0
        if (-not [SafeUploadLife.Native]::ReadFile($handle, $buffer, 4096, [ref]$read, [IntPtr]::Zero)) { return 'RAW_READ_FAILED ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
        $bytes = New-Object byte[] 64
        [Runtime.InteropServices.Marshal]::Copy($buffer, $bytes, 0, 64)
        return ([Text.Encoding]::UTF8.GetString($bytes)).Trim([char]0)
    }
    finally { Free-AlignedBuffer $buffer; [void][SafeUploadLife.Native]::CloseHandle($handle) }
}
function Invoke-Inspector([string[]] $Arguments) {
    $cmdFile = Join-Path $documents ('fence-life-' + $id + '.cmd')
    $cmdOut = Join-Path $documents ('fence-life-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value (@('@echo off') + ($Arguments | ForEach-Object { '"' + $inspector + '" ' + $_ }))
    $taskName = 'SafeUpload-StagedTest-FenceLife-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        if (Test-Path -LiteralPath $cmdOut) { return ((Get-Content -LiteralPath $cmdOut -Raw) -replace '\s+', ' ').Trim() } else { return '(no output)' }
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
}
function Get-Counter-Value([string] $Json, [string] $Name) { if ($Json -match ('"' + $Name + '":(\d+)')) { [int64]$Matches[1] } else { -1 } }
function Get-Padded([string] $Text) { $b = New-Object byte[] 4096; $s = [Text.Encoding]::UTF8.GetBytes($Text); [Array]::Copy($s, $b, $s.Length); return ,$b }

$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-life-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-life-' + $id + '.sys')
$path = Join-Path $scopeDirectory 'life.maptest'
$marker = 'MAPPED WRITE ' + $id
$loaded = $false; $replaced = $false; $scopeCreated = $false; $verifierEnabled = $false
$stream = $null; $mapping = $null; $view = $null

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=fence-lifecycle'
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    [IO.File]::WriteAllBytes($path, (Get-Padded ('BASELINE ' + $id)))
    $flushStream = [IO.File]::Open($path, 'Open', 'ReadWrite', 'ReadWrite')
    [void][SafeUploadLife.Native]::FlushFileBuffers($flushStream.SafeFileHandle.DangerousGetHandle())
    $flushStream.Dispose()
    $clusterSize = [int](Get-CimInstance Win32_Volume -Filter "DriveLetter='C:'").BlockSize
    $lcn = Get-FirstLcn $path
    'FixtureCluster: lcn=' + $lcn + ' clusterSize=' + $clusterSize
    'DiskBeforeLoad=' + (Read-Disk $lcn $clusterSize)
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($stream, ('Local\SafeUpload-Life-' + $id), [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $stream.Dispose(); $stream = $null
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
    & fltmc.exe load SafeUpload | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
    $loaded = $true
    'Status_AfterLoad=' + (Invoke-Inspector @('--admission-fence-status'))
    $bytes = [Text.Encoding]::UTF8.GetBytes($marker)
    $write = try { $view.WriteArray(0, $bytes, 0, $bytes.Length); $view.Flush(); 'SUCCESS' } catch { 'REFUSED: ' + $_.Exception.Message }
    'OldViewWriteAndFlush=' + $write
    Start-Sleep -Seconds 3
    'Disk_AfterRefusedFlush=' + (Read-Disk $lcn $clusterSize)
    try { $view.Dispose() } catch { 'ViewDispose=' + $_.Exception.Message }
    try { $mapping.Dispose() } catch { 'MappingDispose=' + $_.Exception.Message }
    $view = $null; $mapping = $null
    '--- no user mapping remains; sampling the modified-writer retry behaviour'
    for ($sample = 1; $sample -le 6; $sample++) {
        Start-Sleep -Seconds 5
        $json = Invoke-Inspector @('--admission-fence-status')
        $modified = try { [math]::Round((Get-Counter '\Memory\Modified Page List Bytes' -ErrorAction Stop).CounterSamples[0].CookedValue / 1KB) } catch { -1 }
        'Sample{0} t+{1}s entries={2} pagingWritesDenied={3} modifiedListKB={4} systemCpuSeconds={5} disk={6}' -f $sample, ($sample * 5),
            (Get-Counter-Value $json 'entries'), (Get-Counter-Value $json 'pagingWritesDenied'), $modified,
            [math]::Round((Get-Process -Id 4).CPU, 1), (Read-Disk $lcn $clusterSize)
    }
    'Refresh=' + (Invoke-Inspector @('--admission-fence-refresh', '--admission-fence-status'))
    for ($sample = 1; $sample -le 4; $sample++) {
        Start-Sleep -Seconds 15
        $json = Invoke-Inspector @('--admission-fence-status')
        'AfterRefresh{0} t+{1}s entries={2} pagingWritesDenied={3} streamsReleased={4} releaseRefused={5} disk={6}' -f $sample, ($sample * 15), (Get-Counter-Value $json 'entries'), (Get-Counter-Value $json 'pagingWritesDenied'), (Get-Counter-Value $json 'streamsReleased'), (Get-Counter-Value $json 'releaseRefused'), (Read-Disk $lcn $clusterSize)
    }
    $unload = (& fltmc.exe unload SafeUpload 2>&1 | Out-String) -replace '\s+', ' '
    'UnloadAttempt exit=' + $LASTEXITCODE + ' output=' + $unload.Trim()
    $loaded = ($LASTEXITCODE -ne 0)
    if (-not $loaded) {
        'Disk_AtUnload=' + (Read-Disk $lcn $clusterSize)
        for ($sample = 1; $sample -le 3; $sample++) { Start-Sleep -Seconds 15; 'AfterUnload{0} t+{1}s disk={2}' -f $sample, ($sample * 15), (Read-Disk $lcn $clusterSize) }
        $fresh = [IO.File]::Open($path, 'Open', 'ReadWrite', 'ReadWrite')
        'CachedViewAfterUnload=' + (([Text.Encoding]::UTF8.GetString((New-Object byte[] 0)) + (New-Object IO.StreamReader($fresh)).ReadToEnd().Substring(0, 40)).Trim([char]0))
        [void][SafeUploadLife.Native]::FlushFileBuffers($fresh.SafeFileHandle.DangerousGetHandle())
        $fresh.Dispose()
        Start-Sleep -Seconds 3
        'Disk_AfterUnloadAndFlush=' + (Read-Disk $lcn $clusterSize)
    }
    'Verdict_UnapprovedBytesReachedDisk=' + ((Read-Disk $lcn $clusterSize) -like ('*' + $marker + '*'))
}
catch {
    'ScriptError=' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')'
}
finally {
    if ($null -ne $view) { try { $view.Dispose() } catch { } }
    if ($null -ne $mapping) { try { $mapping.Dispose() } catch { } }
    if ($null -ne $stream) { $stream.Dispose() }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) { try { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message } }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    'LifecycleRestoration=OriginalDriverRestored; FilterUnloaded=' + (-not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'))
    'VariantComplete=fence-lifecycle'
}
