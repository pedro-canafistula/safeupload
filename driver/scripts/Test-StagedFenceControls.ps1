<# Controls for the mapped-writable stream fence. Run only on the recorded isolated WIN10-DEBUGGED VM from the
   experiment wrapper. Fixtures A-E live under the bootstrap scope (no agent, no policy: the load-time scan applies),
   F lives outside every scope. Observation only; no result is labeled fixed.
     A in scope, writable mapping, file handle closed      expect FENCED (write refused, protected open refused)
     B in scope, READ-ONLY mapping, handle closed          expect not fenced
     C in scope, no mapping                                expect not fenced
     D in scope, writable mapping, file handle still open  expect FENCED
     E in scope, writable handle open before load, mapping created AFTER load through that handle: expect the section refused
     F OUT of scope, writable mapping before load          expect not fenced (no false positive)
   Fence counters are read through the Inspector as SYSTEM (one client; no agent runs). #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)] [string] $ExpectedInspectorSha256,
    [switch] $Verifier
)
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
function Read-UncachedText([string] $Path, [int] $Length) {
    $handle = [SafeUploadRepro.Native]::CreateFileW($Path, [uint32]2147483648, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]2684354560, [IntPtr]::Zero)
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
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-controls-' + $id)
$outsideDirectory = Join-Path $documents ('SafeUpload-fence-controls-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-controls-' + $id + '.sys')
$changed = [Text.Encoding]::UTF8.GetBytes('MAPPED WRITE ' + $id)
$changedText = [Text.Encoding]::UTF8.GetString($changed)
$fixtures = [ordered]@{}
$streams = @(); $mappings = @(); $views = @()
$loaded = $false; $replaced = $false; $scopeCreated = $false; $outsideCreated = $false; $verifierEnabled = $false

function Get-Padded([string] $Text) {
    $bytes = New-Object byte[] 4096
    $source = [Text.Encoding]::UTF8.GetBytes($Text)
    [Array]::Copy($source, $bytes, $source.Length)
    return ,$bytes
}
function New-Fixture([string] $Name, [string] $Directory) {
    $path = Join-Path $Directory ($Name + '.maptest')
    [IO.File]::WriteAllBytes($path, (Get-Padded ('BASELINE ' + $Name + ' ' + $id)))
    $fixtures[$Name] = $path
    return $path
}
function New-View([IO.FileStream] $Stream, [string] $Name, [bool] $ReadOnly) {
    $access = if ($ReadOnly) { [IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read } else { [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite }
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($Stream, ('Local\SafeUpload-FenceControls-' + $Name + '-' + $id),
        [long]4096, $access, [IO.HandleInheritability]::None, $true)
    $script:mappings += $mapping
    $view = $mapping.CreateViewAccessor(0, 4096, $access)
    $script:views += $view
    return $view
}
function Get-FenceStatus([string] $Label) {
    $cmdFile = Join-Path $documents ('fence-controls-' + $id + '.cmd')
    $cmdOut = Join-Path $documents ('fence-controls-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', ('"' + $inspector + '" --admission-fence-status'))
    $taskName = 'SafeUpload-StagedTest-FenceControls-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 60; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        $text = if (Test-Path -LiteralPath $cmdOut) { (Get-Content -LiteralPath $cmdOut -Raw) -replace '\s+', ' ' } else { '(no output)' }
        "FenceStatus_$Label=" + $text.Trim()
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
}
function Try-Write($View) {
    try { $View.WriteArray(0, $changed, 0, $changed.Length); $View.Flush(); return 'SUCCESS' }
    catch { return 'OBSERVED_REFUSED: ' + $_.Exception.Message }
}
function Try-ProtectedOpen([string] $Path) {
    try { $s = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete); $s.Dispose(); return 'OPENED' }
    catch { return 'OBSERVED_REFUSED: ' + (($_.Exception.Message -replace '\s+', ' ').Trim()) }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=fence-controls'
'TestTimestampUTC=' + [DateTime]::UtcNow.ToString('o')
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()

try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    [void][IO.Directory]::CreateDirectory($outsideDirectory); $outsideCreated = $true
    foreach ($name in 'A', 'D') {                                             # writable, in scope
        $path = New-Fixture $name $scopeDirectory
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        [void](New-View $stream $name $false)
        if ($name -eq 'A') { $stream.Dispose() } else { $streams += $stream }  # A: handle closed, D: handle kept open
        if ($name -eq 'A') { $script:viewA = $views[-1] } else { $script:viewD = $views[-1] }
    }
    $path = New-Fixture 'B' $scopeDirectory                                    # read-only mapping
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    [void](New-View $stream 'B' $true); $stream.Dispose()
    [void](New-Fixture 'C' $scopeDirectory)                                    # no mapping
    $pathE = New-Fixture 'E' $scopeDirectory                                   # handle opened now, mapped after load
    $streamE = [IO.FileStream]::new($pathE, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $streams += $streamE
    $pathF = New-Fixture 'F' $outsideDirectory                                 # out of scope, writable mapping
    $streamF = [IO.FileStream]::new($pathF, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $viewF = New-View $streamF 'F' $false; $streamF.Dispose()
    'FixturesPrepared=A,B,C,D,E(handle only),F(out of scope)'

    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B (special pool, IRQL, pool tracking, I/O, deadlock, DDI)'
    }
    & fltmc.exe load SafeUpload | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
    $loaded = $true
    'FilterLoaded=True (load-time scan completed before fltmc returned)'
    Get-FenceStatus 'AfterLoad'

    foreach ($name in 'A', 'B', 'C', 'D') { 'ProtectedOpen_' + $name + '=' + (Try-ProtectedOpen $fixtures[$name]) }
    Get-FenceStatus 'AfterOpens'

    'Write_A=' + (Try-Write $script:viewA)
    'Write_D=' + (Try-Write $script:viewD)
    'Write_F=' + (Try-Write $viewF)
    # E: the mapping is created AFTER the load through the old handle, so no scan has seen it. The writable-section
    # refusal on an unadmitted in-scope stream must stop it at creation (earlier builds let the write through).
    $viewE = $null
    try { $viewE = New-View $streamE 'E' $false; 'MappingCreate_E=SUCCESS' }
    catch { 'MappingCreate_E=OBSERVED_REFUSED: ' + $_.Exception.Message }
    if ($null -ne $viewE) { 'Write_E=' + (Try-Write $viewE) } else { 'Write_E=NOT_ATTEMPTED (no writable view)' }
    Get-FenceStatus 'AfterWrites'

    foreach ($name in 'A', 'D', 'E', 'F') {
        'UncachedRead_' + $name + '=' + (Read-UncachedText $fixtures[$name] $changed.Length)
    }
    'ExpectedMappedText=' + $changedText
}
finally {
    foreach ($view in $views) { try { $view.Dispose() } catch { 'ViewDisposeObserved=' + $_.Exception.Message } }
    foreach ($mapping in $mappings) { try { $mapping.Dispose() } catch { 'MappingDisposeObserved=' + $_.Exception.Message } }
    foreach ($stream in $streams) { try { $stream.Dispose() } catch { 'StreamDisposeObserved=' + $_.Exception.Message } }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force }
    if ($outsideCreated -and (Test-Path -LiteralPath $outsideDirectory)) { Remove-Item -LiteralPath $outsideDirectory -Recurse -Force }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver was not restored.' }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload filter remained loaded.' }
    if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Policy changed.' }
    'ControlsRestoration=OriginalDriverAndPolicyRestored; FilterUnloaded; FixturesRemoved=' + (-not (Test-Path -LiteralPath $scopeDirectory)) + '/' + (-not (Test-Path -LiteralPath $outsideDirectory))
    'VariantComplete=fence-controls'
}
