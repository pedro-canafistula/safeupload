<# Physical mutation gates for handles and opens that never pass through an admitted stream. Run only on the recorded isolated
   WIN10-DEBUGGED VM from the experiment wrapper (optionally under the volatile Verifier). No agent and no policy: the bootstrap
   scope \SafeUpload\Escopo Monitorado is always protected. Fixtures are opened BEFORE the feature driver loads, so their file
   objects are unowned, then each mutation is attempted AFTER the load:
     - FSCTLs through the old handle: SET_ZERO_DATA, SET_SPARSE, SET_COMPRESSION, DUPLICATE_EXTENTS_TO_FILE (NTFS may not support it),
       and SET_REPARSE_POINT through an old directory handle;
     - an open with DELETE access and FILE_FLAG_DELETE_ON_CLOSE on a protected file;
     - controls that must stay ALLOWED: the same mutations on a file outside every scope, and non-mutating FSCTLs on the protected file.
   Output per probe: REPRODUCED (the mutation took effect), BLOCKED (denied with ACCESS_DENIED and no effect), UNSUPPORTED (another
   error and no effect: not evidence either way) or ALLOWED (control). #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [switch] $Verifier
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class Gate {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern uint GetFileAttributesW(string name);
}
'@
$GENERIC_RW = [uint32]3221225472; $DELETE = [uint32]65536; $SHARE_ALL = 7; $OPEN_EXISTING = 3        # 0xC0000000 and 0x10000 as unsigned
$FLAG_BACKUP_SEMANTICS = 0x02000000; $FLAG_DELETE_ON_CLOSE = 0x04000000
$FSCTL_SET_ZERO_DATA = 0x980C8; $FSCTL_SET_SPARSE = 0x900C4; $FSCTL_SET_COMPRESSION = 0x9C040; $FSCTL_DUPLICATE_EXTENTS_TO_FILE = 0x98344
$FSCTL_SET_REPARSE_POINT = 0x900A4; $FSCTL_GET_COMPRESSION = 0x9003C; $FSCTL_QUERY_ALLOCATED_RANGES = 0x940CF
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-gates-' + $id)
$outsideDirectory = Join-Path $documents ('SafeUpload-fence-gates-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-gates-' + $id + '.sys')
$loaded = $false; $replaced = $false; $verifierEnabled = $false; $scopeCreated = $false; $outsideCreated = $false
$handles = New-Object System.Collections.ArrayList

function Open-Handle([string] $Path, [uint32] $Access, [uint32] $Flags = 0) {
    $h = [Gate]::CreateFileW($Path, $Access, [uint32]$SHARE_ALL, [IntPtr]::Zero, [uint32]$OPEN_EXISTING, $Flags, [IntPtr]::Zero)
    if ($h -eq [IntPtr](-1)) { throw ('open failed: ' + $Path + ' error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    [void]$handles.Add($h); return $h
}
function Invoke-Fsctl([IntPtr] $Handle, [uint32] $Code, [byte[]] $InBuffer, [switch] $NoOutput) {
    [uint32] $returned = 0
    $out = if ($NoOutput) { $null } else { New-Object byte[] 4096 }
    $outSize = if ($NoOutput) { 0 } else { 4096 }
    $inSize = if ($null -eq $InBuffer) { 0 } else { $InBuffer.Length }
    $ok = [Gate]::DeviceIoControl($Handle, $Code, $InBuffer, [uint32]$inSize, $out, [uint32]$outSize, [ref]$returned, [IntPtr]::Zero)
    $err = if ($ok) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    return [pscustomobject]@{ Ok = $ok; Error = $err }
}
function New-MountPointBuffer([string] $TargetDirectory) {
    $target = [Text.Encoding]::Unicode.GetBytes('\??\' + $TargetDirectory); $print = [Text.Encoding]::Unicode.GetBytes($TargetDirectory)
    $buffer = New-Object byte[] (8 + 8 + $target.Length + 2 + $print.Length + 2)
    [BitConverter]::GetBytes([uint32]2684354563).CopyTo($buffer, 0)      # IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
    [BitConverter]::GetBytes([uint16]($buffer.Length - 8)).CopyTo($buffer, 4)
    [BitConverter]::GetBytes([uint16]0).CopyTo($buffer, 8); [BitConverter]::GetBytes([uint16]$target.Length).CopyTo($buffer, 10)
    [BitConverter]::GetBytes([uint16]($target.Length + 2)).CopyTo($buffer, 12); [BitConverter]::GetBytes([uint16]$print.Length).CopyTo($buffer, 14)
    $target.CopyTo($buffer, 16); $print.CopyTo($buffer, 16 + $target.Length + 2)
    return ,$buffer
}
function Get-Attributes([string] $Path) { [Gate]::GetFileAttributesW($Path) }
function Classify($Result, [bool] $Effect) {
    if ($Result.Ok -and $Effect) { return 'REPRODUCED' }
    if ($Result.Ok) { return 'ALLOWED_NO_EFFECT' }
    if ($Result.Error -eq 5) { return 'BLOCKED' }
    return 'UNSUPPORTED(err=' + $Result.Error + ')'
}
function Read-Head([string] $Path) { $s = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite'); try { $b = New-Object byte[] 16; [void]$s.Read($b, 0, 16); return [Text.Encoding]::ASCII.GetString($b).Trim([char]0) } finally { $s.Dispose() } }

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
'Variant=mutation-gates'
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    [void][IO.Directory]::CreateDirectory($outsideDirectory); $outsideCreated = $true
    $payload = New-Object byte[] 8192; [Text.Encoding]::ASCII.GetBytes('BASELINE-DATA').CopyTo($payload, 0)
    $paths = @{}
    foreach ($name in 'zero', 'sparse', 'compress', 'dup', 'doc', 'docOutside', 'control') {
        $dir = if ($name -in 'docOutside') { $outsideDirectory } else { $scopeDirectory }
        $p = Join-Path $dir ($name + '.bin'); [IO.File]::WriteAllBytes($p, $payload); $paths[$name] = $p
    }
    $outsidePath = Join-Path $outsideDirectory 'outside.bin'; [IO.File]::WriteAllBytes($outsidePath, $payload)
    $dirProtected = Join-Path $scopeDirectory 'reparse-dir'; [void][IO.Directory]::CreateDirectory($dirProtected)
    $dirTarget = Join-Path $scopeDirectory 'reparse-target'; [void][IO.Directory]::CreateDirectory($dirTarget)
    [void][IO.Directory]::CreateDirectory((Join-Path $scopeDirectory 'doc-dir')); [void][IO.Directory]::CreateDirectory((Join-Path $outsideDirectory 'doc-dir'))
    $dirOutside = Join-Path $outsideDirectory 'reparse-dir'; [void][IO.Directory]::CreateDirectory($dirOutside)
    $dirOutsideTarget = Join-Path $outsideDirectory 'reparse-target'; [void][IO.Directory]::CreateDirectory($dirOutsideTarget)
    # Old handles, opened BEFORE the driver loads: their file objects are never admitted.
    $hZero = Open-Handle $paths['zero'] $GENERIC_RW
    $hSparse = Open-Handle $paths['sparse'] $GENERIC_RW
    $hCompress = Open-Handle $paths['compress'] $GENERIC_RW
    $hDup = Open-Handle $paths['dup'] $GENERIC_RW
    $hControl = Open-Handle $paths['control'] $GENERIC_RW
    $hOutside = Open-Handle $outsidePath $GENERIC_RW
    $hDir = Open-Handle $dirProtected $GENERIC_RW ([uint32]$FLAG_BACKUP_SEMANTICS)
    $hDirOutside = Open-Handle $dirOutside $GENERIC_RW ([uint32]$FLAG_BACKUP_SEMANTICS)
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

    # --- mutations through the old handles
    $zeroData = New-Object byte[] 16; [BitConverter]::GetBytes([int64]0).CopyTo($zeroData, 0); [BitConverter]::GetBytes([int64]4096).CopyTo($zeroData, 8)
    $r = Invoke-Fsctl $hZero $FSCTL_SET_ZERO_DATA $zeroData
    'Gate_SetZeroData=' + (Classify $r ((Read-Head $paths['zero']) -ne 'BASELINE-DATA')) + ' head=' + (Read-Head $paths['zero'])
    $r = Invoke-Fsctl $hSparse $FSCTL_SET_SPARSE ([byte[]]@(1))
    'Gate_SetSparse=' + (Classify $r (([Gate]::GetFileAttributesW($paths['sparse']) -band 0x200) -ne 0))
    $r = Invoke-Fsctl $hCompress $FSCTL_SET_COMPRESSION ([BitConverter]::GetBytes([uint16]1))
    'Gate_SetCompression=' + (Classify $r (([Gate]::GetFileAttributesW($paths['compress']) -band 0x800) -ne 0))
    $dup = New-Object byte[] 32; [BitConverter]::GetBytes([int64]$hDup).CopyTo($dup, 0); [BitConverter]::GetBytes([int64]0).CopyTo($dup, 8); [BitConverter]::GetBytes([int64]4096).CopyTo($dup, 16); [BitConverter]::GetBytes([int64]4096).CopyTo($dup, 24)
    $r = Invoke-Fsctl $hDup $FSCTL_DUPLICATE_EXTENTS_TO_FILE $dup
    'Gate_DuplicateExtents=' + (Classify $r $false) + ' (NTFS may not support this FSCTL; BLOCKED means the gate engaged)'
    $reparse = New-MountPointBuffer $dirTarget
    $r = Invoke-Fsctl $hDir $FSCTL_SET_REPARSE_POINT $reparse -NoOutput
    'Gate_SetReparsePoint=' + (Classify $r (([Gate]::GetFileAttributesW($dirProtected) -band 0x400) -ne 0))

    # --- delete on close
    $docHandle = [Gate]::CreateFileW($paths['doc'], [uint32]$DELETE, [uint32]$SHARE_ALL, [IntPtr]::Zero, [uint32]$OPEN_EXISTING, [uint32]$FLAG_DELETE_ON_CLOSE, [IntPtr]::Zero)
    $docError = if ($docHandle -eq [IntPtr](-1)) { [Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }
    if ($docHandle -ne [IntPtr](-1)) { [void][Gate]::CloseHandle($docHandle) }
    Start-Sleep -Milliseconds 300
    $docGone = -not (Test-Path -LiteralPath $paths['doc'])
    'Gate_DeleteOnClose=' + $(if ($docHandle -ne [IntPtr](-1) -and $docGone) { 'REPRODUCED' } elseif ($docHandle -eq [IntPtr](-1) -and $docError -eq 5) { 'BLOCKED' } else { 'UNSUPPORTED(open err=' + $docError + ', gone=' + $docGone + ')' })

    # --- directory delete on close (a protected, empty directory)
    $dirDoc = Join-Path $scopeDirectory 'doc-dir'
    $docDirHandle = [Gate]::CreateFileW($dirDoc, [uint32]$DELETE, [uint32]$SHARE_ALL, [IntPtr]::Zero, [uint32]$OPEN_EXISTING, [uint32]($FLAG_BACKUP_SEMANTICS -bor $FLAG_DELETE_ON_CLOSE), [IntPtr]::Zero)
    $docDirError = if ($docDirHandle -eq [IntPtr](-1)) { [Runtime.InteropServices.Marshal]::GetLastWin32Error() } else { 0 }
    if ($docDirHandle -ne [IntPtr](-1)) { [void][Gate]::CloseHandle($docDirHandle) }
    Start-Sleep -Milliseconds 300
    $docDirGone = -not (Test-Path -LiteralPath $dirDoc)
    'Gate_DirectoryDeleteOnClose=' + $(if ($docDirHandle -ne [IntPtr](-1) -and $docDirGone) { 'REPRODUCED' } elseif ($docDirHandle -eq [IntPtr](-1) -and $docDirError -eq 5) { 'BLOCKED' } else { 'UNSUPPORTED(open err=' + $docDirError + ', gone=' + $docDirGone + ')' })
    $dirDocOutside = Join-Path $outsideDirectory 'doc-dir'
    $h = [Gate]::CreateFileW($dirDocOutside, [uint32]$DELETE, [uint32]$SHARE_ALL, [IntPtr]::Zero, [uint32]$OPEN_EXISTING, [uint32]($FLAG_BACKUP_SEMANTICS -bor $FLAG_DELETE_ON_CLOSE), [IntPtr]::Zero)
    if ($h -ne [IntPtr](-1)) { [void][Gate]::CloseHandle($h) }
    Start-Sleep -Milliseconds 300
    'Control_DirectoryDeleteOnCloseOutsideScope=' + $(if ($h -ne [IntPtr](-1) -and -not (Test-Path -LiteralPath $dirDocOutside)) { 'ALLOWED' } else { 'DENIED' })

    # --- controls: must stay allowed
    $r = Invoke-Fsctl $hDirOutside $FSCTL_SET_REPARSE_POINT (New-MountPointBuffer $dirOutsideTarget) -NoOutput
    'Control_SetReparsePointOutsideScope=' + $(if ($r.Ok) { 'ALLOWED' } else { 'DENIED(err=' + $r.Error + ')' })
    $r = Invoke-Fsctl $hOutside $FSCTL_SET_SPARSE ([byte[]]@(1))
    'Control_SetSparseOutsideScope=' + $(if ($r.Ok) { 'ALLOWED' } else { 'DENIED(err=' + $r.Error + ')' })
    $r = Invoke-Fsctl $hControl $FSCTL_GET_COMPRESSION $null
    'Control_GetCompressionProtected=' + $(if ($r.Ok) { 'ALLOWED' } else { 'DENIED(err=' + $r.Error + ')' })
    $range = New-Object byte[] 16; [BitConverter]::GetBytes([int64]8192).CopyTo($range, 8)
    $r = Invoke-Fsctl $hControl $FSCTL_QUERY_ALLOCATED_RANGES $range
    'Control_QueryAllocatedRangesProtected=' + $(if ($r.Ok) { 'ALLOWED' } else { 'DENIED(err=' + $r.Error + ')' })
    $docOutside = [Gate]::CreateFileW($paths['docOutside'], [uint32]$DELETE, [uint32]$SHARE_ALL, [IntPtr]::Zero, [uint32]$OPEN_EXISTING, [uint32]$FLAG_DELETE_ON_CLOSE, [IntPtr]::Zero)
    if ($docOutside -ne [IntPtr](-1)) { [void][Gate]::CloseHandle($docOutside) }
    Start-Sleep -Milliseconds 300
    'Control_DeleteOnCloseOutsideScope=' + $(if ($docOutside -ne [IntPtr](-1) -and -not (Test-Path -LiteralPath $paths['docOutside'])) { 'ALLOWED' } else { 'DENIED' })
}
catch { 'ScriptError=' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')' }
finally {
    foreach ($h in $handles) { try { [void][Gate]::CloseHandle($h) } catch { } }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    # A reparse point that a failed gate let through is removed WITHOUT recursion into its target.
    foreach ($d in $scopeDirectory, $outsideDirectory) {
        if (Test-Path -LiteralPath $d) {
            foreach ($rp in @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })) { try { [IO.Directory]::Delete($rp.FullName, $false) } catch { 'ReparseCleanupError=' + $_.Exception.Message } }
            try { Remove-Item -LiteralPath $d -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message }
        }
    }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    'GatesRestoration=OriginalDriverRestored; FilterUnloaded=' + (-not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'))
    'VariantComplete=mutation-gates'
}
