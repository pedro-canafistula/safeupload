<#
Bounded architecture gate for SafeUpload.ArchitectureProbe. This independently
built driver has no publisher: every version remains private. A disposable S:
volume supplies the application's original identity; C: supplies private bytes.
Run only on the isolated debuggee. Native APIs must succeed without move/copy
fallbacks. The original SafeUpload driver is verified and restored in finally.
#>
param([switch] $Verifier)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$probe = 'C:\Users\vika\Documents\SafeUpload-architecture-probe.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-architecture.sys'
$vhd = 'C:\Users\vika\Documents\SafeUpload-architecture.vhdx'
$diskpart = $vhd + '.txt'
$stageRoot = 'C:\ProgramData\SafeUpload\architecture-probe'
$id = [guid]::NewGuid().ToString('N')
$directory = 'S:\SafeUpload\Architecture Probe'
$target = [IO.Path]::Combine($directory, $id + '.tmp')
$renamed = [IO.Path]::Combine($directory, $id + '.txt')
$systemScript = Join-Path $env:TEMP ('SafeUpload-architecture-' + $id + '.ps1')
$systemResult = $systemScript + '.result'
$taskName = 'SafeUpload-Architecture-' + $id
$observerScript = $systemScript + '.observer.ps1'
$observerLog = $systemScript + '.observer.log'
$observerStop = $systemScript + '.stop'
$observerRequest = $systemScript + '.request'
$observerAck = $systemScript + '.ack'
$privatePathFile = $systemScript + '.private'
$mounted = $false
$replaced = $false
$loaded = $false
$rootCreated = $false
$verifierEnabled = $false
$file = $null
$native = $null
$mapping = $null
$view = $null
$observer = $null
$testFailed = $false
$rebootRequired = $false

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadArchitectureNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle, int cls, IntPtr info, uint length);
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationFile(SafeFileHandle handle, out IoStatus status, IntPtr buffer, uint length, int cls);
    public static string FinalPath(SafeFileHandle handle, uint flags) {
        var buffer = new StringBuilder(2048);
        uint size = GetFinalPathNameByHandle(handle, buffer, 2048, flags);
        if(size == 0) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        if(size >= 2048) throw new Exception("Final path overflow");
        return buffer.ToString();
    }
    public static string VolumeName(SafeFileHandle handle) {
        return QueryName(handle,58);
    }
    public static string QueryName(SafeFileHandle handle, int informationClass) {
        IntPtr buffer=Marshal.AllocHGlobal(4096);
        try {
            IoStatus io;
            int status=NtQueryInformationFile(handle,out io,buffer,4096,informationClass);
            if(status!=0) throw new Exception("Volume query: 0x"+status.ToString("X8"));
            int length=Marshal.ReadInt32(buffer);
            if(length<0 || length>4092 || (length&1)!=0) throw new Exception("Invalid volume name length");
            return Marshal.PtrToStringUni(IntPtr.Add(buffer,4),length/2);
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    public static void Rename(SafeFileHandle handle, string destination) {
        byte[] name=Encoding.Unicode.GetBytes(destination);
        int header=IntPtr.Size==8 ? 20 : 12;
        int lengthOffset=IntPtr.Size==8 ? 16 : 8;
        IntPtr info=Marshal.AllocHGlobal(header+name.Length+2);
        try {
            Marshal.Copy(new byte[header],0,info,header);
            Marshal.WriteInt32(info,lengthOffset,name.Length);
            Marshal.Copy(name,0,IntPtr.Add(info,header),name.Length);
            Marshal.WriteInt16(info,header+name.Length,0);
            if(!SetFileInformationByHandle(handle,3,info,(uint)(header+name.Length+2)))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(info); }
    }
    public static System.IO.MemoryMappedFiles.MemoryMappedFile Map(FileStream file, long capacity) {
        return System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile(file, null, capacity,
            System.IO.MemoryMappedFiles.MemoryMappedFileAccess.ReadWrite,
            System.IO.HandleInheritability.None, true);
    }
}
'@

function Invoke-ProbeSystem([string] $Script) {
    Remove-Item -LiteralPath $systemResult -Force -ErrorAction SilentlyContinue
    $wrapped = '$ErrorActionPreference = ''Stop''; try {' + "`n" + $Script + "`n" +
        "[IO.File]::WriteAllText('$systemResult','OK')" + "`n} catch {" +
        "[IO.File]::WriteAllText('$systemResult',`$_.Exception.ToString()); exit 1 }"
    Set-Content -LiteralPath $systemScript -Value $wrapped -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $systemScript + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($attempt=0; $attempt -lt 120 -and -not (Test-Path -LiteralPath $systemResult); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $systemResult)) { throw 'SYSTEM operation timed out.' }
        $result = Get-Content -LiteralPath $systemResult -Raw
        if ($result -ne 'OK') { throw $result }
    }
    finally { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
}

function Invoke-ProbeDisk([string[]] $Commands) {
    Set-Content -LiteralPath $diskpart -Value $Commands -Encoding Ascii
    $result = & diskpart.exe /s $diskpart 2>&1
    $result | Out-Host
    if ($LASTEXITCODE -ne 0 -or ($result -match 'DiskPart has encountered an error')) {
        throw 'Disposable volume operation failed.'
    }
}

function Assert-ProbeObserver([string] $Phase) {
    Set-Content -LiteralPath $observerRequest -Value $Phase
    for ($attempt=0; $attempt -lt 100; $attempt++) {
        if ($observer.HasExited) { throw "Destination observer exited during $Phase." }
        if ((Test-Path -LiteralPath $observerAck) -and
            (Get-Content -LiteralPath $observerAck -Raw).Trim() -eq $Phase) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Destination observer did not check $Phase."
}

if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original installed driver mismatch.' }
if (-not (Test-Path -LiteralPath $probe)) { throw 'Signed architecture probe missing.' }
if ((Test-Path S:\) -or (Test-Path -LiteralPath $vhd)) { throw 'Disposable volume is already present.' }
if (Test-Path -LiteralPath $stageRoot) { throw 'Private probe root already exists; reconcile previous run first.' }

try {
    Invoke-ProbeDisk @("create vdisk file=`"$vhd`" maximum=128 type=expandable",
        "select vdisk file=`"$vhd`"", 'attach vdisk', 'create partition primary',
        'format fs=ntfs quick label=SafeUploadArchitecture', 'assign letter=S')
    $mounted = $true
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $fixture = Join-Path $directory ('identity-' + $id)
    [IO.File]::WriteAllText($fixture, 'approved identity fixture')
    try {
        $identity = [IO.File]::OpenRead($fixture)
        try { $expectedVolume = [SafeUploadArchitectureNative]::VolumeName($identity.SafeFileHandle) }
        finally { $identity.Dispose() }
    } finally { Remove-Item -LiteralPath $fixture -Force }
    Invoke-ProbeSystem @"
New-Item -ItemType Directory -Path '$stageRoot' | Out-Null
`$acl = New-Object Security.AccessControl.DirectorySecurity
`$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;OICI;FA;;;SY)')
[IO.Directory]::SetAccessControl('$stageRoot', `$acl)
"@
    $rootCreated = $true
    Copy-Item -LiteralPath $installed -Destination $backup -Force
    Copy-Item -LiteralPath $probe -Destination $installed -Force
    $replaced = $true
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Architecture probe load failed.' }
    $loaded = $true
    Write-Output 'ArchitectureProbeLoaded=True'

    $watch = @'
$ErrorActionPreference='Stop'
$samples=0
while (-not (Test-Path -LiteralPath '__STOP__')) {
    foreach ($path in @('__TARGET__','__RENAMED__')) {
        if ([IO.File]::Exists($path)) {
            Add-Content -LiteralPath '__LOG__' -Value ('LEAK ' + $path)
            exit 2
        }
    }
    $samples++
    if (Test-Path -LiteralPath '__REQUEST__') {
        $phase = (Get-Content -LiteralPath '__REQUEST__' -Raw).Trim()
        Set-Content -LiteralPath '__ACK__' -Value $phase
    }
    Start-Sleep -Milliseconds 20
}
Add-Content -LiteralPath '__LOG__' -Value ('samples=' + $samples)
'@
    Set-Content -LiteralPath $observerScript -Value ($watch.Replace('__STOP__',$observerStop).
        Replace('__TARGET__',$target).Replace('__RENAMED__',$renamed).Replace('__LOG__',$observerLog).
        Replace('__REQUEST__',$observerRequest).Replace('__ACK__',$observerAck)) -Encoding UTF8
    $observer = Start-Process powershell.exe -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $observerScript + '"'))
    Assert-ProbeObserver 'ready'

    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $file = [IO.FileStream]::new($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,$share)
    Write-Output 'OriginalVolumeCreate=True'
    Write-Output ('VolumeImmediatelyAfterCreate=' + [SafeUploadArchitectureNative]::VolumeName($file.SafeFileHandle))
    Write-Output ('PathImmediatelyAfterCreate=' + [SafeUploadArchitectureNative]::FinalPath($file.SafeFileHandle,0))
    $file.SetLength(257)
    $bytes = [Text.Encoding]::UTF8.GetBytes('private staged content')
    $file.Write($bytes,0,$bytes.Length)
    $file.Flush($true)
    $file.SetLength(4096)
    $file.Position = 0
    $preserved = [byte[]]::new($bytes.Length)
    if ($file.Read($preserved,0,$preserved.Length) -ne $bytes.Length -or
        [Convert]::ToBase64String($preserved) -ne [Convert]::ToBase64String($bytes)) {
        throw 'Unaligned backing growth lost existing bytes.'
    }
    $file.Position = 256
    if ($file.ReadByte() -ne 0) { throw 'Backing growth did not zero its partial sector.' }
    $file.Position = 4095
    if ($file.ReadByte() -ne 0) { throw 'Backing growth did not zero its final byte.' }
    Write-Output 'UnalignedGrowthPreservesAndZeroes=True'
    Assert-ProbeObserver 'ordinary-write'
    $actualVolume = [SafeUploadArchitectureNative]::VolumeName($file.SafeFileHandle)
    $actualPath = [SafeUploadArchitectureNative]::FinalPath($file.SafeFileHandle,0)
    Write-Output "RequestedPath=$target"
    Write-Output "ExpectedNativeVolume=$expectedVolume"
    Write-Output "ActualNativeVolume=$actualVolume"
    Write-Output "NativeFinalPath=$actualPath"
    if ($actualVolume -ne $expectedVolume -or $actualPath -ine ('\\?\' + $target)) {
        throw 'The upper file object did not preserve destination identity.'
    }
    $native = [SafeUploadArchitectureNative]::CreateFile($target,0x10003,7,[IntPtr]::Zero,3,0x80,[IntPtr]::Zero)
    if ($native.IsInvalid) { throw "Native writable/delete reopen failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    [SafeUploadArchitectureNative]::Rename($native,$renamed)
    Write-Output 'NativeRename=True'
    $renamedPath = [SafeUploadArchitectureNative]::FinalPath($file.SafeFileHandle,0)
    Write-Output "NativePathAfterRename=$renamedPath"
    Write-Output ('NativeFileNameAfterRename=' + [SafeUploadArchitectureNative]::QueryName($file.SafeFileHandle,9))
    Write-Output ('NativeNormalizedNameAfterRename=' + [SafeUploadArchitectureNative]::QueryName($file.SafeFileHandle,48))
    if ($renamedPath -ine ('\\?\' + $renamed)) {
        throw 'An existing handle lost its virtual name after rename.'
    }
    if ([IO.File]::Exists($target)) { throw 'Old virtual name remained visible.' }
    Assert-ProbeObserver 'native-rename'
    $mapping = [SafeUploadArchitectureNative]::Map($file,4096)
    $view = $mapping.CreateViewAccessor(0,4096,[IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $view.Write(64,[byte]0x5A)
    $file.Position = 64
    if ($file.ReadByte() -ne 0x5A) { throw 'Mapped write and ordinary read used different caches.' }
    $file.Position = 65
    $file.WriteByte(0x6B)
    $file.Flush()
    if ($view.ReadByte(65) -ne 0x6B) { throw 'Ordinary write and mapped read used different caches.' }
    Write-Output 'MappedAndOrdinaryIOCoherent=True'
    $native.Dispose(); $native = $null
    $file.Dispose(); $file = $null
    $refusal = & fltmc.exe unload SafeUpload 2>&1
    $refusal | Out-Host
    if ($LASTEXITCODE -eq 0 -or ($refusal -join "`n") -notmatch '0x801f0010') {
        throw 'Driver unload did not refuse a live writable section.'
    }
    Write-Output 'UnloadRefusesLiveMapping=True'
    $view.Write(66,[byte]0x7C)
    $view.Flush()
    Assert-ProbeObserver 'mapped-write-after-close'
    Write-Output 'MappedWriteAfterHandleClose=True'
    $view.Dispose(); $view = $null
    $mapping.Dispose(); $mapping = $null
    $reopened = [IO.File]::OpenRead($renamed)
    try {
        $reopened.Position = 64
        if ($reopened.ReadByte() -ne 0x5A -or $reopened.ReadByte() -ne 0x6B -or $reopened.ReadByte() -ne 0x7C) {
            throw 'Reopen lost cached or mapped bytes.'
        }
        if ([SafeUploadArchitectureNative]::VolumeName($reopened.SafeFileHandle) -ne $expectedVolume) {
            throw 'Reopen changed destination volume.'
        }
    } finally { $reopened.Dispose() }
    Write-Output 'ReopenAfterRename=True'
    Assert-ProbeObserver 'reopen'
    Set-Content -LiteralPath $observerStop -Value 'stop'
    if (-not $observer.WaitForExit(10000)) { throw 'Destination observer did not exit.' }
    $observerEvidence = Get-Content -LiteralPath $observerLog -Raw
    Write-Output "DestinationObserver=$observerEvidence"
    if ($observer.ExitCode -ne 0 -or $observerEvidence -match 'LEAK' -or $observerEvidence -notmatch 'samples=[1-9]') {
        throw 'Destination observer did not establish byte isolation.'
    }
    Save-StagedVerifierEvidence
}
catch { $testFailed = $true; Write-Output ('ArchitectureFailure=' + $_.Exception.ToString()); throw }
finally {
    if ($native) { $native.Dispose() }
    if ($file) { $file.Dispose() }
    if ($view) { $view.Dispose() }
    if ($mapping) { $mapping.Dispose() }
    if ($observer -and -not $observer.HasExited) { Stop-Process -Id $observer.Id -Force }
    if ($loaded) {
        $unloaded = $false
        for ($attempt=0; $attempt -lt 120 -and -not $unloaded; $attempt++) {
            & fltmc.exe unload SafeUpload | Out-Host
            $unloaded = $LASTEXITCODE -eq 0
            if (-not $unloaded) { Start-Sleep -Milliseconds 250 }
        }
        if (-not $unloaded) {
            # Restore the installed binary even when a live kernel section
            # prevents unloading. Retain its fixtures for diagnosis/recovery.
            Move-Item -LiteralPath $installed -Destination ($installed + '.architecture-' + $id + '.loaded')
            $rebootRequired = $true
        }
    }
    if ($verifierEnabled) { & verifier.exe /volatile /removedriver SafeUpload.sys | Out-Host; & verifier.exe /reset | Out-Host }
    if ($replaced) { Copy-Item -LiteralPath $backup -Destination $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver restoration failed.' }
    Write-Output 'OriginalDriverRestored=True'
    if ($rebootRequired) {
        Write-Output 'ArchitectureProbeStillLoaded=True'
        throw 'Probe retained a live section/file object. Original installed bytes are restored; reboot before cleaning the retained fixtures.'
    }
    if ($mounted) {
        $physicalEntries = @(Get-ChildItem -LiteralPath $directory -File)
        Write-Output "ActualDestinationFilesAfterUnload=$($physicalEntries.Count)"
        if ($physicalEntries.Count -ne 0) { throw 'The original destination contains an unapproved file.' }
    }
    if ($rootCreated) {
        if (-not $testFailed) {
            Invoke-ProbeSystem @"
`$files = @(Get-ChildItem -LiteralPath '$stageRoot' -File)
if (`$files.Count -ne 1) { throw 'Expected one private backing file.' }
`$actual = [IO.File]::ReadAllBytes(`$files[0].FullName)
`$expected = [byte[]]::new(4096)
`$prefix = [Text.Encoding]::UTF8.GetBytes('private staged content')
[Array]::Copy(`$prefix, `$expected, `$prefix.Length)
`$expected[64]=0x5A; `$expected[65]=0x6B; `$expected[66]=0x7C
if ([Convert]::ToBase64String(`$actual) -ne [Convert]::ToBase64String(`$expected)) {
    throw 'Private backing differs from the complete expected version.'
}
[IO.File]::WriteAllText('$privatePathFile', `$files[0].FullName)
"@
            Write-Output 'ExactPrivateBackingBytes=True'
            $privatePath = Get-Content -LiteralPath $privatePathFile -Raw
            $denied = $false
            try { [IO.File]::ReadAllBytes($privatePath) | Out-Null }
            catch {
                $reason = $_.Exception
                while ($reason.InnerException) { $reason = $reason.InnerException }
                $denied = $reason -is [UnauthorizedAccessException]
                if (-not $denied) { throw }
            }
            if (-not $denied) { throw 'An ordinary process read the stage after driver unload.' }
            Write-Output 'PrivateACLProtectsAfterUnload=True'
        }
        Invoke-ProbeSystem "Remove-Item -LiteralPath '$stageRoot' -Recurse -Force"
    }
    if ($mounted) { Invoke-ProbeDisk @("select vdisk file=`"$vhd`"", 'detach vdisk') }
    Remove-Item -LiteralPath $vhd,$diskpart,$systemScript,$systemResult,$observerScript,$observerLog,$observerStop `
        -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $observerRequest,$observerAck,$privatePathFile -Force -ErrorAction SilentlyContinue
}
