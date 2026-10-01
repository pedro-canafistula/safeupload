<#
Cross-volume feasibility test on the isolated debuggee VM. Creates a disposable
NTFS VHDX at S:, writes to S:\SafeUpload\Escopo Monitorado, and verifies the
unapproved bytes are held on C:. Always unloads the prototype, restores the
known installed driver, and detaches the VHDX. Requires an elevated session.
#>
param([switch] $NativeIdentityOnly)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-stage.sys'
$prototype = 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys'
$stageDir = 'C:\ProgramData\SafeUpload\staging'
$journalDir = 'C:\ProgramData\SafeUpload\staging-journal'
$serviceZip = 'C:\Users\vika\Documents\stage-service-publish.zip'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$vhd = 'C:\Users\vika\Documents\SafeUpload-stage-crossvolume.vhdx'
$diskpartScript = 'C:\Users\vika\Documents\SafeUpload-stage-diskpart.txt'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$name = 'safeupload-crossvolume-' + [guid]::NewGuid().ToString('N') + '.txt'
$pendingName = 'safeupload-pending-' + [guid]::NewGuid().ToString('N') + '.txt'
$concurrentName = 'safeupload-concurrent-' + [guid]::NewGuid().ToString('N') + '.txt'
$mappedName = 'safeupload-mapped-' + [guid]::NewGuid().ToString('N') + '.txt'
$targetDir = 'S:\SafeUpload\Escopo Monitorado'
$target = "$targetDir\$name"
$pendingTarget = "$targetDir\$pendingName"
$concurrentTarget = "$targetDir\$concurrentName"
$mappedTarget = "$targetDir\$mappedName"
$renameTarget = "$targetDir\$name.renamed.txt"
$hardLinkTarget = "C:\SafeUpload\Escopo Monitorado\$name.linked.txt"
$mounted = $false
$replaced = $false
$loaded = $false
$serviceProcess = $null
$testAgent = $null
$stagePath = $null
$manifestPath = $null
$pendingHandle = $null
$pendingStagePath = $null
$pendingManifestPath = $null
$extraStagePaths = @()
$extraManifestPaths = @()
$nativeIdentityFailure = $null

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadCrossVolumeProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path,
        uint length, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle, int cls,
        IntPtr info, uint length);
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationFile(SafeFileHandle handle, out IoStatus status,
        IntPtr info, uint length, int cls);
    public static string FinalPath(string path) {
        using (var file=File.OpenRead(path)) {
            var result=new StringBuilder(2048);
            if (GetFinalPathNameByHandle(file.SafeFileHandle,result,2048,0)==0)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return result.ToString();
        }
    }
    public static int Rename(string source, string destination) {
        using (var file=CreateFile(source,0x10000,7,IntPtr.Zero,3,0x80,IntPtr.Zero)) {
            if(file.IsInvalid) return Marshal.GetLastWin32Error();
            byte[] name=Encoding.Unicode.GetBytes(destination);
            IntPtr info=Marshal.AllocHGlobal(20+name.Length+2);
            try {
                Marshal.Copy(new byte[20],0,info,20);
                Marshal.WriteInt32(info,16,name.Length);
                Marshal.Copy(name,0,IntPtr.Add(info,20),name.Length);
                Marshal.WriteInt16(info,20+name.Length,0);
                return SetFileInformationByHandle(file,3,info,(uint)(20+name.Length+2))
                    ? 0 : Marshal.GetLastWin32Error();
            }
            finally { Marshal.FreeHGlobal(info); }
        }
    }
    public static string VolumeName(string path) {
        using (var file=File.OpenRead(path)) {
            IntPtr buffer=Marshal.AllocHGlobal(4096);
            try {
                IoStatus io;
                int status=NtQueryInformationFile(file.SafeFileHandle,out io,buffer,4096,58);
                if(status!=0) return "status:0x"+status.ToString("X8");
                int length=Marshal.ReadInt32(buffer);
                if(length<0 || length>4092 || (length&1)!=0) throw new Exception("Invalid volume name length");
                return Marshal.PtrToStringUni(IntPtr.Add(buffer,4),length/2);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
'@

if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
    throw 'Installed driver is not the known original.'
}
if (-not (Test-Path $prototype)) { throw 'Signed prototype missing.' }
if (-not (Test-Path $serviceZip)) { throw 'Self-contained test service missing.' }
if (Test-Path S:\) { throw 'S: is already in use.' }
if (Test-Path $vhd) { throw 'Test VHDX already exists.' }

function Invoke-TestDiskpart([string[]] $commands) {
    Set-Content -LiteralPath $diskpartScript -Value $commands -Encoding Ascii
    $output = & diskpart.exe /s $diskpartScript 2>&1
    $output | Out-Host
    if ($LASTEXITCODE -ne 0 -or ($output -match 'DiskPart has encountered an error')) {
        throw "DiskPart failed: $LASTEXITCODE"
    }
}

function Test-DestinationFileExists([string] $path) {
    return (& powershell.exe -NoProfile -Command "[IO.File]::Exists('$path')") -eq 'True'
}

try {
    Invoke-TestDiskpart @(
        "create vdisk file=`"$vhd`" maximum=128 type=expandable",
        "select vdisk file=`"$vhd`"",
        'attach vdisk',
        'create partition primary',
        'format fs=ntfs quick label=SafeUploadTest',
        'assign letter=S'
    )
    $mounted = $true
    if (-not (Test-Path S:\)) { throw 'S: did not appear.' }
    New-Item -ItemType Directory -Force -Path @(
        $targetDir, 'C:\SafeUpload\Escopo Monitorado') | Out-Null
    $identityFixture = Join-Path $targetDir ('identity-' + [guid]::NewGuid().ToString('N') + '.txt')
    try {
        [IO.File]::WriteAllText($identityFixture, 'volume identity fixture')
        $expectedNativeVolume = [SafeUploadCrossVolumeProbe]::VolumeName($identityFixture)
    }
    finally { Remove-Item -LiteralPath $identityFixture -Force -ErrorAction SilentlyContinue }

    New-Item -ItemType Directory -Force -Path $serviceDir | Out-Null
    & tar.exe -xf $serviceZip -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Could not unpack the test service.' }

    Copy-Item $installed $backup -Force
    Copy-Item $prototype $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Prototype load failed.' }
    $loaded = $true

    $deniedWithoutService = $false
    try { [IO.File]::WriteAllText($target, 'must not reach destination') }
    catch { $deniedWithoutService = $true }
    Write-Output "DeniedWithoutService=$deniedWithoutService"
    if (-not $deniedWithoutService -or [IO.File]::Exists($target)) {
        throw 'The prototype did not fail closed without a service.'
    }

    $testAgent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-service'
    $serviceProcess = $testAgent.Process

    $saved = $false
    for ($attempt = 0; $attempt -lt 15 -and -not $saved; $attempt++) {
        Start-Sleep -Milliseconds 500
        if ($serviceProcess.HasExited) { throw 'Test service exited before connecting.' }
        try {
            [IO.File]::WriteAllText($target, 'CPF: 529.982.247-25')
            $saved = $true
        }
        catch [System.UnauthorizedAccessException] { }
        catch [System.IO.IOException] { }
    }
    if (-not $saved) { throw 'Service never completed a stage allocation.' }

    $writerRead = [IO.File]::ReadAllText($target)
    $nativePath = [SafeUploadCrossVolumeProbe]::FinalPath($target)
    $nativeVolume = [SafeUploadCrossVolumeProbe]::VolumeName($target)
    Write-Output "WriterNativeFinalPath=$nativePath"
    Write-Output "WriterNativeVolumeName=$nativeVolume"
    Write-Output "DestinationNativeVolumeName=$expectedNativeVolume"
    if ($nativePath -ine ('\\?\' + $target)) {
        $nativeIdentityFailure = "Cross-volume handle returned backing-volume identity: $nativePath"
    }
    $otherProcessExists = & powershell.exe -NoProfile -Command "[IO.File]::Exists('$target')"
    $entries = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $target })
    if ($entries.Count -ne 1) { throw "Expected one durable transfer, found $($entries.Count)." }
    $stagePath = $entries[0].Transfer.StagePath
    $transferId = [guid] $entries[0].Transfer.TransferId
    $manifestPath = Join-Path $journalDir ($transferId.ToString('N') + '.json')
    $destinationEntries = @(Get-ChildItem -LiteralPath $targetDir -Filter $name)
    $observerEntryCount = & powershell.exe -NoProfile -Command "@(Get-ChildItem -LiteralPath '$targetDir' -Filter '$name').Count"
    $directStageReadDenied = $false
    try { [IO.File]::ReadAllText($stagePath) | Out-Null }
    catch { $directStageReadDenied = $true }

    Write-Output "WriterRead=$writerRead"
    Write-Output "OtherProcessExists=$otherProcessExists"
    Write-Output "JournalTransferCount=$($entries.Count)"
    Write-Output "JournalState=$($entries[0].State)"
    Write-Output "DestinationEntryCount=$($destinationEntries.Count)"
    Write-Output "OtherProcessDirectoryEntryCount=$observerEntryCount"
    Write-Output "DirectStageReadDenied=$directStageReadDenied"

    if ($NativeIdentityOnly) {
        $inspected = $false
        for ($attempt=0; $attempt -lt 40 -and -not $inspected; $attempt++) {
            Start-Sleep -Milliseconds 250
            $inspected = (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).State -eq 6
        }
        if (-not $inspected) { throw 'The native identity probe could not finish inspection.' }
        $nativeRenameError = [SafeUploadCrossVolumeProbe]::Rename($target, $renameTarget)
        Write-Output "NativeCrossVolumeRenameWin32Error=$nativeRenameError"
        if ($nativeIdentityFailure -or $nativeRenameError -ne 0) {
            throw "$nativeIdentityFailure; native rename after completed inspection: Win32 error $nativeRenameError"
        }
        Write-Output 'NativeCrossVolumeIdentityAndRename=True'
        return
    }

    $renameBlocked = $false
    try { Move-Item -LiteralPath $target -Destination $renameTarget -ErrorAction Stop }
    catch { $renameBlocked = $true }
    $hardLinkBlocked = $false
    try { New-Item -ItemType HardLink -Path $hardLinkTarget -Target $target -ErrorAction Stop | Out-Null }
    catch { $hardLinkBlocked = $true }
    Write-Output "RenameBlocked=$renameBlocked"
    Write-Output "HardLinkBlocked=$hardLinkBlocked"

    $blocked = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $blocked; $attempt++) {
        Start-Sleep -Milliseconds 250
        $current = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if (Test-DestinationFileExists $target) {
            throw 'Sensitive bytes appeared at the destination during analysis.'
        }
        $blocked = $current.State -eq 6
    }
    Write-Output "SensitiveTransferBlocked=$blocked"
    if ($blocked -and $renameBlocked) {
        $nativeRenameError = [SafeUploadCrossVolumeProbe]::Rename($target, $renameTarget)
        Write-Output "NativeCrossVolumeRenameWin32Error=$nativeRenameError"
        if ($nativeRenameError -ne 0) {
            $nativeIdentityFailure += "; native rename failed after inspection: Win32 error $nativeRenameError"
        }
    }

    if ($writerRead -ne 'CPF: 529.982.247-25' -or
        $otherProcessExists -ne 'False' -or
        -not $directStageReadDenied -or
        -not $blocked -or
        $destinationEntries.Count -ne 1 -or
        $observerEntryCount -ne '0' -or
        -not $hardLinkBlocked -or
        (Test-DestinationFileExists $renameTarget) -or
        (Test-DestinationFileExists $hardLinkTarget)) {
        throw 'Cross-volume staging invariant failed.'
    }
    if (-not $renameBlocked -and [IO.File]::ReadAllText($renameTarget) -ne $writerRead) {
        throw 'Virtual rename lost the writer bytes.'
    }

    # Two writable handles must keep one version open until both clean up.
    $firstWriter = [IO.File]::Open($concurrentTarget, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $secondWriter = [IO.File]::Open($concurrentTarget, [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $firstBytes = [Text.Encoding]::UTF8.GetBytes('alpha')
    $secondBytes = [Text.Encoding]::UTF8.GetBytes('beta')
    $firstWriter.Write($firstBytes, 0, $firstBytes.Length)
    [void]$secondWriter.Seek(5, [IO.SeekOrigin]::Begin)
    $secondWriter.Write($secondBytes, 0, $secondBytes.Length)
    $firstWriter.Dispose()
    $firstWriter = $null
    $concurrentEntry = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $concurrentTarget })
    if ($concurrentEntry.Count -ne 1 -or $concurrentEntry[0].State -ne 0 -or
        (Test-DestinationFileExists $concurrentTarget)) {
        throw 'The first cleanup sealed a version with another writer open.'
    }
    $extraStagePaths += $concurrentEntry[0].Transfer.StagePath
    $concurrentManifest = Join-Path $journalDir (
        ([guid] $concurrentEntry[0].Transfer.TransferId).ToString('N') + '.json')
    $extraManifestPaths += $concurrentManifest
    $secondWriter.Dispose()
    $secondWriter = $null
    $concurrentReleased = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $concurrentReleased; $attempt++) {
        Start-Sleep -Milliseconds 250
        $current = Get-Content -LiteralPath $concurrentManifest -Raw | ConvertFrom-Json
        $concurrentReleased = $current.State -eq 5
    }
    $concurrentBytes = & powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$concurrentTarget')"
    Write-Output "ConcurrentReleasedAfterLastClose=$concurrentReleased"
    if (-not $concurrentReleased -or $concurrentBytes -ne 'alphabeta') {
        throw 'Concurrent-writer version did not publish exact inspected bytes.'
    }

    # A later append starts a second version copied from the sealed first.
    # The sensitive second version must not alter the published first one.
    [IO.File]::AppendAllText($concurrentTarget, ' CPF: 529.982.247-25')
    $followupRead = [IO.File]::ReadAllText($concurrentTarget)
    $followupEntries = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $concurrentTarget })
    if ($followupEntries.Count -ne 2) {
        throw "Later open did not allocate a second version: $($followupEntries.Count)."
    }
    $sensitiveFollowup = $followupEntries | Where-Object {
        $_.Transfer.TransferId -ne $concurrentEntry[0].Transfer.TransferId
    }
    $extraStagePaths += $sensitiveFollowup.Transfer.StagePath
    $followupManifest = Join-Path $journalDir (
        ([guid] $sensitiveFollowup.Transfer.TransferId).ToString('N') + '.json')
    $extraManifestPaths += $followupManifest
    $followupBlocked = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $followupBlocked; $attempt++) {
        Start-Sleep -Milliseconds 250
        if ((& powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$concurrentTarget')") -ne 'alphabeta') {
            throw 'Unapproved later-version bytes reached the destination.'
        }
        $current = Get-Content -LiteralPath $followupManifest -Raw | ConvertFrom-Json
        $followupBlocked = $current.State -eq 6
    }
    Write-Output "LaterSensitiveVersionBlocked=$followupBlocked"
    if (-not $followupBlocked -or $followupRead -ne 'alphabeta CPF: 529.982.247-25') {
        throw 'Later append did not preserve the writer view and published version.'
    }

    # Overwrite after a blocked append must get a new empty version, never
    # copy the blocked content into the approved publication.
    [IO.File]::WriteAllText($concurrentTarget, 'clean replacement')
    $overwriteEntries = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $concurrentTarget })
    if ($overwriteEntries.Count -ne 3) {
        throw 'Overwrite did not allocate a third version.'
    }
    $overwriteEntry = $overwriteEntries | Where-Object {
        $_.Transfer.TransferId -ne $concurrentEntry[0].Transfer.TransferId -and
        $_.Transfer.TransferId -ne $sensitiveFollowup.Transfer.TransferId
    }
    $extraStagePaths += $overwriteEntry.Transfer.StagePath
    $overwriteManifest = Join-Path $journalDir (
        ([guid] $overwriteEntry.Transfer.TransferId).ToString('N') + '.json')
    $extraManifestPaths += $overwriteManifest
    $overwriteReleased = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $overwriteReleased; $attempt++) {
        Start-Sleep -Milliseconds 250
        $current = Get-Content -LiteralPath $overwriteManifest -Raw | ConvertFrom-Json
        $overwriteReleased = $current.State -eq 5
    }
    $overwritePublished = & powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$concurrentTarget')"
    Write-Output "LaterOverwriteReleased=$overwriteReleased"
    if (-not $overwriteReleased -or $overwritePublished -ne 'clean replacement') {
        throw 'Later overwrite did not publish only its inspected bytes.'
    }

    # A mapped view can write after its originating file handle closes.
    # The driver must leave that version unsealed until the view is gone.
    $mappedWriter = [IO.File]::Open($mappedTarget, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $mappedBytes = [Text.Encoding]::UTF8.GetBytes('mapped clean bytes')
    $mappedWriter.SetLength($mappedBytes.Length)
    $mapName = 'SafeUploadMap-' + [guid]::NewGuid().ToString('N')
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
        $mappedWriter, $mapName, 0, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
        [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor()
    $mappedWriter.Dispose()
    $mappedWriter = $null
    $view.WriteArray(0, $mappedBytes, 0, $mappedBytes.Length)
    $view.Flush()
    $mappedEntry = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $mappedTarget })
    if ($mappedEntry.Count -ne 1 -or $mappedEntry[0].State -ne 0 -or
        (Test-DestinationFileExists $mappedTarget)) {
        throw 'Writable mapped view was sealed before it was released.'
    }
    $extraStagePaths += $mappedEntry[0].Transfer.StagePath
    $mappedManifest = Join-Path $journalDir (
        ([guid] $mappedEntry[0].Transfer.TransferId).ToString('N') + '.json')
    $extraManifestPaths += $mappedManifest
    $view.Dispose()
    $view = $null
    $mapping.Dispose()
    $mapping = $null
    $mappedReleased = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $mappedReleased; $attempt++) {
        Start-Sleep -Milliseconds 250
        $current = Get-Content -LiteralPath $mappedManifest -Raw | ConvertFrom-Json
        $mappedReleased = $current.State -eq 5
    }
    $mappedPublished = & powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$mappedTarget')"
    Write-Output "MappedReleasedAfterViewClosed=$mappedReleased"
    if (-not $mappedReleased -or $mappedPublished -ne 'mapped clean bytes') {
        throw 'Mapped version did not publish exact inspected bytes.'
    }

    # Hold a second writer open across an agent crash. Recovery must not
    # infer that this version was sealed while its handle still exists.
    $pendingHandle = [IO.File]::Open($pendingTarget, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    $pendingBytes = [Text.Encoding]::UTF8.GetBytes('writer still open')
    $pendingHandle.Write($pendingBytes, 0, $pendingBytes.Length)
    $pendingEntries = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $pendingTarget })
    if ($pendingEntries.Count -ne 1 -or $pendingEntries[0].State -ne 0) {
        throw 'Open writer did not retain one Allocated journal entry.'
    }
    $pendingStagePath = $pendingEntries[0].Transfer.StagePath
    $pendingManifestPath = Join-Path $journalDir (
        ([guid] $pendingEntries[0].Transfer.TransferId).ToString('N') + '.json')

    Stop-StagedTestAgent $testAgent
    $testAgent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-service-restart'
    $serviceProcess = $testAgent.Process
    $unsealed = $false
    for ($attempt = 0; $attempt -lt 20 -and -not $unsealed; $attempt++) {
        Start-Sleep -Milliseconds 250
        if ($serviceProcess.HasExited) { throw 'Test service exited during recovery.' }
        $recovered = Get-Content -LiteralPath $pendingManifestPath -Raw | ConvertFrom-Json
        $unsealed = $recovered.State -eq 8
    }
    Write-Output "UnsealedAfterServiceRestart=$unsealed"
    if (-not $unsealed -or (Test-DestinationFileExists $target)) {
        throw 'An interrupted transfer was not safely held unsealed.'
    }

    Start-Sleep -Milliseconds 500
    $pendingHandle.Dispose()
    $pendingHandle = $null
    $releasedAfterRestart = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $releasedAfterRestart; $attempt++) {
        Start-Sleep -Milliseconds 250
        $recovered = Get-Content -LiteralPath $pendingManifestPath -Raw | ConvertFrom-Json
        $releasedAfterRestart = $recovered.State -eq 5 -and $recovered.SealedOnce
    }
    $publishedBytes = & powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$pendingTarget')"
    Write-Output "ReleasedAfterFinalWriter=$releasedAfterRestart"
    Write-Output "PublishedBytes=$publishedBytes"
    if (-not $releasedAfterRestart -or $publishedBytes -ne 'writer still open') {
        throw 'Final writer cleanup did not publish the inspected pending version.'
    }
}
finally {
    if ($firstWriter) { $firstWriter.Dispose() }
    if ($secondWriter) { $secondWriter.Dispose() }
    if ($mappedWriter) { $mappedWriter.Dispose() }
    if ($view) { $view.Dispose() }
    if ($mapping) { $mapping.Dispose() }
    if ($pendingHandle) { $pendingHandle.Dispose() }
    Stop-StagedTestAgent $testAgent
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($stagePath) {
        $stageDeniedAfterUnload = $false
        try { [IO.File]::ReadAllText($stagePath) | Out-Null }
        catch [System.UnauthorizedAccessException] { $stageDeniedAfterUnload = $true }
        Write-Output "StageReadDeniedAfterUnload=$stageDeniedAfterUnload"
    }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expectedOriginal) {
        throw 'Original driver restoration failed.'
    }
    try {
        if (Test-Path $journalDir) {
            Get-ChildItem -LiteralPath $journalDir -Filter '*.json' | ForEach-Object {
                $entry = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
                if (@($target,$renameTarget,$pendingTarget,$concurrentTarget,$mappedTarget) -contains
                    $entry.Transfer.DestinationPath) {
                    $extraStagePaths += $entry.Transfer.StagePath
                    $extraManifestPaths += $_.FullName
                }
            }
        }
        Remove-StagedTestFiles (@($stagePath,$manifestPath,$pendingStagePath,$pendingManifestPath) +
            $extraStagePaths + $extraManifestPaths)
        Remove-Item -LiteralPath $hardLinkTarget -Force -ErrorAction SilentlyContinue
    }
    finally {
        if ($mounted) {
            Invoke-TestDiskpart @("select vdisk file=`"$vhd`"", 'detach vdisk')
        }
        Remove-Item -LiteralPath $vhd,$diskpartScript -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'OriginalDriverRestored=True'
    if ($stagePath -and -not $stageDeniedAfterUnload) {
        throw 'The private backing stage was exposed after unload.'
    }
}
if ($nativeIdentityFailure) { throw $nativeIdentityFailure }
