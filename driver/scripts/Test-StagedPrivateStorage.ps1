<# Private-stage access test on the isolated debuggee; restores original driver. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-private.sys'
$prototype = 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$serviceZip = 'C:\Users\vika\Documents\stage-service-publish.zip'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$journalDir = 'C:\ProgramData\SafeUpload\staging-journal'
$targetDir = 'C:\SafeUpload\Escopo Monitorado'
$target = Join-Path $targetDir ('safeupload-private-' + [guid]::NewGuid().ToString('N') + '.txt')
$loaded = $false
$replaced = $false
$agent = $null
$stage = $null
$manifest = $null

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class SafeUploadIdProbe {
    [StructLayout(LayoutKind.Sequential)]
    public struct FileInfo {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Created;
        public System.Runtime.InteropServices.ComTypes.FILETIME Accessed;
        public System.Runtime.InteropServices.ComTypes.FILETIME Written;
        public uint VolumeSerial;
        public uint SizeHigh;
        public uint SizeLow;
        public uint Links;
        public uint IndexHigh;
        public uint IndexLow;
    }
    [StructLayout(LayoutKind.Explicit, Size=24)]
    public struct FileIdDescriptor {
        [FieldOffset(0)] public uint Size;
        [FieldOffset(4)] public int Type;
        [FieldOffset(8)] public long FileId;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeFileHandle OpenFileById(SafeFileHandle volume,
        ref FileIdDescriptor id, uint access, uint share, IntPtr security, uint flags);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool CreateRestrictedToken(SafeAccessTokenHandle token, uint flags,
        uint disabledCount, IntPtr disabled, uint deletedCount, IntPtr deleted,
        uint restrictedCount, IntPtr restricted, out SafeAccessTokenHandle result);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool ImpersonateLoggedOnUser(SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool RevertToSelf();

    public static long GetId(string path) {
        using (var file = File.OpenRead(path)) {
            FileInfo info;
            if (!GetFileInformationByHandle(file.SafeFileHandle, out info))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((long)(((ulong)info.IndexHigh << 32) | info.IndexLow));
        }
    }
    public static string ReadById(long fileId, bool backupSemantics) {
        // SSH starts this harness with every admin privilege enabled. Remove
        // backup/restore (and other elevated privileges) for the app probe:
        // SeBackupPrivilege deliberately overrides NTFS read ACLs on Windows.
        SafeAccessTokenHandle original;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0a, out original))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        using (original) {
            SafeAccessTokenHandle restricted;
            if (!CreateRestrictedToken(original, 1, 0, IntPtr.Zero, 0, IntPtr.Zero,
                                       0, IntPtr.Zero, out restricted))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            using (restricted) {
                if (!ImpersonateLoggedOnUser(restricted))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                try { return ReadByIdCore(fileId, backupSemantics); }
                finally {
                    if (!RevertToSelf())
                        throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
            }
        }
    }
    static string ReadByIdCore(long fileId, bool backupSemantics) {
        using (var volume = CreateFile(@"\\.\C:", 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            if (volume.IsInvalid)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var descriptor = new FileIdDescriptor { Size = 24, Type = 0, FileId = fileId };
            using (var handle = OpenFileById(volume, ref descriptor, 0x80000000, 7,
                                             IntPtr.Zero, backupSemantics ? 0x02000000u : 0u)) {
                if (handle.IsInvalid)
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                using (var file = new FileStream(handle, FileAccess.Read))
                using (var reader = new StreamReader(file)) return reader.ReadToEnd();
            }
        }
    }
}
'@

if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) {
    throw 'Installed driver is not the known original.'
}
try {
    New-Item -ItemType Directory -Path $targetDir,$serviceDir -Force | Out-Null
    & tar.exe -xf $serviceZip -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Test agent package could not be extracted.' }
    Copy-Item $installed $backup -Force
    Copy-Item $prototype $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Prototype load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-private-service'
    $saved = $false
    for ($attempt = 0; $attempt -lt 30 -and -not $saved; $attempt++) {
        Start-Sleep -Milliseconds 250
        if ($agent.Process.HasExited) { throw 'LocalSystem test agent exited.' }
        try {
            [IO.File]::WriteAllText($target, 'CPF: 529.982.247-25')
            $saved = $true
        }
        catch [System.IO.IOException] { }
        catch [System.UnauthorizedAccessException] { }
    }
    if (-not $saved) { throw 'The app could not open a private backing stage through its destination.' }
    $read = [IO.File]::ReadAllText($target)
    $fileId = [SafeUploadIdProbe]::GetId($target)
    if ($read -ne 'CPF: 529.982.247-25') { throw 'Writer view returned the wrong staged bytes.' }
    $entries = @(Get-ChildItem -LiteralPath $journalDir -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $target })
    if ($entries.Count -ne 1) { throw 'Expected one allocated private stage.' }
    $stage = $entries[0].Transfer.StagePath
    $manifest = Join-Path $journalDir (([guid]$entries[0].Transfer.TransferId).ToString('N') + '.json')
    $blocked = $false
    for ($attempt = 0; $attempt -lt 40 -and -not $blocked; $attempt++) {
        Start-Sleep -Milliseconds 250
        $blocked = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).State -eq 6
        if ((& powershell.exe -NoProfile -Command "[IO.File]::Exists('$target')") -ne 'False') {
            throw 'Unapproved bytes appeared at the destination.'
        }
    }
    if (-not $blocked) { throw 'Sensitive private stage was not inspected and blocked.' }
    Stop-StagedTestAgent $agent
    $agent = $null
    Save-StagedVerifierEvidence
    & fltmc.exe unload SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Prototype unload failed.' }
    $loaded = $false
    foreach ($backupSemantics in @($false, $true)) {
        $idDenied = $false
        try { [SafeUploadIdProbe]::ReadById($fileId, $backupSemantics) | Out-Null }
        catch {
            if ($_.Exception.GetBaseException().NativeErrorCode -ne 5) { throw }
            $idDenied = $true
        }
        Write-Output "FileIdStageReadDeniedAfterUnload=$idDenied BackupSemantics=$backupSemantics Privileged=False"
        if (-not $idDenied) { throw 'File-ID access bypassed the private backing ACL after unload.' }
    }
    $denied = $false
    try { [IO.File]::ReadAllText($stage) | Out-Null }
    catch [System.UnauthorizedAccessException] { $denied = $true }
    Write-Output "WriterPrivateStageRead=$read"
    Write-Output "StageReadDeniedAfterUnload=$denied"
    if (-not $denied) { throw 'The backing ACL exposed the stage after filter unload.' }
}
finally {
    Stop-StagedTestAgent $agent
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) {
        throw 'Original driver restoration failed.'
    }
    $cleanupPaths = @($stage, $manifest)
    if (Test-Path $journalDir) {
        Get-ChildItem -LiteralPath $journalDir -Filter '*.json' | ForEach-Object {
            $entry = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
            if ($entry.Transfer.DestinationPath -eq $target) {
                $cleanupPaths += $entry.Transfer.StagePath
                $cleanupPaths += $_.FullName
            }
        }
    }
    Remove-StagedTestFiles $cleanupPaths
    Write-Output 'OriginalDriverRestored=True'
}
