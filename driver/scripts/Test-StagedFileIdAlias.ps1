<# Test-only file-ID access probe. Always restores the installed driver. #>
$ErrorActionPreference = 'Stop'
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-id-test.sys'
$prototype = 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$stage = 'C:\SafeUpload\_staging\id-probe-' + [guid]::NewGuid().ToString('N') + '.txt'
$loaded = $false
$replaced = $false

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

    public static long GetId(string path) {
        using (var file = File.OpenRead(path)) {
            FileInfo info;
            if (!GetFileInformationByHandle(file.SafeFileHandle, out info))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return unchecked((long)(((ulong)info.IndexHigh << 32) | info.IndexLow));
        }
    }
    public static string ReadById(long fileId) {
        using (var volume = CreateFile(@"\\.\C:", 0x80000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
            if (volume.IsInvalid)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var descriptor = new FileIdDescriptor { Size = 24, Type = 0, FileId = fileId };
            using (var handle = OpenFileById(volume, ref descriptor, 0x80000000, 7,
                                             IntPtr.Zero, 0x02000000)) {
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
    New-Item -ItemType Directory -Path (Split-Path $stage) -Force | Out-Null
    [IO.File]::WriteAllText($stage, 'stage alias test')
    $id = [SafeUploadIdProbe]::GetId($stage)
    if ([SafeUploadIdProbe]::ReadById($id) -ne 'stage alias test') {
        throw 'The file-ID probe could not read its fixture before driver load.'
    }
    Copy-Item $installed $backup -Force
    Copy-Item $prototype $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Prototype load failed.' }
    $loaded = $true
    $denied = $false
    try { [SafeUploadIdProbe]::ReadById($id) | Out-Null }
    catch {
        $denied = $true
        Write-Output "FileIdStageReadError=$($_.Exception.GetBaseException().Message)"
    }
    Write-Output "FileIdStageReadDenied=$denied"
    if (-not $denied) { throw 'A file-ID open bypassed the stage path guard.' }
}
finally {
    if ($loaded) { & fltmc.exe unload SafeUpload | Out-Host }
    if ($replaced) { Copy-Item $backup $installed -Force }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) {
        throw 'Original driver restoration failed.'
    }
    Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue
    Write-Output 'OriginalDriverRestored=True'
}
