$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if ((Get-FileHash C:\Windows\System32\drivers\SafeUpload.sys).Hash -ne 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE') { throw 'Original driver mismatch' }
if ((& fltmc filters) -match '^SafeUpload\s') { throw 'Filter must be unloaded' }
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SafeUploadArchitectureNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool MoveFileEx(string source, string target, int flags);
    public static void MoveOverwrite(string source, string target) {
        if (!MoveFileEx(source,target,1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
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
    public static void Rename(SafeFileHandle handle, string destination) { RenameFlags(handle,destination,0,false); }
    public static void RenameFlags(SafeFileHandle handle, string destination, int flags, bool extended) {
        byte[] name=Encoding.Unicode.GetBytes(destination);
        int header=IntPtr.Size==8 ? 20 : 12;
        int lengthOffset=IntPtr.Size==8 ? 16 : 8;
        IntPtr info=Marshal.AllocHGlobal(header+name.Length+2);
        try {
            Marshal.Copy(new byte[header],0,info,header);
            Marshal.WriteInt32(info,flags);
            Marshal.WriteInt32(info,lengthOffset,name.Length);
            Marshal.Copy(name,0,IntPtr.Add(info,header),name.Length);
            Marshal.WriteInt16(info,header+name.Length,0);
            if(!SetFileInformationByHandle(handle,extended ? 22 : 3,info,(uint)(header+name.Length+2)))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(info); }
    }
    public static void ParallelWrites(FileStream first, FileStream second) {
        first.Position = 0; second.Position = 4096;
        System.Threading.Tasks.Task.WaitAll(
            System.Threading.Tasks.Task.Run(() => {
                byte[] bytes = Encoding.ASCII.GetBytes(new string('A', 64));
                for (int i=0; i<64; i++) first.Write(bytes,0,bytes.Length);
                first.Flush();
            }),
            System.Threading.Tasks.Task.Run(() => {
                byte[] bytes = Encoding.ASCII.GetBytes(new string('B', 64));
                for (int i=0; i<64; i++) second.Write(bytes,0,bytes.Length);
                second.Flush();
            }));
    }
    public static System.IO.MemoryMappedFiles.MemoryMappedFile Map(FileStream file, long capacity) {
        return System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile(file, null, capacity,
            System.IO.MemoryMappedFiles.MemoryMappedFileAccess.ReadWrite,
            System.IO.HandleInheritability.None, true);
    }
}
'@
$root=Join-Path $env:TEMP ('SafeUpload-rename-control-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root | Out-Null
try {
 foreach($sharing in @(([IO.FileShare]::Read -bor [IO.FileShare]::Delete), ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))) {
    $source=Join-Path $root 'approved.pending'; $target=Join-Path $root 'approved.txt'
    [IO.File]::WriteAllText($source,'new approved')
    [IO.File]::WriteAllText($target,'old approved')
    $reader=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,$sharing)
    try {
      try { [SafeUploadArchitectureNative]::MoveOverwrite($source,$target); Write-Output ('MoveFileOverwrite='+$sharing+':success') }
      catch { Write-Output ('MoveFileOverwrite='+$sharing+':'+$_.Exception.InnerException.ToString()) }
      if([IO.File]::Exists($source)) {
        $handle=[SafeUploadArchitectureNative]::CreateFile($source,0x10000,7,[IntPtr]::Zero,3,0x80,[IntPtr]::Zero)
        try { [SafeUploadArchitectureNative]::RenameFlags($handle,$target,3,$true); Write-Output ('PosixReplacement='+$sharing+':success') }
        finally { $handle.Dispose() }
      }
      $text=[IO.StreamReader]::new($reader)
      try { $old=$text.ReadToEnd() } finally {$text.Dispose()}
      $current=[IO.File]::ReadAllText($target)
      Write-Output ('OldHandle='+$old+'; CurrentName='+$current)
      if($old -ne 'old approved' -or $current -ne 'new approved') {throw 'Replacement identity mismatch'}
    } finally { $reader.Dispose() }
    Remove-Item $target -Force
 }
} finally { Remove-Item $root -Recurse -Force }
