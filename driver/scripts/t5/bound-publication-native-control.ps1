#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfCheckOnly)
# Unprotected builder control: actual parent-relative NTFS create/rename.
# No driver installation, host configuration or protected-runtime claim.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class BoundPublicationNativeControl {
 [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
 [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
  public uint Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Security, Qos;
 }
 [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, byte[] data, uint size);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle handle);
 [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
  out IoStatusBlock status, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
 [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle handle, out IoStatusBlock status, byte[] data, uint size, int kind);
 [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);
 static void Check(int status) { if(status!=0) throw new Win32Exception((int)RtlNtStatusToDosError(status), "Native status 0x"+status.ToString("X8")); }
 static void Leaf(string leaf) {
  if(String.IsNullOrEmpty(leaf) || leaf=="." || leaf==".." || leaf.IndexOfAny(new char[]{'\\','/',':','*','?','\0'})>=0)
   throw new ArgumentException("A simple leaf is required.");
 }
 public static SafeFileHandle Parent(string path) {
  var handle=CreateFileW(path,0x1000A1,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(handle.IsInvalid) { int e=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(e); }
  byte[] basic=new byte[40];
  if(!GetFileInformationByHandleEx(handle,0,basic,40) || (BitConverter.ToUInt32(basic,32)&0x410)!=0x10) {
   handle.Dispose(); throw new IOException("Parent is not a non-reparse directory.");
  }
  return handle;
 }
 public static string Identity(SafeFileHandle handle) {
  byte[] data=new byte[24];
  if(!GetFileInformationByHandleEx(handle,18,data,24)) throw new Win32Exception(Marshal.GetLastWin32Error());
  return BitConverter.ToString(data).Replace("-","");
 }
 public static SafeFileHandle CreateRelative(SafeFileHandle parent,string leaf) {
  Leaf(leaf); byte[] bytes=Encoding.Unicode.GetBytes(leaf);
  IntPtr name=Marshal.AllocHGlobal(bytes.Length+2), unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
  bool held=false;
  try {
   parent.DangerousAddRef(ref held); Marshal.Copy(bytes,0,name,bytes.Length); Marshal.WriteInt16(name,bytes.Length,0);
   var value=new UnicodeString{Length=(ushort)bytes.Length,MaximumLength=(ushort)(bytes.Length+2),Buffer=name};
   Marshal.StructureToPtr(value,unicode,false);
   var attributes=new ObjectAttributes{Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)),Root=parent.DangerousGetHandle(),Name=unicode,Attributes=0x40};
   SafeFileHandle file; IoStatusBlock io;
   int status=NtCreateFile(out file,0x40110000,ref attributes,out io,IntPtr.Zero,0x80,0,2,0x00200062,IntPtr.Zero,0);
   if(status!=0) { file.Dispose(); Check(status); }
   if(file.IsInvalid) { file.Dispose(); throw new IOException("Native create returned no handle."); }
   return file;
  } finally { if(held) parent.DangerousRelease(); Marshal.FreeHGlobal(unicode); Marshal.FreeHGlobal(name); }
 }
 public static byte[] RenameBuffer(IntPtr parent,string leaf) {
  Leaf(leaf); byte[] name=Encoding.Unicode.GetBytes(leaf); int offset=IntPtr.Size==8?20:12;
  byte[] data=new byte[offset+name.Length+2]; BitConverter.GetBytes(3U).CopyTo(data,0);
  if(IntPtr.Size==8) BitConverter.GetBytes(parent.ToInt64()).CopyTo(data,8);
  else BitConverter.GetBytes(parent.ToInt32()).CopyTo(data,4);
  BitConverter.GetBytes(name.Length).CopyTo(data,offset-4); name.CopyTo(data,offset); return data;
 }
 public static void RenameRelative(SafeFileHandle file,SafeFileHandle parent,string leaf) {
  bool held=false;
  try { parent.DangerousAddRef(ref held); byte[] data=RenameBuffer(parent.DangerousGetHandle(),leaf); IoStatusBlock io;
   Check(NtSetInformationFile(file,out io,data,(uint)data.Length,65));
  } finally { if(held) parent.DangerousRelease(); }
 }
 public static void SelfCheck() {
  if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(ObjectAttributes))!=48 || Marshal.SizeOf(typeof(UnicodeString))!=16 || Marshal.SizeOf(typeof(IoStatusBlock))!=16)
   throw new InvalidOperationException("Unexpected native packing.");
  byte[] data=RenameBuffer(new IntPtr(0x12345678),"destination.txt");
  if(BitConverter.ToUInt32(data,0)!=3 || BitConverter.ToInt64(data,8)!=0x12345678 || BitConverter.ToUInt32(data,16)!=30 || data[data.Length-1]!=0)
   throw new InvalidOperationException("Invalid parent-relative rename encoding.");
  foreach(string bad in new string[]{"", ".", "..", "../escape", "x:y", "x\\y", "*.txt"}) {
   bool refused=false; try { RenameBuffer(IntPtr.Zero,bad); } catch(ArgumentException) { refused=true; }
   if(!refused) throw new InvalidOperationException("Unsafe leaf accepted.");
  }
 }
}
'@
[BoundPublicationNativeControl]::SelfCheck()
Write-Output 'NativePackingAndLeafSelfCheck=PASS'
if ($SelfCheckOnly) { return }
$root = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-bound-publication-' + [Guid]::NewGuid().ToString('N'))
$parentPath = Join-Path $root 'parent'
$parent = $null
try {
    [void][IO.Directory]::CreateDirectory($parentPath)
    $parent = [BoundPublicationNativeControl]::Parent($parentPath)
    $parentId = [BoundPublicationNativeControl]::Identity($parent)
    foreach ($size in @(0, 37)) {
        $temporary = '.safeupload-' + [Guid]::NewGuid().ToString('N') + '.pending'
        $leaf = 'result-' + $size + '.txt'
        [byte[]]$bytes = @(for ($i=0; $i -lt $size; $i++) { [byte](65 + ($i % 20)) })
        $file = [BoundPublicationNativeControl]::CreateRelative($parent, $temporary)
        try {
            $id = [BoundPublicationNativeControl]::Identity($file)
            # FileStream owns this handle. Keep the original object through rename.
            $stream = [IO.FileStream]::new($file, [IO.FileAccess]::Write, 4096, $false)
            try {
                $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)
                [BoundPublicationNativeControl]::RenameRelative($file,$parent,$leaf)
                if ([BoundPublicationNativeControl]::Identity($file) -ne $id) { throw 'Rename changed full identity.' }
            } finally { $stream.Dispose() }
        } finally { $file.Dispose() }
        if (([IO.File]::ReadAllBytes((Join-Path $parentPath $leaf)) -join ',') -ne ($bytes -join ',')) { throw 'Published bytes differ.' }
        if (Test-Path -LiteralPath (Join-Path $parentPath $temporary)) { throw 'Temporary name remains.' }
        if ([BoundPublicationNativeControl]::Identity($parent) -ne $parentId) { throw 'Parent identity changed.' }
        Write-Output ('ParentRelativeCreateRename_'+$size+'=PASS Identity='+$id)
    }
    Write-Output 'BoundPublicationNativeControl=PASS'
} finally {
    if ($null -ne $parent) { $parent.Dispose() }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
