#requires -Version 5.1
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class NtfsDispositionControl {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]
 static extern bool SetFileInformationByHandle(SafeFileHandle h,int c,byte[] b,uint n);
 public static SafeFileHandle Open(string p) {
  return OpenFlags(p,0x80);
 }
 public static SafeFileHandle OpenFlags(string p,uint flags) {
  var h=CreateFileW(p,0x10000,7,IntPtr.Zero,3,flags,IntPtr.Zero);
  if(h.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return h;
 }
 public static int DeleteOpen(string p) {
  using(var h=CreateFileW(p,0x10000,7,IntPtr.Zero,3,0x80,IntPtr.Zero))
   return h.IsInvalid?Marshal.GetLastWin32Error():0;
 }
 public static string Set(SafeFileHandle h,bool delete,bool onClose) {
  byte[] b=onClose?BitConverter.GetBytes((uint)(8|(delete?1:0))):new byte[]{(byte)(delete?1:0)};
  bool ok=SetFileInformationByHandle(h,onClose?21:4,b,(uint)b.Length);
  return "Success="+ok+";Win32="+(ok?0:Marshal.GetLastWin32Error());
 }
 public static int Probe(string p) {
  using(var h=CreateFileW(p,0x80,7,IntPtr.Zero,3,0x80,IntPtr.Zero))
   return h.IsInvalid?Marshal.GetLastWin32Error():0;
 }
}
'@
'PSVersion='+$PSVersionTable.PSVersion
$root=Join-Path ([IO.Path]::GetTempPath()) ('safeupload-ntfs-disposition-'+[guid]::NewGuid().ToString('N'))
$volume=Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($root).Substring(0,1))
'NativeControlFileSystem='+$volume.FileSystem
if($volume.FileSystem -ne 'NTFS'){throw 'This control requires NTFS'}
$null=New-Item -ItemType Directory -Path $root
try {
 foreach($mode in @('ordinary-clear-before-cleanup','ordinary-clear-after-cleanup','onclose-other-handle-clear')) {
  $path=Join-Path $root ($mode+'.txt');[IO.File]::WriteAllText($path,'control')
  $a=[NtfsDispositionControl]::Open($path);$b=[NtfsDispositionControl]::Open($path)
  try {
   $onClose=$mode -eq 'onclose-other-handle-clear'
   $set=[NtfsDispositionControl]::Set($a,$true,$onClose)
   $pending=[NtfsDispositionControl]::Probe($path)
   if($mode -eq 'ordinary-clear-after-cleanup'){$a.Dispose()}
   $clear=[NtfsDispositionControl]::Set($b,$false,$onClose)
   $afterClear=[NtfsDispositionControl]::Probe($path)
  }finally{$a.Dispose();$b.Dispose()}
  'Case='+$mode+';Set='+$set+';ProbePendingWin32='+$pending+';ClearOther='+$clear+';ProbeAfterClearWin32='+$afterClear+';ExistsAfterClose='+[IO.File]::Exists($path)
  if(-not $onClose -and ($set -ne 'Success=True;Win32=0' -or $clear -ne 'Success=True;Win32=0' -or $pending -ne 5 -or $afterClear -ne 0 -or -not [IO.File]::Exists($path))){throw 'Native ordinary disposition control failed'}
 }
 $path=Join-Path $root 'create-onclose.txt';[IO.File]::WriteAllText($path,'control')
 $b=[NtfsDispositionControl]::Open($path);$a=[NtfsDispositionControl]::OpenFlags($path,0x04000080)
 try {
  $pending=[NtfsDispositionControl]::Probe($path)
  $clear=[NtfsDispositionControl]::Set($b,$false,$false)
  $afterClear=[NtfsDispositionControl]::Probe($path)
  $a.Dispose();$afterCreatorClose=[NtfsDispositionControl]::Probe($path)
 }finally{$a.Dispose();$b.Dispose()}
 'Case=create-delete-on-close;ProbePendingWin32='+$pending+';ClearOther='+$clear+';ProbeAfterClearWin32='+$afterClear+';ProbeAfterCreatorCloseWin32='+$afterCreatorClose+';ExistsAfterClose='+[IO.File]::Exists($path)
 if($pending -ne 0 -or $clear -ne 'Success=True;Win32=0' -or $afterClear -ne 0 -or $afterCreatorClose -ne 5 -or [IO.File]::Exists($path)){throw 'Native CREATE delete-on-close control failed'}

 $parent=Join-Path $root 'delete-child-authority';$null=New-Item -ItemType Directory -Path $parent
 $path=Join-Path $parent 'target.txt';[IO.File]::WriteAllText($path,'control')
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $fileAcl=[Security.AccessControl.FileSecurity]::new();$fileAcl.SetOwner($sid);$fileAcl.SetAccessRuleProtection($true,$false)
 $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::Delete,[Security.AccessControl.AccessControlType]::Deny))
 $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,([Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Synchronize),[Security.AccessControl.AccessControlType]::Allow))
 Set-Acl -LiteralPath $path -AclObject $fileAcl
 $parentAcl=[Security.AccessControl.DirectorySecurity]::new();$parentAcl.SetOwner($sid);$parentAcl.SetAccessRuleProtection($true,$false)
 $parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
 Set-Acl -LiteralPath $parent -AclObject $parentAcl
 try {
  $allowed=[NtfsDispositionControl]::DeleteOpen($path)
  $deniedAcl=[Security.AccessControl.DirectorySecurity]::new();$deniedAcl.SetOwner($sid);$deniedAcl.SetAccessRuleProtection($true,$false)
  $deniedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,[Security.AccessControl.AccessControlType]::Deny))
  $deniedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,([Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Write),[Security.AccessControl.AccessControlType]::Allow))
  Set-Acl -LiteralPath $parent -AclObject $deniedAcl
  $denied=[NtfsDispositionControl]::DeleteOpen($path)
  'Case=delete-child-authority;FileDeleteExplicitlyDenied=True;ParentDeleteChildGrantedOpenWin32='+$allowed+';BothDeniedOpenWin32='+$denied
  if($allowed -ne 0 -or $denied -ne 5){throw 'Native DELETE_CHILD authority control failed'}
 }finally{Set-Acl -LiteralPath $parent -AclObject $parentAcl}
 'NtfsDispositionControl=COMPLETE;ProductQualified=False'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
