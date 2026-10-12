#requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfCheckOnly)
# Unprotected NTFS controls for the bound-writer design. No driver boot or
# protected-byte claim. All ACL changes are confined to the temporary fixture.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class WriterPermissionNativeControl {
 [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
 [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public uint Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Security, Qos; }
 [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
 public sealed class Result : IDisposable {
  public int Status; public long IoStatus; public ulong Information; public uint GrantedAccess;
  public SafeFileHandle Handle;
  public bool Accepted { get { return Status == 0 && IoStatus == 0 && Handle != null && !Handle.IsInvalid; } }
  public void Dispose() { if (Handle != null) Handle.Dispose(); }
 }
 [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
  out IoStatusBlock status, IntPtr allocation, uint attributesMask, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
 [DllImport("ntdll.dll")] static extern int NtQueryObject(SafeFileHandle handle, int kind, [Out] byte[] data, uint size, out uint returned);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int kind,byte[] data,uint size);
 public static Result Open(string path,uint access,uint share,uint disposition) {
  byte[] bytes=Encoding.Unicode.GetBytes("\\??\\"+Path.GetFullPath(path));
  IntPtr name=Marshal.AllocHGlobal(bytes.Length+2), unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
  try {
   Marshal.Copy(bytes,0,name,bytes.Length); Marshal.WriteInt16(name,bytes.Length,0);
   var value=new UnicodeString{Length=(ushort)bytes.Length,MaximumLength=(ushort)(bytes.Length+2),Buffer=name};
   Marshal.StructureToPtr(value,unicode,false);
   var attributes=new ObjectAttributes{Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)),Name=unicode,Attributes=0x40};
   SafeFileHandle handle; IoStatusBlock io;
   int status=NtCreateFile(out handle,access,ref attributes,out io,IntPtr.Zero,0x80,share,disposition,0x00200060,IntPtr.Zero,0);
   var result=new Result{Status=status,IoStatus=io.Status.ToInt64(),Information=io.Information.ToUInt64(),Handle=handle};
   if(result.Accepted) {
    byte[] basic=new byte[56]; uint returned;
    int query=NtQueryObject(handle,0,basic,(uint)basic.Length,out returned);
    if(query!=0 || returned<8) { result.Dispose(); throw new IOException("Granted-access query failed."); }
    result.GrantedAccess=BitConverter.ToUInt32(basic,4);
   }
   return result;
  } finally { Marshal.FreeHGlobal(unicode); Marshal.FreeHGlobal(name); }
 }
 public static string Identity(string path) {
  using(var result=Open(path,0x00100080,7,1)) {
   if(!result.Accepted) throw new IOException("Identity open failed: "+result.Status.ToString("X8"));
   byte[] bytes=new byte[24];
   if(!GetFileInformationByHandleEx(result.Handle,18,bytes,24)) throw new IOException("Full file-ID query failed.");
   return BitConverter.ToString(bytes).Replace("-","");
  }
 }
 public static uint CheckAccess(uint original,uint disposition) {
  // SeRestorePrivilege must not be enabled in these controls. This is a
  // candidate to compare with native NTFS, not production authorization.
  if(disposition==0) return original|0x00010000|0x00000110;
  if(disposition==4 || disposition==5) return original|0x00000002|0x00000110;
  if(disposition==1 || disposition==3) return original;
  throw new ArgumentException("Unsupported disposition.");
 }
 public static void SelfCheck() {
  if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(ObjectAttributes))!=48 || Marshal.SizeOf(typeof(UnicodeString))!=16 || Marshal.SizeOf(typeof(IoStatusBlock))!=16)
   throw new InvalidOperationException("Unexpected native packing.");
  if(CheckAccess(0x100002,1)!=0x100002 || CheckAccess(0x100002,3)!=0x100002 ||
     CheckAccess(0x100002,4)!=0x100112 || CheckAccess(0x100002,5)!=0x100112 || CheckAccess(0x100002,0)!=0x110112)
   throw new InvalidOperationException("Implicit-access matrix is malformed.");
 }
}
'@
[WriterPermissionNativeControl]::SelfCheck()
Write-Output 'NativePackingAndImplicitAccessSelfCheck=PASS'
if ($SelfCheckOnly) { return }

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$root = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-writer-permissions-' + [Guid]::NewGuid().ToString('N'))
$bytes = [Text.Encoding]::UTF8.GetBytes('original-seed-bytes')
$rows = New-Object 'Collections.Generic.List[object]'
function Set-FixtureAcl([string]$Path, [bool]$Directory, [int]$DeniedRights) {
    if ($Directory) { $acl = New-Object Security.AccessControl.DirectorySecurity }
    else { $acl = New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    if ($DeniedRights -ne 0) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,
            ([Security.AccessControl.FileSystemRights]$DeniedRights), [Security.AccessControl.AccessControlType]::Deny)))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,
        [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)))
    if ($Directory) { [IO.Directory]::SetAccessControl($Path, $acl) }
    else { [IO.File]::SetAccessControl($Path, $acl) }
}
$profiles = @(
    @{ Name='full'; Deny=0; ParentDenyDeleteChild=$true },
    @{ Name='deny-write-data'; Deny=2; ParentDenyDeleteChild=$true },
    @{ Name='deny-write-ea'; Deny=16; ParentDenyDeleteChild=$true },
    @{ Name='deny-write-attributes'; Deny=256; ParentDenyDeleteChild=$true },
    @{ Name='deny-delete'; Deny=65536; ParentDenyDeleteChild=$true },
    @{ Name='deny-delete-parent-allows'; Deny=65536; ParentDenyDeleteChild=$false },
    @{ Name='deny-read-data'; Deny=1; ParentDenyDeleteChild=$true }
)
try {
    [void][IO.Directory]::CreateDirectory($root)
    # Report privileges rather than silently enabling or disabling them.
    $privileges = (& whoami.exe /priv /fo csv | Out-String)
    Write-Output $privileges.TrimEnd()
    if ($LASTEXITCODE -ne 0) { throw 'Privilege inventory failed.' }
    if ($privileges -match '"SeRestorePrivilege"[^\r\n]*"Enabled"') { throw 'This control requires SeRestorePrivilege disabled.' }
    foreach ($profile in $profiles) {
        foreach ($disposition in @(0, 1, 3, 4, 5)) {
            $case = Join-Path $root ($profile.Name + '-' + $disposition)
            [void][IO.Directory]::CreateDirectory($case)
            $nativePath = Join-Path $case 'native.txt'
            $probePath = Join-Path $case 'probe.txt'
            [IO.File]::WriteAllBytes($nativePath, $bytes)
            [IO.File]::WriteAllBytes($probePath, $bytes)
            $id = [WriterPermissionNativeControl]::Identity($probePath)
            Set-FixtureAcl $case $true $(if ($profile.ParentDenyDeleteChild) { 64 } else { 0 })
            Set-FixtureAcl $nativePath $false $profile.Deny
            Set-FixtureAcl $probePath $false $profile.Deny
            $descriptor = [IO.File]::GetAccessControl($probePath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
            $native = $null; $probe = $null
            try {
                $native = [WriterPermissionNativeControl]::Open($nativePath, 0x00100002, 7, $disposition)
                $checkAccess = [WriterPermissionNativeControl]::CheckAccess(0x00100002, $disposition)
                $probe = [WriterPermissionNativeControl]::Open($probePath, $checkAccess, 7, 1)
                $row = [pscustomobject]@{ Profile=$profile.Name; Disposition=$disposition;
                    NativeStatus=('0x{0:X8}' -f $native.Status); NativeIoStatus=$native.IoStatus;
                    NativeInformation=$native.Information; NativeGranted=('0x{0:X8}' -f $native.GrantedAccess);
                    ProbeStatus=('0x{0:X8}' -f $probe.Status); ProbeIoStatus=$probe.IoStatus;
                    ProbeInformation=$probe.Information; ProbeGranted=('0x{0:X8}' -f $probe.GrantedAccess);
                    OutcomeEquivalent=($native.Accepted -eq $probe.Accepted) }
                $rows.Add($row); Write-Output ($row | ConvertTo-Json -Compress)
            } finally {
                if ($null -ne $probe) { $probe.Dispose() }
                if ($null -ne $native) { $native.Dispose() }
            }
            if ([WriterPermissionNativeControl]::Identity($probePath) -ne $id) { throw 'Probe changed full file identity.' }
            if ([IO.File]::GetAccessControl($probePath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -ne $descriptor) { throw 'Probe changed security.' }
            Set-FixtureAcl $nativePath $false 0
            Set-FixtureAcl $probePath $false 0
            Set-FixtureAcl $case $true 0
            if (([IO.File]::ReadAllBytes($probePath) -join ',') -ne ($bytes -join ',')) { throw 'Probe changed source bytes.' }
        }
    }
    $mismatches = @($rows | Where-Object { -not $_.OutcomeEquivalent })
    Write-Output ('NativePermissionRows=' + $rows.Count + ' Mismatches=' + $mismatches.Count)
    if ($mismatches.Count -ne 0) { throw 'Candidate permission checks do not match native NTFS; design remains REVISE.' }
    Write-Output 'WriterPermissionNativeControl=PASS'
} finally {
    if (Test-Path -LiteralPath $root) {
        Get-ChildItem -LiteralPath $root -File -Recurse -Force | ForEach-Object { Set-FixtureAcl $_.FullName $false 0 }
        Get-ChildItem -LiteralPath $root -Directory -Recurse -Force | ForEach-Object { Set-FixtureAcl $_.FullName $true 0 }
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
