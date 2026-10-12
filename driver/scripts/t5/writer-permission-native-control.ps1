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
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class WriterPermissionNativeControl {
 [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
 [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public uint Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Security, Qos; }
 [StructLayout(LayoutKind.Sequential)] struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Id; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential)] struct GenericMapping { public uint Read, Write, Execute, All; }
 [DllImport("advapi32.dll")] static extern void MapGenericMask(ref uint mask,ref GenericMapping mapping);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token,uint access,IntPtr attributes,int level,int type,out IntPtr copy);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disableAll,ref TokenPrivileges state,uint size,out TokenPrivileges previous,out uint returned);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,byte[] data,uint size,out uint returned);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(SafeFileHandle handle,uint information,byte[] data,uint size,out uint needed);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 // Only the private impersonation-token copy is changed. Restore the
 // previous thread context on every exit; never adjust the process token.
 sealed class Subject : IDisposable {
  IntPtr token; WindowsImpersonationContext context;
  public Subject() {
   IntPtr source=IntPtr.Zero;
   try {
    if(!OpenProcessToken(new IntPtr(-1),0xA,out source) ||
       !DuplicateTokenEx(source,0x2E,IntPtr.Zero,2,2,out token)) throw new IOException("Subject token copy failed.");
    Luid restore; if(!LookupPrivilegeValue(null,"SeRestorePrivilege",out restore)) throw new IOException("Restore privilege lookup failed.");
    var state=new TokenPrivileges{Count=1,Id=restore}; TokenPrivileges previous; uint returned;
    if(!AdjustTokenPrivileges(token,false,ref state,(uint)Marshal.SizeOf(typeof(TokenPrivileges)),out previous,out returned))
     throw new IOException("Private-token privilege adjustment failed.");
    uint needed; GetTokenInformation(token,3,null,0,out needed); byte[] data=new byte[needed];
    if(!GetTokenInformation(token,3,data,needed,out needed)) throw new IOException("Private-token privilege query failed.");
    uint count=BitConverter.ToUInt32(data,0);
    for(uint i=0;i<count;i++) {
     int offset=checked(4+(int)i*12);
     if(BitConverter.ToUInt32(data,offset)==restore.Low && BitConverter.ToInt32(data,offset+4)==restore.High &&
        (BitConverter.ToUInt32(data,offset+8)&2)!=0) throw new IOException("Restore privilege remains enabled.");
    }
    context=WindowsIdentity.Impersonate(token);
   } catch { Dispose(); throw; }
   finally { if(source!=IntPtr.Zero) CloseHandle(source); }
  }
  public void Dispose() {
   if(context!=null) { context.Dispose(); context=null; }
   if(token!=IntPtr.Zero) { CloseHandle(token); token=IntPtr.Zero; }
  }
 }
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
  return OpenCore(path,access,share,disposition,0x00200060,null);
 }
 public static Result OpenWithDescriptor(string path,uint access,uint share,uint disposition,byte[] security) {
  return OpenCore(path,access,share,disposition,0x00200060,security);
 }
 public static Result Revalidate(string path) { return OpenCore(path,0,7,1,0x00200040,null); }
 public static Result Metadata(string path) { return OpenCore(path,0x01020000,7,1,0x00200040,null); }
 static Result OpenCore(string path,uint access,uint share,uint disposition,uint options,byte[] security) {
  using(var subject=new Subject()) {
  byte[] bytes=Encoding.Unicode.GetBytes("\\??\\"+Path.GetFullPath(path));
  IntPtr name=Marshal.AllocHGlobal(bytes.Length+2), unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString))), descriptor=IntPtr.Zero;
  try {
   if(security!=null) { descriptor=Marshal.AllocHGlobal(security.Length); Marshal.Copy(security,0,descriptor,security.Length); }
   Marshal.Copy(bytes,0,name,bytes.Length); Marshal.WriteInt16(name,bytes.Length,0);
   var value=new UnicodeString{Length=(ushort)bytes.Length,MaximumLength=(ushort)(bytes.Length+2),Buffer=name};
   Marshal.StructureToPtr(value,unicode,false);
   var attributes=new ObjectAttributes{Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)),Name=unicode,Attributes=0x40,Security=descriptor};
   SafeFileHandle handle; IoStatusBlock io;
   int status=NtCreateFile(out handle,access,ref attributes,out io,IntPtr.Zero,0x80,share,disposition,options,IntPtr.Zero,0);
   var result=new Result{Status=status,IoStatus=io.Status.ToInt64(),Information=io.Information.ToUInt64(),Handle=handle};
   if(result.Accepted) {
    byte[] basic=new byte[56]; uint returned;
    int query=NtQueryObject(handle,0,basic,(uint)basic.Length,out returned);
    if(query!=0 || returned<8) { result.Dispose(); throw new IOException("Granted-access query failed."); }
    result.GrantedAccess=BitConverter.ToUInt32(basic,4);
   }
   return result;
  } finally { if(descriptor!=IntPtr.Zero) Marshal.FreeHGlobal(descriptor); Marshal.FreeHGlobal(unicode); Marshal.FreeHGlobal(name); }
  }
 }
 public static string Identity(string path) {
  using(var result=Open(path,0x00100080,7,1)) {
   if(!result.Accepted) throw new IOException("Identity open failed: "+result.Status.ToString("X8"));
   return IdentityHandle(result.Handle);
  }
 }
 public static string IdentityHandle(SafeFileHandle handle) {
  byte[] bytes=new byte[24];
  if(!GetFileInformationByHandleEx(handle,18,bytes,24)) throw new IOException("Full file-ID query failed: "+Marshal.GetLastWin32Error());
  return BitConverter.ToString(bytes).Replace("-","");
 }
 public static string Security(SafeFileHandle handle) {
  uint needed; GetKernelObjectSecurity(handle,0x1F,null,0,out needed); byte[] data=new byte[needed];
  if(!GetKernelObjectSecurity(handle,0x1F,data,needed,out needed)) throw new IOException("Complete security query failed: "+Marshal.GetLastWin32Error());
  return new System.Security.AccessControl.RawSecurityDescriptor(data,0).GetSddlForm(System.Security.AccessControl.AccessControlSections.All);
 }
 public static uint CheckAccess(uint original,uint disposition) {
  // SeRestorePrivilege must not be enabled in these controls. This is a
  // candidate to compare with native NTFS, not production authorization.
  if(disposition==0) return original|0x00010000|0x00000110;
  if(disposition==4 || disposition==5) return original|0x00000002|0x00000110;
  if(disposition==1 || disposition==3) return original;
  throw new ArgumentException("Unsupported disposition.");
 }
 public static uint ProjectGrant(uint original,uint checkedGrant) {
  if((original&0x02000000)!=0) return checkedGrant;
  var mapping=new GenericMapping{Read=0x120089,Write=0x120116,Execute=0x1200A0,All=0x1F01FF};
  MapGenericMask(ref original,ref mapping); return checkedGrant&original;
 }
 public static void SelfCheck() {
  if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(ObjectAttributes))!=48 || Marshal.SizeOf(typeof(UnicodeString))!=16 || Marshal.SizeOf(typeof(IoStatusBlock))!=16 || Marshal.SizeOf(typeof(TokenPrivileges))!=16)
   throw new InvalidOperationException("Unexpected native packing.");
  if(CheckAccess(0x100002,1)!=0x100002 || CheckAccess(0x100002,3)!=0x100002 ||
     CheckAccess(0x100002,4)!=0x100112 || CheckAccess(0x100002,5)!=0x100112 || CheckAccess(0x100002,0)!=0x110112)
   throw new InvalidOperationException("Implicit-access matrix is malformed.");
  if(ProjectGrant(0x40000000,0x1F01FF)!=0x120116 || ProjectGrant(0x100002,0x110112)!=0x100002)
   throw new InvalidOperationException("App-grant projection is malformed.");
 }
 public static void RequireSubject() { using(var subject=new Subject()) {} }
 public static string ProcessPrivileges() {
  IntPtr token; if(!OpenProcessToken(new IntPtr(-1),8,out token)) throw new IOException("Process privilege query open failed.");
  try {
   uint needed; GetTokenInformation(token,3,null,0,out needed); byte[] bytes=new byte[needed];
   if(!GetTokenInformation(token,3,bytes,needed,out needed)) throw new IOException("Process privilege query failed.");
   return Convert.ToBase64String(bytes);
  } finally { CloseHandle(token); }
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
$cases = @()
foreach ($profile in $profiles) {
    $cases += $profile
    foreach ($share in @(1, 3, 7)) {
        $cases += @{ Name=($profile.Name + '-guard-share-' + $share); Deny=$profile.Deny;
            ParentDenyDeleteChild=$profile.ParentDenyDeleteChild; GuardShare=$share }
    }
}
try {
    [void][IO.Directory]::CreateDirectory($root)
    # Process privileges are recorded and never changed. Native calls use
    # a scoped private token copy with Restore disabled.
    $privileges = (& whoami.exe /priv /fo csv | Out-String)
    Write-Output $privileges.TrimEnd()
    if ($LASTEXITCODE -ne 0) { throw 'Privilege inventory failed.' }
    $processPrivileges = [WriterPermissionNativeControl]::ProcessPrivileges()
    [WriterPermissionNativeControl]::RequireSubject()
    if ([WriterPermissionNativeControl]::ProcessPrivileges() -ne $processPrivileges) { throw 'Subject check changed process privileges.' }
    Write-Output 'PrivateNativeSubjectRestoreDisabled=PASS ProcessTokenUnchanged=True'
    foreach ($denyAttributes in @($false,$true)) {
        $path=Join-Path $root ('zero-revalidation-' + $denyAttributes + '.txt')
        [IO.File]::WriteAllBytes($path,$bytes)
        $identity=[WriterPermissionNativeControl]::Identity($path)
        Set-FixtureAcl $path $false $(if($denyAttributes) {128} else {0})
        $lease=$null; $zero=$null; $metadata=$null
        try {
            $lease=[WriterPermissionNativeControl]::Open($path,0x00100002,0,1)
            if(-not $lease.Accepted) { throw 'Original share-zero writer lease failed.' }
            $zero=[WriterPermissionNativeControl]::Revalidate($path)
            if(-not $zero.Accepted -or $zero.GrantedAccess -ne 0) { throw 'Zero-access path check failed or acquired authority.' }
            $zeroId=$null; $zeroIdError=$null
            try { $zeroId=[WriterPermissionNativeControl]::IdentityHandle($zero.Handle) }
            catch { $zeroIdError=$_.Exception.Message }
            if($null -ne $zeroId -and $zeroId -ne $identity) { throw 'Zero-access check resolved another file.' }
            $metadata=[WriterPermissionNativeControl]::Metadata($path)
            if(-not $metadata.Accepted -or $metadata.GrantedAccess -ne 0x01020000) { throw 'Read-only security metadata check failed or acquired data authority.' }
            $security=[WriterPermissionNativeControl]::Security($metadata.Handle)
            Write-Output ([pscustomobject]@{Control='ShareZeroRevalidation';DenyReadAttributes=$denyAttributes;
                ZeroGranted=('0x{0:X8}' -f $zero.GrantedAccess);ZeroId=$zeroId;ZeroIdError=$zeroIdError;
                MetadataGranted=('0x{0:X8}' -f $metadata.GrantedAccess);Security=$security} | ConvertTo-Json -Compress)
        } finally {
            if($null -ne $metadata) {$metadata.Dispose()}; if($null -ne $zero) {$zero.Dispose()}; if($null -ne $lease) {$lease.Dispose()}
        }
        Set-FixtureAcl $path $false 0
        if([WriterPermissionNativeControl]::Identity($path) -ne $identity -or
            ([IO.File]::ReadAllBytes($path) -join ',') -ne ($bytes -join ',')) { throw 'Revalidation changed source identity or bytes.' }
    }
    $explicit=New-Object Security.AccessControl.FileSecurity
    $explicit.SetSecurityDescriptorSddlForm(('O:'+ $sid.Value + 'G:' + $sid.Value + 'D:P(A;;FR;;;' + $sid.Value + ')'))
    $explicitBytes=$explicit.GetSecurityDescriptorBinaryForm()
    foreach($present in @($false,$true)) {
        $dispositions=$(if($present) {@(0,1,3,4,5)} else {@(0,2,3,5)})
        foreach($disposition in $dispositions) {
            $path=Join-Path $root ('explicit-descriptor-' + $present + '-' + $disposition + '.txt')
            $before=$null
            if($present) {
                [IO.File]::WriteAllBytes($path,$bytes)
                $before=[IO.File]::GetAccessControl($path,[Security.AccessControl.AccessControlSections]::All).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
            }
            $file=[WriterPermissionNativeControl]::OpenWithDescriptor($path,0x00100002,7,$disposition,$explicitBytes)
            try {
                if(-not $file.Accepted) { throw ('Explicit descriptor native CREATE failed: 0x{0:X8}' -f $file.Status) }
                $after=[IO.File]::GetAccessControl($path,[Security.AccessControl.AccessControlSections]::All).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
                Write-Output ([pscustomobject]@{Control='SuppliedDescriptor';Present=$present;Disposition=$disposition;
                    Information=$file.Information;Granted=('0x{0:X8}' -f $file.GrantedAccess);SecurityBefore=$before;SecurityAfter=$after;
                    ExistingSecurityRetained=($present -and $before -eq $after)} | ConvertTo-Json -Compress)
            } finally {$file.Dispose()}
            Set-FixtureAcl $path $false 0
        }
    }
    foreach ($profile in $cases) {
        foreach ($disposition in @(0, 1, 3, 4, 5)) {
          foreach ($access in @([uint32]0x00100002, [uint32]0x00100004, [uint32]0x00100001,
              [uint32]0x40100000, [uint32]3222274048, [uint32]0x10100000, [uint32]0x02100000)) {
            $case = Join-Path $root ($profile.Name + '-' + $disposition + '-' + $access.ToString('X8'))
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
            $nativeDescriptor = [IO.File]::GetAccessControl($nativePath, [Security.AccessControl.AccessControlSections]::All).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
            $native = $null; $probe = $null; $nativeGuard = $null; $probeGuard = $null
            try {
                if ($null -ne $profile.GuardShare) {
                    # The guard observes attributes only when READ_DATA is denied.
                    # Otherwise it reserves the native read-sharing class.
                    $guardAccess = $(if (($profile.Deny -band 1) -ne 0) { 0x00100080 } else { 0x00100081 })
                    $nativeGuard = [WriterPermissionNativeControl]::Open($nativePath, $guardAccess, $profile.GuardShare, 1)
                    $probeGuard = [WriterPermissionNativeControl]::Open($probePath, $guardAccess, $profile.GuardShare, 1)
                    if (-not $nativeGuard.Accepted -or -not $probeGuard.Accepted) { throw 'Sharing guard could not open.' }
                }
                $native = [WriterPermissionNativeControl]::Open($nativePath, $access, 7, $disposition)
                $checkAccess = [WriterPermissionNativeControl]::CheckAccess($access, $disposition)
                $probe = [WriterPermissionNativeControl]::Open($probePath, $checkAccess, 7, 1)
                $projection = [WriterPermissionNativeControl]::ProjectGrant($access, $probe.GrantedAccess)
                $nativeAfter = [IO.File]::GetAccessControl($nativePath, [Security.AccessControl.AccessControlSections]::All).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
                $row = [pscustomobject]@{ Profile=$profile.Name; Disposition=$disposition; GuardShare=$profile.GuardShare;
                    RequestedAccess=('0x{0:X8}' -f $access); ProjectedAppGrant=('0x{0:X8}' -f $projection);
                    NativeSecurityBefore=$nativeDescriptor; NativeSecurityAfter=$nativeAfter;
                    NativeStatus=('0x{0:X8}' -f $native.Status); NativeIoStatus=$native.IoStatus;
                    NativeInformation=$native.Information; NativeGranted=('0x{0:X8}' -f $native.GrantedAccess);
                    ProbeStatus=('0x{0:X8}' -f $probe.Status); ProbeIoStatus=$probe.IoStatus;
                    ProbeInformation=$probe.Information; ProbeGranted=('0x{0:X8}' -f $probe.GrantedAccess);
                    OutcomeEquivalent=($native.Accepted -eq $probe.Accepted -and $native.Status -eq $probe.Status);
                    AppGrantEquivalent=(-not $native.Accepted -or ($probe.Accepted -and $native.GrantedAccess -eq $projection)) }
                $rows.Add($row); Write-Output ($row | ConvertTo-Json -Compress)
                if ($profile.Name -eq 'full' -and -not $native.Accepted) {
                    throw ('Positive native fixture was denied: access=0x{0:X8} disposition={1} status=0x{2:X8}' -f $access,$disposition,$native.Status)
                }
            } finally {
                if ($null -ne $probe) { $probe.Dispose() }
                if ($null -ne $native) { $native.Dispose() }
                if ($null -ne $probeGuard) { $probeGuard.Dispose() }
                if ($null -ne $nativeGuard) { $nativeGuard.Dispose() }
            }
            if ([WriterPermissionNativeControl]::Identity($probePath) -ne $id) { throw 'Probe changed full file identity.' }
            if ([IO.File]::GetAccessControl($probePath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -ne $descriptor) { throw 'Probe changed security.' }
            Set-FixtureAcl $nativePath $false 0
            Set-FixtureAcl $probePath $false 0
            Set-FixtureAcl $case $true 0
            if (([IO.File]::ReadAllBytes($probePath) -join ',') -ne ($bytes -join ',')) { throw 'Probe changed source bytes.' }
          }
        }
    }
    $mismatches = @($rows | Where-Object { -not $_.OutcomeEquivalent -or -not $_.AppGrantEquivalent })
    if ([WriterPermissionNativeControl]::ProcessPrivileges() -ne $processPrivileges) { throw 'Native controls changed process privileges.' }
    Write-Output 'ProcessPrivilegesRetained=PASS'
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
