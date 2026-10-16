#requires -Version 5.1
# Native measurement support only. Loading this file runs managed signature/packing checks, never native code.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class SecurityDescriptorNativeControl {
 [StructLayout(LayoutKind.Sequential)] struct GenericMapping { public uint Read, Write, Execute, All; }
 [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct TokenPrivileges { public uint Count; public Luid Id; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct StreamHeader {
  public uint Id, Attributes; public long Size; public uint NameBytes; public char FirstNameCharacter;
 }
 [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet=CharSet.Unicode)]
 delegate void Progress([MarshalAs(UnmanagedType.LPWStr)] string name, uint status, ref int setting, IntPtr args,
  [MarshalAs(UnmanagedType.Bool)] bool securitySet);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool ConvertToAutoInheritPrivateObjectSecurity([In] byte[] parent, [In] byte[] current, out IntPtr result,
  IntPtr objectType, byte isDirectory, ref GenericMapping mapping); // BOOLEAN, not BOOL.
 [DllImport("advapi32.dll", ExactSpelling=true)] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool DestroyPrivateObjectSecurity(ref IntPtr descriptor);
 [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode)]
 static extern uint SetNamedSecurityInfoW(string path, int kind, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
 [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode)]
 static extern uint TreeResetNamedSecurityInfoW(string path, int kind, uint information, IntPtr owner, IntPtr group, IntPtr dacl,
  IntPtr sacl, [MarshalAs(UnmanagedType.Bool)] bool keepExplicit, Progress progress, int setting, IntPtr args);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool AccessCheck([In] byte[] descriptor, IntPtr token, uint desired, ref GenericMapping mapping,
  [Out] byte[] privileges, ref uint privilegeBytes, out uint granted, [MarshalAs(UnmanagedType.Bool)] out bool allowed);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool OpenThreadToken(IntPtr thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool asSelf, out IntPtr token);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int type, out IntPtr copy);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disabledCount, IntPtr disabled, uint deletedCount,
  IntPtr deleted, uint restrictedCount, [In] SidAndAttributes[] restricted, out IntPtr copy);
 [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool LookupPrivilegeValueW(string system, string name, out Luid id);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TokenPrivileges state,
  uint size, IntPtr previous, IntPtr returned);
 [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool SetThreadToken(IntPtr thread, IntPtr token);
 [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool BackupRead(SafeFileHandle file, [Out] byte[] buffer, uint size, out uint read,
  [MarshalAs(UnmanagedType.Bool)] bool abort, [MarshalAs(UnmanagedType.Bool)] bool security, ref IntPtr context);
 [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)]
 static extern bool BackupWrite(SafeFileHandle file, [In] byte[] buffer, uint size, out uint written,
  [MarshalAs(UnmanagedType.Bool)] bool abort, [MarshalAs(UnmanagedType.Bool)] bool security, ref IntPtr context);
 static GenericMapping FileMapping() { return new GenericMapping{Read=0x120089,Write=0x120116,Execute=0x1200A0,All=0x1F01FF}; }
 static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
 public static byte[] Convert(byte[] parent, byte[] expected) {
  var mapping=FileMapping(); IntPtr output=IntPtr.Zero;
  try {
   Check(ConvertToAutoInheritPrivateObjectSecurity(parent,expected,out output,IntPtr.Zero,0,ref mapping));
   uint size=GetSecurityDescriptorLength(output);
   if(size<20 || size>131228) throw new IOException("Converted descriptor exceeds the fixture bound.");
   byte[] bytes=new byte[size]; Marshal.Copy(output,bytes,0,bytes.Length); return bytes;
  } finally { if(output!=IntPtr.Zero) Check(DestroyPrivateObjectSecurity(ref output)); }
 }
 static IntPtr Dacl(byte[] descriptor) {
  var raw=new RawSecurityDescriptor(descriptor,0);
  if(raw.DiscretionaryAcl==null) throw new ArgumentException("A non-NULL fixture DACL is required.");
  byte[] bytes=new byte[raw.DiscretionaryAcl.BinaryLength]; raw.DiscretionaryAcl.GetBinaryForm(bytes,0);
  IntPtr acl=Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes,0,acl,bytes.Length); return acl;
 }
 public static void SetParentDacl(string path, byte[] descriptor) {
  IntPtr acl=Dacl(descriptor);
  try { uint error=SetNamedSecurityInfoW(path,1,4,IntPtr.Zero,IntPtr.Zero,acl,IntPtr.Zero); if(error!=0) throw new Win32Exception((int)error); }
  finally { Marshal.FreeHGlobal(acl); }
 }
 public sealed class TreeRow { public string Name; public uint Status; public bool SecuritySet; }
 public static TreeRow[] ResetTree(string path, byte[] descriptor, bool keepExplicit) {
  IntPtr acl=Dacl(descriptor); var receipts=new List<TreeRow>(); uint firstError=0;
  Progress callback=delegate(string name,uint error,ref int setting,IntPtr args,bool securitySet) {
   receipts.Add(new TreeRow{Name=name,Status=error,SecuritySet=securitySet});
   if(error!=0 && firstError==0) firstError=error;
  };
  try {
   uint error=TreeResetNamedSecurityInfoW(path,1,4,IntPtr.Zero,IntPtr.Zero,acl,IntPtr.Zero,keepExplicit,callback,2,IntPtr.Zero);
   GC.KeepAlive(callback);
   if(error!=0 || firstError!=0) throw new Win32Exception((int)(error!=0?error:firstError),"Tree reset or child callback failed.");
   if(receipts.Count==0) throw new IOException("Tree reset reported no object callbacks.");
   return receipts.ToArray();
  } finally { Marshal.FreeHGlobal(acl); }
 }
 public sealed class AccessRow {
  public string Sid; public uint Desired, Granted; public bool Allowed;
 }
 // These are fixed restricted-SID probes of a SYSTEM-derived impersonation token, not tokens for arbitrary users.
 public static readonly string[] ProbeSids={"S-1-5-18","S-1-1-0","S-1-5-11","S-1-5-32-545","S-1-5-7"};
 public static readonly uint[] ProbeRights={1,2,4,0x20,0x80,0x100,0x10000,0x20000,0x40000,0x80000,0x120089,0x120116,0x1F01FF,0x02000000};
 public static AccessRow[] AccessMatrix(byte[] descriptor) {
  var rows=new List<AccessRow>(); IntPtr process=IntPtr.Zero, impersonation=IntPtr.Zero;
  try {
   Check(OpenProcessToken(new IntPtr(-1),0xA,out process));
   Check(DuplicateTokenEx(process,0xA,IntPtr.Zero,2,2,out impersonation));
   foreach(string sid in ProbeSids) {
    byte[] bytes=new byte[new SecurityIdentifier(sid).BinaryLength]; new SecurityIdentifier(sid).GetBinaryForm(bytes,0);
    IntPtr binary=Marshal.AllocHGlobal(bytes.Length), restricted=IntPtr.Zero;
    try {
     Marshal.Copy(bytes,0,binary,bytes.Length);
     Check(CreateRestrictedToken(impersonation,1,0,IntPtr.Zero,0,IntPtr.Zero,1,new SidAndAttributes[]{new SidAndAttributes{Sid=binary}},out restricted));
     foreach(uint desired in ProbeRights) {
      uint size=1024,granted; bool allowed; byte[] privileges=new byte[size]; var mapping=FileMapping();
      Check(AccessCheck(descriptor,restricted,desired,ref mapping,privileges,ref size,out granted,out allowed));
      rows.Add(new AccessRow{Sid=sid,Desired=desired,Granted=granted,Allowed=allowed});
     }
    } finally { if(restricted!=IntPtr.Zero) Check(CloseHandle(restricted)); Marshal.FreeHGlobal(binary); }
   }
   return rows.ToArray();
  } finally { if(impersonation!=IntPtr.Zero) Check(CloseHandle(impersonation)); if(process!=IntPtr.Zero) Check(CloseHandle(process)); }
 }
 // Only backup/restore uses these privileges, on a private thread token. CREATE measurements never use it.
 sealed class BackupSubject : IDisposable {
  IntPtr token, previous; bool attached;
  public BackupSubject() {
   IntPtr process=IntPtr.Zero;
   try {
    if(!OpenThreadToken(new IntPtr(-2),0xC,true,out previous) && Marshal.GetLastWin32Error()!=1008) Check(false);
    Check(OpenProcessToken(new IntPtr(-1),0xA,out process));
    Check(DuplicateTokenEx(process,0x2E,IntPtr.Zero,2,2,out token));
    foreach(string name in new string[]{"SeBackupPrivilege","SeRestorePrivilege","SeSecurityPrivilege"}) {
     Luid id; Check(LookupPrivilegeValueW(null,name,out id)); var state=new TokenPrivileges{Count=1,Id=id,Attributes=2};
     Check(AdjustTokenPrivileges(token,false,ref state,0,IntPtr.Zero,IntPtr.Zero));
     if(Marshal.GetLastWin32Error()==1300) throw new IOException("Private backup privilege unavailable: "+name);
    }
    Check(SetThreadToken(IntPtr.Zero,token)); attached=true;
   } catch { Dispose(); throw; }
   finally { if(process!=IntPtr.Zero) Check(CloseHandle(process)); }
  }
  public void Dispose() {
   try { if(attached) { Check(SetThreadToken(IntPtr.Zero,previous)); attached=false; } }
   finally { if(token!=IntPtr.Zero) { Check(CloseHandle(token)); token=IntPtr.Zero; } if(previous!=IntPtr.Zero) { Check(CloseHandle(previous)); previous=IntPtr.Zero; } }
  }
 }
 public static byte[] SecurityStream(byte[] backup) {
  int offset=0; byte[] security=null;
  while(offset<backup.Length) {
   if(backup.Length-offset<20) throw new IOException("Truncated backup header.");
   uint id=BitConverter.ToUInt32(backup,offset),name=BitConverter.ToUInt32(backup,offset+16);
   long size=BitConverter.ToInt64(backup,offset+8), start=(long)offset+20+name, end=start+size;
   if(size<0 || start>backup.Length || end<start || end>backup.Length) throw new IOException("Invalid backup stream bounds.");
   if(id==3) {
    if(security!=null || size<20) throw new IOException("Missing or duplicate backup security payload.");
    security=new byte[checked((int)size)]; Array.Copy(backup,(int)start,security,0,security.Length);
   }
   offset=(int)end;
  }
  if(security==null) throw new IOException("BackupRead omitted BACKUP_SECURITY_DATA.");
  return security;
 }
 static SafeFileHandle BackupFile(string path,uint access) {
  var file=CreateFileW(path,access,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(file.IsInvalid) { int error=Marshal.GetLastWin32Error(); file.Dispose(); throw new Win32Exception(error,"Backup handle open failed: "+path); }
  return file;
 }
 public static byte[] BackupRoundTrip(string source, string destination) {
  using(var subject=new BackupSubject())
  using(var input=BackupFile(source,0x81000000))
  using(var output=BackupFile(destination,0x410E0000)) {
   IntPtr readContext=IntPtr.Zero,writeContext=IntPtr.Zero; uint count;
   try {
    byte[] stream;
    using(var capture=new MemoryStream()) {
     byte[] buffer=new byte[65536];
     while(true) {
      Check(BackupRead(input,buffer,(uint)buffer.Length,out count,false,true,ref readContext));
      if(count==0) break;
      if(capture.Length+count>1048576) throw new IOException("Backup fixture exceeds the 1-MiB bound.");
      capture.Write(buffer,0,(int)count);
     }
     stream=capture.ToArray();
    }
    byte[] security=SecurityStream(stream);
    Check(BackupWrite(output,stream,(uint)stream.Length,out count,false,true,ref writeContext));
    if(count!=stream.Length) throw new IOException("BackupWrite consumed an incomplete stream.");
    return security;
   } finally {
    try { if(readContext!=IntPtr.Zero) Check(BackupRead(input,null,0,out count,true,true,ref readContext)); }
    finally { if(writeContext!=IntPtr.Zero) Check(BackupWrite(output,null,0,out count,true,true,ref writeContext)); }
   }
  }
 }
 static void Signature(string name,Type result,params Type[] parameters) {
  var method=typeof(SecurityDescriptorNativeControl).GetMethod(name,BindingFlags.NonPublic|BindingFlags.Static);
  if(method==null || method.ReturnType!=result) throw new InvalidOperationException("Native return signature: "+name);
  var args=method.GetParameters(); if(args.Length!=parameters.Length) throw new InvalidOperationException("Native arity: "+name);
  for(int i=0;i<args.Length;i++) {
   if(args[i].ParameterType!=parameters[i]) throw new InvalidOperationException("Native parameter: "+name+"/"+i);
   if(parameters[i]==typeof(bool) || parameters[i]==typeof(bool).MakeByRefType()) {
    var attr=(MarshalAsAttribute)Attribute.GetCustomAttribute(args[i],typeof(MarshalAsAttribute));
    if(attr==null || attr.Value!=UnmanagedType.Bool) throw new InvalidOperationException("Native BOOL packing: "+name);
   }
  }
  var dll=(DllImportAttribute)Attribute.GetCustomAttribute(method,typeof(DllImportAttribute));
  bool unicode=name.EndsWith("W",StringComparison.Ordinal);
  bool error=name!="GetSecurityDescriptorLength" && name!="SetNamedSecurityInfoW" && name!="TreeResetNamedSecurityInfoW";
  string library=name=="CreateFileW" || name=="CloseHandle" || name=="BackupRead" || name=="BackupWrite" ? "kernel32.dll" : "advapi32.dll";
  if(dll==null || dll.Value!=library || !dll.ExactSpelling || dll.SetLastError!=error || dll.CallingConvention!=CallingConvention.Winapi ||
     (unicode && dll.CharSet!=CharSet.Unicode)) throw new InvalidOperationException("Native import metadata: "+name);
  if(result==typeof(bool)) {
   var attr=(MarshalAsAttribute)Attribute.GetCustomAttribute(method.ReturnParameter,typeof(MarshalAsAttribute));
   if(attr==null || attr.Value!=UnmanagedType.Bool) throw new InvalidOperationException("Native return BOOL: "+name);
  }
 }
 public static void SelfCheck() {
  if(IntPtr.Size!=8 || Marshal.SizeOf(typeof(GenericMapping))!=16 || Marshal.SizeOf(typeof(SidAndAttributes))!=16 ||
     Marshal.OffsetOf(typeof(SidAndAttributes),"Attributes").ToInt32()!=8 || Marshal.SizeOf(typeof(Luid))!=8 ||
     Marshal.SizeOf(typeof(TokenPrivileges))!=16 || Marshal.OffsetOf(typeof(TokenPrivileges),"Id").ToInt32()!=4 ||
     Marshal.OffsetOf(typeof(TokenPrivileges),"Attributes").ToInt32()!=12 || Marshal.SizeOf(typeof(StreamHeader))!=24 ||
     Marshal.OffsetOf(typeof(StreamHeader),"FirstNameCharacter").ToInt32()!=20) throw new InvalidOperationException("Native packing failed.");
  Type p=typeof(IntPtr),pr=p.MakeByRefType(),u=typeof(uint),ur=u.MakeByRefType(),b=typeof(bool),s=typeof(string),a=typeof(byte[]),
   i=typeof(int),g=typeof(GenericMapping).MakeByRefType(),h=typeof(SafeFileHandle);
  Signature("ConvertToAutoInheritPrivateObjectSecurity",b,a,a,pr,p,typeof(byte),g);
  Signature("GetSecurityDescriptorLength",u,p); Signature("DestroyPrivateObjectSecurity",b,pr);
  Signature("SetNamedSecurityInfoW",u,s,i,u,p,p,p,p);
  Signature("TreeResetNamedSecurityInfoW",u,s,i,u,p,p,p,p,b,typeof(Progress),i,p);
  Signature("AccessCheck",b,a,p,u,g,a,ur,ur,b.MakeByRefType());
  Signature("OpenProcessToken",b,p,u,pr); Signature("OpenThreadToken",b,p,u,b,pr);
  Signature("DuplicateTokenEx",b,p,u,p,i,i,pr);
  Signature("CreateRestrictedToken",b,p,u,u,p,u,p,u,typeof(SidAndAttributes[]),pr);
  Signature("LookupPrivilegeValueW",b,s,s,typeof(Luid).MakeByRefType());
  Signature("AdjustTokenPrivileges",b,p,b,typeof(TokenPrivileges).MakeByRefType(),u,p,p);
  Signature("SetThreadToken",b,p,p); Signature("CloseHandle",b,p);
  Signature("CreateFileW",h,s,u,u,p,u,u,p);
  Signature("BackupRead",b,h,a,u,ur,b,b,pr); Signature("BackupWrite",b,h,a,u,ur,b,b,pr);
  int imports=0;
  foreach(var method in typeof(SecurityDescriptorNativeControl).GetMethods(BindingFlags.NonPublic|BindingFlags.Static)) {
   if(Attribute.IsDefined(method,typeof(DllImportAttribute))) imports++;
  }
  if(imports!=17) throw new InvalidOperationException("New import requires a signature self-check.");
  var callback=(UnmanagedFunctionPointerAttribute)Attribute.GetCustomAttribute(typeof(Progress),typeof(UnmanagedFunctionPointerAttribute));
  var invoke=typeof(Progress).GetMethod("Invoke"); var args=invoke.GetParameters();
  if(callback.CallingConvention!=CallingConvention.Winapi || callback.CharSet!=CharSet.Unicode || invoke.ReturnType!=typeof(void) ||
     args.Length!=5 || args[0].ParameterType!=s || args[1].ParameterType!=u || args[2].ParameterType!=i.MakeByRefType() ||
     args[3].ParameterType!=p || args[4].ParameterType!=b ||
     ((MarshalAsAttribute)Attribute.GetCustomAttribute(args[0],typeof(MarshalAsAttribute))).Value!=UnmanagedType.LPWStr ||
     ((MarshalAsAttribute)Attribute.GetCustomAttribute(args[4],typeof(MarshalAsAttribute))).Value!=UnmanagedType.Bool)
   throw new InvalidOperationException("Tree callback ABI failed.");
  var mapping=FileMapping();
  if(mapping.Read!=0x120089 || mapping.Write!=0x120116 || mapping.Execute!=0x1200A0 || mapping.All!=0x1F01FF || ProbeSids.Length!=5 || ProbeRights.Length!=14)
   throw new InvalidOperationException("File mapping/access matrix changed.");
  // Serialized backup headers have a 20-byte prefix, although sizeof(WIN32_STREAM_ID) is 24.
  byte[] sample=new byte[40]; BitConverter.GetBytes(3U).CopyTo(sample,0); BitConverter.GetBytes(20L).CopyTo(sample,8);
  if(SecurityStream(sample).Length!=20) throw new InvalidOperationException("Backup stream decoder failed.");
  foreach(byte[] bad in new byte[][]{new byte[19],new byte[20],new byte[21]}) {
   bool rejected=false; try { SecurityStream(bad); } catch(IOException) { rejected=true; }
   if(!rejected) throw new InvalidOperationException("Malformed backup accepted.");
  }
 }
}
'@
[SecurityDescriptorNativeControl]::SelfCheck()
Write-Output 'SecurityDescriptorNativeSignaturePackingSelfCheck=PASS NativeCalls=False Imports=17'
