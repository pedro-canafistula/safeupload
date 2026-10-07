# Windows PowerShell 5.1. One C# 5 helper; no driver/service calls.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not ('StagedInvariant.Native' -as [type])) {
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace StagedInvariant {
 public sealed class ObservationException : Exception {
  public string Phase; public int NativeCode; public Container[] Containers; public Image PartialImage;
  public ObservationException(string phase, string message, int code) : base(message) { Phase=phase; NativeCode=code; }
  public ObservationException(string phase, string message, Exception inner) : base(message,inner) { Phase=phase; NativeCode=0; }
 }
 public sealed class Handle : IDisposable {
  public SafeFileHandle Value;
  public Handle(IntPtr p) { Value=new SafeFileHandle(p,true); }
  public void Dispose() { if (!Value.IsClosed && !Value.IsInvalid) { if (!Native.CloseHandle(Value.DangerousGetHandle())) throw Native.Error("CloseHandle"); Value.SetHandleAsInvalid(); } Value.Dispose(); }
 }
 public sealed class Run { public long Vcn, NextVcn, Lcn; public long Clusters { get { return NextVcn-Vcn; } } }
 public sealed class Attribute {
  public uint Type; public ushort Id, Flags; public string Name; public bool NonResident;
  public long StartVcn, LastVcn, Allocation, Eof, ValidData; public ushort CompressionUnit;
  public byte[] Value; public Run[] Runs; public ulong RecordReference;
 }
 public sealed class Record {
  public uint Number; public ushort Sequence, Flags; public ulong BaseReference;
  public byte[] Raw, Fixed; public Attribute[] Attributes;
 }
 public sealed class AttributeListEntry { public uint Type; public ushort Id; public string Name; public long StartVcn; public ulong Reference; }
 public sealed class NameEntry {
  public string Name; public byte Namespace; public ulong Reference, Parent;
  public long Allocated, Eof; public uint Attributes; public long Creation, Modified, Changed, Accessed;
 }
 public sealed class Identity {
  public ulong VolumeSerial, Reference; public string FileId;
  public long Allocation, Eof, Creation, Modified, Changed, Accessed;
  public uint Attributes, Links; public bool Directory, DeletePending;
 }
 public sealed class Geometry {
  public int Sector, PhysicalSector, Alignment, Cluster, RecordSize, IndexSize;
  public long MftLcn, TotalBytes; public ulong Serial; public string Guid, Mount, Device;
 }
 public sealed class Container { public string Kind; public long Offset; public byte[] Bytes; public string Sha256; }
 public sealed class Image {
  public Identity Identity; public bool Resident; public byte[] Logical; public string Digest;
  public Run[] Runs; public Record[] Records; public Container[] Containers;
  public NameEntry[] Names; public NameEntry[] FileNames; public uint SecurityId; public Identity RawMetadata; public Attribute[] Attributes; public string[] CrossCheckErrors;
 }
 public sealed class Reader { public Identity Before, After; public string Digest, Status; public long Length; public int NativeCode; }
 public sealed class Volume : IDisposable {
  public Handle Raw; public Geometry Geometry; public Run[] MftRuns; public Container[] BootstrapContainers;
  public void Dispose() { if (Raw!=null) Raw.Dispose(); }
 }
 public static class Native {
  public static string LoadedModuleHash;
  public const int MaxImage=64*1024*1024, MaxAllocation=128*1024*1024, MaxRecords=256, MaxAttributes=1024, MaxRuns=8192, MaxEntries=16384;
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ReadFile(SafeFileHandle h,IntPtr b,uint n,out uint r,IntPtr o);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool SetFilePointerEx(SafeFileHandle h,long d,out long p,uint m);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool DeviceIoControl(SafeFileHandle h,uint c,byte[] i,uint ni,[Out] byte[] o,uint no,out uint nr,IntPtr v);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int c,[Out] byte[] b,uint n);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(SafeFileHandle h,[Out] byte[] b);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetVolumePathNameW(string p,StringBuilder b,uint n);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetVolumeNameForVolumeMountPointW(string p,StringBuilder b,uint n);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string p);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetVolumeInformationW(string p,StringBuilder n,uint nn,out uint serial,out uint max,out uint flags,StringBuilder fs,uint nf);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDeviceW(string p,StringBuilder b,uint n);
  [DllImport("ntdll.dll")] static extern int RtlDecompressBuffer(ushort format,[Out] byte[] output,uint capacity,byte[] input,uint size,out uint final);
  public static ObservationException Error(string phase) { int n=Marshal.GetLastWin32Error(); return new ObservationException(phase,new Win32Exception(n).Message,n); }
  public static void Require(bool ok,string phase,string message) { if (!ok) throw new ObservationException(phase,message,0); }
  static void Bounds(byte[] b,int o,int n) { Require(b!=null && o>=0 && n>=0 && o<=b.Length-n,"Decode","Truncated or out-of-bounds field"); }
  public static ushort U16(byte[] b,int o) { Bounds(b,o,2); return BitConverter.ToUInt16(b,o); }
  public static uint U32(byte[] b,int o) { Bounds(b,o,4); return BitConverter.ToUInt32(b,o); }
  public static ulong U64(byte[] b,int o) { Bounds(b,o,8); return BitConverter.ToUInt64(b,o); }
  public static long I64(byte[] b,int o) { Bounds(b,o,8); return BitConverter.ToInt64(b,o); }
  public static byte[] Slice(byte[] b,int o,int n) { Bounds(b,o,n); byte[] r=new byte[n]; Buffer.BlockCopy(b,o,r,0,n); return r; }
  public static string Hash(byte[] b) { Require(b!=null,"Hash","Null image"); using(SHA256 s=SHA256.Create()) return BitConverter.ToString(s.ComputeHash(b)).Replace("-",""); }
  static bool Power(int n) { return n>0 && (n & (n-1))==0; }
  public static Handle Open(string path,bool raw,bool directory) {
   Require(!String.IsNullOrWhiteSpace(path),"Open","Empty path");
   IntPtr p=CreateFileW(path,0x80000000,7,IntPtr.Zero,3,(raw?0xA0000000u:0u)|(directory?0x02000000u:0u),IntPtr.Zero);
   if(p==new IntPtr(-1)) throw Error("CreateFileW"); return new Handle(p);
  }
  static byte[] Io(Handle h,uint code,byte[] input,int length) {
   byte[] b=new byte[length]; uint n; if(!DeviceIoControl(h.Value,code,input,(uint)(input==null?0:input.Length),b,(uint)b.Length,out n,IntPtr.Zero)) throw Error("DeviceIoControl:"+code);
   Require(n<=b.Length,"DeviceIoControl","Invalid output length"); return Slice(b,0,(int)n);
  }
  public static void ValidateTransfer(long buffer,long offset,int length,int alignment) {
   Require(buffer!=0 && offset>=0 && length>0 && Power(alignment) && buffer%alignment==0 && offset%alignment==0 && length%alignment==0,"Read","Unaligned transfer");
  }
  public static void ValidateReadResult(long start,long end,long rounded,int transfer,uint count,bool eofAllowed,long eof) {
   Require(start>=0 && end>=start && rounded>=end && rounded-start==transfer && transfer>0,"Read","Bad result range");
   Require(count<=transfer,"Read","Oversized read");
   if(count!=transfer) Require(eofAllowed && end<=eof && rounded>eof && count==eof-start,"Read","Short read");
   Require(count>=end-start,"Read","Truncated requested read");
  }
  public static byte[] ReadAligned(Handle h,long offset,int length,int alignment,bool eofAllowed,long eof) {
   Require(h!=null,"Read","Null handle");
   lock(h) {
   Require(offset>=0 && length>=0 && length<=MaxAllocation && Power(alignment),"Read","Bad range/alignment");
   if(length==0) return new byte[0];
   long start=offset-offset%alignment, end=checked(offset+length), rounded=checked((end+alignment-1)/alignment*alignment);
   int transfer=checked((int)(rounded-start)); Require(transfer<=MaxAllocation+alignment,"Read","Transfer cap");
   IntPtr allocation=Marshal.AllocHGlobal(checked(transfer+alignment));
   try {
    long address=allocation.ToInt64(); IntPtr buffer=new IntPtr(checked((address+alignment-1)&~((long)alignment-1)));
    ValidateTransfer(buffer.ToInt64(),start,transfer,alignment);
    long position; if(!SetFilePointerEx(h.Value,start,out position,0)) throw Error("SetFilePointerEx"); Require(position==start,"Read","Seek mismatch");
    uint count; if(!ReadFile(h.Value,buffer,(uint)transfer,out count,IntPtr.Zero)) throw Error("ReadFile");
    ValidateReadResult(start,end,rounded,transfer,count,eofAllowed,eof);
    byte[] result=new byte[length]; Marshal.Copy(new IntPtr(buffer.ToInt64()+offset-start),result,0,length); return result;
   } finally { Marshal.FreeHGlobal(allocation); }
   }
  }
  public static string ResolveGuid(string path) {
   StringBuilder mount=new StringBuilder(1024),guid=new StringBuilder(1024);
   if(!GetVolumePathNameW(path,mount,1024)) throw Error("GetVolumePathNameW");
   if(!GetVolumeNameForVolumeMountPointW(mount.ToString(),guid,1024)) throw Error("GetVolumeNameForVolumeMountPointW"); return guid.ToString();
  }
  public static Geometry DecodeBoot(byte[] boot) {
   Bounds(boot,0,512); Require(Encoding.ASCII.GetString(boot,3,8)=="NTFS    " && U16(boot,510)==0xAA55,"Boot","Not NTFS boot sector");
   int sector=U16(boot,11),spc=boot[13]; Require(Power(sector) && sector>=512 && sector<=4096 && Power(spc) && spc<=128,"Boot","Bad sector/cluster geometry");
   Geometry g=new Geometry(); g.Sector=sector; g.Cluster=checked(sector*spc); g.MftLcn=I64(boot,48); g.TotalBytes=checked(I64(boot,40)*sector); g.Serial=U64(boot,72);
   int rec=(sbyte)boot[64],idx=(sbyte)boot[68]; Require(rec!=0 && rec>=-16 && idx!=0 && idx>=-16,"Boot","Bad record geometry");
   g.RecordSize=rec<0?1<<-rec:checked(rec*g.Cluster); g.IndexSize=idx<0?1<<-idx:checked(idx*g.Cluster);
   Require(g.RecordSize>=sector && g.RecordSize<=65536 && g.RecordSize%sector==0 && g.IndexSize>=sector && g.IndexSize<=65536 && g.IndexSize%sector==0 && g.MftLcn>=0 && checked(g.MftLcn*g.Cluster)<g.TotalBytes,"Boot","Invalid volume bounds"); return g;
  }
  public static Volume OpenVolume(string guid,string scope) {
   Require(!String.IsNullOrWhiteSpace(guid) && guid.StartsWith("\\\\?\\Volume{") && guid.EndsWith("}\\"),"Volume","Use a volume GUID with trailing backslash");
   Require(String.Equals(guid,ResolveGuid(scope),StringComparison.OrdinalIgnoreCase),"Volume","Scope/volume mismatch");
   StringBuilder mount=new StringBuilder(1024); if(!GetVolumePathNameW(scope,mount,1024)) throw Error("GetVolumePathNameW");
   Require(GetDriveTypeW(mount.ToString())==3,"Volume","Not a fixed volume");
   uint serial,max,flags; StringBuilder fs=new StringBuilder(64);
   if(!GetVolumeInformationW(mount.ToString(),null,0,out serial,out max,out flags,fs,64)) throw Error("GetVolumeInformationW"); Require(fs.ToString()=="NTFS","Volume","Not NTFS");
   List<Container> bootstrap=new List<Container>(); Volume v=new Volume(); v.Raw=Open(guid.TrimEnd('\\'),true,false);
   try {
    byte[] disk=Io(v.Raw,0x70000,null,24); Require(disk.Length>=24,"Geometry","Short disk geometry"); int sector=(int)U32(disk,20);
    byte[] q=new byte[12]; Buffer.BlockCopy(BitConverter.GetBytes(6),0,q,0,4); byte[] a=Io(v.Raw,0x2D1400,q,64);
    Require(a.Length>=28 && U32(a,0)>=28 && U32(a,4)>=28,"Alignment","Short alignment descriptor");
    int logical=(int)U32(a,16),physical=(int)U32(a,20); Require(sector==logical && Power(logical) && Power(physical) && physical>=logical && physical<=65536,"Alignment","Invalid alignment descriptor");
    byte[] boot=ReadAligned(v.Raw,0,4096,physical,false,0); AddContainer(bootstrap,"BOOT",0,boot); Geometry g=DecodeBoot(boot); Require(g.Sector==sector,"Geometry","Boot/IOCTL sector mismatch");
    g.PhysicalSector=physical; g.Alignment=physical; g.Guid=guid; g.Mount=mount.ToString();
    StringBuilder dev=new StringBuilder(4096); if(QueryDosDeviceW(guid.Substring(4).TrimEnd('\\'),dev,4096)==0) throw Error("QueryDosDeviceW"); g.Device=dev.ToString(); v.Geometry=g;
    byte[] n=Io(v.Raw,0x90064,null,128); Require(n.Length>=96,"VolumeData","Truncated NTFS volume data");
    Require(U64(n,0)==g.Serial && U32(n,40)==g.Sector && U32(n,44)==g.Cluster && U32(n,48)==g.RecordSize && I64(n,64)==g.MftLcn && I64(n,8)*g.Sector==g.TotalBytes,"VolumeData","Boot/FSCTL geometry mismatch");
    byte[] mft=ReadAligned(v.Raw,checked(g.MftLcn*g.Cluster),g.RecordSize,g.Alignment,false,0); AddContainer(bootstrap,"MFT_BOOTSTRAP",checked(g.MftLcn*g.Cluster),mft); Record m=DecodeRecord(mft,g.Sector,0); CrossRecord(v,m);
    Require(m.BaseReference==0 && (m.Flags&1)!=0,"MFT","Invalid base MFT record");
    List<Run> runs=new List<Run>(); foreach(Attribute at in m.Attributes) if(at.Type==0x80 && at.Name=="" && at.NonResident) runs.AddRange(at.Runs);
    Require(runs.Count>0 && runs[0].Vcn==0,"MFT","No bootstrap runlist"); v.MftRuns=runs.ToArray();
    // Extension records must be reachable using the already-known bootstrap runs.
    List<Container> discard=bootstrap; List<Record> records=new List<Record>(); records.Add(m);
    Attribute[] all=ResolveAttributes(v,m,records,discard); List<Attribute> data=Select(all,0x80,"");
    v.MftRuns=MergeRuns(data); Require(v.MftRuns.Length>0 && v.MftRuns[0].Vcn==0,"MFT","Incomplete MFT runs"); v.BootstrapContainers=bootstrap.ToArray(); return v;
   } catch(Exception e) {
    ObservationException failure=e as ObservationException; if(failure==null) failure=new ObservationException("OpenVolume",e.Message,e); failure.Containers=bootstrap.ToArray();
    try { v.Dispose(); } catch(Exception close) { ObservationException both=new ObservationException("OpenVolumeCleanup","Open and cleanup failed",new AggregateException(failure,close)); both.Containers=bootstrap.ToArray(); throw both; } throw failure;
   }
  }
  public static byte[] Fixup(byte[] raw,int sector,string signature) {
   Require(raw!=null && Power(sector) && sector>=512 && raw.Length>=sector && raw.Length%sector==0,"USA","Truncated/unaligned record");
   Require(Encoding.ASCII.GetString(raw,0,4)==signature,"USA","Bad signature"); int offset=U16(raw,4),count=U16(raw,6);
   Require(count==raw.Length/sector+1 && (signature=="FILE"?offset>=48:offset>=40) && offset%2==0 && offset<=sector-2 && count*2<=sector-offset-2,"USA","Bad fixup array bounds/count");
   byte[] b=(byte[])raw.Clone(); ushort usn=U16(raw,offset);
   for(int i=1;i<count;i++) { int tail=i*sector-2; Require(U16(raw,tail)==usn,"USA","Bad sector fixup"); b[tail]=raw[offset+2*i]; b[tail+1]=raw[offset+2*i+1]; } return b;
  }
  public static Run[] DecodeRuns(byte[] b,int offset,int limit,long start,long last) {
   Require(start>=0 && last>=start-1 && last<long.MaxValue,"Runlist","Bad VCN interval"); Bounds(b,offset,limit-offset);
   List<Run> runs=new List<Run>(); long vcn=start,lcn=0; bool ended=false;
   for(int p=offset;p<limit;) {
    int header=b[p++]; if(header==0) { ended=true; break; }
    int ns=header&15,no=header>>4; Require(ns>=1 && ns<=8 && no<=8 && p<=limit-ns-no && runs.Count<MaxRuns,"Runlist","Truncated/invalid/capped run");
    ulong size=0; for(int j=0;j<ns;j++) size|=(ulong)b[p+j]<<(8*j); p+=ns; Require(size>0 && size<=long.MaxValue,"Runlist","Zero/overflow run length");
    long address=-1;
    if(no>0) { ulong delta=0; for(int j=0;j<no;j++) delta|=(ulong)b[p+j]<<(8*j); if(no<8 && (b[p+no-1]&128)!=0) delta|=ulong.MaxValue<<(no*8); lcn=checked(lcn+unchecked((long)delta)); Require(lcn>=0,"Runlist","Negative allocated LCN"); address=lcn; } p+=no;
    long next=checked(vcn+(long)size); Require(next<=last+1,"Runlist","VCN exceeds attribute"); runs.Add(new Run { Vcn=vcn,NextVcn=next,Lcn=address }); vcn=next;
   }
   Require(ended && vcn==last+1,"Runlist","Missing terminator/incomplete mapping"); return runs.ToArray();
  }
  public static Record DecodeRecord(byte[] raw,int sector,uint expected) {
   return DecodeRecordBody(raw,Fixup(raw,sector,"FILE"),expected);
  }
  static Record DecodeRecordBody(byte[] raw,byte[] b,uint expected) {
   Require(b.Length>=48,"Record","Short header");
   Record r=new Record(); r.Number=U32(b,44); r.Sequence=U16(b,16); r.Flags=U16(b,22); r.BaseReference=U64(b,32); r.Raw=(byte[])raw.Clone(); r.Fixed=b;
   Require(r.Number==expected && r.Sequence!=0 && (r.Flags&1)!=0,"Record","Wrong record number/sequence or not in use");
   int first=U16(b,20); uint used=U32(b,24),allocated=U32(b,28);
   Require(allocated==b.Length && used<=allocated && first>=Math.Max(48,U16(b,4)+2*U16(b,6)) && first%8==0 && used>=first+4,"Record","Bad record bounds");
   List<Attribute> attrs=new List<Attribute>(); bool ended=false;
   for(int p=first;p<used;) {
    uint type=U32(b,p); if(type==0xFFFFFFFF) { ended=true; break; }
    Require(attrs.Count<MaxAttributes && p<=used-16,"Attribute","Attribute cap/header truncation"); uint len=U32(b,p+4);
    Require(len>=24 && len%8==0 && len<=used-p,"Attribute","Bad attribute length"); int end=checked(p+(int)len); byte form=b[p+8],namelen=b[p+9]; int nameoff=U16(b,p+10);
    Require(form<=1 && (namelen==0 || (nameoff>=(form==1?64:24) && nameoff+namelen*2<=len)),"Attribute","Bad form/name");
    Attribute a=new Attribute(); a.Type=type; a.Id=U16(b,p+14); a.Flags=U16(b,p+12); Require((a.Flags&255)==0 || (a.Flags&255)==1,"Compression","Unsupported compression format"); a.NonResident=form==1; a.Name=namelen==0?"":Encoding.Unicode.GetString(b,p+nameoff,namelen*2); a.RecordReference=((ulong)r.Sequence<<48)|r.Number;
    if(!a.NonResident) { uint n=U32(b,p+16); int vo=U16(b,p+20); Require(vo>=24 && vo<=len && n<=len-vo,"Attribute","Truncated resident value"); a.Value=Slice(b,p+vo,(int)n); a.Eof=n; a.ValidData=n; a.Allocation=n; a.Runs=new Run[0]; }
    else {
     Require(len>=64,"Attribute","Short nonresident header"); a.StartVcn=I64(b,p+16); a.LastVcn=I64(b,p+24); int ro=U16(b,p+32); a.CompressionUnit=U16(b,p+34);
     a.Allocation=I64(b,p+40); a.Eof=I64(b,p+48); a.ValidData=I64(b,p+56);
     Require(ro>=64 && ro<len && a.Allocation>=0 && a.Eof>=0 && a.ValidData>=0 && a.ValidData<=a.Eof && a.CompressionUnit<=8,"Attribute","Bad nonresident sizes/offset");
     a.Runs=DecodeRuns(b,p+ro,end,a.StartVcn,a.LastVcn); foreach(Run run in a.Runs) Require(a.Type!=0x80 || run.Lcn>=0 || (a.Flags&0x8001)!=0,"Runlist","Hole without sparse/compressed flags"); a.Value=null;
    }
    attrs.Add(a); p=end;
   }
   Require(ended,"Attribute","Missing attribute terminator"); r.Attributes=attrs.ToArray(); return r;
  }
  public static NameEntry DecodeName(byte[] b,int o,int n,ulong reference) {
   Bounds(b,o,n); Require(n>=66,"Name","Short FILE_NAME"); int chars=b[o+64]; Require(66+chars*2==n && chars>0 && b[o+65]<=3,"Name","Bad name bounds/namespace");
   NameEntry e=new NameEntry(); e.Name=Encoding.Unicode.GetString(b,o+66,chars*2); Require(e.Name.IndexOf('\0')<0,"Name","NUL name"); e.Namespace=b[o+65]; e.Reference=reference; e.Parent=U64(b,o); Require((reference>>48)!=0 && (e.Parent>>48)!=0,"Name","Zero file/parent sequence"); e.Creation=I64(b,o+8); e.Modified=I64(b,o+16); e.Changed=I64(b,o+24); e.Accessed=I64(b,o+32); e.Allocated=I64(b,o+40); e.Eof=I64(b,o+48); e.Attributes=U32(b,o+56); return e;
  }
  // Internal nodes hold active separator entries as well as child pointers.
  public static NameEntry[] DecodeIndex(byte[] b,int header,int limit,out long[] children) {
   Bounds(b,header,16); Require(limit<=b.Length && limit>=header+16,"Index","Bad index bounds");
   uint first=U32(b,header),used=U32(b,header+4),allocated=U32(b,header+8);
   Require(first>=16 && first%8==0 && used>=first+16 && used<=allocated && allocated<=limit-header && b[header+12]<=1,"Index","Bad index header");
   Require(header!=24 || header+first>=U16(b,4)+2*U16(b,6),"Index","Entries overlap fixup array");
   List<NameEntry> entries=new List<NameEntry>(); List<long> nodes=new List<long>(); bool ended=false;
   for(int p=checked(header+(int)first);p<header+used;) {
    Require(entries.Count<MaxEntries && nodes.Count<MaxEntries && p<=header+used-16,"Index","Entry cap/truncation"); int length=U16(b,p+8),key=U16(b,p+10),flags=U16(b,p+12),tail=(flags&1)!=0?8:0;
    Require((flags&~3)==0 && length>=16+tail && length%8==0 && length<=header+used-p && key<=length-16-tail,"Index","Bad entry bounds/flags");
    Require((tail!=0)==(b[header+12]==1),"Index","Child/header flag mismatch");
    if(tail!=0) { long child=I64(b,p+length-8); Require(child>=0,"Index","Negative child VCN"); nodes.Add(child); }
    if((flags&2)!=0) { Require(key==0 && p+length==header+used,"Index","Bad end entry"); ended=true; break; }
    entries.Add(DecodeName(b,p+16,key,U64(b,p))); p+=length;
   }
   Require(ended,"Index","Missing terminal entry"); children=nodes.ToArray(); return entries.ToArray();
  }
  public static NameEntry[] DecodeIndexRoot(byte[] root) {
   Require(root!=null && root.Length>=32 && U32(root,0)==0x30 && U32(root,4)==1,"IndexRoot","Not a filename index"); long[] children; return DecodeIndex(root,16,root.Length,out children);
  }
  public static byte[] DecodeLznt1(byte[] input,int outputLength) {
   Require(input!=null && input.Length>0 && outputLength>0 && outputLength<=MaxImage,"Compression","Bad compression bounds");
   // Decompress into a buffer larger than the unit: RtlDecompressBuffer reports success with a truncated result when the
   // output buffer is too small, so over-long (malformed) data would pass for a unit-sized buffer. Require EXACTLY the unit.
   byte[] big=new byte[outputLength+8192]; uint final; int status=RtlDecompressBuffer(2,big,(uint)big.Length,input,(uint)input.Length,out final);
   if(status!=0) throw new ObservationException("LZNT1","RtlDecompressBuffer NTSTATUS",status);
   Require(final==outputLength,"LZNT1","Decompressed length is not exactly the unit");
   byte[] output=new byte[outputLength]; Buffer.BlockCopy(big,0,output,0,outputLength); return output;
  }
  public static Identity GetIdentity(Handle h) {
   byte[] id=new byte[24],standard=new byte[24],basic=new byte[40],old=new byte[52];
   if(!GetFileInformationByHandleEx(h.Value,18,id,24)) throw Error("FileIdInfo");
   if(!GetFileInformationByHandleEx(h.Value,1,standard,24)) throw Error("FileStandardInfo");
   if(!GetFileInformationByHandleEx(h.Value,0,basic,40)) throw Error("FileBasicInfo");
   if(!GetFileInformationByHandle(h.Value,old)) throw Error("GetFileInformationByHandle");
   Identity x=new Identity(); x.VolumeSerial=U64(id,0); x.FileId=BitConverter.ToString(Slice(id,8,16)).Replace("-",""); x.Reference=((ulong)U32(old,44)<<32)|U32(old,48);
   Require(U64(id,8)==x.Reference && U64(id,16)==0,"Identity","Unsupported/non-NTFS 128-bit file identity");
   x.Allocation=I64(standard,0); x.Eof=I64(standard,8); x.Links=U32(standard,16); x.DeletePending=standard[20]!=0; x.Directory=standard[21]!=0;
   x.Creation=I64(basic,0); x.Accessed=I64(basic,8); x.Modified=I64(basic,16); x.Changed=I64(basic,24); x.Attributes=U32(basic,32);
   Require(x.Allocation>=0 && x.Eof>=0 && x.Eof<=MaxImage && (x.Attributes&0x4400)==0 && (x.Directory || x.Links<=1),"Identity","EFS/reparse/hardlink/size ambiguity");
   byte[] cs=new byte[4]; if(!GetFileInformationByHandleEx(h.Value,23,cs,4)) { int code=Marshal.GetLastWin32Error(); if(code!=87 || x.Directory) throw new ObservationException("FileCaseSensitiveInfo",new Win32Exception(code).Message,code); } else Require(U32(cs,0)==0,"Identity","Case-sensitive fixture");
   return x;
  }
  public static bool SameIdentity(Identity a,Identity b) { return a.VolumeSerial==b.VolumeSerial && a.FileId==b.FileId && a.Reference==b.Reference && a.Eof==b.Eof && a.Allocation==b.Allocation && a.Attributes==b.Attributes && a.Links==b.Links && a.DeletePending==b.DeletePending && a.Modified==b.Modified && a.Changed==b.Changed; }
  public static Run[] DecodeRetrievalPage(byte[] output,int returned,long start) {
   Require(output!=null && returned>=16 && returned<=output.Length,"Retrieval","Short extent header"); uint count=U32(output,0); long vcn=I64(output,8);
   Require(count>0 && count<=128 && returned>=16+count*16 && vcn==start && start>=0,"Retrieval","Bad extent count/start/progress");
   List<Run> page=new List<Run>();
   for(int j=0;j<count;j++) { long next=I64(output,16+16*j),lcn=I64(output,24+16*j); Require(next>vcn && lcn>=-1,"Retrieval","Bad extent bounds"); page.Add(new Run { Vcn=vcn,NextVcn=next,Lcn=lcn }); vcn=next; }
   return page.ToArray();
  }
  public static AttributeListEntry[] DecodeAttributeList(byte[] bytes) {
   Require(bytes!=null && bytes.Length>0 && bytes.Length<=MaxImage,"AttributeList","Bad list bounds"); List<AttributeListEntry> entries=new List<AttributeListEntry>(); HashSet<string> keys=new HashSet<string>();
   for(int p=0;p<bytes.Length;) {
    Require(entries.Count<MaxAttributes && p<=bytes.Length-26,"AttributeList","Cap/truncated list"); uint type=U32(bytes,p); int size=U16(bytes,p+4),chars=bytes[p+6],no=bytes[p+7];
    Require(size>=26 && size%8==0 && size<=bytes.Length-p && (chars==0 || (no>=26 && no+chars*2<=size)),"AttributeList","Bad list entry");
    AttributeListEntry e=new AttributeListEntry(); e.Type=type; e.Id=U16(bytes,p+24); e.Name=chars==0?"":Encoding.Unicode.GetString(bytes,p+no,chars*2); e.StartVcn=I64(bytes,p+8); e.Reference=U64(bytes,p+16);
    Require(e.StartVcn>=0 && (e.Reference>>48)!=0 && keys.Add(e.Type+":"+e.Name+":"+e.StartVcn),"AttributeList","Bad reference/VCN/duplicate list entry"); entries.Add(e); p+=size;
   } return entries.ToArray();
  }
  public static void ValidateExtension(Record basis,Record target,ulong reference) {
   Require(target.Number==(reference&0x0000FFFFFFFFFFFFUL) && target.Sequence==(ushort)(reference>>48) &&
    (target.Number==basis.Number?target.BaseReference==0:target.BaseReference==(((ulong)basis.Sequence<<48)|basis.Number)),"AttributeList","Sequence/base mismatch");
  }
  public static Run[] Retrieval(Handle h) {
   List<Run> runs=new List<Run>(); long start=0;
   for(int page=0;page<MaxRuns;page++) {
    byte[] input=BitConverter.GetBytes(start),output=new byte[16+16*128]; uint returned;
    bool ok=DeviceIoControl(h.Value,0x90073,input,8,output,(uint)output.Length,out returned,IntPtr.Zero); int code=ok?0:Marshal.GetLastWin32Error();
    if(!ok && code==38) { Require(start==0,"Retrieval","Unexpected EOF while paging"); return new Run[0]; }
    if(!ok && code!=234) throw new ObservationException("Retrieval",new Win32Exception(code).Message,code);
    Run[] pageRuns=DecodeRetrievalPage(output,(int)returned,start); Require(runs.Count+pageRuns.Length<=MaxRuns,"Retrieval","Run cap"); runs.AddRange(pageRuns);
    long next=pageRuns[pageRuns.Length-1].NextVcn; Require(next>start,"Retrieval","Nonprogressing page"); start=next; if(ok) return runs.ToArray();
   }
   throw new ObservationException("Retrieval","Page cap",0);
  }
  static void CrossRecord(Volume v,Record r) {
   byte[] data=Io(v.Raw,0x90068,BitConverter.GetBytes((long)r.Number),v.Geometry.RecordSize+16);
   Require(data.Length>=12 && (U64(data,0)&0x0000FFFFFFFFFFFFUL)==r.Number && U32(data,8)==r.Raw.Length && data.Length>=12+r.Raw.Length,"FileRecord","Lower/mismatched/truncated FSCTL record");
   // FSCTL_GET_NTFS_FILE_RECORD returns the record with the update-sequence fixups ALREADY APPLIED (verified on Win10 19045:
   // tails restored, USA array intact), unlike a raw read. Fixup() applies only to raw data; here just validate the signature.
   byte[] fixedRecord=Slice(data,12,r.Raw.Length); Require(Encoding.ASCII.GetString(fixedRecord,0,4)=="FILE","FileRecord","FSCTL record signature");
   Require(U32(fixedRecord,44)==r.Number && U16(fixedRecord,16)==r.Sequence && U64(fixedRecord,32)==r.BaseReference,"FileRecord","Raw/FSCTL identity mismatch");
  }
  static void AddContainer(List<Container> list,string kind,long offset,byte[] bytes) {
   Require(list.Count<MaxEntries,"Containers","Container cap"); list.Add(new Container { Kind=kind,Offset=offset,Bytes=bytes,Sha256=Hash(bytes) });
  }
  static byte[] ReadMapped(Volume v,Run[] runs,long offset,int length,List<Container> containers,string kind) {
   Require(offset>=0 && length>=0 && length<=MaxAllocation,"Map","Bad mapping range"); byte[] output=new byte[length]; long end=checked(offset+length),cursor=offset; int cluster=v.Geometry.Cluster;
   foreach(Run r in runs) {
    long lo=checked(r.Vcn*cluster),hi=checked(r.NextVcn*cluster); if(cursor>=end) break; if(hi<=cursor) continue; Require(lo<=cursor,"Map","Mapping gap");
    int n=checked((int)Math.Min(end-cursor,hi-cursor)); Require(r.Lcn>=0,"Map","Sparse MFT/record map"); long physical=checked(r.Lcn*cluster+cursor-lo);
    Require(physical>=0 && checked(physical+n)<=v.Geometry.TotalBytes,"Map","Physical bounds");
    for(int done=0;done<n;) { int chunk=Math.Min(1024*1024,n-done); byte[] b=ReadAligned(v.Raw,checked(physical+done),chunk,v.Geometry.Alignment,false,0); Buffer.BlockCopy(b,0,output,checked((int)(cursor-offset)+done),chunk); AddContainer(containers,kind,physical+done,b); done+=chunk; } cursor+=n;
   }
   Require(cursor==end,"Map","Truncated run mapping"); return output;
  }
  static Record ReadRecord(Volume v,uint number,List<Container> containers) {
   Record r=DecodeRecord(ReadMapped(v,v.MftRuns,checked((long)number*v.Geometry.RecordSize),v.Geometry.RecordSize,containers,"MFT"),v.Geometry.Sector,number); CrossRecord(v,r); return r;
  }
  // Private-stage fallback only. The source is the trusted NTFS metadata
  // cache, explicitly not an on-disk MFT/index proof. No stage-file open.
  public static Record DecodeCachedRecord(byte[] fixedRecord,int sector,uint expected) {
   Require(fixedRecord!=null && Power(sector) && fixedRecord.Length>=sector && fixedRecord.Length%sector==0 &&
    Encoding.ASCII.GetString(fixedRecord,0,4)=="FILE","CachedRecord","Bad cached record geometry/signature");
   int usa=U16(fixedRecord,4),count=U16(fixedRecord,6);
   Require(count==fixedRecord.Length/sector+1 && usa>=8 && usa+count*2<=U16(fixedRecord,20),"CachedRecord","Bad cached USA bounds");
   bool encoded=true,applied=true,cleared=true; ushort usn=U16(fixedRecord,usa);
   for(int i=1;i<count;i++) { ushort tail=U16(fixedRecord,i*sector-2); encoded &= tail==usn; applied &= tail==U16(fixedRecord,usa+i*2); cleared &= U16(fixedRecord,usa+i*2)==0; }
   // NTFS can return its normalized cache image with the saved USA tails cleared.
   // This trusted API image has structural/identity validation, not raw-sector integrity.
   Require(encoded || applied || cleared,"CachedRecord","Mixed or invalid FSCTL record fixups");
   return DecodeRecordBody(fixedRecord,encoded?Fixup(fixedRecord,sector,"FILE"):(byte[])fixedRecord.Clone(),expected);
  }
  public static ulong DecodePrivateDirectoryPage(byte[] page,string leaf,out int entries) {
   Require(page!=null && page.Length>=106 && !String.IsNullOrWhiteSpace(leaf),"PrivateDirectory","Bad directory page/leaf");
   entries=0; ulong selected=0;
   for(int p=0;;) {
    Require(p<=page.Length-104 && entries<MaxEntries,"PrivateDirectory","Entry bounds/cap");
    uint next=U32(page,p),chars=U32(page,p+60);
    Require(chars>0 && chars<=510 && chars%2==0 && chars<=page.Length-p-104,"PrivateDirectory","Bad name length");
    Require(next==0 || (next>=104+chars && next%8==0 && next<=page.Length-p-104),"PrivateDirectory","Bad next entry bounds/alignment");
    string name=Encoding.Unicode.GetString(page,p+104,(int)chars); Require(name.IndexOf('\0')<0,"PrivateDirectory","NUL name");
    if(name==leaf) {
     ulong reference=U64(page,p+96);
     Require(selected==0 && (reference>>48)!=0 && (U32(page,p+56)&0x4410)==0,"PrivateDirectory","Duplicate/invalid private identity/type");
     selected=reference;
    }
    entries++; if(next==0) return selected; p=checked(p+(int)next);
   }
  }
  static ulong PrivateDirectoryReference(Handle directory,string leaf,List<Container> containers) {
   ulong selected=0; int total=0;
   for(int page=0;page<64;page++) {
    byte[] bytes=new byte[65536];
    if(!GetFileInformationByHandleEx(directory.Value,page==0?11:10,bytes,(uint)bytes.Length)) {
     int code=Marshal.GetLastWin32Error(); if(code==18) {Require(selected!=0,"PrivateDirectory","Private name absent in cached directory");return selected;}
     throw new ObservationException("PrivateDirectory",new Win32Exception(code).Message,code);
    }
    AddContainer(containers,"KERNEL_DIRECTORY_QUERY",-1,bytes);
    int count; ulong found=DecodePrivateDirectoryPage(bytes,leaf,out count); total=checked(total+count);
    Require(total<=MaxEntries && (found==0 || selected==0),"PrivateDirectory","Directory cap/duplicate private name"); if(found!=0) selected=found;
   }
   throw new ObservationException("PrivateDirectory","Directory page cap",0);
  }
  static Record ReadCachedRecord(Volume v,uint number,List<Container> containers) {
   byte[] data=Io(v.Raw,0x90068,BitConverter.GetBytes((long)number),v.Geometry.RecordSize+16);
   AddContainer(containers,"FSCTL_CACHED_FILE_RECORD",-1,data);
   Require(data.Length>=12 && (U64(data,0)&0x0000FFFFFFFFFFFFUL)==number && U32(data,8)==v.Geometry.RecordSize &&
    data.Length>=12+v.Geometry.RecordSize,"CachedRecord","FSCTL lower-record fallback/length mismatch");
   return DecodeCachedRecord(Slice(data,12,v.Geometry.RecordSize),v.Geometry.Sector,number);
  }
  static Attribute[] ResolveAttributes(Volume v,Record baseRecord,List<Record> records,List<Container> containers) {
   List<Attribute> all=new List<Attribute>(baseRecord.Attributes); List<Attribute> lists=Select(baseRecord.Attributes,0x20,"");
   Require(lists.Count<=1,"AttributeList","Split attribute list unsupported"); if(lists.Count==0) return all.ToArray();
   Attribute list=lists[0]; byte[] bytes=list.NonResident?ReadStream(v,lists,containers,"ATTRIBUTE_LIST"):list.Value;
   HashSet<ulong> loaded=new HashSet<ulong>(); loaded.Add(((ulong)baseRecord.Sequence<<48)|baseRecord.Number);
   foreach(AttributeListEntry e in DecodeAttributeList(bytes)) {
    uint type=e.Type; string name=e.Name; long start=e.StartVcn; ulong reference=e.Reference; ushort id=e.Id;
    uint number=checked((uint)(reference&0x0000FFFFFFFFFFFFUL));
    Record target=null; foreach(Record rec in records) if(rec.Number==number) target=rec;
    if(target==null) { Require(records.Count<MaxRecords && !loaded.Contains(reference),"AttributeList","Record cap/cycle"); target=ReadRecord(v,number,containers); ValidateExtension(baseRecord,target,reference); records.Add(target); loaded.Add(reference); all.AddRange(target.Attributes); }
    ValidateExtension(baseRecord,target,reference);
    int matches=0; foreach(Attribute at in target.Attributes) if(at.Type==type && at.Id==id && at.Name==name && (at.NonResident?at.StartVcn==start:start==0)) matches++;
    Require(matches==1,"AttributeList","Unresolved/duplicate entry");
   }
   Require(all.Count<=MaxAttributes,"AttributeList","Attribute cap"); return all.ToArray();
  }
  static List<Attribute> Select(Attribute[] attrs,uint type,string name) { List<Attribute> list=new List<Attribute>(); foreach(Attribute a in attrs) if(a.Type==type && a.Name==name) list.Add(a); list.Sort(delegate(Attribute a,Attribute b) { return a.StartVcn.CompareTo(b.StartVcn); }); return list; }
  static Run[] MergeRuns(List<Attribute> list) {
   List<Run> runs=new List<Run>(); long next=0;
   foreach(Attribute a in list) { Require(a.NonResident && a.StartVcn==next,"Runlist","Mixed resident or split/gapped attributes"); foreach(Run r in a.Runs) { Require(r.Vcn==next && runs.Count<MaxRuns,"Runlist","Gap/overlap/cap"); runs.Add(r); next=r.NextVcn; } }
   return runs.ToArray();
  }
  static bool SameRuns(Run[] a,Run[] b) {
   // Compare maps at every boundary; APIs may coalesce adjacent raw runs.
   int i=0,j=0; long cursor=0;
   while(i<a.Length && j<b.Length) { Run x=a[i],y=b[j]; if(x.Vcn>cursor || y.Vcn>cursor || (x.Lcn<0)!=(y.Lcn<0) || (x.Lcn>=0 && x.Lcn+cursor-x.Vcn!=y.Lcn+cursor-y.Vcn)) return false; cursor=Math.Min(x.NextVcn,y.NextVcn); if(cursor==x.NextVcn)i++; if(cursor==y.NextVcn)j++; }
   return i==a.Length && j==b.Length;
  }
  static byte[] ReadStream(Volume v,List<Attribute> attrs,List<Container> containers,string kind) {
   Require(attrs.Count>0,"Stream","Missing stream"); Attribute a=attrs[0]; Require(a.Eof<=MaxImage && a.Allocation<=MaxAllocation && (a.Flags&0x4000)==0,"Stream","EFS/stream cap");
   if(!a.NonResident) { Require(attrs.Count==1,"Stream","Split resident stream"); return (byte[])a.Value.Clone(); }
   Run[] runs=MergeRuns(attrs); long mapped=runs.Length==0?0:checked(runs[runs.Length-1].NextVcn*v.Geometry.Cluster); Require(mapped<=MaxAllocation && mapped>=a.Eof,"Stream","Bad mapped size");
   byte[] map=new byte[(int)mapped]; long physicalCount=0;
   foreach(Run r in runs) if(r.Lcn>=0) {
    long n=checked(r.Clusters*v.Geometry.Cluster),physical=checked(r.Lcn*v.Geometry.Cluster); physicalCount=checked(physicalCount+n); Require(physical>=0 && checked(physical+n)<=v.Geometry.TotalBytes,"Stream","Physical volume bounds");
    for(int done=0;done<n;) { int chunk=(int)Math.Min(1024*1024,n-done); byte[] b=ReadAligned(v.Raw,physical+done,chunk,v.Geometry.Alignment,false,0); Buffer.BlockCopy(b,0,map,checked((int)(r.Vcn*v.Geometry.Cluster)+done),chunk); AddContainer(containers,kind,physical+done,b); done+=chunk; }
   }
   if((a.Flags&1)!=0) {
    Require(a.CompressionUnit>0,"Compression","Missing compression unit"); int unit=checked((1<<a.CompressionUnit)*v.Geometry.Cluster); Require(unit<=MaxImage && mapped%unit==0,"Compression","Incomplete unit map");
    byte[] decoded=new byte[map.Length];
    for(int pos=0;pos<map.Length;pos+=unit) {
     long first=pos/v.Geometry.Cluster,last=(pos+unit)/v.Geometry.Cluster; int allocated=0; bool hole=false;
     foreach(Run r in runs) { long lo=Math.Max(first,r.Vcn),hi=Math.Min(last,r.NextVcn); if(hi<=lo) continue; if(r.Lcn<0) hole=true; else { Require(!hole,"Compression","Allocation after compression-tail hole"); allocated=checked(allocated+(int)((hi-lo)*v.Geometry.Cluster)); } }
     if(allocated==unit) Buffer.BlockCopy(map,pos,decoded,pos,unit);
     else if(allocated!=0) { byte[] result=DecodeLznt1(Slice(map,pos,allocated),unit); Buffer.BlockCopy(result,0,decoded,pos,unit); }
    }
    map=decoded;
   } else Require(a.CompressionUnit==0,"Compression","Unknown compression representation");
   // VDL protects logical unwritten bytes; physical bytes are still archived/judged.
   Require(a.ValidData<=a.Eof && a.Eof<=map.Length,"Stream","EOF/VDL bounds"); if(a.ValidData<a.Eof) Array.Clear(map,(int)a.ValidData,(int)(a.Eof-a.ValidData));
   return Slice(map,0,(int)a.Eof);
  }
  public static NameEntry[] ValidateNames(NameEntry[] names) {
   Require(names!=null && names.Length<=MaxEntries,"Directory","Name count cap"); Dictionary<string,ulong> refs=new Dictionary<string,ulong>(StringComparer.OrdinalIgnoreCase);
   foreach(NameEntry n in names) { ulong reference; if(refs.TryGetValue(n.Name,out reference)) Require(reference==n.Reference,"Directory","Case/alias ambiguity"); else refs.Add(n.Name,n.Reference); } return names;
  }
  static NameEntry[] Directory(Volume v,Attribute[] attributes,List<Container> containers) {
   List<Attribute> roots=Select(attributes,0x90,"$I30"); Require(roots.Count==1 && !roots[0].NonResident,"Directory","Missing/resident index root"); byte[] root=roots[0].Value;
   Require(U32(root,0)==0x30 && U32(root,4)==1 && U32(root,8)==v.Geometry.IndexSize,"Directory","Index root geometry mismatch");
   long[] children; List<NameEntry> names=new List<NameEntry>(DecodeIndex(root,16,root.Length,out children));
   List<Attribute> allocation=Select(attributes,0xA0,"$I30"),bitmap=Select(attributes,0xB0,"$I30");
   if(allocation.Count==0) { Require(children.Length==0 && bitmap.Count==0,"Directory","Missing index allocation"); return ValidateNames(names.ToArray()); }
   Require(allocation[0].NonResident && bitmap.Count>0,"Directory","Bad allocation/bitmap"); byte[] blocks=ReadStream(v,allocation,containers,"INDEX_ALLOCATION"),bits=ReadStream(v,bitmap,containers,"INDEX_BITMAP");
   Require(blocks.Length%v.Geometry.IndexSize==0,"Directory","Truncated index allocation"); int count=blocks.Length/v.Geometry.IndexSize;
   Require(count<=MaxEntries && bits.Length*8>=count && bits.Length<=(MaxEntries+7)/8,"Directory","Bitmap truncation/cap");
   for(int bit=count;bit<bits.Length*8;bit++) Require((bits[bit/8]&(1<<(bit%8)))==0,"Directory","Active bitmap bit beyond allocation"); Dictionary<long,int> active=new Dictionary<long,int>();
   for(int i=0;i<count;i++) if((bits[i/8]&(1<<(i%8)))!=0) {
    byte[] block=Fixup(Slice(blocks,i*v.Geometry.IndexSize,v.Geometry.IndexSize),v.Geometry.Sector,"INDX"); long vcn=I64(block,16),expected=checked((long)i*v.Geometry.IndexSize/(v.Geometry.Cluster<=v.Geometry.IndexSize?v.Geometry.Cluster:v.Geometry.Sector));
    Require(vcn==expected && !active.ContainsKey(vcn),"Directory","Bad/duplicate INDX VCN"); active.Add(vcn,i);
   }
   HashSet<long> visited=new HashSet<long>(); Queue<long> pending=new Queue<long>(children);
   while(pending.Count>0) { Require(visited.Count<MaxEntries,"Directory","Traversal cap"); long node=pending.Dequeue(); Require(active.ContainsKey(node) && visited.Add(node),"Directory","Missing/cyclic index child"); int i=active[node]; byte[] block=Fixup(Slice(blocks,i*v.Geometry.IndexSize,v.Geometry.IndexSize),v.Geometry.Sector,"INDX"); long[] sub; names.AddRange(DecodeIndex(block,24,block.Length,out sub)); Require(names.Count<=MaxEntries,"Directory","Name cap"); foreach(long child in sub) pending.Enqueue(child); }
   Require(visited.Count==active.Count,"Directory","Unreachable active index block"); return ValidateNames(names.ToArray());
  }
  public static Image Capture(Volume v,Handle h) {
   List<Container> containers=new List<Container>(); Image image=null; List<string> issues=new List<string>();
   try {
   Identity before=GetIdentity(h); Require(before.VolumeSerial==v.Geometry.Serial,"Capture","Different volume serial"); uint number=checked((uint)(before.Reference&0x0000FFFFFFFFFFFFUL));
   List<Record> records=new List<Record>(); Record baseRecord=ReadRecord(v,number,containers); records.Add(baseRecord);
   Require(baseRecord.BaseReference==0 && baseRecord.Sequence==(ushort)(before.Reference>>48) && ((baseRecord.Flags&2)!=0)==before.Directory,"Capture","Record/handle identity mismatch");
   Attribute[] attrs=ResolveAttributes(v,baseRecord,records,containers); image=new Image(); image.Identity=before; image.Records=records.ToArray(); image.Attributes=attrs;
   List<NameEntry> fileNames=new List<NameEntry>(); foreach(Attribute a in attrs) {
    if(a.Type==0x30) { Require(!a.NonResident,"Capture","Nonresident FILE_NAME"); fileNames.Add(DecodeName(a.Value,0,a.Value.Length,before.Reference)); }
    if(a.Type==0x10) { Require(!a.NonResident && a.Value.Length>=72,"Capture","Bad STANDARD_INFORMATION"); image.SecurityId=U32(a.Value,52);
     image.RawMetadata=new Identity { Creation=I64(a.Value,0),Modified=I64(a.Value,8),Changed=I64(a.Value,16),Accessed=I64(a.Value,24),Attributes=U32(a.Value,32)|(before.Directory?0x10u:0u),Links=before.Links }; }
    if(a.Type==0x80) Require(a.Name=="","Capture","ADS ambiguity");
   }
   Require((fileNames.Count>0 || before.Links==0) && image.RawMetadata!=null,"Capture","Missing FILE_NAME/STANDARD_INFORMATION"); image.FileNames=fileNames.ToArray();
   if(before.Directory) { image.Names=Directory(v,attrs,containers); image.Logical=new byte[0]; image.Runs=new Run[0]; image.Resident=true; }
   else {
    List<Attribute> data=Select(attrs,0x80,""); Require(data.Count>0,"Capture","Missing DATA"); Attribute first=data[0]; if(first.Eof!=before.Eof) issues.Add("Raw/API EOF mismatch"); image.Resident=!first.NonResident;
    image.Runs=image.Resident?new Run[0]:MergeRuns(data); image.Names=new NameEntry[0]; image.Logical=ReadStream(v,data,containers,"DATA");
    Run[] api=Retrieval(h); if(!SameRuns(image.Runs,api)) issues.Add("Retrieval/raw runlist mismatch");
    if(first.NonResident && (first.Flags&0x8001)==0 && first.Allocation!=before.Allocation) issues.Add("Raw/API allocation mismatch");
   }
   image.Digest=Hash(image.Logical); image.Containers=containers.ToArray(); image.CrossCheckErrors=issues.ToArray(); Require(SameIdentity(before,GetIdentity(h)),"Stability","Identity changed during raw capture"); return image;
   } catch(Exception cause) {
    ObservationException failure=cause as ObservationException; if(failure==null) failure=new ObservationException("Capture",cause.Message,cause); failure.Containers=containers.ToArray();
    if(image!=null && image.Logical!=null) { image.Containers=containers.ToArray(); image.Digest=Hash(image.Logical); image.CrossCheckErrors=issues.ToArray(); failure.PartialImage=image; }
    throw failure;
   }
  }
  // Trusted observer only: resolve a file from its raw parent index without a
  // named/file-ID open of the private stream. StageAdmit intentionally refuses
  // those opens for every process except the authenticated service.
  public static Image CaptureNamedRaw(Volume v,Handle directory,string leaf) {return CapturePrivateCore(v,directory,leaf,false);}
  public static Image CaptureNamedTrusted(Volume v,Handle directory,string leaf) {return CapturePrivateCore(v,directory,leaf,true);}
  static Image CapturePrivateCore(Volume v,Handle directory,string leaf,bool cachedMetadata) {
   Require(!String.IsNullOrWhiteSpace(leaf) && leaf.IndexOfAny(new char[]{'\\','/',':'})<0,"PrivateSnapshot","Invalid leaf");
   List<Container> containers=new List<Container>(); Image image=null;
   try {
    Image parent=null; Identity parentIdentity; NameEntry match=null;
    if(cachedMetadata) {
     parentIdentity=GetIdentity(directory); Require(parentIdentity.Directory && parentIdentity.VolumeSerial==v.Geometry.Serial,"PrivateSnapshot","Cached parent identity invalid");
     match=new NameEntry{Name=leaf,Reference=PrivateDirectoryReference(directory,leaf,containers)};
    } else {
     parent=Capture(v,directory); containers.AddRange(parent.Containers);
     Require(parent.Identity.Directory && parent.CrossCheckErrors.Length==0,"PrivateSnapshot","Parent capture invalid"); parentIdentity=parent.Identity;
     foreach(NameEntry n in parent.Names) if(n.Namespace!=2 && n.Name==leaf) { Require(match==null,"PrivateSnapshot","Ambiguous parent name"); match=n; }
     Require(match!=null,"PrivateSnapshot","Private name absent in raw parent index");
    }
    uint number=checked((uint)(match.Reference&0x0000FFFFFFFFFFFFUL));
    Record basis=cachedMetadata?ReadCachedRecord(v,number,containers):ReadRecord(v,number,containers); List<Record> records=new List<Record>(); records.Add(basis);
    Require(basis.Sequence==(ushort)(match.Reference>>48) && basis.BaseReference==0 && (basis.Flags&2)==0,"PrivateSnapshot","Record identity/type/link ambiguity");
    if(cachedMetadata) Require(Select(basis.Attributes,0x20,"").Count==0,"PrivateSnapshot","Cached split-record stage unsupported");
    Attribute[] attrs=cachedMetadata?basis.Attributes:ResolveAttributes(v,basis,records,containers); List<NameEntry> names=new List<NameEntry>(); Attribute standard=null;
    foreach(Attribute a in attrs) {
     if(a.Type==0x30) { Require(!a.NonResident,"PrivateSnapshot","Nonresident name"); names.Add(DecodeName(a.Value,0,a.Value.Length,match.Reference)); }
     if(a.Type==0x10) { Require(standard==null && !a.NonResident && a.Value.Length>=72,"PrivateSnapshot","Invalid standard information"); standard=a; }
     if(a.Type==0x80) Require(a.Name=="","PrivateSnapshot","ADS ambiguity");
    }
    Require(standard!=null && (U32(standard.Value,32)&0x4410)==0,"PrivateSnapshot","Reparse/EFS/directory ambiguity");
    int bound=0,aliases=0; foreach(NameEntry n in names) {
     Require(n.Parent==parentIdentity.Reference,"PrivateSnapshot","Additional parent/hard-link ambiguity");
     if((n.Namespace==1 || n.Namespace==3) && n.Name==leaf) bound++;
     else { Require(n.Namespace==2,"PrivateSnapshot","Additional private name/hard-link ambiguity"); aliases++; }
    }
    Require(bound==1 && aliases<=1 && U16(basis.Fixed,18)==names.Count,"PrivateSnapshot","FILE_NAME/header does not bind one Win32 name and optional DOS alias");
    List<Attribute> data=Select(attrs,0x80,""); Require(data.Count>0,"PrivateSnapshot","Missing data");
    byte[] logical=ReadStream(v,data,containers,"PRIVATE_DATA");
    List<Container> secondContainers=new List<Container>(); byte[] second=ReadStream(v,data,secondContainers,"PRIVATE_DATA_REPEAT");
    Require(logical.Length==second.Length && Hash(logical)==Hash(second),"PrivateSnapshot","Private bytes changed during read");
    containers.AddRange(secondContainers);
    foreach(Record record in records) { Record after=cachedMetadata?ReadCachedRecord(v,record.Number,containers):ReadRecord(v,record.Number,containers); Require(Hash(record.Raw)==Hash(after.Raw),"PrivateSnapshot","Private record/runlist changed during read"); }
    if(cachedMetadata) {
     Require(PrivateDirectoryReference(directory,leaf,containers)==match.Reference && SameIdentity(parentIdentity,GetIdentity(directory)),"PrivateSnapshot","Cached private name/parent identity changed during read");
    } else {
     Image parentAfter=Capture(v,directory); containers.AddRange(parentAfter.Containers);
     Require(Fingerprint(parent)==Fingerprint(parentAfter),"PrivateSnapshot","Parent index changed during read");
    }
    byte[] id=new byte[16]; Buffer.BlockCopy(BitConverter.GetBytes(match.Reference),0,id,0,8);
    Identity identity=new Identity{VolumeSerial=v.Geometry.Serial,Reference=match.Reference,FileId=BitConverter.ToString(id).Replace("-",""),
     Eof=logical.Length,Allocation=data[0].NonResident?data[0].Allocation:logical.Length,Attributes=U32(standard.Value,32),Links=1,
     Creation=I64(standard.Value,0),Modified=I64(standard.Value,8),Changed=I64(standard.Value,16),Accessed=I64(standard.Value,24)};
    image=new Image{Identity=identity,RawMetadata=identity,SecurityId=U32(standard.Value,52),Attributes=attrs,FileNames=names.ToArray(),Names=new NameEntry[0],
     Logical=logical,Digest=Hash(logical),Resident=!data[0].NonResident,Runs=data[0].NonResident?MergeRuns(data):new Run[0],Records=records.ToArray(),
     Containers=containers.ToArray(),CrossCheckErrors=new string[0]};
    return image;
   } catch(Exception cause) {
    ObservationException failure=cause as ObservationException; if(failure==null) failure=new ObservationException("PrivateSnapshot",cause.Message,cause);
    failure.Containers=containers.ToArray(); failure.PartialImage=image; throw failure;
   }
  }
  public static string Fingerprint(Image image) {
   StringBuilder s=new StringBuilder(); s.Append(image.Identity.FileId).Append(':').Append(image.Identity.Eof).Append(':').Append(image.Identity.Allocation).Append(':').Append(image.Identity.Attributes);
   foreach(Run r in image.Runs) s.Append('|').Append(r.Vcn).Append(',').Append(r.NextVcn).Append(',').Append(r.Lcn);
   bool directory=(image.Identity.Attributes&0x10)!=0;
   // A directory's MFT record (LSN, timestamps) and its index entries' copies of child sizes/attributes are updated lazily by NTFS
   // while the children are written (observer-selfcheck-live run 4: "Directory changed across bracket" with nothing changed by the caller).
   // A directory is fingerprinted by what the invariant cares about: its identity, runs and its names with file reference and namespace.
   // The MFT record bytes (LSN at offset 8, $STANDARD_INFORMATION times/USN) also change lazily after a write while the data and layout
   // do not (run 6: "Content/layout changed across bracket" right after a patch and restore). Content is covered by the image Digest compared
   // alongside this fingerprint and layout by identity, EOF, allocation and runs, so record numbers (not bytes) are what is fingerprinted.
   foreach(Record r in image.Records) s.Append('|').Append(r.Number);
   List<string> names=new List<string>(); foreach(NameEntry n in image.Names) names.Add(directory?(n.Name+":"+n.Reference+":"+n.Namespace):(n.Name+":"+n.Reference+":"+n.Eof+":"+n.Attributes));
   names.Sort(StringComparer.Ordinal); foreach(string n in names) s.Append('|').Append(n);
   return Hash(Encoding.UTF8.GetBytes(s.ToString()));
  }
  public static Reader Fresh(string path,bool raw,int alignment) {
   Reader r=new Reader(); r.Status="ERROR";
   try { using(Handle h=Open(path,raw,false)) {
    r.Before=GetIdentity(h); byte[] bytes;
    if(raw) { byte[] a=new byte[4]; if(!GetFileInformationByHandleEx(h.Value,17,a,4)) throw Error("FileAlignmentInfo"); int required=checked((int)U32(a,0)+1); alignment=Math.Max(alignment,required); bytes=ReadAligned(h,0,checked((int)r.Before.Eof),alignment,true,r.Before.Eof); }
    else { bytes=new byte[(int)r.Before.Eof]; using(SafeFileHandle borrowed=new SafeFileHandle(h.Value.DangerousGetHandle(),false)) using(FileStream stream=new FileStream(borrowed,FileAccess.Read,65536,false)) { int total=0; while(total<bytes.Length) { int n=stream.Read(bytes,total,bytes.Length-total); Require(n>0,"Fresh","Short buffered read"); total+=n; } r.After=GetIdentity(h); } }
    if(raw) r.After=GetIdentity(h); Require(SameIdentity(r.Before,r.After),"Stability","Fresh reader identity changed"); r.Digest=Hash(bytes); r.Length=bytes.Length; r.Status="OK";
   } } catch(ObservationException e) { r.NativeCode=e.NativeCode; throw; } return r;
  }
  public static Reader ReadHeld(Handle h) {
   Reader r=new Reader(); r.Before=GetIdentity(h); byte[] bytes=new byte[(int)r.Before.Eof];
   using(SafeFileHandle borrowed=new SafeFileHandle(h.Value.DangerousGetHandle(),false)) using(FileStream stream=new FileStream(borrowed,FileAccess.Read,65536,false)) {
    Require(stream.Seek(0,SeekOrigin.Begin)==0,"HeldReader","Seek mismatch"); int total=0;
    while(total<bytes.Length) { int n=stream.Read(bytes,total,bytes.Length-total); Require(n>0,"HeldReader","Short buffered read"); total+=n; }
    r.After=GetIdentity(h);
   }
   Require(SameIdentity(r.Before,r.After),"Stability","Held reader identity changed"); r.Digest=Hash(bytes); r.Length=bytes.Length; r.Status="OK"; return r;
  }
  public static int CountDifferences(byte[] a,byte[] b) {
   Require(a!=null && b!=null,"Predicate","Null comparison image"); int count=Math.Abs(a.Length-b.Length);
   for(int i=0;i<Math.Min(a.Length,b.Length);i++) if(a[i]!=b[i]) count++; return count;
  }
  public static int Find(byte[] container,byte[] pattern) {
   Require(pattern!=null && pattern.Length>0,"Predicate","Empty forbidden pattern"); if(container==null) return -1;
   for(int i=0;i<=container.Length-pattern.Length;i++) { int j=0; for(;j<pattern.Length && container[i+j]==pattern[j];j++); if(j==pattern.Length)return i; } return -1;
  }
 }
}
'@
    [StagedInvariant.Native]::LoadedModuleHash = [StagedInvariant.Native]::Hash([IO.File]::ReadAllBytes($PSCommandPath))
}
if ([StagedInvariant.Native]::LoadedModuleHash -cne [StagedInvariant.Native]::Hash([IO.File]::ReadAllBytes($PSCommandPath))) {
    throw 'A different observer helper is already loaded. Start a fresh powershell.exe process for these exact module bytes.'
}

function New-IORecord([string] $Kind, [hashtable] $Fields) {
    $record = [pscustomobject]$Fields
    $record.PSObject.TypeNames.Insert(0, ('StagedInvariant.' + $Kind))
    return $record
}
function Get-IOTime($Context) {
    return [ordered]@{ Utc = [DateTime]::UtcNow.ToString('o'); Qpc = [Diagnostics.Stopwatch]::GetTimestamp()
        QpcFrequency = [Diagnostics.Stopwatch]::Frequency; BootId = $Context.BootId }
}
function New-IOError([string] $Phase, $Exception) {
    $chain = @(); $code = $null; $nativePhase = $null
    $queue=[Collections.Generic.Queue[Exception]]::new(); $seen=[Collections.Generic.HashSet[Exception]]::new()
    $queue.Enqueue($Exception)
    while ($queue.Count -gt 0) {
        $e=$queue.Dequeue(); if (-not $seen.Add($e)) { continue }
        $node=[ordered]@{ Type=$e.GetType().FullName; Message=$e.Message; HResult=$e.HResult; Stack=$e.StackTrace; NativeCode=$null; NativePhase=$null }
        if ($e -is [StagedInvariant.ObservationException]) { $code=$e.NativeCode; $nativePhase=$e.Phase; $node.NativeCode=$code; $node.NativePhase=$nativePhase }
        if ($e -is [ComponentModel.Win32Exception]) { $code=$e.NativeErrorCode; $node.NativeCode=$code }
        $chain += [pscustomobject]$node
        if ($null -ne $e.InnerException) { $queue.Enqueue($e.InnerException) }
        if ($e -is [AggregateException]) { foreach ($inner in $e.InnerExceptions) { $queue.Enqueue($inner) } }
    }
    return New-IORecord 'Error' @{ Phase = $Phase; NativePhase = $nativePhase; NativeCode = $code; Chain = $chain; Verdict = 'INCONCLUSIVE' }
}
function Assert-IOContext($Context) {
    if ($null -eq $Context -or $Context.Status -ne 'OK' -or $Context.Closed) { throw 'A live successful observer context is required.' }
}
function Save-IOBytes($Context, [byte[]] $Bytes, [string] $Kind) {
    if ($null -eq $Bytes) { throw 'Null artifact is not an empty image.' }
    $id = [guid]::NewGuid().ToString('N')
    $path = Join-Path $Context.EvidenceDirectory ($Kind + '-' + $id + '.bin')
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::Read, 65536, [IO.FileOptions]::WriteThrough)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $artifact = New-IORecord 'Artifact' @{ Path = $path; Kind = $Kind; Length = [long]$Bytes.Length; Sha256 = [StagedInvariant.Native]::Hash($Bytes) }
    $line = [Text.Encoding]::UTF8.GetBytes(($artifact | ConvertTo-Json -Compress) + "`n")
    $manifest = [IO.FileStream]::new((Join-Path $Context.EvidenceDirectory 'manifest.ndjson'), [IO.FileMode]::Append,
        [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $manifest.Write($line,0,$line.Length); $manifest.Flush($true) } finally { $manifest.Dispose() }
    return $artifact
}
function Save-IOImage($Context, $Image, [string] $Path, [string] $Role) {
    $containers = @()
    foreach ($c in $Image.Containers) {
        $artifact = Save-IOBytes $Context $c.Bytes $c.Kind
        $containers += [pscustomobject]@{ Offset = $c.Offset; Length = [long]$c.Bytes.Length; Kind = $c.Kind; Artifact = $artifact }
    }
    $logical = Save-IOBytes $Context $Image.Logical 'logical'
    $sddl = $null
    if (-not [string]::IsNullOrEmpty($Path) -and (Test-Path -LiteralPath $Path)) {
        $acl = Get-Acl -LiteralPath $Path
        $sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group -bor [Security.AccessControl.AccessControlSections]::Access)
    }
    return New-IORecord 'StorageImage' @{ Path = $Path; Role = $Role; Identity = $Image.Identity; Resident = $Image.Resident; CrossCheckErrors = @($Image.CrossCheckErrors)
        Length = [long]$Image.Logical.Length; Sha256 = $Image.Digest; Runs = @($Image.Runs); FileNames = @($Image.FileNames)
        DirectoryEntries = @($Image.Names | Sort-Object Name, Namespace, Reference); RawMetadata = $Image.RawMetadata; SecurityId = $Image.SecurityId; Sddl = $sddl
        Attributes = @($Image.Attributes | ForEach-Object { [pscustomobject]@{ Type=$_.Type; Id=$_.Id; Flags=$_.Flags; Name=$_.Name; RecordReference=$_.RecordReference
            NonResident=$_.NonResident; StartVcn=$_.StartVcn; LastVcn=$_.LastVcn; Allocation=$_.Allocation; Eof=$_.Eof; ValidData=$_.ValidData; CompressionUnit=$_.CompressionUnit; Runs=@($_.Runs) } })
        Records = @($Image.Records | ForEach-Object { [pscustomobject]@{ Number = $_.Number; Sequence = $_.Sequence; BaseReference = $_.BaseReference
            RawSha256 = [StagedInvariant.Native]::Hash($_.Raw); FixedSha256 = [StagedInvariant.Native]::Hash($_.Fixed) } })
        Containers = $containers; LogicalArtifact = $logical; Fingerprint = [StagedInvariant.Native]::Fingerprint($Image) }
}
function Read-InvariantPrivateSnapshot {
    [CmdletBinding()] param([Parameter(Mandatory=$true)]$Context,[Parameter(Mandatory=$true)][string]$Path)
    Assert-IOContext $Context
    $full=[IO.Path]::GetFullPath($Path)
    $parent=[IO.Path]::GetDirectoryName($full);$leaf=[IO.Path]::GetFileName($full)
    # This helper is a private staging proof, never a substitute for a public
    # destination's API/raw cross-check and supplemental-reader contract.
    if($parent -ine 'C:\ProgramData\SafeUpload\staging' -or $leaf -cnotmatch '^[0-9a-fA-F]{32}\.[A-Za-z0-9]+$'){throw 'Private snapshot path outside exact stage namespace.'}
    if([StagedInvariant.Native]::ResolveGuid($parent) -ine $Context.Geometry.Guid){throw 'Private snapshot is on another volume.'}
    $held=@();$native=$null
    try {
        $ancestor=$parent
        while(-not [string]::IsNullOrEmpty($ancestor)){
            if(((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse private snapshot ancestor.'}
            $held+=[StagedInvariant.Native]::Open($ancestor,$false,$true)
            $ancestor=[IO.Path]::GetDirectoryName($ancestor)
        }
        $metadataSource='RawIndexAndMft';$rawAttempt=$null
        try {$native=[StagedInvariant.Native]::CaptureNamedRaw($Context.Volume,$held[0],$leaf)}
        catch {
            $caught=$_.Exception;$archived=@()
            for($error=$caught;$null -ne $error;$error=$error.InnerException){
                if($error -is [StagedInvariant.ObservationException] -and $null -ne $error.Containers){
                    foreach($container in $error.Containers){$archived+=@{Kind=$container.Kind;Offset=$container.Offset;Artifact=(Save-IOBytes $Context $container.Bytes ('private-partial-'+$container.Kind))}}
                }
            }
            $rawAttempt=@{Status='ERROR';Error=(New-IOError 'PrivateRawMetadata' $caught);ArchivedContainers=$archived}
            $native=[StagedInvariant.Native]::CaptureNamedTrusted($Context.Volume,$held[0],$leaf)
            $metadataSource='TrustedKernelDirectoryAndCachedMft'
        }
        # No named stage-file security query/open: raw index + MFT reference is
        # the file binding. The sealed service manifest supplies expected A.
        $saved=Save-IOImage $Context $native $null 'PrivateSealedSnapshot'
        $saved | Add-Member -NotePropertyName MetadataSource -NotePropertyValue $metadataSource
        $saved | Add-Member -NotePropertyName DataSource -NotePropertyValue $(if($native.Resident){$metadataSource+'ResidentData'}else{'RawVolumeNonresidentRuns'})
        $saved | Add-Member -NotePropertyName RawAttempt -NotePropertyValue $rawAttempt
        $saved | Add-Member -NotePropertyName StagePath -NotePropertyValue $full
        return $saved
    } catch {
        for($error=$_.Exception;$null -ne $error;$error=$error.InnerException){
            if($error -is [StagedInvariant.ObservationException] -and $null -ne $error.Containers){
                foreach($container in $error.Containers){$null=Save-IOBytes $Context $container.Bytes ('private-partial-'+$container.Kind)}
            }
        }
        throw
    } finally {foreach($handle in $held){$handle.Dispose()}}
}
function Get-IOEntryKey($Entry) { return ('{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}' -f $Entry.Name, $Entry.Namespace, $Entry.Reference, $Entry.Eof, $Entry.Attributes, $Entry.Parent, $Entry.Allocated, $Entry.Creation, $Entry.Modified, $Entry.Changed, $Entry.Accessed) }
function Assert-IOParentMatch($Image, $Parent, [string] $Leaf) {
    $match = @($Parent.Names | Where-Object { $_.Name -ceq $Leaf -and $_.Reference -eq $Image.Identity.Reference -and $_.Namespace -ne 2 })
    if ($match.Count -ne 1) { throw 'Raw parent index does not identify the requested name/file reference.' }
    $names = @($Image.FileNames | Where-Object { $_.Name -ceq $Leaf -and $_.Parent -eq $Parent.Identity.Reference -and $_.Namespace -ne 2 })
    if ($names.Count -ne 1) { throw 'Raw FILE_NAME parent/name does not match parent index.' }
}
function Get-IOPath($Context, [string] $Name) {
    if ([string]::IsNullOrWhiteSpace($Name) -or [IO.Path]::IsPathRooted($Name) -or $Name.Contains(':')) { throw 'Destination must be a nonempty relative path without ADS.' }
    $path = [IO.Path]::GetFullPath((Join-Path $Context.ScopePath $Name))
    if (-not $path.StartsWith($Context.ScopePath + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Destination escapes scope.' }
    # Check every ancestor; a junction on an intermediate directory is also ambiguous.
    $parent = $path
    while ($parent.Length -ge $Context.ScopePath.Length) {
        if (Test-Path -LiteralPath $parent) {
            $item = Get-Item -LiteralPath $parent -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse fixture ancestor.' }
        }
        if ($parent -eq $Context.ScopePath) { break }; $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return $path
}
function Open-InvariantObserver {
    [CmdletBinding()] param([Parameter(Mandatory=$true)][string] $VolumeGuid,
        [Parameter(Mandatory=$true)][string] $ScopePath, [Parameter(Mandatory=$true)][string] $EvidenceDirectory,
        [Parameter(Mandatory=$true)][string] $CaseId)
    $volume = $null; $evidence = $null
    try {
        foreach ($s in @($VolumeGuid, $ScopePath, $EvidenceDirectory, $CaseId)) { if ([string]::IsNullOrWhiteSpace($s)) { throw 'Empty required argument.' } }
        if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Windows PowerShell 5.1 is required.' }
        if (-not [Diagnostics.Stopwatch]::IsHighResolution) { throw 'A QPC-backed Stopwatch is required.' }
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated independent observer required.' }
        $scope = [IO.Path]::GetFullPath($ScopePath).TrimEnd('\')
        if (-not (Test-Path -LiteralPath $scope -PathType Container)) { throw 'Scope directory must already exist.' }
        $ancestor = $scope
        while (-not [string]::IsNullOrEmpty($ancestor)) {
            if (((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse scope ancestor.' }
            $ancestor = [IO.Path]::GetDirectoryName($ancestor)
        }
        $evidence = [IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\')
        if ($evidence -eq $scope -or $evidence.StartsWith($scope + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence must be outside the scope.' }
        # An evidence directory is owned by exactly one context; never reuse/overwrite.
        if (Test-Path -LiteralPath $evidence) { throw 'Evidence directory already exists; supply a unique path.' }
        [void][IO.Directory]::CreateDirectory($evidence)
        $windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $build = [string]$windows.CurrentBuildNumber + '.' + [string]$windows.UBR
        if ($build -ne '19045.2965') { throw ('Observer contract requires Windows 10 19045.2965; found ' + $build) }
        $volume = [StagedInvariant.Native]::OpenVolume($VolumeGuid, $scope)
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
        $context = New-IORecord 'Context' @{ Schema = 'StagedInvariant/1'; Status = 'OK'; Closed = $false; CaseId = $CaseId
            ScopePath = $scope; EvidenceDirectory = $evidence; Volume = $volume; Geometry = $volume.Geometry
            DecoderVersion = 'bounded-ntfs-v1'; ModuleSha256 = [StagedInvariant.Native]::LoadedModuleHash; BootId = $env:COMPUTERNAME + '/' + $boot; Build = $build
            TargetBuildSupported = ($build -eq '19045.2965'); ObserverPid = $PID
            ObserverSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            BaselineCaptured = $false; BootstrapArtifacts = @(); InitialScope = $null; Handles = @{}; Publications = @(); NextSequence = [long]0; LastSampleQpc = [long]0; LastSampleStartQpc = [long]0; Errors = @() }
        foreach ($c in $volume.BootstrapContainers) {
            $context.BootstrapArtifacts += [pscustomobject]@{ Offset=$c.Offset; Kind=$c.Kind; Artifact=(Save-IOBytes $context $c.Bytes $c.Kind) }
        }
        # A read-only raw parent capture validates directory identity and representation at open.
        $h = [StagedInvariant.Native]::Open($scope, $false, $true)
        try { $context.InitialScope = Save-IOImage $context ([StagedInvariant.Native]::Capture($volume, $h)) $scope 'OpenScope' } finally { $h.Dispose() }
        return $context
    } catch {
        $openException = $_.Exception
        $errorRecord = New-IOError 'Open' $openException
        if (-not [string]::IsNullOrWhiteSpace($evidence) -and (Test-Path -LiteralPath $evidence)) {
            $partialContext=[pscustomobject]@{ EvidenceDirectory=$evidence }
            for ($e=$openException; $null -ne $e; $e=$e.InnerException) {
                if ($e -is [StagedInvariant.ObservationException] -and $null -ne $e.Containers) {
                    foreach ($c in $e.Containers) { try { $null=Save-IOBytes $partialContext $c.Bytes 'open-partial' } catch { $errorRecord.Chain += (New-IOError 'OpenArtifact' $_.Exception).Chain } }
                }
            }
        }
        if ($null -ne $volume) { try { $volume.Dispose() } catch { $errorRecord.Chain += (New-IOError 'OpenCleanup' $_.Exception).Chain } }
        return New-IORecord 'Context' @{ Schema = 'StagedInvariant/1'; Status = 'ERROR'; Closed = $true; Error = $errorRecord }
    }
}
function Get-IOCapture($Context, [string[]] $Names, [switch] $Retained) {
    $images = @(); $parents = @{}; $readers = @(); $held = @(); $lookups = @(); $before=$null; $path=$null; $currentLookup=$false
    try {
        foreach ($name in $Names) {
            $before=$null; $currentLookup=$true
            $path = Get-IOPath $Context $name; $parentPath = [IO.Path]::GetDirectoryName($path)
            if (-not $parents.ContainsKey($parentPath)) {
                $ph = [StagedInvariant.Native]::Open($parentPath, $false, $true)
                $held += $ph
                $parents[$parentPath] = @{ Handle = $ph; Before = [StagedInvariant.Native]::Capture($Context.Volume, $ph) }
                $images += Save-IOImage $Context $parents[$parentPath].Before $parentPath 'Parent'
            }
            $parent = $parents[$parentPath].Before
            # Native create reports exact missing-name status; Test-Path access failures cannot prove absence.
            $h = $null
            try { $h = [StagedInvariant.Native]::Open($path, $false, $false) }
            catch {
                $err = New-IOError 'Lookup' $_.Exception
                if ($err.NativeCode -ne 2) { throw }
                if (@($parent.Names | Where-Object { $_.Name -ieq [IO.Path]::GetFileName($path) }).Count -ne 0) { throw 'Missing lookup but present raw index entry.' }
                $images += New-IORecord 'StorageImage' @{ Path = $path; Role = 'Current'; Absent = $true; ParentReference = $parent.Identity.Reference }
            }
            if ($null -ne $h) {
                $held += $h
                $before = [StagedInvariant.Native]::Capture($Context.Volume, $h)
                Assert-IOParentMatch $before $parent ([IO.Path]::GetFileName($path))
                $lookups += @{ Handle = $h; Before = $before; Path = $path }
                $saved = Save-IOImage $Context $before $path 'Current'
                $saved | Add-Member -NotePropertyName Absent -NotePropertyValue $false
                $images += $saved
                foreach ($raw in @($false, $true)) {
                    try { $reader = [StagedInvariant.Native]::Fresh($path, $raw, $Context.Geometry.Alignment)
                        if ($reader.Before.FileId -ne $before.Identity.FileId) { throw 'Fresh reader resolved another generation.' }
                        $readers += New-IORecord 'FreshReader' @{ Path = $path; Unbuffered = $raw; Status = 'OK'; Result = $reader; Error = $null }
                    } catch { $readers += New-IORecord 'FreshReader' @{ Path = $path; Unbuffered = $raw; Status = 'ERROR'; Result = $null; Error = (New-IOError 'FreshReader' $_.Exception) } }
                }
            }
        }
        if ($Retained) {
            $currentLookup=$false
            foreach ($key in @($Context.Handles.Keys)) {
                $entry = $Context.Handles[$key]; $before = [StagedInvariant.Native]::Capture($Context.Volume, $entry.Handle)
                $lookups += @{ Handle = $entry.Handle; Before = $before; Path = $null }
                $retainedImage = Save-IOImage $Context $before $null ('Retained:' + $key)
                $retainedImage | Add-Member -NotePropertyName RetainedVersion -NotePropertyValue $entry.Version
                $images += $retainedImage
                try { $readers += New-IORecord 'FreshReader' @{ Path=$null; Role='Retained'; FileId=$key; Unbuffered=$false; Status='OK'; Result=([StagedInvariant.Native]::ReadHeld($entry.Handle)); Error=$null } }
                catch { $readers += New-IORecord 'FreshReader' @{ Path=$null; Role='Retained'; FileId=$key; Unbuffered=$false; Status='ERROR'; Result=$null; Error=(New-IOError 'HeldReader' $_.Exception) } }
                # Original physical clusters are history, even if moved/freed. They are never reidentified.
                foreach ($c in $entry.Original.Containers) {
                    $bytes = [StagedInvariant.Native]::ReadAligned($Context.Volume.Raw, $c.Offset, [int]$c.Length, $Context.Geometry.Alignment, $false, 0)
                    $images += New-IORecord 'HistoricalContainer' @{ Role = 'Historical'; OriginalFileId = $key; Kind = $c.Kind
                        Offset = $c.Offset; Length = $c.Length; OriginalSha256 = $c.Artifact.Sha256; Artifact = (Save-IOBytes $Context $bytes 'historical') }
                }
            }
        }
        # Bracket content with raw identities/maps/records and each affected directory index.
        foreach ($l in $lookups) {
            $after = [StagedInvariant.Native]::Capture($Context.Volume, $l.Handle)
            if ([StagedInvariant.Native]::Fingerprint($l.Before) -ne [StagedInvariant.Native]::Fingerprint($after) -or
                $l.Before.Digest -ne $after.Digest) { throw [StagedInvariant.ObservationException]::new('Stability', 'Content/layout changed across bracket.', 0) }
            if ($null -ne $l.Path) {
                $newLookup = [StagedInvariant.Native]::Open($l.Path, $false, $false)
                try { if (-not [StagedInvariant.Native]::SameIdentity($l.Before.Identity, [StagedInvariant.Native]::GetIdentity($newLookup))) {
                    throw [StagedInvariant.ObservationException]::new('Stability', 'Path generation changed across bracket.', 0) }
                } finally { $newLookup.Dispose() }
            }
        }
        foreach ($p in @($parents.Keys)) {
            $after = [StagedInvariant.Native]::Capture($Context.Volume, $parents[$p].Handle)
            if ([StagedInvariant.Native]::Fingerprint($parents[$p].Before) -ne [StagedInvariant.Native]::Fingerprint($after)) {
                throw [StagedInvariant.ObservationException]::new('Stability', 'Directory changed across bracket.', 0) }
        }
        if (@($images | Where-Object { $null -ne $_.PSObject.Properties['CrossCheckErrors'] -and $_.CrossCheckErrors.Count -gt 0 }).Count -gt 0) {
            throw [StagedInvariant.ObservationException]::new('CrossCheck','Raw/API EOF, allocation or runlist cross-check failed.',0)
        }
        return New-IORecord 'Capture' @{ Status = 'OK'; Images = $images; Readers = $readers; Error = $null }
    } catch {
        # Archive even containers read immediately before a decoder failure.
        $caught = $_.Exception
        if ($currentLookup -and $null -ne $before) {
            $partialImage=Save-IOImage $Context $before $path 'Current'
            $partialImage | Add-Member -NotePropertyName Absent -NotePropertyValue $false
            $images += $partialImage
        }
        for ($e = $caught; $null -ne $e; $e = $e.InnerException) {
            if ($e -is [StagedInvariant.ObservationException] -and $null -ne $e.PartialImage) {
                $partialPath=$path; $partialRole='Current'
                if (-not $currentLookup) { $partialPath=$null; $partialRole='Retained:' + $key }
                if ($e.PartialImage.Identity.Directory) { $partialPath=$parentPath; $partialRole='Parent' }
                $decoded=Save-IOImage $Context $e.PartialImage $partialPath $partialRole
                if ($partialRole -like 'Retained:*') { $decoded | Add-Member -NotePropertyName RetainedVersion -NotePropertyValue $entry.Version }
                if ($partialRole -eq 'Current') { $decoded | Add-Member -NotePropertyName Absent -NotePropertyValue $false }
                $images += $decoded
            }
            if ($e -is [StagedInvariant.ObservationException] -and $null -ne $e.Containers) {
                $partial = @()
                foreach ($c in $e.Containers) { $partial += [pscustomobject]@{ Offset=$c.Offset; Length=[long]$c.Bytes.Length; Kind=$c.Kind; Artifact=(Save-IOBytes $Context $c.Bytes 'partial') } }
                if ($partial.Count -gt 0) { $images += New-IORecord 'PartialContainer' @{ Role='Partial'; Path=$null; Containers=$partial } }
            }
        }
        return New-IORecord 'Capture' @{ Status = 'ERROR'; Images = $images; Readers = $readers; Error = (New-IOError 'Capture' $caught) }
    } finally {
        foreach ($handle in $held) { try { $handle.Dispose() } catch { $Context.Errors += New-IOError 'CaptureCleanup' $_.Exception } }
    }
}
function Capture-InvariantBaseline {
    [CmdletBinding()] param([Parameter(Mandatory=$true)] $Context,
        [Parameter(Mandatory=$true)][string[]] $DestinationNames, [Parameter(Mandatory=$true)][hashtable] $ExpectedImages)
    try {
        Assert-IOContext $Context
        if ($Context.BaselineCaptured) { throw 'Baseline capture is one-use; never rebaseline unexpected bytes.' }
        $Context.BaselineCaptured=$true
        $unique=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $DestinationNames) { if (-not $unique.Add((Get-IOPath $Context $name))) { throw 'Duplicate/case-ambiguous destination name.' } }
        if ($DestinationNames.Count -eq 0 -or $DestinationNames.Count -gt 256) { throw 'Destination count must be 1..256.' }
        $capture = Get-IOCapture $Context $DestinationNames
        if ($capture.Status -ne 'OK') { return New-IORecord 'Baseline' @{ Status = 'ERROR'; Error = $capture.Error; Partial = $capture; Names = $DestinationNames } }
        foreach ($name in $DestinationNames) {
            if (-not $ExpectedImages.ContainsKey($name)) { throw 'Every name requires independently supplied bytes, or null for expected absence.' }
            $path = Get-IOPath $Context $name; $image = @($capture.Images | Where-Object { $_.Role -eq 'Current' -and $_.Path -eq $path })[0]
            $expected = $ExpectedImages[$name]
            if ($null -eq $expected) { if (-not $image.Absent) { throw 'Expected absent destination exists.' }; continue }
            if ($expected -isnot [byte[]]) { throw 'ExpectedImages values must be byte[] or null.' }
            if ($image.Absent -or $image.Length -ne $expected.Length -or $image.Sha256 -ne [StagedInvariant.Native]::Hash($expected)) { throw 'Raw baseline does not match independent fixture bytes; flush legitimate setup first.' }
            foreach ($r in @($capture.Readers | Where-Object { $_.Path -eq $path })) {
                if ($r.Status -ne 'OK' -or $r.Result.Digest -ne $image.Sha256) { throw 'Baseline fresh reader mismatch/error.' }
            }
            $h = [StagedInvariant.Native]::Open($path, $false, $false)
            $keep = $false
            try {
                if (-not [StagedInvariant.Native]::SameIdentity($image.Identity, [StagedInvariant.Native]::GetIdentity($h))) { throw 'Baseline changed before retaining handle.' }
                if ($Context.Handles.ContainsKey($image.Identity.FileId)) { throw 'Duplicate/rebaseline destination identity.' }
                $Context.Handles[$image.Identity.FileId] = @{ Handle = $h; Original = $image; Version = 'Baseline' }; $keep = $true
            } finally { if (-not $keep) { $h.Dispose() } }
        }
        return New-IORecord 'Baseline' @{ Schema = 'StagedInvariant/1'; Status = 'OK'; CaseId = $Context.CaseId; Time = (Get-IOTime $Context)
            Names = $DestinationNames; Images = $capture.Images; Readers = $capture.Readers; Geometry = $Context.Geometry; Build = $Context.Build; ObserverPid = $Context.ObserverPid; ObserverSid = $Context.ObserverSid; Error = $null }
    } catch { return New-IORecord 'Baseline' @{ Status = 'ERROR'; Error = (New-IOError 'Baseline' $_.Exception) } }
}
function Register-InvariantPublication {
    [CmdletBinding()] param([Parameter(Mandatory=$true)] $Context, [Parameter(Mandatory=$true)] $ApprovalRecord,
        [Parameter(Mandatory=$true)][byte[]] $SealedImage)
    $observedGrant=$false; $validating=$true
    try {
        Assert-IOContext $Context
        $observedGrant=($null -ne $ApprovalRecord.PSObject.Properties['Source'] -and $ApprovalRecord.Source -ceq 'ActualServiceJournalAndPermit' -and
            $null -ne $ApprovalRecord.PSObject.Properties['ActualServiceGrant'] -and $ApprovalRecord.ActualServiceGrant -eq $true)
        if ($SealedImage.Length -gt [StagedInvariant.Native]::MaxImage -or $Context.Publications.Count -ge 256) { throw 'Approval image/count cap exceeded.' }
        # Input record is evidence supplied by the real service/journal adapter, never a fixture token.
        foreach ($field in @('Source', 'TransferId', 'DestinationGeneration', 'PolicyGeneration', 'EpochGeneration', 'TempPath', 'FinalPath',
            'ExpiryUtc', 'ServiceSid', 'ServicePid', 'AttemptId', 'ApprovedLength', 'ApprovedSha256', 'PermitLength', 'PermitSha256',
            'ApprovedQpc', 'PermitGrantQpc', 'ExpiryQpc', 'JournalSequence', 'PermitSequence', 'JournalIdentity', 'PermitIdentity', 'BootId', 'SnapshotImmutable', 'ActualServiceGrant')) {
            if ($null -eq $ApprovalRecord.PSObject.Properties[$field] -or [string]::IsNullOrWhiteSpace([string]$ApprovalRecord.$field)) { throw ('Missing approval field: ' + $field) }
        }
        if ($ApprovalRecord.Source -ne 'ActualServiceJournalAndPermit' -or $ApprovalRecord.SnapshotImmutable -ne $true -or $ApprovalRecord.ActualServiceGrant -ne $true -or
            $ApprovalRecord.ServiceSid -notmatch '^S-1-5-80-' -or [long]$ApprovalRecord.ServicePid -le 0 -or $ApprovalRecord.BootId -ne $Context.BootId) { throw 'Real immutable inspected service snapshot and permit evidence required.' }
        foreach ($field in @('TransferId','DestinationGeneration','PolicyGeneration','EpochGeneration','TempPath','FinalPath','ExpiryUtc','ServiceSid','ServicePid','AttemptId')) {
            if ($null -eq $ApprovalRecord.JournalIdentity.PSObject.Properties[$field] -or $null -eq $ApprovalRecord.PermitIdentity.PSObject.Properties[$field] -or
                $ApprovalRecord.$field -cne $ApprovalRecord.JournalIdentity.$field -or $ApprovalRecord.$field -cne $ApprovalRecord.PermitIdentity.$field) { throw ('Journal/permit identity mismatch: ' + $field) }
        }
        if ($ApprovalRecord.JournalIdentity.State -cne 'Approved' -or $ApprovalRecord.PermitIdentity.Granted -ne $true) { throw 'Journal is not Approved or real permit was not granted.' }
        $now = [Diagnostics.Stopwatch]::GetTimestamp()
        if ([long]$ApprovalRecord.ApprovedQpc -gt [long]$ApprovalRecord.PermitGrantQpc -or [long]$ApprovalRecord.PermitGrantQpc -gt $now -or [long]$ApprovalRecord.ExpiryQpc -le $now -or
            [DateTime]::Parse($ApprovalRecord.ExpiryUtc).ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Bad approval/grant/expiry ordering.' }
        $digest = [StagedInvariant.Native]::Hash($SealedImage)
        if ($digest -cne $ApprovalRecord.ApprovedSha256 -or $digest -cne $ApprovalRecord.PermitSha256 -or
            $SealedImage.Length -ne [long]$ApprovalRecord.ApprovedLength -or $SealedImage.Length -ne [long]$ApprovalRecord.PermitLength) { throw 'Inspection snapshot/journal/permit digest or length mismatch.' }
        foreach ($path in @($ApprovalRecord.TempPath, $ApprovalRecord.FinalPath)) {
            $full = [IO.Path]::GetFullPath($path)
            if ($full -cne $path -or -not $full.StartsWith($Context.ScopePath + '\', [StringComparison]::OrdinalIgnoreCase) -or $full.Substring($Context.ScopePath.Length).Contains(':')) { throw 'Approval path not exact/in-scope.' }
        }
        if ($ApprovalRecord.TempPath -eq $ApprovalRecord.FinalPath -or @($Context.Publications | Where-Object { $_.Approval.AttemptId -eq $ApprovalRecord.AttemptId }).Count -ne 0) { throw 'Duplicate attempt or invalid temp/final paths.' }
        # Clone before hashing again/archiving: caller mutation cannot later expand authorization.
        $copy = [byte[]]$SealedImage.Clone()
        if ([StagedInvariant.Native]::Hash($copy) -ne $digest) { throw 'Snapshot changed during registration.' }
        $validating=$false
        $approved = New-IORecord 'ApprovedImage' @{ Status = 'OK'; Time = (Get-IOTime $Context); Approval = $ApprovalRecord.PSObject.Copy()
            Length = [long]$copy.Length; Sha256 = $digest; SnapshotArtifact = (Save-IOBytes $Context $copy 'approved'); Error = $null }
        $Context.Publications += $approved; return $approved
    } catch {
        $errorRecord=New-IOError 'RegisterPublication' $_.Exception
        if ($observedGrant -and $validating) { $errorRecord.Verdict='FAIL' }
        return New-IORecord 'ApprovedImage' @{ Status='ERROR'; Error=$errorRecord }
    }
}
function Capture-InvariantSample {
    [CmdletBinding()] param([Parameter(Mandatory=$true)] $Context, [Parameter(Mandatory=$true)] $Baseline,
        [Parameter(Mandatory=$true)][string] $Phase, [Parameter(Mandatory=$true)][long] $OperationSequence)
    $captures=@(); $attempts=@(); $capture=$null; $start=$null
    try {
        Assert-IOContext $Context
        if ($Baseline.Status -ne 'OK' -or [string]::IsNullOrWhiteSpace($Phase) -or $OperationSequence -lt 0) { throw 'Successful baseline/nonempty phase/nonnegative sequence required.' }
        if ($Baseline.CaseId -cne $Context.CaseId -or $Baseline.Geometry.Guid -cne $Context.Geometry.Guid -or $Baseline.Time.BootId -cne $Context.BootId) { throw 'Baseline belongs to another observer case/volume/boot.' }
        $start = Get-IOTime $Context; $attempts = @(); $captures = @(); $watch = [Diagnostics.Stopwatch]::StartNew()
        for ($i = 0; $i -lt 10 -and $watch.ElapsedMilliseconds -lt 2000; $i++) {
            $begin = [Diagnostics.Stopwatch]::GetTimestamp()
            $capture = Get-IOCapture $Context $Baseline.Names -Retained
            $captures += $capture
            $attempts += [pscustomobject]@{ Attempt = $i + 1; StartQpc = $begin; EndQpc = [Diagnostics.Stopwatch]::GetTimestamp(); Status = $capture.Status; Error = $capture.Error }
            if ($capture.Status -eq 'OK') { break }
            if ($capture.Error.NativePhase -ne 'Stability') { break }
        }
        if ($capture.Status -eq 'OK') {
            foreach ($image in @($capture.Images | Where-Object { $_.Role -eq 'Current' -and -not $_.Absent })) {
                if ($Context.Handles.ContainsKey($image.Identity.FileId)) { continue }
                $approval = @($Context.Publications | Where-Object { $_.Approval.FinalPath -ceq $image.Path -and $_.Sha256 -ceq $image.Sha256 -and $_.Length -eq $image.Length -and $_.Time.Qpc -le $start.Qpc })
                if ($approval.Count -eq 1) {
                    $handle = [StagedInvariant.Native]::Open($image.Path,$false,$false); $keep=$false
                    try {
                        if (-not [StagedInvariant.Native]::SameIdentity($image.Identity,[StagedInvariant.Native]::GetIdentity($handle))) { throw 'Approved generation changed before retained handle.' }
                        $Context.Handles[$image.Identity.FileId]=@{ Handle=$handle; Original=$image; Version=$approval[0].Approval.AttemptId }; $keep=$true
                    } finally { if (-not $keep) { $handle.Dispose() } }
                }
            }
        }
        $end = Get-IOTime $Context; $gap = $null; $cadence=$null
        if ($Context.LastSampleStartQpc -ne 0) { $cadence=1000.0*($start.Qpc-$Context.LastSampleStartQpc)/$start.QpcFrequency }
        $Context.LastSampleStartQpc=$start.Qpc
        if ($Context.LastSampleQpc -ne 0) { $gap = 1000.0 * ($start.Qpc - $Context.LastSampleQpc) / $start.QpcFrequency }
        $Context.LastSampleQpc = $end.Qpc; $Context.NextSequence++
        return New-IORecord 'Sample' @{ Schema = 'StagedInvariant/1'; Status = $capture.Status; CaseId = $Context.CaseId
            Sequence = $Context.NextSequence; OperationSequence = $OperationSequence; Phase = $Phase; Start = $start; End = $end
            GapMs = $gap; CadenceMs=$cadence; DurationMs = $watch.Elapsed.TotalMilliseconds; Attempts = $attempts; Captures = $captures
            Images = $capture.Images; Readers = $capture.Readers; Error = $capture.Error; CleanupErrors = @($Context.Errors) }
    } catch {
        $errorRecord=New-IOError 'Sample' $_.Exception; $end=$null; $sequence=$null; $images=@(); $readers=@()
        if ($null -ne $capture) { $images=$capture.Images; $readers=$capture.Readers }
        if ($null -ne $start) { $end=Get-IOTime $Context; $Context.NextSequence++; $sequence=$Context.NextSequence; $Context.LastSampleQpc=$end.Qpc; $Context.LastSampleStartQpc=$start.Qpc }
        return New-IORecord 'Sample' @{ Status='ERROR'; Phase=$Phase; OperationSequence=$OperationSequence; Sequence=$sequence; Start=$start; End=$end; GapMs=$null; CadenceMs=$null; DurationMs=$(if ($null -ne $start) {1000.0*($end.Qpc-$start.Qpc)/$start.QpcFrequency} else {$null})
            Captures=$captures; Attempts=$attempts; Images=$images; Readers=$readers; CleanupErrors=@(); Error=$errorRecord }
    }
}
function Read-IOArtifact($Artifact) {
    if ($Artifact.Length -gt [StagedInvariant.Native]::MaxAllocation -or [string]::IsNullOrWhiteSpace($Artifact.Path)) { throw 'Artifact bounds/path.' }
    $bytes = [IO.File]::ReadAllBytes($Artifact.Path)
    if ($bytes.Length -ne $Artifact.Length -or [StagedInvariant.Native]::Hash($bytes) -cne $Artifact.Sha256) { throw 'Artifact changed/missing/truncated.' }
    return ,$bytes
}
function New-IOAssertion([string] $Name, [string] $Verdict, [string] $Reason, $Sequence, $Path) {
    return New-IORecord 'Assertion' @{ Name = $Name; Verdict = $Verdict; Reason = $Reason; SampleSequence = $Sequence; Path = $Path }
}
function Test-InvariantCadence($Baseline, $Samples, $Operations, $Fence) {
    Set-StrictMode -Off # Missing proof fields produce INCONCLUSIVE, including older evidence.

    # Evaluate the synchronous actor timeline, not a substitute lower mutation ledger.
    # Treat an entire open/write/flush/close attempt as live, including between calls.
    $windows=@();$receipts=@();$assertions=@();$valid=$false
    try {
        $frequency=[long]$Baseline.Time.QpcFrequency
        if ($frequency -le 0 -or $Fence.Complete -ne $true -or $Fence.BootId -cne $Baseline.Time.BootId -or
            $Fence.QpcFrequency -ne $frequency -or $Fence.ExpectedAttempts -ne 101 -or
            $Fence.ReleasedQpc -gt $Fence.CompletedQpc) { throw 'Missing complete writer barrier/completion/QPC fence.' }
        $assigned=0;$last=[long]$Fence.ReleasedQpc
        for($n=0;$n -lt $Fence.ExpectedAttempts;$n++) {
            $calls=@($Operations | Where-Object Trial -eq $n)
            if ($calls.Count -notin @(1,4) -or $calls[0].Class -notin @('writer-open','writer-open-deny')) { throw 'Incomplete native attempt timeline.' }
            if (($calls.Count -eq 1 -and ($calls[0].Class -cne 'writer-open-deny' -or $calls[0].NativeCode -eq 0)) -or
                ($calls.Count -eq 4 -and (($calls.Class -join ',') -cne 'writer-open,cached-write,flush,close' -or $calls[0].NativeCode -ne 0))) { throw 'Native call order is incomplete.' }
            foreach($call in $calls) {
                if ($call.StartQpc -lt $last -or $call.EndQpc -lt $call.StartQpc -or $call.EndQpc -gt $Fence.CompletedQpc) { throw 'Native QPC order outside writer fence.' }
                $last=[long]$call.EndQpc
            }
            $assigned+=$calls.Count
            $windows+= [pscustomobject]@{Trial=$n;StartQpc=$calls[0].StartQpc;EndQpc=$calls[-1].EndQpc}
        }
        if ($Operations.Count -ne $assigned) { throw 'Unassigned operation records.' }
        if($Samples.Count -eq 0 -or @($windows | Where-Object {$_.EndQpc -gt $Samples[-1].End.Qpc}).Count){throw 'Actor operations extend beyond the final observation.'}
        if($Baseline.CaseId -cne 'S00-observer-control' -and @($windows | Where-Object {$_.StartQpc -lt $Baseline.Time.Qpc}).Count){throw 'Pre-baseline actor operations are allowed only for the S00 control fixture setup.'}
        $valid=$true
    } catch { $failure=$_.Exception.Message }
    $previous=[long]$Baseline.Time.Qpc;$previousStart=$previous;$sequence=0
    foreach($s in $Samples) {
        $ordered=($valid -and $s.Status -eq 'OK' -and $s.Sequence -eq ($sequence+1) -and
            $s.Start.BootId -ceq $Baseline.Time.BootId -and $s.End.BootId -ceq $Baseline.Time.BootId -and
            $s.Start.QpcFrequency -eq $frequency -and $s.End.QpcFrequency -eq $frequency -and
            $s.Start.Qpc -ge $previous -and $s.End.Qpc -ge $s.Start.Qpc)
        foreach($interval in @(
            @{Kind='Gap';Start=$previous;End=$s.Start.Qpc;Assertion='CadenceGap'},
            @{Kind='Capture';Start=$s.Start.Qpc;End=$s.End.Qpc;Assertion='CadenceCoverage'})) {
            $overlap=@($windows | Where-Object { $_.StartQpc -le $interval.End -and $_.EndQpc -ge $interval.Start })
            $accounted=($ordered -and $overlap.Count -eq 0)
            $reason=if(-not $valid){$failure}elseif(-not $ordered){'Invalid sample boot/frequency/order/status.'}
                elseif($overlap.Count){'Actor attempt may occur unobserved; no lower ledger exists to bridge this interval.'}
                else{'No actor attempt intersects this interval; complete synchronous writer fence. Kernel mutations remain outside this adapter.'}
            $receipt=[pscustomobject]@{SampleSequence=$s.Sequence;Kind=$interval.Kind;BootId=$Baseline.Time.BootId;QpcFrequency=$frequency;
                StartQpc=$interval.Start;EndQpc=$interval.End;DurationMs=$(if($ordered){1000.0*($interval.End-$interval.Start)/$frequency}else{$null});
                RecordedDurationMs=$s.DurationMs;RecordedGapMs=$s.GapMs;RecordedCadenceMs=$s.CadenceMs;
                StartToStartMs=$(if($ordered){1000.0*($s.Start.Qpc-$previousStart)/$frequency}else{$null});
                OverlappingAttempts=@($overlap | ForEach-Object {$_.Trial});Accounted=$accounted;Reason=$reason}
            $receipts+=$receipt
            $assertions+=New-IOAssertion $interval.Assertion $(if($accounted){'PASS'}else{'INCONCLUSIVE'}) ($receipt | ConvertTo-Json -Depth 5 -Compress) $s.Sequence $null
        }
        $previous=$s.End.Qpc;$previousStart=$s.Start.Qpc;$sequence=$s.Sequence
    }
    return [pscustomobject]@{Scope='Synchronous actor only; never lower writes';Complete=($valid -and $Samples.Count -gt 0 -and @($receipts | Where-Object {-not $_.Accounted}).Count -eq 0);
        WriterFence=$Fence;AttemptWindows=$windows;Intervals=$receipts;Assertions=$assertions}
}
function Test-InvariantMetadata($Image, $Expectation, $Sample, $Policy) {
    Set-StrictMode -Off # Missing proof fields produce INCONCLUSIVE, including older evidence.

    $assertions=@();$fields=@('Attributes','Creation','Modified','Changed','Accessed','Links')
    if ($null -eq $Expectation.PSObject.Properties['Metadata']) {
        return New-IOAssertion 'MetadataCoverage' 'INCONCLUSIVE' 'Exact per-fixture metadata expectation missing.' $Sample.Sequence $Image.Path
    }
    $m=$Expectation.Metadata;$complete=$true
    # Older/partial fixtures may have a flat or absent metadata object. Do not
    # index Properties on a null Raw/Api object (even with StrictMode off).
    if ($null -eq $m) {
        return New-IOAssertion 'MetadataCoverage' 'INCONCLUSIVE' 'Exact per-fixture metadata expectation missing.' $Sample.Sequence $Image.Path
    }
    foreach ($view in @('Raw','Api')) {
        if ($null -eq $m.PSObject.Properties[$view] -or $null -eq $m.$view) {
            return New-IOAssertion 'MetadataCoverage' 'INCONCLUSIVE' ('Exact per-fixture metadata ' + $view + ' expectation missing.') $Sample.Sequence $Image.Path
        }
    }
    foreach($field in $fields) {
        if ($null -eq $m.Raw.PSObject.Properties[$field] -or $null -eq $m.Api.PSObject.Properties[$field]) {
            $complete=$false;continue
        }
        if($field -eq 'Accessed' -and $m.AccessRule -ceq 'NtfsReadWindow') {
            # LastAccess is the only permitted divergence. Both values remain bounded;
            # disabled disk updates must retain exactly the baseline disk value.
            $known=($m.AccessWindowStartFileTime -gt 0 -and $Policy.Status -ceq 'OK' -and $Policy.Before.Value -eq $Policy.After.Value -and
                $Policy.Before.Value -in @(0,1,2,3) -and $Policy.Before.BootId -ceq $Sample.Start.BootId -and
                $Policy.After.BootId -ceq $Sample.Start.BootId -and $Policy.Before.VolumeGuid -ceq $m.VolumeGuid -and
                $Policy.After.VolumeGuid -ceq $m.VolumeGuid -and $Policy.Before.Qpc -le $Sample.Start.Qpc -and $Policy.After.Qpc -ge $Sample.End.Qpc)
            if(-not $known) { $complete=$false;$assertions+=New-IOAssertion 'MetadataCrossCheck' 'INCONCLUSIVE' 'Accessed: fsutil disablelastaccess policy missing, changed, or not bound to this volume/boot/window.' $Sample.Sequence $Image.Path;continue }
            $raw=[long]$Image.RawMetadata.Accessed;$api=[long]$Image.Identity.Accessed
            $upper=[DateTime]::Parse($Sample.End.Utc).ToUniversalTime().ToFileTimeUtc()
            $disabled=($Policy.Before.Value -in @(1,3))
            $good=($m.AccessWindowStartFileTime -gt 0 -and $raw -ge $m.Raw.Accessed -and $api -ge $m.Api.Accessed -and $raw -le $api -and $api -le $upper)
            if($api -ne $m.Api.Accessed){$good=$good -and $api -ge $m.AccessWindowStartFileTime}
            if($disabled){$good=$good -and $raw -eq $m.Raw.Accessed}
            else{$good=$good -and ($api-$raw) -le [TimeSpan]::FromHours(1).Ticks}
            $reason='Accessed: '+$m.AccessReason+'; fsutil='+$Policy.Before.Value+'; raw='+$raw+'; API='+$api+'; baselineRaw='+$m.Raw.Accessed+'; baselineAPI='+$m.Api.Accessed+'; upper='+$upper
            $assertions+=New-IOAssertion 'MetadataCrossCheck' $(if($good){'PASS'}else{'FAIL'}) $reason $Sample.Sequence $Image.Path
            $assertions+=New-IOAssertion 'FileMetadata' $(if($good){'PASS'}else{'FAIL'}) $reason $Sample.Sequence $Image.Path
        } else {
            if($field -ne 'Links'){$assertions+=New-IOAssertion 'MetadataCrossCheck' $(if($Image.RawMetadata.$field -eq $Image.Identity.$field){'PASS'}else{'INCONCLUSIVE'}) ('Exact raw/API field: '+$field) $Sample.Sequence $Image.Path}
            $reason=if($field -eq 'Links'){'Exact baseline Links: API handle link count copied into RawMetadata by the unchanged decoder; no independent raw link-count claim.'}else{'Exact baseline field: '+$field}
            $assertions+=New-IOAssertion 'FileMetadata' $(if($Image.RawMetadata.$field -eq $m.Raw.$field -and $Image.Identity.$field -eq $m.Api.$field){'PASS'}else{'FAIL'}) $reason $Sample.Sequence $Image.Path
        }
    }
    if($null -eq $m.PSObject.Properties['SecurityId'] -or [string]::IsNullOrWhiteSpace($m.Sddl)){$complete=$false}
    else{$assertions+=New-IOAssertion 'FileSecurity' $(if($Image.SecurityId -eq $m.SecurityId -and $Image.Sddl -ceq $m.Sddl){'PASS'}else{'FAIL'}) 'Exact baseline owner/DACL/security ID.' $Sample.Sequence $Image.Path}
    $assertions+=New-IOAssertion 'MetadataCoverage' $(if($complete){'PASS'}else{'INCONCLUSIVE'}) ('Per-fixture fields: '+($fields -join ',')+'; tolerated field Accessed only under the recorded NtfsReadWindow rule.') $Sample.Sequence $Image.Path
    return $assertions
}
function Test-InvariantExternalCoverage($Baseline, $Timeline, [switch] $SyntheticRun) {
    Set-StrictMode -Off # Missing proof fields produce INCONCLUSIVE, including older evidence.

    $e=$Timeline.ExternalEvidence;$reasons=@()
    if ($SyntheticRun -and $e.Provenance -cne 'SyntheticTestEvidence') { $reasons+='Synthetic run requires explicitly synthetic external evidence provenance.' }
    elseif (-not $SyntheticRun -and $e.Provenance -eq 'SyntheticTestEvidence') { $reasons+='Synthetic test external evidence requires an explicitly synthetic run.' }
    if($Baseline.Build -cne '19045.2965' -or $e.Build -cne $Baseline.Build){$reasons+='Build 19045.2965 attestation missing.'}
    if([string]::IsNullOrWhiteSpace($e.PrepareBootId) -or $e.PrepareBootId -ceq $Baseline.Time.BootId -or $e.ActiveBootId -cne $Baseline.Time.BootId){$reasons+='Activating boot identity missing.'}
    if($e.ObserverPid -ne $Baseline.ObserverPid -or $e.ObserverPid -le 0 -or $e.ObserverSid -cne $Baseline.ObserverSid -or $e.ObserverSid -cne 'S-1-5-18'){$reasons+='SYSTEM observer identity not attested.'}
    $writers=@($Timeline.WriterIdentities)
    if($writers.Count -ne 1){$reasons+='One standard-user writer required.'}else{
        $w=$writers[0]
        if($w.Elevated -ne $false -or $w.IsAdministrator -ne $false -or $w.Pid -le 0 -or $w.Pid -eq $e.ObserverPid -or
            $w.Sid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' -or $w.Sid -ceq $e.ObserverSid -or
            $w.BootId -cne $e.ActiveBootId -or $e.ActorProvenance.OwnerSid -cne $w.Sid -or $e.ActorProvenance.Pid -ne $w.Pid -or
            $e.ActorProvenance.SessionId -ne $w.SessionId){$reasons+='OS writer identity/session provenance missing.'}
    }
    if($e.ObserverProcess.OwnerSid -cne $e.ObserverSid -or $e.ObserverProcess.Pid -ne $e.ObserverPid){$reasons+='OS observer identity not attested.'}
    if($Timeline.CadenceProof.Complete -ne $true){$reasons+='Synchronous actor cadence has unaccounted intervals.'}
    # Only the host can append the independent restoration evidence.
    if($e.Restoration.Known -ne $true){$reasons+='Awaiting host independent baseline plus restoration reboot.'}
    return New-IOAssertion 'ExternalCoverage' $(if($reasons.Count){'INCONCLUSIVE'}else{'PASS'}) $(if($reasons.Count){$reasons -join ' '}else{'Platform, boot, SYSTEM observer, OS standard-user identity, actor cadence and independent restoration attested.'}) $null $null
}
function Get-IOExpectedBytes($Baseline, $ApprovedImages, $Timeline, $Expectation, [string] $Path, [long] $Qpc, [switch] $DigestOnly) {
    if ($Expectation.Version -eq 'Baseline') {
        $image = @($Baseline.Images | Where-Object { $_.Role -eq 'Current' -and $_.Path -eq $Path })
        if ($image.Count -ne 1 -or $image[0].Absent) { throw 'No existing baseline image for version.' }
        if ($DigestOnly) { return [pscustomobject]@{ Length=$image[0].Length; Sha256=$image[0].Sha256 } }
        return ,(Read-IOArtifact $image[0].LogicalArtifact)
    }
    $a = @($ApprovedImages | Where-Object { $_.Status -eq 'OK' -and $_.Approval.AttemptId -eq $Expectation.Version })
    if ($a.Count -ne 1) { throw 'Unknown/ambiguous approval version.' }
    $a = $a[0]
    if ($a.Approval.PermitGrantQpc -gt $Qpc -or $a.Time.Qpc -gt $Qpc -or
        ($a.Approval.FinalPath -cne $Path -and $a.Approval.TempPath -cne $Path) -or
        $Expectation.Generation -ne $a.Approval.DestinationGeneration) { throw 'Grant/path/destination-generation mismatch.' }
    if ($null -ne $Expectation.PSObject.Properties['Kind']) {
        if ($Expectation.Kind -eq 'Final' -and $a.Approval.FinalPath -cne $Path) { throw 'Final version does not name the permitted final path.' }
        if ($Expectation.Kind -eq 'Temp' -and $a.Approval.TempPath -cne $Path) { throw 'Temp path mismatch.' }
    }
    if ($DigestOnly) { return [pscustomobject]@{ Length=$a.Length; Sha256=$a.Sha256 } }
    return ,(Read-IOArtifact $a.SnapshotArtifact)
}
function Test-NoUnapprovedByte {
    [CmdletBinding()] param([Parameter(Mandatory=$true)] $Baseline, [object[]] $ApprovedImages = @(),
        [Parameter(Mandatory=$true)][object[]] $Samples, [Parameter(Mandatory=$true)] $MutationLedger,
        [Parameter(Mandatory=$true)] $ExpectedTimeline, [switch] $SyntheticRun)
    $assertions = @(); $forbidden = 0; $differences = @()
    try {
        if ($Baseline.Status -ne 'OK') { throw 'Successful baseline required.' }
        # Scan every partial attempt first. A later observation error never hides a recorded leak.
        foreach ($s in $Samples) {
            if ($null -eq $s.PSObject.Properties['Captures']) { continue }
            foreach ($cap in $s.Captures) {
                foreach ($image in $cap.Images) {
                    $artifacts = @()
                    if ($null -ne $image.PSObject.Properties['Containers']) { $artifacts += @($image.Containers | ForEach-Object { $_.Artifact }) }
                    if ($null -ne $image.PSObject.Properties['LogicalArtifact']) { $artifacts += $image.LogicalArtifact }
                    if ($null -ne $image.PSObject.Properties['Artifact']) { $artifacts += $image.Artifact }
                    foreach ($artifact in $artifacts) {
                        try {
                            $bytes = Read-IOArtifact $artifact
                            foreach ($pattern in $ExpectedTimeline.ForbiddenBlocks) {
                                $offset = [StagedInvariant.Native]::Find($bytes, $pattern)
                                if ($offset -ge 0) { $forbidden += $pattern.Length; $assertions += New-IOAssertion 'ForbiddenBlock' 'FAIL' ('Artifact ' + $artifact.Path + ' offset ' + $offset) $s.Sequence $null }
                            }
                        } catch { $assertions += New-IOAssertion 'ArtifactCoverage' 'INCONCLUSIVE' $_.Exception.ToString() $s.Sequence $null }
                    }
                }
            }
        }
        if ($Samples.Count -eq 0) { throw 'No samples.' }
        $lastSeq = 0; $lastQpc = $Baseline.Time.Qpc
        foreach ($orderedSample in $Samples) {
            if ($null -eq $orderedSample.PSObject.Properties['Sequence']) { continue }
            if ($orderedSample.Sequence -le $lastSeq -or $orderedSample.Start.Qpc -lt $lastQpc -or $orderedSample.Start.BootId -cne $Baseline.Time.BootId) {
                $assertions += New-IOAssertion 'SampleOrdering' 'INCONCLUSIVE' 'QPC/boot/sequence order not established.' $orderedSample.Sequence $null
            }
            $lastSeq = $orderedSample.Sequence; $lastQpc = $orderedSample.End.Qpc

        }
        $operations=@();$fence=$null
        if($null -ne $ExpectedTimeline.PSObject.Properties['Operations']){$operations=$ExpectedTimeline.Operations}
        if($null -ne $ExpectedTimeline.PSObject.Properties['WriterFence']){$fence=$ExpectedTimeline.WriterFence}
        # Hashtable and deserialized objects both occur in the harness.
        if($ExpectedTimeline -is [System.Collections.IDictionary]){$operations=$ExpectedTimeline['Operations'];$fence=$ExpectedTimeline['WriterFence']}
        $assertions += (Test-InvariantCadence $Baseline $Samples $operations $fence).Assertions
        foreach ($rejected in @($ApprovedImages | Where-Object { $_.Status -ne 'OK' })) {
            $assertions += New-IOAssertion 'PublicationRegistration' $rejected.Error.Verdict 'Approval/snapshot/actual grant registration failed.' $null $null
        }
        foreach ($s in $Samples) {
            if ($s.Status -ne 'OK') { $assertions += New-IOAssertion 'CaptureCoverage' 'INCONCLUSIVE' 'Incomplete sample; partial leak evidence retained.' $null $null
                if ($null -eq $s.PSObject.Properties['Captures']) { continue }
            }
            $cp = @($ExpectedTimeline.Checkpoints | Where-Object { $_.OperationSequence -eq $s.OperationSequence -and $_.Phase -ceq $s.Phase })
            if ($cp.Count -ne 1) { $assertions += New-IOAssertion 'Timeline' 'INCONCLUSIVE' 'Missing/ambiguous checkpoint.' $s.Sequence $null; continue }; $cp = $cp[0]
            if ($s.CleanupErrors.Count -ne 0) { $assertions += New-IOAssertion 'Disposal' 'INCONCLUSIVE' 'Native cleanup failed.' $s.Sequence $null }
            $frames=@()
            foreach ($capturedPass in $s.Captures) { foreach ($capturedImage in $capturedPass.Images) {
                $frames += [pscustomobject]@{ Image=$capturedImage; Stable=($capturedPass.Status -eq 'OK'); Readers=$capturedPass.Readers }
            } }
            $observedImages=@($frames | ForEach-Object { $_.Image })
            foreach ($wanted in $cp.Storage) {
                if (@($observedImages | Where-Object { $_.Role -eq 'Current' -and $_.Path -ceq $wanted.Path }).Count -eq 0) { $assertions += New-IOAssertion 'MissingStorage' 'INCONCLUSIVE' 'Expected path not captured.' $s.Sequence $wanted.Path }
            }
            foreach ($wanted in $cp.Directories) {
                if (@($observedImages | Where-Object { $_.Role -eq 'Parent' -and $_.Path -ceq $wanted.Path }).Count -eq 0) { $assertions += New-IOAssertion 'MissingDirectory' 'INCONCLUSIVE' 'Expected parent not captured.' $s.Sequence $wanted.Path }
            }
            foreach ($frame in $frames) {
                $image=$frame.Image
                if ($image.Role -eq 'Historical') {
                    if ($image.Artifact.Sha256 -ne $image.OriginalSha256) { $differences += [pscustomobject]@{ Sequence = $s.Sequence; Role = 'Historical'; Offset = $image.Offset; Before = $image.OriginalSha256; After = $image.Artifact.Sha256 }
                        # Freed allocation is archived history. It cannot be assigned to another identity without proof.
                        if ($image.Kind -eq 'DATA') { $assertions += New-IOAssertion 'HistoricalAllocation' 'INCONCLUSIVE' 'Historical physical allocation changed; ownership/reuse requires future ledger adapter.' $s.Sequence $null } }
                    continue
                }
                if ($null -ne $image.PSObject.Properties['CrossCheckErrors'] -and $image.CrossCheckErrors.Count -gt 0) { $assertions += New-IOAssertion 'RawApiCrossCheck' 'INCONCLUSIVE' ($image.CrossCheckErrors -join ';') $s.Sequence $image.Path }
                if ($null -ne $image.PSObject.Properties['Identity']) {
                    $bi = @($Baseline.Images | Where-Object { $null -ne $_.PSObject.Properties['Identity'] -and $_.Identity.FileId -eq $image.Identity.FileId })
                    if ($bi.Count -gt 0) { foreach ($c in $image.Containers) {
                        $bc = @($bi[0].Containers | Where-Object { $_.Kind -eq $c.Kind -and $_.Offset -eq $c.Offset -and $_.Length -eq $c.Length })
                        if ($bc.Count -ne 1 -or $bc[0].Artifact.Sha256 -cne $c.Artifact.Sha256) {
                            $first = $null; $count = $null
                            if ($bc.Count -eq 1) {
                                $oldBytes = Read-IOArtifact $bc[0].Artifact; $newBytes = Read-IOArtifact $c.Artifact; $count = 0
                                for ($di = 0; $di -lt $oldBytes.Length; $di++) { if ($oldBytes[$di] -ne $newBytes[$di]) { if ($null -eq $first) { $first = $di }; $count++ } }
                            }
                            $differences += [pscustomobject]@{ Sequence=$s.Sequence; Path=$image.Path; Role=$image.Role; Kind=$c.Kind; Offset=$c.Offset
                                FirstDifferenceOffset=$first; DifferingBytes=$count; After=$c.Artifact.Sha256; Artifact=$c.Artifact.Path }
                        }
                    } }
                }
                if ($image.Role -like 'Retained:*') {
                    $oldId = $image.Role.Substring(9); $old = @($Baseline.Images | Where-Object { $_.Role -eq 'Current' -and -not $_.Absent -and $_.Identity.FileId -eq $oldId })
                    $oldDigest=$null; $oldLength=$null
                    if ($image.RetainedVersion -eq 'Baseline') { if ($old.Count -eq 1) { $oldDigest=$old[0].Sha256; $oldLength=$old[0].Length } }
                    else { $approvedOld=@($ApprovedImages | Where-Object { $_.Status -eq 'OK' -and $_.Approval.AttemptId -ceq $image.RetainedVersion })
                        if ($approvedOld.Count -eq 1) { $oldDigest=$approvedOld[0].Sha256; $oldLength=$approvedOld[0].Length } }
                    if ($null -eq $oldDigest -or $image.Sha256 -cne $oldDigest -or $image.Length -ne $oldLength) { $assertions += New-IOAssertion 'RetainedImage' 'FAIL' 'Held old identity changed.' $s.Sequence $null }
                    $oldReaders=@($frame.Readers | Where-Object { $null -ne $_.PSObject.Properties['Role'] -and $_.Role -eq 'Retained' -and $_.FileId -ceq $oldId })
                    if ($oldReaders.Count -ne 1 -or $oldReaders[0].Status -ne 'OK') { $assertions += New-IOAssertion 'RetainedReaderCoverage' 'INCONCLUSIVE' 'Held old reader unavailable.' $s.Sequence $null }
                    elseif ($oldReaders[0].Result.Digest -cne $oldDigest -or $oldReaders[0].Result.Length -ne $oldLength) { $assertions += New-IOAssertion 'RetainedReaderImage' 'FAIL' 'Held reader complete image changed.' $s.Sequence $null }
                    continue
                }
                if ($image.Role -eq 'Parent') {
                    $parentExpect = @($cp.Directories | Where-Object { $_.Path -ceq $image.Path })
                    if ($parentExpect.Count -ne 1) { $assertions += New-IOAssertion 'DirectoryCoverage' 'INCONCLUSIVE' 'No exact expected directory listing/security.' $s.Sequence $image.Path; continue }
                    $actualKeys = @($image.DirectoryEntries | ForEach-Object { Get-IOEntryKey $_ } | Sort-Object)
                    $directoryVersions=@($parentExpect[0])
                    if ($null -ne $parentExpect[0].PSObject.Properties['Alternates']) { $directoryVersions += @($parentExpect[0].Alternates) }
                    $directoryMatch=$false
                    foreach ($dv in $directoryVersions) {
                        $expectedKeys=@($dv.Entries | ForEach-Object { Get-IOEntryKey $_ } | Sort-Object)
                        if (($expectedKeys -join "`n") -ceq ($actualKeys -join "`n") -and $dv.SecurityId -eq $image.SecurityId -and
                            (-not $frame.Stable -or $dv.Sddl -ceq $image.Sddl)) { $directoryMatch=$true }
                    }
                    if (-not $directoryMatch) { $assertions += New-IOAssertion 'DirectoryMetadata' 'FAIL' 'Active names/IDs/sizes/attributes/security differ from every exact allowed transition.' $s.Sequence $image.Path }
                    foreach ($c in $image.Containers) {
                        $bp = @($Baseline.Images | Where-Object { $_.Role -eq 'Parent' -and $_.Path -eq $image.Path })
                        if ($bp.Count -eq 1) { $bc = @($bp[0].Containers | Where-Object { $_.Kind -eq $c.Kind -and $_.Offset -eq $c.Offset -and $_.Length -eq $c.Length })
                            if ($bc.Count -ne 1 -or $bc[0].Artifact.Sha256 -ne $c.Artifact.Sha256) { $differences += [pscustomobject]@{ Sequence = $s.Sequence; Role = 'Parent'; Path = $image.Path; Kind = $c.Kind; Offset = $c.Offset; After = $c.Artifact.Sha256 } } }
                    }
                    continue
                }
                $expect = @($cp.Storage | Where-Object { $_.Path -ceq $image.Path })
                if ($expect.Count -ne 1) { $assertions += New-IOAssertion 'StorageCoverage' 'INCONCLUSIVE' 'No expected destination version.' $s.Sequence $image.Path; continue }; $expect = $expect[0]
                if ($image.Absent) {
                    if ($expect.Kind -ne 'Absent') { $assertions += New-IOAssertion 'DestinationPresence' 'FAIL' 'Expected destination absent.' $s.Sequence $image.Path }; continue
                }
                if ($expect.Kind -eq 'Absent') { $assertions += New-IOAssertion 'DestinationPresence' 'FAIL' 'Forbidden destination exists.' $s.Sequence $image.Path; continue }
                try {
                    # A trusted captured digest already establishes a whole-image violation.
                    # Loss/tampering of an artifact later cannot downgrade that violation.
                    if ($expect.Kind -eq 'Final') {
                        $versions=@($expect); if ($null -ne $expect.PSObject.Properties['Alternates']) { $versions += @($expect.Alternates) }
                        $matchesVersion=$false
                        foreach ($version in $versions) {
                            $known=Get-IOExpectedBytes $Baseline $ApprovedImages $ExpectedTimeline $version $image.Path $s.Start.Qpc -DigestOnly
                            if ($known.Length -eq $image.Length -and $known.Sha256 -ceq $image.Sha256) { $matchesVersion=$true }
                        }
                        if (-not $matchesVersion) { $forbidden++; $assertions += New-IOAssertion 'CompleteImage' 'FAIL' 'Captured full digest/length differs from every authorized version.' $s.Sequence $image.Path }
                    }
                    $approvedBytes = Get-IOExpectedBytes $Baseline $ApprovedImages $ExpectedTimeline $expect $image.Path $s.Start.Qpc
                    $expectedBytes = $approvedBytes
                    if ($expect.Kind -eq 'Final' -and $null -ne $expect.PSObject.Properties['Alternates']) {
                        foreach ($alternative in $expect.Alternates) {
                            $candidate = Get-IOExpectedBytes $Baseline $ApprovedImages $ExpectedTimeline $alternative $image.Path $s.Start.Qpc
                            if ($image.Length -eq $candidate.Length -and $image.Sha256 -ceq [StagedInvariant.Native]::Hash($candidate) -and
                                ([string]::IsNullOrWhiteSpace($alternative.FileId) -or $alternative.FileId -ceq $image.Identity.FileId)) {
                                $approvedBytes = $candidate; $expectedBytes = $candidate; $expect = $alternative; break
                            }
                        }
                    }
                    if ($expect.Kind -eq 'Temp') {
                        if ($expect.Version -eq 'Baseline') { throw 'Temporary must have a real service grant.' }
                        $grant = @($ApprovedImages | Where-Object { $_.Approval.AttemptId -eq $expect.Version })[0]
                        if ($grant.Approval.TempPath -cne $image.Path -or $grant.Time.Qpc -gt $s.Start.Qpc) { throw 'Temp grant path/time/expiry mismatch.' }
                        if ($image.Length -gt $approvedBytes.Length) { throw 'Temp exceeds snapshot EOF.' }
                        if ($expect.Unwritten -eq 'Zero') { $expectedBytes = [byte[]]::new([int]$image.Length) }
                        elseif ($expect.Unwritten -eq 'Baseline') {
                            $b = @($Baseline.Images | Where-Object { $_.Role -eq 'Current' -and $_.Path -eq $image.Path -and -not $_.Absent })
                            if ($b.Count -ne 1) { throw 'No temp baseline for unwritten storage.' }; $expectedBytes = Read-IOArtifact $b[0].LogicalArtifact
                        } else { throw 'Unknown unwritten temporary storage.' }
                        foreach ($range in $expect.WrittenRanges) {
                            if ($range.Offset -lt 0 -or $range.Length -le 0 -or $range.Offset + $range.Length -gt $image.Length -or $range.FileId -ne $image.Identity.FileId -or -not $range.LowerCompleted) { throw 'Invalid temp copy checkpoint.' }
                            [Array]::Copy($approvedBytes, [long]$range.Offset, $expectedBytes, [long]$range.Offset, [long]$range.Length)
                        }
                    } elseif ($expect.Kind -ne 'Final') { throw 'Unknown storage kind.' }
                    if ($frame.Stable) {
                        $policy=$null
                        if($ExpectedTimeline -is [System.Collections.IDictionary]){$policy=$ExpectedTimeline['LastAccessPolicy']}
                        elseif($null -ne $ExpectedTimeline.PSObject.Properties['LastAccessPolicy']){$policy=$ExpectedTimeline.LastAccessPolicy}
                        $assertions += Test-InvariantMetadata $image $expect $s $policy
                    }
                    if (-not [string]::IsNullOrWhiteSpace($expect.FileId) -and $expect.FileId -cne $image.Identity.FileId) { $assertions += New-IOAssertion 'DestinationGeneration' 'FAIL' 'Unexpected file ID.' $s.Sequence $image.Path }
                    if ($image.Length -ne $expectedBytes.Length -or $image.Sha256 -cne [StagedInvariant.Native]::Hash($expectedBytes)) {
                        $assertions += New-IOAssertion 'CompleteImage' 'FAIL' 'Length/digest differs from exact allowed generation/image.' $s.Sequence $image.Path
                        $observedBytes=Read-IOArtifact $image.LogicalArtifact; $forbidden += [StagedInvariant.Native]::CountDifferences($expectedBytes,$observedBytes)
                    }
                    # Allocation outside EOF: compare VCN-positioned raw data with full expected image plus captured slack or explicitly zero padding.
                    $baseImage = @($Baseline.Images | Where-Object { $_.Role -eq 'Current' -and $_.Path -eq $image.Path -and -not $_.Absent })
                    foreach ($c in @($image.Containers | Where-Object { $_.Kind -eq 'DATA' })) {
                        $bytes = Read-IOArtifact $c.Artifact
                        $same = @(); if ($baseImage.Count -eq 1) { $same = @($baseImage[0].Containers | Where-Object { $_.Offset -eq $c.Offset -and $_.Length -eq $c.Length -and $_.Kind -eq 'DATA' }) }
                        if ($same.Count -eq 1 -and $same[0].Artifact.Sha256 -ceq $c.Artifact.Sha256 -and $expect.Version -eq 'Baseline') { continue }
                        if (($image.Identity.Attributes -band 0x800) -ne 0) { throw 'Changed compressed physical allocation needs an independently specified container image.' }
                        $run = @($image.Runs | Where-Object { $_.Lcn -ge 0 -and $c.Offset -ge $_.Lcn * $Baseline.Geometry.Cluster -and $c.Offset + $c.Length -le ($_.Lcn + $_.Clusters) * $Baseline.Geometry.Cluster })
                        if ($run.Count -ne 1) { throw 'Cannot position allocation container.' }
                        $logicalOffset = $run[0].Vcn * $Baseline.Geometry.Cluster + $c.Offset - $run[0].Lcn * $Baseline.Geometry.Cluster
                        $want = [byte[]]::new([int]$c.Length)
                        if ($same.Count -eq 1) { $want = Read-IOArtifact $same[0].Artifact }
                        elseif (-not $expect.ZeroPadding) { throw 'New allocation has no zero-initialization/padding authorization.' }
                        $take = [Math]::Max(0, [Math]::Min($want.Length, $expectedBytes.Length - $logicalOffset))
                        if ($take -gt 0) { [Array]::Copy($expectedBytes, [long]$logicalOffset, $want, [long]0, [long]$take) }
                        if ([StagedInvariant.Native]::Hash($want) -cne $c.Artifact.Sha256) { $assertions += New-IOAssertion 'AllocationImage' 'FAIL' ('Unexpected allocated bytes at volume offset ' + $c.Offset) $s.Sequence $image.Path }
                    }
                    if ($frame.Stable) { $currentReaders=@($frame.Readers | Where-Object { $_.Path -eq $image.Path })
                    if ($currentReaders.Count -ne 2 -or @($currentReaders | Where-Object { $_.Unbuffered }).Count -ne 1) { $assertions += New-IOAssertion 'FreshReaderCoverage' 'INCONCLUSIVE' 'Both fresh readers required.' $s.Sequence $image.Path }
                    foreach ($reader in $currentReaders) {
                        if ($reader.Status -eq 'OK') {
                            if ($reader.Result.Digest -cne $image.Sha256 -or $reader.Result.Length -ne $image.Length) { $assertions += New-IOAssertion 'FreshReaderImage' 'FAIL' 'Supplemental complete reader differs.' $s.Sequence $image.Path }
                        } else {
                            $denial = @($cp.ReadDenials | Where-Object { $_.Path -ceq $reader.Path -and $_.Unbuffered -eq $reader.Unbuffered -and $_.NativeCode -eq $reader.Error.NativeCode })
                            if ($cp.State -ne 'Activating' -or $denial.Count -ne 1) { $assertions += New-IOAssertion 'FreshReaderCoverage' 'INCONCLUSIVE' 'Reader error without exact Activating denial.' $s.Sequence $image.Path }
                        }
                    }
                    }
                } catch { $assertions += New-IOAssertion 'AllowedImageCoverage' 'INCONCLUSIVE' $_.Exception.ToString() $s.Sequence $image.Path }
            }
        }
        foreach ($cp in $ExpectedTimeline.Checkpoints) {
            if (@($Samples | Where-Object { $_.Status -eq 'OK' -and $_.OperationSequence -eq $cp.OperationSequence -and $_.Phase -ceq $cp.Phase }).Count -eq 0) {
                $assertions += New-IOAssertion 'MissingCheckpoint' 'INCONCLUSIVE' $cp.Phase $null $null
            }
        }
        # Temporal proof is deliberately separate from full-image observations.
        if ($Baseline.Build -cne '19045.2965' -or $ExpectedTimeline.WriterIdentities.Count -eq 0) { $assertions += New-IOAssertion 'PlatformActors' 'INCONCLUSIVE' 'Target build or standard-user writer evidence absent.' $null $null }
        foreach ($writer in $ExpectedTimeline.WriterIdentities) {
            if ($writer.Pid -le 0 -or $writer.Sid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' -or $writer.IsAdministrator -or $writer.Pid -eq $Baseline.ObserverPid -or $writer.Sid -ceq $Baseline.ObserverSid -or $writer.Elevated -or $writer.Sid -ceq 'S-1-5-18' -or $writer.BootId -cne $Baseline.Time.BootId) {
                $assertions += New-IOAssertion 'ObserverIdentity' 'INCONCLUSIVE' 'Writer is not an independent standard-user process.' $null $null
            }
        }
        $assertions += Test-InvariantExternalCoverage $Baseline $ExpectedTimeline -SyntheticRun:$SyntheticRun
        # Synthetic evidence is usable only by an explicitly marked evaluation
        # run. No production proof requirement is bypassed in either mode.
        $ledgerProvenance=$null
        if ($MutationLedger -is [System.Collections.IDictionary]) { $ledgerProvenance=$MutationLedger['Provenance'] }
        elseif ($null -ne $MutationLedger.PSObject.Properties['Provenance']) { $ledgerProvenance=$MutationLedger.Provenance }
        if ($SyntheticRun) {
            if ($ledgerProvenance -cne 'SyntheticTestLedger') {
                $assertions += New-IOAssertion 'PredicateCoverage' 'INCONCLUSIVE' 'Synthetic run requires explicitly synthetic test ledger provenance.' $null $null
            }
        } elseif ($ledgerProvenance -eq 'SyntheticTestLedger') {
            $assertions += New-IOAssertion 'PredicateCoverage' 'INCONCLUSIVE' 'Synthetic test ledger cannot establish production PredicateCoverage or NoUnapprovedByte.' $null $null
        }
        if (-not $MutationLedger.Complete -or $MutationLedger.Overflow -or $MutationLedger.Entries.Count -eq 0) { throw 'Driver lower admission/completion mutation ledger unavailable: user-mode calls and raw samples cannot prove PredicateCoverage or NoUnapprovedByte.' }
        $next = [long]$MutationLedger.FirstSequence
        foreach ($entry in $MutationLedger.Entries) {
            if ($entry.Sequence -ne $next -or -not $entry.PostComplete) { throw 'Ledger gap/missing lower completion.' }; $next++
            if (-not $entry.LowerAdmitted) {
                if (-not $entry.DeniedBeforeLower) { throw 'Denied mutation lacks causal before-lower evidence.' }
                $denial=@($ExpectedTimeline.ExpectedDenials | Where-Object { $_.Sequence -eq $entry.Sequence })
                if ($denial.Count -ne 1 -or $entry.NativeResult -eq 0) { throw 'Denied mutation lacks exact table/status evidence.' }
                foreach ($f in @('FileId','VolumeSerial','SopIdentity','EpochGeneration','Operation','Paging','Offset','Length','NativeResult','AttemptId','PolicyGeneration','DestinationGeneration','PayloadSha256','Path')) {
                    if ($entry.$f -cne $denial[0].$f) { throw ('Denied ledger field mismatch: ' + $f) }
                }; continue
            }
            $allow = @($ExpectedTimeline.AllowedMutations | Where-Object { $_.Sequence -eq $entry.Sequence })
            if ($allow.Count -ne 1) { $assertions += New-IOAssertion 'LowerMutation' 'FAIL' 'Unaccounted lower mutation (including write then erase).' $null $entry.Path; continue }; $allow = $allow[0]
            foreach ($f in @('FileId','VolumeSerial','SopIdentity','EpochGeneration','Operation','Paging','Offset','Length','NativeResult','AttemptId','PolicyGeneration','DestinationGeneration','PayloadSha256')) {
                if ($entry.$f -cne $allow.$f) { $assertions += New-IOAssertion 'LowerMutationIdentity' 'FAIL' ('Ledger field mismatch: ' + $f) $null $entry.Path }
            }
            if ($entry.Operation -eq 'Write') {
                $expected = Get-IOExpectedBytes $Baseline $ApprovedImages $ExpectedTimeline $allow $entry.Path $entry.Qpc
                if ($entry.Offset -lt 0 -or $entry.Length -le 0 -or $entry.Offset + $entry.Length -gt $expected.Length) { throw 'Ledger write range lacks specified image/padding.' }
                $range = [StagedInvariant.Native]::Slice($expected, [int]$entry.Offset, [int]$entry.Length)
                if ([StagedInvariant.Native]::Hash($range) -cne $entry.PayloadSha256) { $assertions += New-IOAssertion 'LowerPayload' 'FAIL' 'Submitted lower payload not the authorized snapshot at these offsets.' $null $entry.Path }
                if ($allow.Version -eq 'Baseline' -and $allow.Class -ne 'TrustedSetup') { throw 'Baseline cannot authorize a protected write.' }
                if ($allow.Version -ne 'Baseline') {
                    $a = @($ApprovedImages | Where-Object { $_.Approval.AttemptId -eq $allow.Version })[0]
                    if ($entry.AttemptId -ne $a.Approval.AttemptId -or $entry.PolicyGeneration -ne $a.Approval.PolicyGeneration -or
                        $entry.EpochGeneration -ne $a.Approval.EpochGeneration -or $entry.Qpc -ge $a.Approval.ExpiryQpc -or $entry.Qpc -gt $allow.RevokeQpc -or -not $allow.PermitActive) { throw 'Expired/revoked/stale permit at lower write.' }
                }
            } elseif ($allow.Class -ne 'ExactMetadataTransition') { throw 'Metadata lower mutation requires exact table authorization.' }
        }
        if ($next - 1 -ne $MutationLedger.LastSequence) { throw 'Ledger final sequence mismatch.' }
    } catch { $assertions += New-IOAssertion 'PredicateCoverage' 'INCONCLUSIVE' $_.Exception.ToString() $null $null }
    $verdict = 'PASS'
    if (@($assertions | Where-Object { $_.Verdict -eq 'FAIL' }).Count -gt 0) { $verdict = 'FAIL' }
    elseif (@($assertions | Where-Object { $_.Verdict -eq 'INCONCLUSIVE' }).Count -gt 0) { $verdict = 'INCONCLUSIVE' }
    $proofReason=if ($SyntheticRun) { 'Synthetic test only: full-image evidence combined with synthetic temporal proof and synthetic test ledger. FAIL takes precedence.' }
        else { 'Full-image evidence combined with temporal proof; driver lower admission/completion mutation ledger is required for NoUnapprovedByte. FAIL takes precedence.' }
    $assertions += New-IOAssertion 'NoUnapprovedByte' $verdict $proofReason $null $null
    return New-IORecord 'Verdict' @{ Schema = 'StagedInvariant/1'; Verdict = $verdict; ForbiddenByteCount = $forbidden
        Assertions = $assertions; RawDifferences = $differences; SyntheticRun = [bool]$SyntheticRun; AuthoritativeCaseExport = $false }
}
function Close-InvariantObserver {
    [CmdletBinding()] param([Parameter(Mandatory=$true)] $Context)
    $errors = @()
    if ($null -eq $Context -or $Context.Status -ne 'OK') { return New-IORecord 'Disposal' @{ Status = 'ERROR'; Errors = @('No successful context.') } }
    if ($Context.Closed) { return New-IORecord 'Disposal' @{ Status = 'ERROR'; Errors = @('Context already closed.') } }
    foreach ($entry in $Context.Handles.Values) { try { $entry.Handle.Dispose() } catch { $errors += New-IOError 'CloseRetained' $_.Exception } }
    try { $Context.Volume.Dispose() } catch { $errors += New-IOError 'CloseVolume' $_.Exception }
    $Context.Closed = $true; $errors += $Context.Errors
    return New-IORecord 'Disposal' @{ Status = $(if ($errors.Count -eq 0) { 'OK' } else { 'ERROR' }); Errors = $errors; Time = (Get-IOTime $Context) }
}
Export-ModuleMember -Function Read-InvariantPrivateSnapshot, Test-InvariantCadence, Test-InvariantExternalCoverage, Open-InvariantObserver, Capture-InvariantBaseline, Register-InvariantPublication, Capture-InvariantSample, Test-NoUnapprovedByte, Close-InvariantObserver
