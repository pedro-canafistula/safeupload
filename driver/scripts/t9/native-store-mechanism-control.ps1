#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SelfCheck,
    [ValidateSet('19045.2965','19045.6466')][string]$ExpectedOS = '19045.2965',
    [switch]$ExpectBuilderTable = $true,
    [string]$TempParent = [IO.Path]::GetTempPath(),
    [string]$ProgressPath
)
# N-U4-06, unprotected exact-target mechanism evidence, NOT protected-pair qualification.
# Windows PowerShell 5.1 / x64 / built-in Add-Type only; no SDK or test host.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
$progressClock = [Diagnostics.Stopwatch]::StartNew()
function Write-Progress51([string]$Text) { if ($ProgressPath) { [IO.File]::AppendAllText($ProgressPath, ([string]$progressClock.ElapsedMilliseconds + ' ms ' + $Text + [Environment]::NewLine)) } }
Write-Progress51 'AddTypeStart'
if (-not ('T9NativeStoreControl' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

public sealed class T9NativeStoreControl {
    public const uint SourceAccess=0x130083, SegmentAccess=0x120083, ReadAccess=0x120081, AnchorAccess=0x120081;
    public const uint Options=0x20006A;
    public readonly List<object> Events=new List<object>();
    public string FirstDifference;
    public int ReplacementCount, AllocationCount;
    public bool TargetBaselineMatches, ExpectedBaselineMatches;
    string context="Environment";
    long nativeA, unit;
    byte[] fileSecurity;

    [StructLayout(LayoutKind.Sequential)] public struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] public struct OBJECT_ATTRIBUTES {
        public uint Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQos;
    }
    [StructLayout(LayoutKind.Sequential)] public struct IO_STATUS_BLOCK { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)] public struct FILE_RENAME_INFORMATION_EX {
        public uint Flags; public IntPtr RootDirectory; public uint FileNameLength; public ushort FileName;
    }
    [StructLayout(LayoutKind.Sequential)] public struct FILE_ALLOCATION_INFORMATION { public long AllocationSize; }
    [StructLayout(LayoutKind.Sequential)] public struct FILE_STANDARD_INFORMATION {
        public long AllocationSize, EndOfFile; public uint NumberOfLinks; public byte DeletePending, Directory;
    }
    [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public uint Length; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct OSVERSIONINFO {
        public uint Size, Major, Minor, Build, Platform;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string ServicePack;
    }
    [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref OBJECT_ATTRIBUTES attributes,
        out IO_STATUS_BLOCK io, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
    [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle handle, out IO_STATUS_BLOCK io, byte[] data, uint size, int kind);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationFile(SafeFileHandle handle, out IO_STATUS_BLOCK io, [Out] byte[] data, uint size, int kind);
    [DllImport("ntdll.dll")] static extern int NtQueryVolumeInformationFile(SafeFileHandle handle, out IO_STATUS_BLOCK io, [Out] byte[] data, uint size, int kind);
    [DllImport("ntdll.dll")] static extern int NtWriteFile(SafeFileHandle handle, IntPtr evt, IntPtr apc, IntPtr context,
        out IO_STATUS_BLOCK io, IntPtr buffer, uint length, ref long offset, IntPtr key);
    [DllImport("ntdll.dll")] static extern int NtReadFile(SafeFileHandle handle, IntPtr evt, IntPtr apc, IntPtr context,
        out IO_STATUS_BLOCK io, IntPtr buffer, uint length, ref long offset, IntPtr key);
    [DllImport("ntdll.dll")] static extern int NtFlushBuffersFile(SafeFileHandle handle, out IO_STATUS_BLOCK io);
    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)] static extern int RtlGetVersion(ref OSVERSIONINFO version);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(
        string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES security);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder label, int labelSize,
        out uint serial, out uint componentLength, out uint flags, StringBuilder format, int formatSize);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumePathNameW(string path, StringBuilder volume, uint size);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, uint size, out uint needed);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    public sealed class ReplacementRow {
        public string Mechanism, RenameStatus;
        public bool KeepPredecessor, ShareDelete, DeleteAccess, HeldAtIssue;
        public uint NewLinks, CurrentLinks;
        public bool NewDeletePending, CurrentDeletePending, NewIdentityPreserved, CurrentIdentityMatches;
        public uint? OldLinks;
        public bool? OldDeletePending, OldBytesReadable, OldIdentityPreserved;
        public bool IndependentSuccessorOpenable, CurrentBytesReadable;
        public string Key { get { return Mechanism+"/"+KeepPredecessor+"/"+ShareDelete+"/"+DeleteAccess; } }
    }
    public sealed class Observation {
        public string Identity;
        public long AllocationSize, EndOfFile;
        public uint Links;
        public bool DeletePending, Directory;
    }
    public sealed class AllocationSample {
        public string Step;
        public long AllocationSize, EndOfFile, Offset, Length;
    }
    public sealed class AllocationRow {
        public string Mechanism;
        public long L, A, U, P, Q, Peak, Written, NormalizedEOF;
        public int Writes;
        public readonly List<AllocationSample> Samples=new List<AllocationSample>();
    }
    static Dictionary<string,object> Fields(params object[] pairs) {
        var d=new Dictionary<string,object>();
        for(int i=0;i<pairs.Length;i+=2) d.Add((string)pairs[i],pairs[i+1]);
        return d;
    }
    // Diagnostic liveness only: one flushed line per case change, never part of a verdict.
    public string ProgressPath;
    readonly System.Diagnostics.Stopwatch clock=System.Diagnostics.Stopwatch.StartNew();
    string progressCase;
    void Progress() {
        if(ProgressPath==null || context==progressCase) return;
        progressCase=context;
        File.AppendAllText(ProgressPath,clock.ElapsedMilliseconds+" ms seq="+(Events.Count+1)+" "+context+Environment.NewLine);
    }
    void Emit(string kind, params object[] pairs) {
        Progress();
        var d=Fields(pairs); d.Add("Kind",kind); d.Add("Case",context); d.Add("Sequence",Events.Count+1); Events.Add(d);
    }
    static string Hex(int value) { return "0x"+unchecked((uint)value).ToString("X8"); }
    void Difference(string text) { if(FirstDifference==null) FirstDifference=text; }
    void Receipt(string operation, int status, IO_STATUS_BLOCK io, params object[] pairs) {
        Progress();
        var d=Fields(pairs); d.Add("Kind","Native"); d.Add("Case",context); d.Add("Sequence",Events.Count+1);
        d.Add("Operation",operation); d.Add("NTSTATUS",Hex(status));
        d.Add("IoStatus",Hex(unchecked((int)io.Status.ToInt64()))); d.Add("Information",io.Information.ToUInt64()); Events.Add(d);
    }
    static void Require(int status, string step) { if(status!=0) throw new IOException(step+" returned "+Hex(status)); }
    void Completion(int status, IO_STATUS_BLOCK io, string step) {
        Require(status,step); Require(unchecked((int)io.Status.ToInt64()),step+" IO_STATUS_BLOCK");
    }
    static void CheckWin32(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static long Round(long value, long quantum) { return checked(((value+quantum-1)/quantum)*quantum); }
    static bool PowerOfTwo(long x) { return x>0 && (x & (x-1))==0; }
    static void Leaf(string leaf) {
        if(String.IsNullOrEmpty(leaf) || leaf=="." || leaf==".." || leaf.IndexOfAny(new char[]{'\\','/',':','*','?','\0'})>=0)
            throw new ArgumentException("Not a single leaf");
    }
    public static byte[] RenameBuffer(IntPtr parent, string leaf, uint flags) {
        Leaf(leaf); if(parent==IntPtr.Zero || (flags!=1 && flags!=3)) throw new ArgumentException("Invalid rename");
        byte[] name=Encoding.Unicode.GetBytes(leaf), buffer=new byte[Math.Max(24,20+name.Length)];
        BitConverter.GetBytes(flags).CopyTo(buffer,0); BitConverter.GetBytes(parent.ToInt64()).CopyTo(buffer,8);
        BitConverter.GetBytes(name.Length).CopyTo(buffer,16); name.CopyTo(buffer,20); return buffer;
    }
    byte[] Query(SafeFileHandle file, int kind, int size, string step, bool volume) {
        byte[] data=new byte[size]; IO_STATUS_BLOCK io;
        int status=volume ? NtQueryVolumeInformationFile(file,out io,data,(uint)size,kind) : NtQueryInformationFile(file,out io,data,(uint)size,kind);
        Receipt(volume?"NtQueryVolumeInformationFile":"NtQueryInformationFile",status,io,"Step",step,"Class",kind,"BufferSize",size);
        Completion(status,io,step);
        if(io.Information.ToUInt64()<(ulong)size) throw new IOException("Short query: "+step);
        return data;
    }
    Observation Observe(SafeFileHandle file, string step) {
        byte[] standard=Query(file,5,24,step+"/Standard",false), id=Query(file,59,24,step+"/Identity",false);
        var value=new Observation { Identity=BitConverter.ToString(id).Replace("-",""),
            AllocationSize=BitConverter.ToInt64(standard,0), EndOfFile=BitConverter.ToInt64(standard,8),
            Links=BitConverter.ToUInt32(standard,16), DeletePending=standard[20]!=0, Directory=standard[21]!=0 };
        if(BitConverter.ToUInt64(id,8)==0 && BitConverter.ToUInt64(id,16)==0) throw new IOException("Zero file ID");
        Emit("Observation","Step",step,"Object",value); return value;
    }
    SafeFileHandle Open(SafeFileHandle parent, string leaf, uint access, uint share, bool create) {
        Leaf(leaf);
        IntPtr name=Marshal.StringToHGlobalUni(leaf), text=IntPtr.Zero, security=IntPtr.Zero;
        bool held=false;
        try {
            var u=new UNICODE_STRING { Length=checked((ushort)(leaf.Length*2)), MaximumLength=checked((ushort)(leaf.Length*2+2)), Buffer=name };
            text=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING))); Marshal.StructureToPtr(u,text,false);
            if(create) { security=Marshal.AllocHGlobal(fileSecurity.Length); Marshal.Copy(fileSecurity,0,security,fileSecurity.Length); }
            parent.DangerousAddRef(ref held);
            var a=new OBJECT_ATTRIBUTES { Length=(uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)), RootDirectory=parent.DangerousGetHandle(),
                ObjectName=text, Attributes=0x40, SecurityDescriptor=security };
            SafeFileHandle file; IO_STATUS_BLOCK io;
            int status=NtCreateFile(out file,access,ref a,out io,IntPtr.Zero,0x80,share,create?2u:1u,Options,IntPtr.Zero,0);
            Receipt("NtCreateFile",status,io,"Leaf",leaf,"Access",access,"Share",share,"Options",Options,"Disposition",create?2:1);
            try {
                Completion(status,io,"Open "+leaf);
                if(file==null || file.IsInvalid || io.Information.ToUInt64()!=(create?2ul:1ul)) throw new IOException("Invalid create/open receipt");
                return file;
            } catch { if(file!=null) file.Dispose(); throw; }
        } finally {
            if(held) parent.DangerousRelease(); if(text!=IntPtr.Zero) Marshal.FreeHGlobal(text);
            if(security!=IntPtr.Zero) Marshal.FreeHGlobal(security); Marshal.FreeHGlobal(name);
        }
    }
    int Set(SafeFileHandle file, byte[] data, int kind, string step, bool required) {
        IO_STATUS_BLOCK io; int status=NtSetInformationFile(file,out io,data,(uint)data.Length,kind);
        Receipt("NtSetInformationFile",status,io,"Step",step,"Class",kind,"BufferSize",data.Length);
        if(required) Completion(status,io,step);
        else if(status==0) Completion(status,io,step);
        return status;
    }
    void Flush(SafeFileHandle file, string step) {
        IO_STATUS_BLOCK io; int status=NtFlushBuffersFile(file,out io); Receipt("NtFlushBuffersFile",status,io,"Step",step); Completion(status,io,step);
    }
    void Write(SafeFileHandle file, long offset, int length, int alignment, byte fill) {
        IntPtr raw=Marshal.AllocHGlobal(checked(length+alignment-1));
        try {
            IntPtr aligned=new IntPtr(Round(raw.ToInt64(),alignment)); byte[] bytes=new byte[length];
            for(int i=0;i<length;i++) bytes[i]=fill;
            Marshal.Copy(bytes,0,aligned,length); IO_STATUS_BLOCK io;
            int status=NtWriteFile(file,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out io,aligned,(uint)length,ref offset,IntPtr.Zero);
            Receipt("NtWriteFile",status,io,"Offset",offset,"Length",length,"BufferAlignment",alignment);
            Completion(status,io,"Write"); if(io.Information.ToUInt64()!=(ulong)length) throw new IOException("Short write");
        } finally { Marshal.FreeHGlobal(raw); }
    }
    bool ReadBytes(SafeFileHandle file, int logical, byte fill, string step) {
        int length=checked((int)Round(logical,nativeA)); IntPtr raw=Marshal.AllocHGlobal(checked(length+(int)nativeA-1));
        try {
            IntPtr aligned=new IntPtr(Round(raw.ToInt64(),nativeA)); IO_STATUS_BLOCK io; long offset=0;
            int status=NtReadFile(file,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out io,aligned,(uint)length,ref offset,IntPtr.Zero);
            Receipt("NtReadFile",status,io,"Step",step,"Offset",0,"Length",length);
            bool equal=status==0 && io.Status==IntPtr.Zero && io.Information.ToUInt64()>=(ulong)logical && io.Information.ToUInt64()<=(ulong)length;
            if(equal) { byte[] bytes=new byte[logical]; Marshal.Copy(aligned,bytes,0,logical); foreach(byte b in bytes) if(b!=fill) equal=false; }
            Emit("ReadObservation","Step",step,"ReadableAndExpectedBytesMatch",equal); return equal;
        } finally { Marshal.FreeHGlobal(raw); }
    }
    SafeFileHandle Prepare(SafeFileHandle anchor, string leaf, int logical, byte fill) {
        SafeFileHandle file=Open(anchor,leaf,SourceAccess,7,true);
        try {
            long padded=Round(logical,nativeA); Set(file,BitConverter.GetBytes(padded),19,"Prepare/Preallocate",true);
            Write(file,0,(int)padded,(int)nativeA,fill); Flush(file,"Prepare/F1");
            Set(file,BitConverter.GetBytes((long)logical),20,"Prepare/EOF",true); Flush(file,"Prepare/F2"); return file;
        } catch { file.Dispose(); throw; }
    }

    // Explicit builder table, order within each row: keep F/T, share-delete F/T,
    // predecessor DELETE access F/T (DELETE has no measured effect).
    // Provenance: t9-inc3-native-results-2.md and ReplacementNativeTests.cs.
    static readonly string[] Mechanisms={"Classic","Extended","ExtendedPosix","ReleasedClassic"};
    static readonly string[,] BuilderStatuses={
        {"0x00000000","0x00000000","0x00000000","0x00000000","0xC0000022","0xC0000022","0xC0000022","0xC0000022"},
        {"0x00000000","0x00000000","0x00000000","0x00000000","0xC0000022","0xC0000022","0xC0000022","0xC0000022"},
        {"0x00000000","0x00000000","0x00000000","0x00000000","0xC0000043","0xC0000043","0x00000000","0x00000000"},
        {"0x00000000","0x00000000","0x00000000","0x00000000","0x00000000","0x00000000","0x00000000","0x00000000"}
    };
    public static List<ReplacementRow> BuilderTable() {
        var rows=new List<ReplacementRow>();
        for(int m=0;m<4;m++) for(int k=0;k<2;k++) for(int s=0;s<2;s++) for(int d=0;d<2;d++) {
            bool held=k==1 && m!=3, success=BuilderStatuses[m,k*4+s*2+d]=="0x00000000";
            rows.Add(new ReplacementRow { Mechanism=Mechanisms[m], KeepPredecessor=k==1, ShareDelete=s==1, DeleteAccess=d==1,
                HeldAtIssue=held, RenameStatus=BuilderStatuses[m,k*4+s*2+d], NewLinks=1, CurrentLinks=1,
                NewIdentityPreserved=true, CurrentIdentityMatches=true, CurrentBytesReadable=true,
                OldLinks=held?(uint?)(success?0u:1u):null, OldDeletePending=held?(bool?)success:null,
                OldBytesReadable=held?(bool?)true:null, OldIdentityPreserved=held?(bool?)true:null,
                IndependentSuccessorOpenable=success });
        }
        return rows;
    }
    // Compare the entire observation tuple, not just the syscall's status.
    public static string CompareTable(List<ReplacementRow> actual) {
        List<ReplacementRow> expected=BuilderTable();
        if(actual.Count!=32) return "Replacement row count expected 32, got "+actual.Count;
        var seen=new HashSet<string>();
        foreach(ReplacementRow row in actual) if(!seen.Add(row.Key)) return "Duplicate replacement row "+row.Key;
        foreach(ReplacementRow e in expected) {
            ReplacementRow a=actual.Find(delegate(ReplacementRow r) { return r.Key==e.Key; });
            if(a==null) return "Missing replacement row "+e.Key;
            foreach(FieldInfo f in typeof(ReplacementRow).GetFields(BindingFlags.Public|BindingFlags.Instance)) {
                object want=f.GetValue(e), got=f.GetValue(a);
                if(!Object.Equals(want,got)) return e.Key+" "+f.Name+" expected "+(want??"Unavailable")+", got "+(got??"Unavailable");
            }
        }
        return null;
    }
    public static string Verdict(string difference, bool expectBuilderTable) {
        // PowerShell marshals a null string property to String.Empty.
        return !String.IsNullOrEmpty(difference)?"DIFFERS":expectBuilderTable?"PASS":"RECORDED";
    }
    ReplacementRow Replacement(SafeFileHandle anchor, ReplacementRow vector, int index) {
        context="Replacement/"+vector.Key;
        string target="target-"+index, source="source-"+index;
        SafeFileHandle predecessor=null;
        Observation oldBefore;
        using(SafeFileHandle seed=Prepare(anchor,target,128,1)) oldBefore=Observe(seed,"OldSeed");
        using(SafeFileHandle output=Prepare(anchor,source,192,2)) {
            Observation newBefore=Observe(output,"NewBefore");
            try {
                uint access=ReadAccess | (vector.DeleteAccess?0x10000u:0u), share=vector.ShareDelete?7u:3u;
                predecessor=Open(anchor,target,access,share,false);
                Observation opened=Observe(predecessor,"OldBefore");
                if(opened.Identity!=oldBefore.Identity) throw new IOException("Predecessor identity changed before issue");
                byte[] attributes=Query(predecessor,35,8,"TargetAttributes",false);
                uint attrs=BitConverter.ToUInt32(attributes,0);
                if((attrs & 0x411)!=0) throw new IOException("Target readonly/reparse/directory confounder");
                bool held=vector.KeepPredecessor && vector.Mechanism!="ReleasedClassic";
                if(!held) { predecessor.Dispose(); predecessor=null; }
                int cls=vector.Mechanism=="Extended" || vector.Mechanism=="ExtendedPosix"?65:10;
                uint flags=vector.Mechanism=="ExtendedPosix"?3u:1u;
                Emit("ReplacementConfiguration","Class",cls,"Flags",flags,"SourceAccess",SourceAccess,"SourceShare",7,
                    "AnchorAccess",AnchorAccess,"AnchorShare",3,"PredecessorAccess",access,"PredecessorShare",share,
                    "Options",Options,"HeldAtIssue",held,"SeedHandleClosed",true,"OtherTestOwnedTargetHandles",0,
                    "TestOwnedSections",0,"TestOwnedViews",0,"ExternalOwners","NotEnumerated","TargetAttributes",attrs,"RenameAttempts",1);
                // No fallback/retry. Parent remains held across this synchronous call.
                int status=Set(output,RenameBuffer(anchor.DangerousGetHandle(),target,flags),cls,"Rename",false);
                bool success=status==0;
                if(success) Flush(output,"F3");
                Observation newAfter=Observe(output,"NewHeldAfter");
                var row=new ReplacementRow { Mechanism=vector.Mechanism, KeepPredecessor=vector.KeepPredecessor,
                    ShareDelete=vector.ShareDelete, DeleteAccess=vector.DeleteAccess, HeldAtIssue=held, RenameStatus=Hex(status),
                    NewLinks=newAfter.Links, NewDeletePending=newAfter.DeletePending,
                    NewIdentityPreserved=newAfter.Identity==newBefore.Identity && newAfter.EndOfFile==192 && !newAfter.Directory };
                if(held) {
                    Observation oldAfter=Observe(predecessor,"OldHeldAfter");
                    row.OldLinks=oldAfter.Links; row.OldDeletePending=oldAfter.DeletePending;
                    row.OldIdentityPreserved=oldAfter.Identity==oldBefore.Identity && oldAfter.EndOfFile==128 && !oldAfter.Directory;
                    row.OldBytesReadable=ReadBytes(predecessor,128,1,"OldHeldBytesAfter");
                } else Emit("ObservationUnavailable","Step","OldHeldAfter","Reason","No predecessor handle or section retained");
                using(SafeFileHandle independent=Open(anchor,target,ReadAccess,7,false)) {
                    Observation current=Observe(independent,"IndependentCurrentAfter");
                    row.CurrentLinks=current.Links; row.CurrentDeletePending=current.DeletePending;
                    row.IndependentSuccessorOpenable=current.Identity==newBefore.Identity;
                    row.CurrentIdentityMatches=current.Identity==(success?newBefore.Identity:oldBefore.Identity) &&
                        current.EndOfFile==(success?192:128) && !current.Directory;
                    row.CurrentBytesReadable=ReadBytes(independent,success?192:128,success?(byte)2:(byte)1,"IndependentCurrentBytesAfter");
                }
                Emit("ReplacementResult","Result",row); return row;
            } finally { if(predecessor!=null) predecessor.Dispose(); }
        }
    }
    void Capture(AllocationRow row, SafeFileHandle file, string identity, string step, long offset, long length) {
        Observation o=Observe(file,step);
        row.Peak=Math.Max(row.Peak,o.AllocationSize);
        row.Samples.Add(new AllocationSample { Step=step, AllocationSize=o.AllocationSize, EndOfFile=o.EndOfFile, Offset=offset, Length=length });
        if(o.Identity!=identity || o.Links!=1 || o.DeletePending || o.Directory) throw new IOException("Allocation object changed: "+step);
        if(step=="Create" && (o.AllocationSize!=0 || o.EndOfFile!=0)) throw new IOException("Allocation fixture not empty");
        if(step=="Write" && o.EndOfFile!=offset+length) throw new IOException("Unexpected EOF after write");
        Emit("AllocationSample","Mechanism",row.Mechanism,"L",row.L,"A",row.A,"U",row.U,"P",row.P,"Q",row.Q,
            "Step",step,"Offset",offset,"Length",length,"AllocationSize",o.AllocationSize,"EOF",o.EndOfFile,"Peak",row.Peak,
            "BoundAsserted",row.Mechanism!="Chunked","ObservedOverQ",row.Peak>row.Q);
    }
    public static string CompareAllocation(AllocationRow row) {
        if(row.Mechanism=="Chunked") return null; // Measured only: NO empirical overshoot expectation.
        if(row.Mechanism!="Single" && row.Mechanism!="PreallocatedSingle" && row.Mechanism!="PreallocatedChunked") return "Unknown allocation mechanism";
        if(row.P!=Round(row.L,row.A) || row.Q!=Round(row.P,row.U) || row.Samples.Count==0) return "Invalid allocation geometry/coverage";
        long peak=0;
        foreach(AllocationSample sample in row.Samples) {
            if(sample.AllocationSize<0 || sample.AllocationSize>row.Q) return row.Mechanism+" L="+row.L+" A="+row.A+" "+sample.Step+" AllocationSize="+sample.AllocationSize+" exceeds Q="+row.Q;
            peak=Math.Max(peak,sample.AllocationSize);
        }
        if(row.Peak!=peak) return "Allocation peak was lost";
        return null;
    }
    void Allocation(SafeFileHandle anchor, string mechanism, int logical, int alignment, int index) {
        context="Allocation/"+mechanism+"/"+alignment+"/"+logical;
        var row=new AllocationRow { Mechanism=mechanism, L=logical, A=alignment, U=unit, P=Round(logical,alignment) };
        row.Q=Round(row.P,unit);
        Emit("AllocationConfiguration","Access",SegmentAccess,"Share",7,"Options",Options,"NativeA",nativeA,"A",alignment,"U",unit);
        using(SafeFileHandle file=Open(anchor,"allocation-"+index,SegmentAccess,7,true)) {
            string identity=Observe(file,"InitialIdentity").Identity;
            Capture(row,file,identity,"Create",0,0);
            if(mechanism.StartsWith("Preallocated",StringComparison.Ordinal)) {
                Set(file,BitConverter.GetBytes(row.P),19,"AllocationBeforeWrite",true);
                Capture(row,file,identity,"AllocationBeforeWrite",0,row.P);
            }
            int stride=mechanism.EndsWith("Single",StringComparison.Ordinal)?(int)row.P:alignment;
            // As in the builder discovery, stop extending this object at its
            // first observed overrun. Chunked has no peak assertion: recording
            // an overrun changes neither its verdict nor any expected table.
            for(long offset=0;offset<row.P;offset+=stride) {
                Write(file,offset,stride,alignment,0x5A); row.Writes++; row.Written=offset+stride;
                Capture(row,file,identity,"Write",offset,stride);
                if(row.Peak>row.Q) break;
            }
            Flush(file,"F1"); Capture(row,file,identity,"F1",0,0);
            row.NormalizedEOF=Math.Min(row.L,row.Written);
            Set(file,BitConverter.GetBytes(row.NormalizedEOF),20,"EOF",true); Capture(row,file,identity,"EOF",0,row.NormalizedEOF);
            Flush(file,"F2"); Capture(row,file,identity,"F2",0,0);
            Set(file,BitConverter.GetBytes(row.P),19,"AllocationNormalize",true); Capture(row,file,identity,"AllocationNormalize",0,row.P);
            Flush(file,"FlushAfterAllocation"); Capture(row,file,identity,"FlushAfterAllocation",0,0);
            if(row.Samples[row.Samples.Count-1].EndOfFile!=row.NormalizedEOF) throw new IOException("EOF normalization failed");
            string difference=CompareAllocation(row); if(difference!=null) Difference(difference);
            Emit("AllocationResult","Result",row,"Comparison",mechanism=="Chunked"?"RecordedOnly":difference==null?"PASS":"DIFFERS");
            AllocationCount++;
        }
    }
    // Native negative expectations (not learned from a run): NtWriteFile and
    // NtFlushBuffersFile require FILE_WRITE_DATA/FILE_APPEND_DATA; allocation
    // and EOF information require FILE_WRITE_DATA. The current-role Read|DELETE mask grants neither.
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntflushbuffersfile
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile
    // MS-ERREF 2.3.1: https://learn.microsoft.com/openspecs/windows_protocols/ms-erref/
    // ACCESS_DENIED=0xC0000022. Failure IO_STATUS_BLOCK fields
    // are raw observations, not a fabricated completion/information guarantee.
    public static readonly string[] FaultStages={"Allocation","Write","F1","EOF","F2","Rename","F3"};
    public int FaultCount, RetentionCount, ReleaseCount;
    public sealed class ChargeObject {
        public string Key, State;
        public long Q, Retained;
        public Observation Object;
    }
    public sealed class RetentionFrame {
        public string Step;
        public long Total;
        public readonly List<ChargeObject> Objects=new List<ChargeObject>();
    }
    public sealed class FaultRow {
        public string Stage, Status, IoStatus, Classification;
        public ulong Information;
        public int RenameAttempts, SuccessfulRenames;
        public long L=192, P=4096, Q=4096, NormalizedEOF;
        public Observation Before, After, Normalized;
        public readonly List<RetentionFrame> Frames=new List<RetentionFrame>();
    }
    public sealed class ReleaseRow {
        public string RenameStatus, LinkedReopenStatus, HeldReopenStatus, ClosedReopenStatus;
        public string Classification;
        public int RenameAttempts=1;
        public bool NativeDestroyed, PersistedReleaseVerified, AccountingReleased;
        public Observation Before, Held, Successor;
        public readonly List<RetentionFrame> Frames=new List<RetentionFrame>();
    }
    static bool Same(Observation a, Observation b) {
        return a!=null && b!=null && a.Identity==b.Identity && a.AllocationSize==b.AllocationSize &&
            a.EndOfFile==b.EndOfFile && a.Links==b.Links && a.DeletePending==b.DeletePending && a.Directory==b.Directory;
    }
    // Per-object max(Q, Round(each observed allocation,U)), then additive by
    // identity; never count the new/current alias twice. Matches Plan.Observe.
    static string CompareRetention(List<RetentionFrame> frames) {
        if(frames.Count<4) return "Missing retention frames";
        var retained=new Dictionary<string,long>(); var identities=new Dictionary<string,string>();
        bool unlinked=false;
        foreach(RetentionFrame frame in frames) {
            if(frame.Step=="UnlinkedHeld" || frame.Step=="PrefixRename") unlinked=true;
            if(frame.Objects.Count!=3) return "Missing current/new/residue charge";
            if(frame.Objects[0].Key!="New" || frame.Objects[1].Key!="Predecessor" || frame.Objects[2].Key!="Residue") return "Invalid charge order";
            var seen=new HashSet<string>(); long sum=0;
            foreach(ChargeObject obj in frame.Objects) {
                if(!seen.Add(obj.Key) || (obj.Key!="New" && obj.Key!="Predecessor" && obj.Key!="Residue") || obj.Q!=4096)
                    return "Invalid charge inventory";
                long prior=retained.ContainsKey(obj.Key)?retained[obj.Key]:obj.Q;
                if(obj.Object!=null) {
                    Observation o=obj.Object;
                    if(String.IsNullOrEmpty(o.Identity) || o.Directory || o.AllocationSize<0 || o.EndOfFile<0 || o.Links>1 ||
                        o.DeletePending!=(o.Links==0)) return "Invalid retained object observation";
                    if(identities.ContainsKey(obj.Key) && identities[obj.Key]!=o.Identity) return "Retained identity changed";
                    identities[obj.Key]=o.Identity;
                    prior=Math.Max(prior,Round(o.AllocationSize,4096));
                } else if(frame.Step!="Closed") return "Missing live observation";
                bool release=frames.Exists(delegate(RetentionFrame f){return f.Step=="UnlinkedHeld";});
                if((obj.Object==null)!=(frame.Step=="Closed" && obj.Key==(release?"Predecessor":"New"))) return "Missing/extra close observation";
                if(obj.Key!="New" && obj.Object!=null) {
                    ChargeObject initial=frames[0].Objects.Find(delegate(ChargeObject c){return c.Key==obj.Key;});
                    Observation first=initial==null?null:initial.Object;
                    if(first==null || first.AllocationSize!=obj.Object.AllocationSize || first.EndOfFile!=obj.Object.EndOfFile ||
                        (obj.Key=="Residue" && !Same(first,obj.Object))) return "Current/residue changed";
                }
                string state=obj.Key=="Predecessor" && unlinked?
                    (frame.Step=="Closed" && release?"UnlinkedDrained":"UnlinkedHeld"):"Linked";
                if(obj.Object!=null && (obj.Object.Links==0)!=(state=="UnlinkedHeld")) return "Link state mismatch";
                if(obj.State!=state || obj.Retained!=prior) return "R_phys/state changed without persisted transition at "+frame.Step;
                retained[obj.Key]=prior; sum=checked(sum+prior);
            }
            if(new HashSet<string>(identities.Values).Count!=3 || frame.Total!=sum) return "Non-additive/aliased R_phys";
        }
        return null;
    }
    static string[] FaultSteps(int stage) {
        var steps=new List<string>(); steps.Add("Initial");
        for(int i=0;i<stage;i++) steps.Add("Prefix"+FaultStages[i]);
        steps.AddRange(new string[]{"BeforeFault","AfterFault","NormalizeEOF","NormalizeF2","NormalizeAllocation","Normalized","Closed"});
        return steps.ToArray();
    }
    static string CompareFault(FaultRow row) {
        int stage=Array.IndexOf(FaultStages,row.Stage);
        if(stage<0 || row.Status!=(stage==5?"0xC0000043":"0xC0000022") || row.Classification!="Held") return "Fault status/classification";
        if(row.RenameAttempts!=(stage>=5?1:0) || row.SuccessfulRenames!=(stage==6?1:0)) return "Repeated/missing native rename";
        if(row.L!=192 || row.P!=4096 || row.Q!=4096 || row.NormalizedEOF!=(stage<2?0:192)) return "Fault geometry/EOF";
        if(!Same(row.Before,row.After)) return "Refused call changed state";
        if(row.Before==null || row.Before.AllocationSize!=3*row.Q || row.Before.EndOfFile!=(stage<2?0:stage<4?4096:192) || row.Before.Links!=1 || row.Before.DeletePending || row.Before.Directory ||
            row.Normalized==null || row.Normalized.Identity!=row.Before.Identity || row.Normalized.AllocationSize!=row.Q ||
            row.Normalized.EndOfFile!=row.NormalizedEOF || row.Normalized.Links!=1 || row.Normalized.DeletePending || row.Normalized.Directory)
            return "Missing real overrun/normalization";
        string[] steps=FaultSteps(stage);
        if(row.Frames.Count!=steps.Length) return "Fault retention coverage";
        for(int i=0;i<steps.Length;i++) if(row.Frames[i].Step!=steps[i]) return "Fault retention order";
        string retention=CompareRetention(row.Frames); if(retention!=null) return retention;
        if(!Same(row.Before,row.Frames.Find(delegate(RetentionFrame f){return f.Step=="BeforeFault";}).Objects[0].Object) || !Same(row.After,row.Frames.Find(delegate(RetentionFrame f){return f.Step=="AfterFault";}).Objects[0].Object) ||
            !Same(row.Normalized,row.Frames.Find(delegate(RetentionFrame f){return f.Step=="Normalized";}).Objects[0].Object)) return "Fault/retention observation mismatch";
        for(int i=0;i<3;i++) {
            RetentionFrame before=row.Frames.Find(delegate(RetentionFrame f){return f.Step=="BeforeFault";}),
                after=row.Frames.Find(delegate(RetentionFrame f){return f.Step=="AfterFault";});
            if(!Same(before.Objects[i].Object,after.Objects[i].Object)) return "Refusal changed current/residue";
        }
        return null;
    }
    public static string CompareFaults(List<FaultRow> rows) {
        if(rows.Count!=7) return "Fault row count expected 7";
        var seen=new HashSet<string>();
        foreach(FaultRow row in rows) {
            if(!seen.Add(row.Stage)) return "Duplicate fault row";
            string diff=CompareFault(row); if(diff!=null) return row.Stage+" "+diff;
        }
        return null;
    }
    static string CompareRelease(ReleaseRow row) {
        // Exact discovery hypotheses: no not-found status family or fallback.
        // MS-ERREF: DELETE_PENDING C0000056; NO_SUCH_FILE C000000F.
        // NtCreateFile FILE_OPEN_BY_FILE_ID and FileInternalInformation:
        // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile
        // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_internal_information
        // These two NTFS identity-reopen statuses require builder discovery,
        // then independent 19045.2965 reproduction; docs name statuses but do
        // not guarantee this POSIX-unlink combination on either revision.
        if(row.RenameAttempts!=1) return "Repeated/missing release rename";
        if(row.RenameStatus!="0x00000000" || row.LinkedReopenStatus!="0x00000000" || row.HeldReopenStatus!="0x00000000" ||
            row.ClosedReopenStatus!="0xC000000D") return "Release identity status";
        if(!row.NativeDestroyed || row.PersistedReleaseVerified || row.AccountingReleased || row.Classification!="NativeDestroyedChargeHeld")
            return "Release proof boundary/classification";
        if(row.Before==null || row.Held==null || row.Successor==null || row.Before.Identity!=row.Held.Identity ||
            row.Before.Identity==row.Successor.Identity || row.Held.AllocationSize!=row.Before.AllocationSize || row.Held.AllocationSize<4096 ||
            row.Held.EndOfFile!=row.Before.EndOfFile || row.Held.Links!=0 || !row.Held.DeletePending || row.Held.Directory ||
            row.Before.Links!=1 || row.Before.DeletePending || row.Successor.Links!=1 || row.Successor.DeletePending) return "Predecessor lifetime";
        string[] steps={"Initial","BeforeReplace","UnlinkedHeld","Closed"};
        if(row.Frames.Count!=steps.Length) return "Release retention coverage";
        for(int i=0;i<steps.Length;i++) if(row.Frames[i].Step!=steps[i]) return "Release retention order";
        string retention=CompareRetention(row.Frames); if(retention!=null) return retention;
        if(!Same(row.Before,row.Frames[1].Objects[1].Object) || !Same(row.Held,row.Frames[2].Objects[1].Object) ||
            !Same(row.Successor,row.Frames[2].Objects[0].Object)) return "Release/retention observation mismatch";
        return CompareRetention(row.Frames);
    }
    RetentionFrame Retain(string step, SafeFileHandle output, SafeFileHandle old, SafeFileHandle residue,
        Dictionary<string,long> charges) {
        var frame=new RetentionFrame { Step=step };
        string[] keys={"New","Predecessor","Residue"}; SafeFileHandle[] handles={output,old,residue};
        for(int i=0;i<keys.Length;i++) {
            Observation o=handles[i]==null?null:Observe(handles[i],step+"/"+keys[i]);
            long debit=charges.ContainsKey(keys[i])?charges[keys[i]]:4096;
            if(o!=null) debit=Math.Max(debit,Round(o.AllocationSize,unit));
            charges[keys[i]]=debit;
            frame.Objects.Add(new ChargeObject { Key=keys[i], Q=4096, Retained=debit, Object=o,
                State=i==1 && o!=null && o.Links==0?"UnlinkedHeld":i==1 && step=="Closed" && old==null?"UnlinkedDrained":"Linked" });
            frame.Total=checked(frame.Total+debit);
        }
        return frame;
    }
    Dictionary<string,long> Precharge() {
        var charges=new Dictionary<string,long> { {"New",4096}, {"Predecessor",4096}, {"Residue",4096} };
        Emit("ModelReservation","Q",4096,"Objects",new string[]{"New","Predecessor","Residue"},"Total",12288,"AccountingModelOnly",true);
        return charges;
    }
    FaultRow Fault(SafeFileHandle anchor, int stage) {
        context="Fault/"+FaultStages[stage];
        var row=new FaultRow { Stage=FaultStages[stage], NormalizedEOF=stage<2?0:192, Classification="Held" };
        var charges=Precharge();
        string leaf="fault-new-"+stage, target="fault-current-"+stage;
        using(SafeFileHandle residue=Prepare(anchor,"fault-residue-"+stage,128,3)) {
            using(SafeFileHandle seed=Prepare(anchor,target,128,1)) {}
            // Rename negative alone removes FILE_SHARE_DELETE; all other roles
            // use exact production masks/sharing/options. Refusal handle below
            // is the production data-read CompanionCurrent role (Read|DELETE), not an exception.
            using(SafeFileHandle old=Open(anchor,target,ReadAccess|0x10000,stage==5?3u:7u,false)) {
                SafeFileHandle output=Open(anchor,leaf,SourceAccess,7,true);
                try {
                    row.Frames.Add(Retain("Initial",output,old,residue,charges));
                    if(stage>0) { Set(output,BitConverter.GetBytes(row.P),19,"Prefix/Allocation",true); row.Frames.Add(Retain("PrefixAllocation",output,old,residue,charges)); }
                    if(stage>1) { Write(output,0,(int)row.P,(int)nativeA,2); row.Frames.Add(Retain("PrefixWrite",output,old,residue,charges)); }
                    if(stage>2) { Flush(output,"Prefix/F1"); row.Frames.Add(Retain("PrefixF1",output,old,residue,charges)); }
                    if(stage>3) { Set(output,BitConverter.GetBytes(row.L),20,"Prefix/EOF",true); row.Frames.Add(Retain("PrefixEOF",output,old,residue,charges)); }
                    if(stage>4) { Flush(output,"Prefix/F2"); row.Frames.Add(Retain("PrefixF2",output,old,residue,charges)); }
                    if(stage>5) {
                        row.RenameAttempts++;
                        Set(output,RenameBuffer(anchor.DangerousGetHandle(),target,3),65,"Prefix/Rename",true); row.SuccessfulRenames++;
                        row.Frames.Add(Retain("PrefixRename",output,old,residue,charges));
                    }
                    // Real bounded allocator mutation, deliberately above Q.
                    // This is a negative fixture: production would already be
                    // Held on observing it, before issuing further mutations.
                    Set(output,BitConverter.GetBytes(3*row.Q),19,"InjectRealOverrun",true);
                    row.Frames.Add(Retain("BeforeFault",output,old,residue,charges));
                    row.Before=row.Frames.Find(delegate(RetentionFrame f){return f.Step=="BeforeFault";}).Objects[0].Object;
                    IO_STATUS_BLOCK io; int status;
                    using(SafeFileHandle read=Open(anchor,stage==6?target:leaf,ReadAccess|0x10000,7,false)) {
                        if(stage==0 || stage==3) {
                            byte[] data=BitConverter.GetBytes(stage==0?row.P:row.L);
                            status=NtSetInformationFile(read,out io,data,8,stage==0?19:20);
                        } else if(stage==1) {
                            IntPtr raw=Marshal.AllocHGlobal(8191);
                            try { long offset=0; IntPtr aligned=new IntPtr(Round(raw.ToInt64(),nativeA));
                                Marshal.Copy(new byte[4096],0,aligned,4096);
                                status=NtWriteFile(read,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out io,
                                aligned,4096,ref offset,IntPtr.Zero); }
                            finally { Marshal.FreeHGlobal(raw); }
                        } else if(stage==2 || stage==4 || stage==6) status=NtFlushBuffersFile(read,out io);
                        else {
                            byte[] rename=RenameBuffer(anchor.DangerousGetHandle(),target,3); row.RenameAttempts++;
                            status=NtSetInformationFile(output,out io,rename,(uint)rename.Length,65);
                        }
                    }
                    Receipt(stage==1?"NtWriteFile":stage==0 || stage==3 || stage==5?"NtSetInformationFile":"NtFlushBuffersFile",status,io,
                        "InjectedFault",true,"Step","Fault","Stage",row.Stage,"Class",stage==0?19:stage==3?20:stage==5?65:0,
                        "Flags",stage==5?3:0,"Offset",0,"Length",stage==1?4096:0,"Cause",stage==5?"PredecessorNoShareDelete":"CurrentRoleMissingWriteData",
                        "Access",stage==5?SourceAccess:(ReadAccess|0x10000),"Share",7,"Options",Options);
                    if(stage==5 && status==0) row.SuccessfulRenames++;
                    row.Status=Hex(status); row.IoStatus=Hex(unchecked((int)io.Status.ToInt64())); row.Information=io.Information.ToUInt64();
                    row.Frames.Add(Retain("AfterFault",output,old,residue,charges)); row.After=row.Frames[row.Frames.Count-1].Objects[0].Object;
                    // Admitted EOF/allocation normalization only; never replay
                    // a failed write/rename or turn the Held row into Committed.
                    Set(output,BitConverter.GetBytes(row.NormalizedEOF),20,"Normalize/EOF",true);
                    row.Frames.Add(Retain("NormalizeEOF",output,old,residue,charges));
                    Flush(output,"Normalize/F2"); row.Frames.Add(Retain("NormalizeF2",output,old,residue,charges));
                    Set(output,BitConverter.GetBytes(row.P),19,"Normalize/Allocation",true);
                    row.Frames.Add(Retain("NormalizeAllocation",output,old,residue,charges)); Flush(output,"Normalize/FinalBarrier");
                    row.Frames.Add(Retain("Normalized",output,old,residue,charges)); row.Normalized=row.Frames.Find(delegate(RetentionFrame f){return f.Step=="Normalized";}).Objects[0].Object;
                    output.Dispose(); output=null;
                    row.Frames.Add(Retain("Closed",output,old,residue,charges));
                } finally { if(output!=null) output.Dispose(); }
            }
        }
        string diff=CompareFault(row); if(diff!=null) Difference(row.Stage+": "+diff);
        Emit("FaultResult","Result",row,"Comparison",diff==null?"PASS":"DIFFERS"); FaultCount++;
        Emit("RetentionResult","Key",row.Stage,"Frames",row.Frames,"Comparison",diff==null?"PASS":"DIFFERS"); RetentionCount++;
        return row;
    }
    string ReopenId(SafeFileHandle anchor, byte[] id, string step, string expectedIdentity) {
        IntPtr name=Marshal.AllocHGlobal(8), text=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        try {
            Marshal.Copy(id,0,name,8);
            var u=new UNICODE_STRING { Length=8, MaximumLength=8, Buffer=name }; Marshal.StructureToPtr(u,text,false);
            var a=new OBJECT_ATTRIBUTES { Length=(uint)Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)), RootDirectory=anchor.DangerousGetHandle(), ObjectName=text, Attributes=0x40 };
            SafeFileHandle file; IO_STATUS_BLOCK io;
            int status=NtCreateFile(out file,ReadAccess,ref a,out io,IntPtr.Zero,0x80,7,1,Options|0x2000,IntPtr.Zero,0);
            Receipt("NtCreateFile/ById",status,io,"Step",step,"FileInternalId",BitConverter.ToString(id),"ExpectedIdentity",expectedIdentity,
                "Access",ReadAccess,"Share",7,"Options",Options|0x2000);
            using(file) {
                if(status==0) {
                    Completion(status,io,step);
                    Observation o=Observe(file,step+"/Reopened");
                    if(o.Identity!=expectedIdentity) Difference("FileId reopen returned wrong identity");
                    // Measured on builder 19045.6466 (nu406b2): the held, POSIX-unlinked predecessor is
                    // still reopenable by FileId; it must be the same unlinked DeletePending object.
                    if(step=="HeldById" && (o.Links!=0 || !o.DeletePending)) Difference("Held FileId reopen is not the unlinked DeletePending object");
                }
            }
            return Hex(status);
        } finally { Marshal.FreeHGlobal(text); Marshal.FreeHGlobal(name); }
    }
    long FreeClusters(SafeFileHandle anchor, string step) {
        byte[] size=Query(anchor,3,24,step,true);
        return BitConverter.ToInt64(size,8);
    }
    void Release(SafeFileHandle anchor) {
        context="Release/Predecessor";
        var row=new ReleaseRow { Classification="NativeDestroyedChargeHeld" }; var charges=Precharge();
        using(SafeFileHandle residue=Prepare(anchor,"release-residue",128,3))
        using(SafeFileHandle output=Prepare(anchor,"release-new",192,2)) {
            using(SafeFileHandle seed=Prepare(anchor,"release-current",128,1)) {}
            SafeFileHandle old=Open(anchor,"release-current",ReadAccess|0x10000,7,false);
            try {
                row.Frames.Add(Retain("Initial",output,old,residue,charges));
                row.Before=Observe(old,"BeforeReplace");
                byte[] id=Query(old,6,8,"Predecessor/FileInternalInformation",false);
                row.LinkedReopenStatus=ReopenId(anchor,id,"LinkedById",row.Before.Identity);
                row.Frames.Add(Retain("BeforeReplace",output,old,residue,charges));
                long before=FreeClusters(anchor,"FreeBeforeReplace");
                byte[] rename=RenameBuffer(anchor.DangerousGetHandle(),"release-current",3);
                row.RenameStatus=Hex(Set(output,rename,65,"Replace",false));
                Flush(output,"Release/FinalBarrier");
                row.Frames.Add(Retain("UnlinkedHeld",output,old,residue,charges));
                row.Held=row.Frames[2].Objects[1].Object; row.Successor=row.Frames[2].Objects[0].Object;
                row.HeldReopenStatus=ReopenId(anchor,id,"HeldById",row.Before.Identity);
                long held=FreeClusters(anchor,"FreeWhileHeld");
                old.Dispose(); old=null;
                row.ClosedReopenStatus=ReopenId(anchor,id,"ClosedById",row.Before.Identity);
                // The identical by-ID request succeeded while held; after the last close NTFS
                // refuses the stale file reference with STATUS_INVALID_PARAMETER (measured, nu406b2).
                row.NativeDestroyed=row.ClosedReopenStatus=="0xC000000D";
                row.Frames.Add(Retain("Closed",output,old,residue,charges));
                long closed=FreeClusters(anchor,"FreeAfterClose");
                Emit("FreeClusterObservation","Before",before,"Held",held,"AfterClose",closed,"Asserted",false,
                    "Reason","Shared volume activity and NTFS deferred frees preclude exact attribution; no tolerance invented");
            } finally { if(old!=null) old.Dispose(); }
        }
        string diff=CompareRelease(row); if(diff!=null) Difference(diff);
        Emit("ReleaseResult","Result",row,"Comparison",diff==null?"PASS":"DIFFERS",
            "NativeEvidence","Exact FileId no longer reopenable after last predecessor handle closes",
            "AgentEvidenceRemaining","Persisted identity-bound MetadataStorageTransition; this control never refunds the charge"); ReleaseCount++;
        Emit("RetentionResult","Key","Release","Frames",row.Frames,"Comparison",diff==null?"PASS":"DIFFERS"); RetentionCount++;
    }

    byte[] Descriptor(string sid, bool directory) {
        string ace=directory?"OICI":"";
        string sddl="O:"+sid+"G:"+sid+"D:P(A;"+ace+";FA;;;"+sid+")(A;"+ace+";FA;;;SY)(A;"+ace+";FA;;;BA)";
        IntPtr descriptor; uint size;
        CheckWin32(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out descriptor,out size));
        try { byte[] data=new byte[size]; Marshal.Copy(descriptor,data,0,data.Length); return data; }
        finally { LocalFree(descriptor); }
    }
    void PrivateDirectory(string path, string sid) {
        byte[] data=Descriptor(sid,true); IntPtr descriptor=Marshal.AllocHGlobal(data.Length);
        try {
            Marshal.Copy(data,0,descriptor,data.Length);
            var security=new SECURITY_ATTRIBUTES { Length=(uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), Descriptor=descriptor };
            CheckWin32(CreateDirectoryW(path,ref security));
        } finally { Marshal.FreeHGlobal(descriptor); }
    }
    void Token(WindowsIdentity identity) {
        uint needed;
        // GetTokenInformation(TokenIntegrityLevel) reports a native SID_AND_ATTRIBUTES.
        GetTokenInformation(identity.Token,25,IntPtr.Zero,0,out needed);
        int sizeError=Marshal.GetLastWin32Error();
        if(needed==0 || sizeError!=122) throw new Win32Exception(sizeError,"Token integrity sizing");
        IntPtr data=Marshal.AllocHGlobal(checked((int)Math.Max(needed,4u)));
        try {
            CheckWin32(GetTokenInformation(identity.Token,25,data,needed,out needed));
            IntPtr sid=Marshal.ReadIntPtr(data); byte count=Marshal.ReadByte(GetSidSubAuthorityCount(sid));
            if(count==0) throw new IOException("Integrity SID has no RID");
            uint rid=unchecked((uint)Marshal.ReadInt32(GetSidSubAuthority(sid,(uint)(count-1))));
            CheckWin32(GetTokenInformation(identity.Token,20,data,4,out needed)); int elevated=Marshal.ReadInt32(data);
            CheckWin32(GetTokenInformation(identity.Token,18,data,4,out needed)); int elevationType=Marshal.ReadInt32(data);
            Emit("Token","User",identity.Name,"SID",identity.User.Value,"Elevated",elevated!=0,"ElevationType",elevationType,
                "IntegrityRID",rid,"Integrity",rid>=0x4000?"System":rid>=0x3000?"High":rid>=0x2000?"Medium":rid>=0x1000?"Low":"Untrusted",
                "ImpersonationLevel",identity.ImpersonationLevel.ToString());
        } finally { Marshal.FreeHGlobal(data); }
    }
    void Geometry(SafeFileHandle anchor, string root) {
        var format=new StringBuilder(32); uint serial, componentLength, flags;
        CheckWin32(GetVolumeInformationByHandleW(anchor,null,0,out serial,out componentLength,out flags,format,format.Capacity));
        var volume=new StringBuilder(1024); CheckWin32(GetVolumePathNameW(root,volume,(uint)volume.Capacity));
        byte[] device=Query(anchor,4,8,"Device",true), size=Query(anchor,3,24,"Size",true),
            sectors=Query(anchor,11,28,"Sectors",true), alignment=Query(anchor,17,4,"Alignment",false);
        long sector=BitConverter.ToUInt32(size,20), sectorsPerCluster=BitConverter.ToUInt32(size,16);
        unit=checked(sector*sectorsPerCluster);
        long required=0;
        for(int i=0;i<4;i++) required=Math.Max(required,BitConverter.ToUInt32(sectors,i*4));
        nativeA=Math.Max(4096,Math.Max(required,checked((long)BitConverter.ToUInt32(alignment,0)+1)));
        Emit("Volume","Volume",volume.ToString(),"Serial",serial,"FileSystem",format.ToString(),"ClusterSize",unit,
            "BytesPerSector",sector,"SectorsPerCluster",sectorsPerCluster,"NativeA",nativeA,"RawSectorInformation",BitConverter.ToString(sectors),
            "AlignmentRequirement",BitConverter.ToUInt32(alignment,0),"DeviceType",BitConverter.ToUInt32(device,0),"Characteristics",BitConverter.ToUInt32(device,4));
        if(format.ToString()!="NTFS" || BitConverter.ToUInt32(device,0)!=7 || (BitConverter.ToUInt32(device,4)&1)!=0)
            throw new IOException("Requires a fixed nonremovable NTFS volume");
        if(!PowerOfTwo(unit) || !PowerOfTwo(nativeA) || nativeA!=4096 || unit!=4096 || sector!=BitConverter.ToUInt32(sectors,0))
            throw new IOException("Builder geometry differs: requires native A=U=4096; no simulated-native claim");
    }
    public void Run(string parent, bool expectBuilderTable, string expectedOS) {
        string root=null; bool created=false;
        try {
            if(Environment.OSVersion.Platform!=PlatformID.Win32NT) throw new PlatformNotSupportedException("Runtime requires Windows; use -SelfCheck offline");
            var version=new OSVERSIONINFO { Size=(uint)Marshal.SizeOf(typeof(OSVERSIONINFO)) };
            int status=RtlGetVersion(ref version); Emit("OSVersion","Operation","RtlGetVersion","NTSTATUS",Hex(status)); Require(status,"RtlGetVersion");
            object ubr;
            using(RegistryKey key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion",false)) ubr=key==null?null:key.GetValue("UBR");
            ExpectedBaselineMatches=HostMatches(version.Major,version.Minor,version.Build,ubr,expectedOS);
            TargetBaselineMatches=HostMatches(version.Major,version.Minor,version.Build,ubr,"19045.2965");
            Emit("Environment","OS",version.Major+"."+version.Minor+"."+version.Build+"."+(ubr??"Unknown"),
                "TargetBaselineMatches",TargetBaselineMatches,"ExpectedBaselineMatches",ExpectedBaselineMatches,"ExpectedOS",expectedOS,"MechanismDiscovery",expectedOS=="19045.6466","TargetEvidence",expectedOS=="19045.2965","ExpectBuilderTable",expectBuilderTable,
                "KernelPrecondition","Run without the new metadata kernel loaded; operator must record installed driver hash separately",
                "RegistryAccess","ReadOnly UBR","ProductQualification",false);
            if(!ExpectedBaselineMatches) Difference("OS baseline differs from expected Windows 10 "+expectedOS);
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                Token(identity); fileSecurity=Descriptor(identity.User.Value,false);
                parent=Path.GetFullPath(parent);
                if(!Directory.Exists(parent)) throw new DirectoryNotFoundException(parent);
                // Do not traverse a reparse ancestor or clean up somebody else's tree.
                for(string part=parent;part!=null;part=Path.GetDirectoryName(part))
                    if((File.GetAttributes(part)&FileAttributes.ReparsePoint)!=0) throw new IOException("Reparse temp ancestor");
                root=Path.Combine(parent,"safeupload-t9-native-"+Guid.NewGuid().ToString("N"));
                PrivateDirectory(root,identity.User.Value); created=true;
            }
            Emit("TemporaryDirectory","Path",root,"PrivateDacl",true);
            using(SafeFileHandle anchor=CreateFileW(root,AnchorAccess,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero)) {
                if(anchor.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                Emit("Anchor","Operation","CreateFileW","Win32Error",0,"Access",AnchorAccess,"Share",3,"Flags",0x02200000);
                Geometry(anchor,root);
                var rows=new List<ReplacementRow>();
                foreach(ReplacementRow v in BuilderTable()) { rows.Add(Replacement(anchor,v,rows.Count)); ReplacementCount++; }
                if(expectBuilderTable) { string diff=CompareTable(rows); if(diff!=null) Difference(diff); }
                int index=0;
                foreach(string mechanism in new string[]{"Single","PreallocatedSingle","PreallocatedChunked","Chunked"})
                    foreach(int quantum in new int[]{4096,65536})
                        foreach(int length in new int[]{64,192,1192,8192,65537,131072}) Allocation(anchor,mechanism,length,quantum,index++);
                var faults=new List<FaultRow>();
                for(int stage=0;stage<7;stage++) faults.Add(Fault(anchor,stage));
                string faultDiff=CompareFaults(faults); if(faultDiff!=null) Difference(faultDiff);
                Release(anchor);
            }
            if(!Coverage(ReplacementCount,AllocationCount,FaultCount,RetentionCount,ReleaseCount)) Difference("Incomplete native case coverage");
        } catch(Exception error) {
            Difference(context+": "+error.Message); Emit("Error","Exception",error.GetType().FullName,"Message",error.Message);
        } finally {
            context="Cleanup";
            if(created) {
                try { Directory.Delete(root,true); Emit("Cleanup","Path",root,"Removed",!Directory.Exists(root)); }
                catch(Exception error) { Difference("Cleanup: "+error.Message); Emit("Cleanup","Path",root,"Removed",false,"Message",error.Message); }
            }
        }
    }
    static void Assert(bool condition, string text) { if(!condition) throw new InvalidOperationException(text); }
    static void Layout(Type type, int size, params object[] offsets) {
        Assert(Marshal.SizeOf(type)==size,type.Name+" size");
        for(int i=0;i<offsets.Length;i+=2) Assert(Marshal.OffsetOf(type,(string)offsets[i]).ToInt32()==(int)offsets[i+1],type.Name+"."+offsets[i]);
    }
    static void Signature(string name, params Type[] parameters) {
        MethodInfo method=typeof(T9NativeStoreControl).GetMethod(name,BindingFlags.NonPublic|BindingFlags.Static);
        Assert(method!=null && method.ReturnType==typeof(int),name+" return");
        var import=(DllImportAttribute)Attribute.GetCustomAttribute(method,typeof(DllImportAttribute));
        Assert(import!=null && import.Value=="ntdll.dll" && import.CallingConvention==CallingConvention.Winapi,name+" import");
        ParameterInfo[] actual=method.GetParameters(); Assert(actual.Length==parameters.Length,name+" arity");
        for(int i=0;i<actual.Length;i++) Assert(actual[i].ParameterType==parameters[i],name+" parameter "+i);
        Assert(actual[name=="NtCreateFile"?3: name=="NtWriteFile" || name=="NtReadFile"?4:1].IsOut,name+" out IO_STATUS_BLOCK");
    }
    static Observation FakeObservation(string key, long allocation, long eof, uint links) {
        return new Observation { Identity=key+"-identity", AllocationSize=allocation, EndOfFile=eof, Links=links, DeletePending=links==0 };
    }
    static List<RetentionFrame> FakeFrames(string[] steps, bool release, int stage) {
        var frames=new List<RetentionFrame>(); bool overrun=false, replaced=false;
        foreach(string step in steps) {
            if(step=="BeforeFault") overrun=true;
            if(step=="PrefixRename") replaced=true;
            var frame=new RetentionFrame { Step=step };
            foreach(string key in new string[]{"New","Predecessor","Residue"}) {
                long allocation=4096, eof=key=="New"?192:128;
                if(!release && key=="New") {
                    if(step=="Initial") { allocation=0; eof=0; }
                    else if(step=="PrefixAllocation") eof=0;
                    else if(step=="PrefixWrite" || step=="PrefixF1") eof=4096;
                    else if(step=="BeforeFault" || step=="AfterFault") { allocation=12288; eof=stage<2?0:stage<4?4096:192; }
                    else if(step=="NormalizeEOF" || step=="NormalizeF2") { allocation=12288; eof=stage<2?0:192; }
                    else if(step.StartsWith("Normal",StringComparison.Ordinal)) eof=stage<2?0:192;
                }
                bool unlinked=key=="Predecessor" && (replaced || release && (step=="UnlinkedHeld" || step=="Closed"));
                Observation observation=FakeObservation(key,allocation,eof,unlinked?0u:1u);
                if(step=="Closed" && key==(release?"Predecessor":"New")) observation=null;
                long retained=!release && key=="New" && overrun?12288:4096;
                frame.Objects.Add(new ChargeObject { Key=key, Q=4096, Retained=retained, Object=observation,
                    State=unlinked?(step=="Closed" && release?"UnlinkedDrained":"UnlinkedHeld"):"Linked" }); frame.Total+=retained;
            }
            frames.Add(frame);
        }
        return frames;
    }
    static FaultRow FakeFault(int stage) {
        var row=new FaultRow { Stage=FaultStages[stage], Status=stage==5?"0xC0000043":"0xC0000022", Classification="Held", NormalizedEOF=stage<2?0:192, RenameAttempts=stage>=5?1:0, SuccessfulRenames=stage==6?1:0 };
        row.Frames.AddRange(FakeFrames(FaultSteps(stage),false,stage));
        row.Before=FakeObservation("New",12288,stage<2?0:stage<4?4096:192,1);
        row.After=FakeObservation("New",12288,row.Before.EndOfFile,1);
        row.Normalized=FakeObservation("New",4096,row.NormalizedEOF,1); return row;
    }
    static List<FaultRow> FakeFaults() {
        var rows=new List<FaultRow>(); for(int i=0;i<7;i++) rows.Add(FakeFault(i)); return rows;
    }
    static ReleaseRow FakeRelease() {
        var row=new ReleaseRow { RenameStatus="0x00000000", LinkedReopenStatus="0x00000000", HeldReopenStatus="0x00000000",
            ClosedReopenStatus="0xC000000D", NativeDestroyed=true, Classification="NativeDestroyedChargeHeld",
            Before=FakeObservation("Predecessor",4096,128,1), Held=FakeObservation("Predecessor",4096,128,0), Successor=FakeObservation("New",4096,192,1) };
        row.Frames.AddRange(FakeFrames(new string[]{"Initial","BeforeReplace","UnlinkedHeld","Closed"},true,0)); return row;
    }
    static void FlipField(object target, FieldInfo field) {
        object value=field.GetValue(target);
        if(field.FieldType==typeof(string)) field.SetValue(target,"MUTANT");
        else if(field.FieldType==typeof(bool)) field.SetValue(target,!(bool)value);
        else if(field.FieldType==typeof(int)) field.SetValue(target,(int)value+1);
        else if(field.FieldType==typeof(long)) field.SetValue(target,(long)value+1);
        else if(field.FieldType==typeof(uint)) field.SetValue(target,9u);
        else throw new InvalidOperationException("Unsupported mutation "+field.Name);
    }
    public static bool HostMatches(uint major, uint minor, uint build, object ubr, string expected) {
        return major==10 && minor==0 && build==19045 && ubr!=null && build+"."+Convert.ToInt32(ubr)==expected;
    }
    static bool Coverage(int replacement, int allocation, int fault, int retention, int release) {
        return replacement==32 && allocation==48 && fault==7 && retention==8 && release==1;
    }
    static void FaultReleaseSelfCheck() {
        Assert(HostMatches(10,0,19045,2965,"19045.2965") && HostMatches(10,0,19045,6466,"19045.6466"),"Host oracle");
        Assert(!HostMatches(10,0,19045,6466,"19045.2965") && !HostMatches(10,0,19045,2965,"19045.6466") &&
            !HostMatches(11,0,19045,2965,"19045.2965") && !HostMatches(10,1,19045,2965,"19045.2965") &&
            !HostMatches(10,0,19044,2965,"19045.2965") && !HostMatches(10,0,19045,null,"19045.2965"),"Host mutant escaped");
        Assert(Coverage(32,48,7,8,1) && !Coverage(31,48,7,8,1) && !Coverage(32,47,7,8,1) &&
            !Coverage(32,48,6,8,1) && !Coverage(32,48,7,7,1) && !Coverage(32,48,7,8,0),"Coverage mutant escaped");
        Assert(CompareFaults(FakeFaults())==null,"Fault oracle rejected itself");
        Assert(CompareRelease(FakeRelease())==null,"Release oracle rejected itself");
        for(int stage=0;stage<7;stage++) {
            foreach(string name in new string[]{"Stage","Status","Classification","L","P","Q","NormalizedEOF","RenameAttempts","SuccessfulRenames"}) {
                var rows=FakeFaults(); FlipField(rows[stage],typeof(FaultRow).GetField(name));
                Assert(CompareFaults(rows)!=null,"Fault field mutant escaped: "+name);
            }
            foreach(string name in new string[]{"Before","After","Normalized"}) foreach(FieldInfo field in typeof(Observation).GetFields()) {
                var rows=FakeFaults(); FlipField(typeof(FaultRow).GetField(name).GetValue(rows[stage]),field);
                Assert(CompareFaults(rows)!=null,"Refusal/normalization state mutant escaped: "+name+"/"+field.Name);
            }
        }
        var missing=FakeFaults(); missing.RemoveAt(0); Assert(CompareFaults(missing)!=null,"Missing fault row escaped");
        var duplicate=FakeFaults(); duplicate[1]=duplicate[0]; Assert(CompareFaults(duplicate)!=null,"Duplicate fault row escaped");
        foreach(string name in new string[]{"RenameStatus","LinkedReopenStatus","HeldReopenStatus","ClosedReopenStatus","Classification",
            "NativeDestroyed","PersistedReleaseVerified","AccountingReleased","RenameAttempts"}) {
            var row=FakeRelease(); FlipField(row,typeof(ReleaseRow).GetField(name));
            Assert(CompareRelease(row)!=null,"Release status/proof-boundary mutant escaped: "+name);
        }
        foreach(string name in new string[]{"Before","Held","Successor"}) foreach(FieldInfo field in typeof(Observation).GetFields()) {
            var row=FakeRelease(); FlipField(typeof(ReleaseRow).GetField(name).GetValue(row),field);
            Assert(CompareRelease(row)!=null,"Release observation mutant escaped: "+name+"/"+field.Name);
        }
        // Exercise every sample, including fault, normalization, unlink and last
        // close. A decrement is rejected even if Total is changed consistently.
        for(int mode=0;mode<8;mode++) {
            List<RetentionFrame> baseline=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
            for(int f=0;f<baseline.Count;f++) {
                var frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                frames[f].Total--; Assert(CompareRetention(frames)!=null,"Nonadditive debit escaped");
                for(int o=0;o<3;o++) foreach(string name in new string[]{"Key","Q","Retained","State"}) {
                    frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                    FlipField(frames[f].Objects[o],typeof(ChargeObject).GetField(name));
                    Assert(CompareRetention(frames)!=null,"Retention field mutant escaped: "+name);
                }
                for(int o=0;o<3;o++) {
                    frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                    frames[f].Objects[o].Retained--; frames[f].Total--;
                    Assert(CompareRetention(frames)!=null,"R_phys refund escaped");
                }
                for(int o=0;o<3;o++) {
                    foreach(string name in new string[]{"Identity","Directory","Links","DeletePending","AllocationSize","EndOfFile"}) {
                        frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                        Observation observation=frames[f].Objects[o].Object;
                        if(observation==null) continue;
                        FieldInfo field=typeof(Observation).GetField(name);
                        if(field.FieldType==typeof(long)) field.SetValue(observation,-1L); else FlipField(observation,field);
                        Assert(CompareRetention(frames)!=null,"Retention observation mutant escaped: "+name);
                    }
                    frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                    if(frames[f].Objects[o].Object!=null) {
                        frames[f].Objects[o].Object=null;
                        Assert(CompareRetention(frames)!=null,"Missing live observation escaped");
                    }
                }
                frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                frames[f].Objects.RemoveAt(0); Assert(CompareRetention(frames)!=null,"Missing charge escaped");
                frames=mode==7?FakeRelease().Frames:FakeFault(mode).Frames;
                frames[f].Objects[1]=frames[f].Objects[0]; Assert(CompareRetention(frames)!=null,"Duplicate charge escaped");
                if(mode==7) {
                    var row=FakeRelease(); row.Frames[f].Step="MUTANT"; Assert(CompareRelease(row)!=null,"Release step mutant escaped");
                    row=FakeRelease(); row.Frames.RemoveAt(f); Assert(CompareRelease(row)!=null,"Missing release frame escaped");
                } else {
                    var row=FakeFault(mode); row.Frames[f].Step="MUTANT"; Assert(CompareFault(row)!=null,"Fault step mutant escaped");
                    row=FakeFault(mode); row.Frames.RemoveAt(f); Assert(CompareFault(row)!=null,"Missing fault frame escaped");
                }
            }
        }
        // An object which can still be reopened is not destroyed.
        var reopenable=FakeRelease(); reopenable.ClosedReopenStatus="0x00000000";
        Assert(CompareRelease(reopenable)!=null,"Destroyed object reopenable mutant escaped");
    }

    public static void SelfCheck() {
        FaultReleaseSelfCheck();
        Assert(IntPtr.Size==8,"x64 process required");
        Layout(typeof(FILE_RENAME_INFORMATION_EX),24,"Flags",0,"RootDirectory",8,"FileNameLength",16,"FileName",20);
        Layout(typeof(FILE_ALLOCATION_INFORMATION),8,"AllocationSize",0);
        Layout(typeof(FILE_STANDARD_INFORMATION),24,"AllocationSize",0,"EndOfFile",8,"NumberOfLinks",16,"DeletePending",20,"Directory",21);
        Layout(typeof(UNICODE_STRING),16,"Length",0,"MaximumLength",2,"Buffer",8);
        Layout(typeof(OBJECT_ATTRIBUTES),48,"Length",0,"RootDirectory",8,"ObjectName",16,"Attributes",24,"SecurityDescriptor",32,"SecurityQos",40);
        Layout(typeof(IO_STATUS_BLOCK),16,"Status",0,"Information",8);
        Type h=typeof(SafeFileHandle), p=typeof(IntPtr), u=typeof(uint), i=typeof(int), b=typeof(byte[]), io=typeof(IO_STATUS_BLOCK).MakeByRefType();
        Signature("NtCreateFile",h.MakeByRefType(),u,typeof(OBJECT_ATTRIBUTES).MakeByRefType(),io,p,u,u,u,u,p,u);
        Signature("NtSetInformationFile",h,io,b,u,i); Signature("NtQueryInformationFile",h,io,b,u,i);
        Signature("NtQueryVolumeInformationFile",h,io,b,u,i); Signature("NtFlushBuffersFile",h,io);
        Signature("NtWriteFile",h,p,p,p,io,p,u,typeof(long).MakeByRefType(),p);
        Signature("NtReadFile",h,p,p,p,io,p,u,typeof(long).MakeByRefType(),p);
        Assert(typeof(T9NativeStoreControl).GetMethod("NtCreateFile",BindingFlags.NonPublic|BindingFlags.Static).GetParameters()[0].IsOut,"out handle");
        byte[] rename=RenameBuffer(new IntPtr(0x12345678),"target",3);
        Assert(rename.Length==32 && BitConverter.ToUInt32(rename,0)==3 && BitConverter.ToInt64(rename,8)==0x12345678 &&
            BitConverter.ToUInt32(rename,16)==12 && Encoding.Unicode.GetString(rename,20,12)=="target","Rename wire bytes");
        Assert(RenameBuffer(new IntPtr(1),"x",1).Length==24,"Minimum rename struct size");
        foreach(string bad in new string[]{"", ".", "..", "a/b", "a\\b", "x:y", "*", "\0"}) {
            bool refused=false; try { RenameBuffer(new IntPtr(1),bad,3); } catch(ArgumentException) { refused=true; }
            Assert(refused,"Leaf escape accepted");
        }
        Assert(Verdict(CompareTable(BuilderTable()),true)=="PASS","Builder table rejected itself");
        Assert(Verdict(null,false)=="RECORDED" && Verdict("difference",false)=="DIFFERS","Record-only mode verdict");
        Assert(Verdict("",true)=="PASS","PowerShell empty-string marshaling");
        for(int row=0;row<32;row++) {
            var changed=BuilderTable(); changed[row].RenameStatus="0xDEADBEEF";
            Assert(Verdict(CompareTable(changed),true)=="DIFFERS","Flipped NTSTATUS was not DIFFERS");
            foreach(string field in new string[]{"NewLinks","CurrentLinks","NewDeletePending","CurrentDeletePending","NewIdentityPreserved",
                "CurrentIdentityMatches","IndependentSuccessorOpenable","CurrentBytesReadable","OldLinks","OldDeletePending","OldBytesReadable","OldIdentityPreserved","HeldAtIssue"}) {
                changed=BuilderTable(); FieldInfo f=typeof(ReplacementRow).GetField(field); object value=f.GetValue(changed[row]);
                object mutant=f.FieldType==typeof(uint)?(object)9u:f.FieldType==typeof(uint?)?(object)(uint?)9:
                    f.FieldType==typeof(bool?)?(object)(bool?)(value==null || !(bool)value):(object)!(bool)value;
                f.SetValue(changed[row],mutant); Assert(CompareTable(changed)!=null,"Observation mutant escaped: "+field);
            }
        }
        var missing=BuilderTable(); missing.RemoveAt(0); Assert(CompareTable(missing)!=null,"Missing row escaped");
        var duplicate=BuilderTable(); duplicate[1]=duplicate[0]; Assert(CompareTable(duplicate)!=null,"Duplicate row escaped");
        var reordered=BuilderTable(); reordered.Reverse(); Assert(CompareTable(reordered)==null,"Row order affected comparison");
        foreach(string mechanism in new string[]{"Single","PreallocatedSingle","PreallocatedChunked","Chunked"})
            foreach(int a in new int[]{4096,65536}) foreach(int l in new int[]{64,192,1192,8192,65537,131072}) {
                var r=new AllocationRow { Mechanism=mechanism, L=l, A=a, U=4096, P=Round(l,a) }; r.Q=Round(r.P,r.U); r.Peak=r.Q;
                r.Samples.Add(new AllocationSample { Step="Write", AllocationSize=r.Q });
                Assert(CompareAllocation(r)==null,"Bounded allocation rejected");
                r.Samples[0].AllocationSize=r.Q+4096; r.Peak=r.Q+4096;
                Assert((CompareAllocation(r)!=null)==(mechanism!="Chunked"),"Allocation overrun/record-only mutant");
                r.Samples[0].AllocationSize=r.Q; r.Peak=0;
                Assert((CompareAllocation(r)!=null)==(mechanism!="Chunked"),"Lost peak mutant");
            }
    }
}
'@
}
    [T9NativeStoreControl]::SelfCheck()
    if ($SelfCheck) {
        [pscustomobject]@{Kind='SelfCheck'; NativeCalls=$false; Packing='PASS'; Signatures='PASS'; TableMutations='PASS'; AllocationMutations='PASS'; FaultRetentionReleaseMutations='PASS'} | ConvertTo-Json -Compress
        Write-Output 'NativeStoreMechanismSelfCheck=PASS'
        return
    }
    Write-Progress51 'AddTypeAndSelfCheckDone'
    $control = New-Object T9NativeStoreControl
    if ($ProgressPath) { $control.ProgressPath = $ProgressPath }
    $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    [pscustomobject]@{Kind='Script'; SHA256=$scriptHash; PSVersion=$PSVersionTable.PSVersion.ToString(); ProcessBits=([IntPtr]::Size*8)} | ConvertTo-Json -Compress
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Runtime requires Windows PowerShell 5.1.' }
    Write-Progress51 'RunStart'
    $control.Run($TempParent,[bool]$ExpectBuilderTable,$ExpectedOS)
    Write-Progress51 'RunReturned'
    foreach ($record in $control.Events) { $record | ConvertTo-Json -Depth 12 -Compress }
    Write-Progress51 'EventsWritten'
    $verdict = [T9NativeStoreControl]::Verdict($control.FirstDifference,[bool]$ExpectBuilderTable)
    [pscustomobject]@{Kind='Verdict'; Verdict=$verdict; FirstDifference=$control.FirstDifference; ReplacementRows=$control.ReplacementCount; AllocationRows=$control.AllocationCount; FaultRows=$control.FaultCount; RetentionRows=$control.RetentionCount; ReleaseRows=$control.ReleaseCount; ExpectedOS=$ExpectedOS; MechanismDiscovery=($ExpectedOS -eq '19045.6466'); TargetEvidence=($ExpectedOS -eq '19045.2965'); ProductQualification=$false; PersistedReleaseVerified=$false; TargetBaselineMatches=$control.TargetBaselineMatches; ExpectedBaselineMatches=$control.ExpectedBaselineMatches; LabStop=($verdict -eq 'DIFFERS')} | ConvertTo-Json -Compress
    Write-Output ('NativeStoreMechanism='+$verdict)
    if ($verdict -eq 'DIFFERS') { exit 1 }
} catch {
    [pscustomobject]@{Kind='Fatal'; Message=$_.Exception.Message; LabStop=$true} | ConvertTo-Json -Compress
    Write-Output 'NativeStoreMechanism=DIFFERS'
    exit 1
}
