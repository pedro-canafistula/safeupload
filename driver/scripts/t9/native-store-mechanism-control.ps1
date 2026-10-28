#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$SelfCheck,
    [switch]$ExpectBuilderTable = $true,
    [string]$TempParent = [IO.Path]::GetTempPath()
)
# N-U4-06, unprotected exact-target mechanism evidence, NOT protected-pair qualification.
# Windows PowerShell 5.1 / x64 / built-in Add-Type only; no SDK or test host.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
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
    public bool TargetBaselineMatches;
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
    void Emit(string kind, params object[] pairs) {
        var d=Fields(pairs); d.Add("Kind",kind); d.Add("Case",context); d.Add("Sequence",Events.Count+1); Events.Add(d);
    }
    static string Hex(int value) { return "0x"+unchecked((uint)value).ToString("X8"); }
    void Difference(string text) { if(FirstDifference==null) FirstDifference=text; }
    void Receipt(string operation, int status, IO_STATUS_BLOCK io, params object[] pairs) {
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
    public void Run(string parent, bool expectBuilderTable) {
        string root=null; bool created=false;
        try {
            if(Environment.OSVersion.Platform!=PlatformID.Win32NT) throw new PlatformNotSupportedException("Runtime requires Windows; use -SelfCheck offline");
            var version=new OSVERSIONINFO { Size=(uint)Marshal.SizeOf(typeof(OSVERSIONINFO)) };
            int status=RtlGetVersion(ref version); Emit("OSVersion","Operation","RtlGetVersion","NTSTATUS",Hex(status)); Require(status,"RtlGetVersion");
            object ubr;
            using(RegistryKey key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion",false)) ubr=key==null?null:key.GetValue("UBR");
            TargetBaselineMatches=version.Major==10 && version.Build==19045 && ubr!=null && Convert.ToInt32(ubr)==2965;
            Emit("Environment","OS",version.Major+"."+version.Minor+"."+version.Build+"."+(ubr??"Unknown"),
                "TargetBaselineMatches",TargetBaselineMatches,"ExpectedOS","10.0.19045.2965","ExpectBuilderTable",expectBuilderTable,
                "KernelPrecondition","Run without the new metadata kernel loaded; operator must record installed driver hash separately",
                "RegistryAccess","ReadOnly UBR","ProductQualification",false);
            if(!TargetBaselineMatches) Difference("OS baseline differs from Windows 10 19045.2965");
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
            }
            if(ReplacementCount!=32 || AllocationCount!=48) Difference("Incomplete native case coverage");
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
    public static void SelfCheck() {
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
        [pscustomobject]@{Kind='SelfCheck'; NativeCalls=$false; Packing='PASS'; Signatures='PASS'; TableMutations='PASS'; AllocationMutations='PASS'} | ConvertTo-Json -Compress
        Write-Output 'NativeStoreMechanismSelfCheck=PASS'
        return
    }
    $control = New-Object T9NativeStoreControl
    $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    [pscustomobject]@{Kind='Script'; SHA256=$scriptHash; PSVersion=$PSVersionTable.PSVersion.ToString(); ProcessBits=([IntPtr]::Size*8)} | ConvertTo-Json -Compress
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Runtime requires Windows PowerShell 5.1.' }
    $control.Run($TempParent,[bool]$ExpectBuilderTable)
    foreach ($record in $control.Events) { $record | ConvertTo-Json -Depth 12 -Compress }
    $verdict = [T9NativeStoreControl]::Verdict($control.FirstDifference,[bool]$ExpectBuilderTable)
    [pscustomobject]@{Kind='Verdict'; Verdict=$verdict; FirstDifference=$control.FirstDifference; ReplacementRows=$control.ReplacementCount; AllocationRows=$control.AllocationCount; TargetBaselineMatches=$control.TargetBaselineMatches; LabStop=($verdict -eq 'DIFFERS')} | ConvertTo-Json -Compress
    Write-Output ('NativeStoreMechanism='+$verdict)
    if ($verdict -eq 'DIFFERS') { exit 1 }
} catch {
    [pscustomobject]@{Kind='Fatal'; Message=$_.Exception.Message; LabStop=$true} | ConvertTo-Json -Compress
    Write-Output 'NativeStoreMechanism=DIFFERS'
    exit 1
}
