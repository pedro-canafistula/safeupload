using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class StagedIdentityProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)]
    struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct ObjectAttributes {
        public int Length; public IntPtr Root, Name; public uint Attributes;
        public IntPtr Security, Quality;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int cls, byte[] info, int size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeFileHandle OpenFileById(SafeFileHandle hint, byte[] id,
        uint access, uint share, IntPtr security, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFilePointerEx(SafeFileHandle file, long distance, out long position, uint method);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadFile(SafeFileHandle file, byte[] data, uint size, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(SafeFileHandle file, byte[] data, uint size, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetEndOfFile(SafeFileHandle file);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FlushFileBuffers(SafeFileHandle file);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle file, int cls, byte[] info, int size);
    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryFile(SafeFileHandle file, IntPtr ev, IntPtr apc,
        IntPtr context, out IoStatus io, byte[] info, uint length, int cls,
        [MarshalAs(UnmanagedType.U1)] bool single, IntPtr pattern,
        [MarshalAs(UnmanagedType.U1)] bool restart);
    [DllImport("ntdll.dll")]
    static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes,
        out IoStatus io, IntPtr allocationSize, uint fileAttributes, uint share,
        uint disposition, uint options, IntPtr ea, uint eaLength);
    [DllImport("ntdll.dll")]
    static extern uint RtlNtStatusToDosError(int status);
    static void Check(bool success) { if(!success) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static SafeFileHandle CheckHandle(SafeFileHandle file) {
        if(file.IsInvalid) { int error=Marshal.GetLastWin32Error(); file.Dispose(); throw new Win32Exception(error); }
        return file;
    }
    public static SafeFileHandle Open(string path, bool writer, bool create) {
        return CheckHandle(CreateFile(path,writer ? 0xC0010000 : 0x80000000,7,
            IntPtr.Zero,create ? 2u : 3u,0x80,IntPtr.Zero));
    }
    public static byte[] Identity(SafeFileHandle file) {
        var info=new byte[24]; Check(GetFileInformationByHandleEx(file,18,info,info.Length)); return info;
    }
    public static byte[] VolumeIdentity(string volumeHint) {
        using(var hint=CheckHandle(CreateFile(volumeHint,0x80,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)))
            return Identity(hint);
    }
    public static SafeFileHandle Relative(string directory, string basename) {
        using(var root=CheckHandle(CreateFile(directory,0x80,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero))) {
            IntPtr text=Marshal.StringToHGlobalUni(basename);
            IntPtr name=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
            try {
                var unicode=new UnicodeString { Length=checked((ushort)(basename.Length*2)),
                    MaximumLength=checked((ushort)(basename.Length*2+2)), Buffer=text };
                Marshal.StructureToPtr(unicode,name,false);
                var attributes=new ObjectAttributes { Length=Marshal.SizeOf(typeof(ObjectAttributes)),
                    Root=root.DangerousGetHandle(), Name=name, Attributes=0x40 };
                SafeFileHandle result; IoStatus io;
                int status=NtCreateFile(out result,0x80100000,ref attributes,out io,
                    IntPtr.Zero,0x80,7,1,0x60,IntPtr.Zero,0);
                GC.KeepAlive(root);
                if(status!=0) { if(result!=null) result.Dispose(); throw new Win32Exception((int)RtlNtStatusToDosError(status)); }
                return result;
            } finally { Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(text); }
        }
    }
    public static string RenameRace(SafeFileHandle writer, string first, string second, byte[] identity) {
        int done=0, successful=0, refused=0;
        var timer=System.Diagnostics.Stopwatch.StartNew();
        var reader=System.Threading.Tasks.Task.Run(() => {
            while(System.Threading.Volatile.Read(ref done)==0 || successful<100) {
                if(timer.ElapsedMilliseconds>15000) throw new Exception("File-ID race exceeded its deadline");
                try {
                    using(var file=ById("C:\\",identity,false)) {
                        if(Convert.ToBase64String(Identity(file))!=Convert.ToBase64String(identity))
                            throw new Exception("Rename race returned another identity");
                        if(Read(file)!="CPF: 529.982.247-25 prior private") throw new Exception("Rename race returned other bytes");
                    }
                    successful++;
                } catch(Win32Exception error) { if(error.NativeErrorCode!=32) throw; refused++; }
            }
        });
        try { for(int index=0;index<6;index++) { Rename(writer,second,false); Rename(writer,first,false); } }
        finally { System.Threading.Volatile.Write(ref done,1); reader.GetAwaiter().GetResult(); }
        return "Reads="+successful+" SharingRetries="+refused+" Moves=12 Milliseconds="+timer.ElapsedMilliseconds;
    }
    public static SafeFileHandle ById(string volumeHint, byte[] identity, bool writer) {
        using(var hint=CheckHandle(CreateFile(volumeHint,0x80,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero))) {
            var descriptor=new byte[24]; BitConverter.GetBytes(24).CopyTo(descriptor,0);
            BitConverter.GetBytes(2).CopyTo(descriptor,4); Array.Copy(identity,8,descriptor,8,16);
            return CheckHandle(OpenFileById(hint,descriptor,writer ? 0xC0010000 : 0x80000000,7,IntPtr.Zero,0));
        }
    }
    public static int TryById(string volumeHint, byte[] identity, bool writer) {
        try { using(var file=ById(volumeHint,identity,writer)) return 0; }
        catch(Win32Exception error) { return error.NativeErrorCode; }
    }
    public static void Write(SafeFileHandle file, string text) {
        long position; uint written; byte[] data=Encoding.UTF8.GetBytes(text);
        Check(SetFilePointerEx(file,0,out position,0)); Check(WriteFile(file,data,(uint)data.Length,out written,IntPtr.Zero));
        if(written!=data.Length) throw new Exception("Short write");
        Check(SetEndOfFile(file)); Check(FlushFileBuffers(file));
    }
    public static string Read(SafeFileHandle file) {
        long position; uint read; var data=new byte[65536];
        Check(SetFilePointerEx(file,0,out position,0)); Check(ReadFile(file,data,(uint)data.Length,out read,IntPtr.Zero));
        return Encoding.UTF8.GetString(data,0,(int)read);
    }
    public static void Rename(SafeFileHandle file, string target, bool replace) {
        byte[] name=Encoding.Unicode.GetBytes(target); int offset=IntPtr.Size==8 ? 20 : 12;
        var info=new byte[offset+name.Length+2]; BitConverter.GetBytes(replace ? 3 : 0).CopyTo(info,0);
        BitConverter.GetBytes(name.Length).CopyTo(info,offset-4); name.CopyTo(info,offset);
        Check(SetFileInformationByHandle(file,22,info,info.Length));
    }
    public static byte[] DirectoryId(string directory, string basename) {
        using(var file=CheckHandle(CreateFile(directory,0x100001,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero))) {
            var info=new byte[65536]; bool first=true;
            for(int page=0;page<256;page++) {
                IoStatus io; int status=NtQueryDirectoryFile(file,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,
                    out io,info,(uint)info.Length,60,false,IntPtr.Zero,first); first=false;
                if(status!=0) throw new Exception("Directory ID query: 0x"+status.ToString("X8"));
                int size=checked((int)io.Information.ToUInt64()), offset=0;
                while(offset<size) {
                    if(size-offset<88) throw new Exception("Short directory ID header");
                    int length=BitConverter.ToInt32(info,offset+60);
                    if(length<0 || (length&1)!=0 || length>size-offset-88) throw new Exception("Invalid directory ID name");
                    if(Encoding.Unicode.GetString(info,offset+88,length)==basename) {
                        var id=new byte[16]; Array.Copy(info,offset+72,id,0,16); return id;
                    }
                    int next=BitConverter.ToInt32(info,offset);
                    if(next==0) break;
                    if(next<88 || next>size-offset) throw new Exception("Invalid directory ID offset");
                    offset+=next;
                }
            }
            throw new Exception("Directory identity was not found");
        }
    }
}
