using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class StagedLockProbe
{
    [StructLayout(LayoutKind.Sequential)]
    struct Overlapped { public IntPtr Internal, InternalHigh; public uint Offset, OffsetHigh; public IntPtr Event; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool LockFileEx(SafeFileHandle file, uint flags, uint reserved, uint low, uint high, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UnlockFileEx(SafeFileHandle file, uint reserved, uint low, uint high, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CancelIoEx(SafeFileHandle file, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetOverlappedResult(SafeFileHandle file, IntPtr overlapped, out uint bytes, bool wait);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadFile(SafeFileHandle file, byte[] bytes, uint count, out uint read, ref Overlapped overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(SafeFileHandle file, byte[] bytes, uint count, out uint written, ref Overlapped overlapped);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle file, IntPtr targetProcess,
        out SafeFileHandle duplicate, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError=true)] static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", EntryPoint="DuplicateHandle", SetLastError=true)]
    static extern bool DuplicateRemote(IntPtr sourceProcess, SafeFileHandle file, SafeFileHandle targetProcess,
        out IntPtr duplicate, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern SafeFileHandle CreateFileMapping(SafeFileHandle file, IntPtr security, uint protection,
        uint high, uint low, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFile(SafeFileHandle section, uint access, uint high, uint low, UIntPtr count);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool UnmapViewOfFile(IntPtr address);

    public static SafeFileHandle Open(string path, bool asynchronous)
    {
        var file = CreateFile(path, 0xC0010000, 7, IntPtr.Zero, 3, asynchronous ? 0x40000080u : 0x80u, IntPtr.Zero);
        if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        return file;
    }
    sealed class Request : IDisposable
    {
        static readonly System.Collections.Generic.List<Request> abandoned = new System.Collections.Generic.List<Request>();
        public IntPtr Pointer;
        SafeFileHandle pendingFile;
        readonly ManualResetEvent signal = new ManualResetEvent(false);
        public Request(uint offset)
        {
            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Overlapped)));
            Marshal.StructureToPtr(new Overlapped { Offset=offset, Event=signal.SafeWaitHandle.DangerousGetHandle() }, Pointer, false);
        }
        public void Wait() { if (!signal.WaitOne(5000)) throw new Exception("Lock completion exceeded 5 seconds."); }
        public int Begin(SafeFileHandle file, uint flags) {
            int error=Error(LockFileEx(file,flags,0,16,0,Pointer));
            if(error==997) pendingFile=file;
            return error;
        }
        public void Dispose() {
            if(pendingFile!=null && !signal.WaitOne(0)) {
                CancelIoEx(pendingFile,Pointer);
                // Keep the OVERLAPPED and event alive if the driver cannot
                // cancel. The failed gate's restore helper then requires reboot.
                if(!signal.WaitOne(5000)) { lock(abandoned) abandoned.Add(this); return; }
            }
            Marshal.FreeHGlobal(Pointer); signal.Dispose();
        }
    }
    static void Expect(int actual, int expected, string operation)
    { if (actual != expected) throw new Exception(operation + ": expected " + expected + ", actual " + actual); }
    static int Error(bool success) { return success ? 0 : Marshal.GetLastWin32Error(); }
    public static int Lock(SafeFileHandle file, uint offset, uint flags)
    {
        using (var request=new Request(offset)) return request.Begin(file,flags);
    }
    static void Unlock(SafeFileHandle file, uint offset)
    {
        using (var request=new Request(offset)) {
            int error=Error(UnlockFileEx(file,0,16,0,request.Pointer));
            if(error==997) { request.Wait(); uint count; error=Error(GetOverlappedResult(file,request.Pointer,out count,false)); }
            Expect(error,0,"unlock");
        }
    }
    public static int Write(SafeFileHandle file, uint offset)
    {
        var ov=new Overlapped { Offset=offset }; uint count;
        return Error(WriteFile(file,new byte[]{(byte)'B'},1,out count,ref ov));
    }
    static int Read(SafeFileHandle file, uint offset)
    {
        var ov=new Overlapped { Offset=offset }; uint count;
        return Error(ReadFile(file,new byte[1],1,out count,ref ov));
    }
    public static long Send(SafeFileHandle file, uint pid)
    {
        using (var process=OpenProcess(0x40,false,pid)) {
            if(process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr remote;
            if(!DuplicateRemote(GetCurrentProcess(),file,process,out remote,0,false,2))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return remote.ToInt64();
        }
    }
    public static void Run(string path)
    {
        using (var first=Open(path,false))
        using (var second=Open(path,false))
        using (var waiting=Open(path,true))
        {
            SafeFileHandle copy;
            if (!DuplicateHandle(GetCurrentProcess(),first,GetCurrentProcess(),out copy,0,false,2))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            using (copy)
            {
                Expect(Lock(first,0,3),0,"exclusive lock");
                Expect(Write(first,0),0,"exclusive owner write");
                Expect(Write(copy,1),0,"duplicate owner write");
                Expect(Read(second,0),33,"competing exclusive read");
                Expect(Write(second,0),33,"competing exclusive write");
                Expect(Write(second,32),0,"unlocked write");
                using (var request=new Request(0))
                {
                    Expect(request.Begin(waiting,2),997,"waiting lock");
                    if (!CancelIoEx(waiting,request.Pointer)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    request.Wait(); uint count;
                    Expect(Error(GetOverlappedResult(waiting,request.Pointer,out count,false)),995,"cancelled lock");
                }
                using (var request=new Request(0))
                {
                    Expect(request.Begin(waiting,2),997,"waiting lock after cancellation");
                    Unlock(first,0);
                    request.Wait(); uint count;
                    Expect(Error(GetOverlappedResult(waiting,request.Pointer,out count,false)),0,"granted waiting lock");
                    Unlock(waiting,0);
                }
                Expect(Lock(first,0,1),0,"first shared lock");
                Expect(Lock(second,0,1),0,"second shared lock");
                Expect(Write(first,0),33,"shared owner write");
                Expect(Read(second,0),0,"shared read");
                Unlock(first,0); Unlock(second,0);
                Expect(Lock(first,8192,3),0,"lock beyond EOF"); Unlock(first,8192);

                Expect(Lock(first,0,3),0,"mapped lock");
                using (var section=CreateFileMapping(second,IntPtr.Zero,4,0,0,null))
                {
                    if (section.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    IntPtr view=MapViewOfFile(section,2,0,0,UIntPtr.Zero);
                    if (view==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                    try { Marshal.WriteByte(view,0,(byte)'M'); }
                    finally { if (!UnmapViewOfFile(view)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
                }
                Unlock(first,0);
                Expect(Lock(first,16,3),0,"cleanup lock");
                first.Dispose();
                Expect(Write(second,16),33,"duplicate keeps locks alive");
            }
            Expect(Write(second,16),0,"final duplicate cleanup releases locks");
        }
    }
}
