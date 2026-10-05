// Private SYSTEM-side client for the separately built qualification filter.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public sealed class SafeUploadSectionFaultClient : IDisposable
{
    public const uint WriteArm = 5, WriteRelease = 6, WriteDisarm = 7, WriteStatus = 8,
        WriteSyntheticFailure = 9;
    [DllImport("fltlib.dll", CharSet=CharSet.Unicode)]
    static extern int FilterVolumeInstanceFindFirst(string volume, int informationClass, byte[] buffer,
        uint bytes, out uint returned, out IntPtr find);
    [DllImport("fltlib.dll")]
    static extern int FilterVolumeInstanceFindNext(IntPtr find, int informationClass, byte[] buffer,
        uint bytes, out uint returned);
    [DllImport("fltlib.dll")]
    static extern int FilterVolumeInstanceFindClose(IntPtr find);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint capacity, uint flags);
    public sealed class Instance {
        public string Name, Altitude, Volume, Filter;
    }
    static string Field(byte[] buffer, int start, int returned, int lengthOffset) {
        int length = BitConverter.ToUInt16(buffer, start + lengthOffset);
        int offset = BitConverter.ToUInt16(buffer, start + lengthOffset + 2);
        if (length == 0 || (length & 1) != 0 || offset < 20 || offset > returned - start ||
            length > returned - start - offset) throw new InvalidOperationException("Invalid instance string");
        return Encoding.Unicode.GetString(buffer, start + offset, length);
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, byte[] information, uint bytes);
    public static SafeFileHandle OpenAttributes(string path) {
        SafeFileHandle file = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
        if (file.IsInvalid) { int error=Marshal.GetLastWin32Error(); file.Dispose(); throw new System.ComponentModel.Win32Exception(error); }
        return file;
    }
    public static string Identity(SafeFileHandle file) {
        byte[] identity = new byte[24];
        if (!GetFileInformationByHandleEx(file, 18, identity, 24)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        return BitConverter.ToString(identity).Replace("-", "");
    }
    public static string VolumeForHandle(SafeFileHandle file) {
        StringBuilder path = new StringBuilder(4096);
        uint length = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 2);
        if (length == 0 || length >= path.Capacity) throw new InvalidOperationException("Final NT path unavailable");
        string full = path.ToString();
        if (!full.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Not a local NT volume");
        int end = full.IndexOf('\\', 8);
        if (end < 0) throw new InvalidOperationException("Final NT volume missing");
        return full.Substring(0, end);
    }
    public static Instance[] Inventory(string volume) {
        byte[] buffer = new byte[16384]; uint returned; IntPtr find;
        int hr = FilterVolumeInstanceFindFirst(volume, 2, buffer, (uint)buffer.Length, out returned, out find);
        if (hr != 0) throw new COMException("Instance enumeration start", hr);
        List<Instance> result = new List<Instance>();
        try {
            for (;;) {
                if (returned < 20 || returned > buffer.Length) throw new InvalidOperationException("Instance enumeration length");
                int start = 0;
                for (;;) {
                    if (start > returned - 20 || result.Count >= 128) throw new InvalidOperationException("Instance enumeration capacity");
                    result.Add(new Instance { Name=Field(buffer,start,(int)returned,4), Altitude=Field(buffer,start,(int)returned,8),
                        Volume=Field(buffer,start,(int)returned,12), Filter=Field(buffer,start,(int)returned,16) });
                    uint next = BitConverter.ToUInt32(buffer,start);
                    if (next == 0) break;
                    if (next < 20 || next > returned - start - 20) throw new InvalidOperationException("Instance enumeration offset");
                    start += (int)next;
                }
                hr = FilterVolumeInstanceFindNext(find, 2, buffer, (uint)buffer.Length, out returned);
                if (hr == unchecked((int)0x80070103)) break;
                if (hr != 0) throw new COMException("Instance enumeration continuation",hr);
            }
        } finally {
            int close = FilterVolumeInstanceFindClose(find);
            if (close != 0) throw new COMException("Instance enumeration close",close);
        }
        return result.ToArray();
    }
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    static extern int FilterConnectCommunicationPort(string name, uint options, IntPtr context,
        ushort contextBytes, IntPtr security, out SafeFileHandle port);
    [DllImport("fltlib.dll")]
    static extern int FilterSendMessage(SafeFileHandle port, byte[] input, uint inputBytes,
        byte[] output, uint outputBytes, out uint returned);
    readonly SafeFileHandle port;
    public SafeUploadSectionFaultClient() {
        int hr = FilterConnectCommunicationPort("\\SafeUploadSectionFaultPort", 0, IntPtr.Zero, 0, IntPtr.Zero, out port);
        if (hr != 0) { if (port != null) port.Dispose(); throw new COMException("Fault port connection", hr); }
    }
    public sealed class State {
        public uint Version, Mode, CurrentHeld;
        public ulong Matched, Failed, Held, TimedOut, InvalidIrql, ArmedFileObject, ArmGeneration;
    }
    public sealed class WriteState {
        public uint Version, Mode, CurrentHeld, PostFlags;
        public ulong ArmGeneration, Matched, Held, Released, LowerPosts, Canceled, TimedOut, ArmedFileObject;
        public int LowerStatus;
        public ulong LowerInformation, LowerCallbackData, SyntheticFailures, WriteOffset;
        public uint WriteLength, IrpFlags;
    }
    public State Send(uint command, IntPtr file) {
        byte[] input = new byte[16], output = new byte[72]; uint returned;
        Array.Copy(BitConverter.GetBytes(1u), 0, input, 0, 4);
        Array.Copy(BitConverter.GetBytes(command), 0, input, 4, 4);
        Array.Copy(BitConverter.GetBytes(unchecked((ulong)file.ToInt64())), 0, input, 8, 8);
        int hr = FilterSendMessage(port, input, (uint)input.Length, output, (uint)output.Length, out returned);
        if (hr != 0) throw new COMException("Fault control message", hr);
        if (returned != output.Length || BitConverter.ToUInt32(output, 0) != 1 || BitConverter.ToUInt32(output, 60) != 0)
            throw new InvalidOperationException("Fault reply schema mismatch");
        return new State { Version=BitConverter.ToUInt32(output,0), Mode=BitConverter.ToUInt32(output,4),
            Matched=BitConverter.ToUInt64(output,8), Failed=BitConverter.ToUInt64(output,16),
            Held=BitConverter.ToUInt64(output,24), TimedOut=BitConverter.ToUInt64(output,32),
            InvalidIrql=BitConverter.ToUInt64(output,40), ArmedFileObject=BitConverter.ToUInt64(output,48),
            CurrentHeld=BitConverter.ToUInt32(output,56), ArmGeneration=BitConverter.ToUInt64(output,64) };
    }
    // Version-2 write commands are additive; the legacy v1 section wire format above is unchanged.
    public WriteState SendWrite(uint command, SafeFileHandle file = null) {
        byte[] input = new byte[24], output = new byte[128]; uint returned;
        Array.Copy(BitConverter.GetBytes(2u), 0, input, 0, 4);
        Array.Copy(BitConverter.GetBytes(command), 0, input, 4, 4);
        bool fileReference = false;
        int hr;
        try {
            if (file != null && !file.IsInvalid && !file.IsClosed) {
                file.DangerousAddRef(ref fileReference);
                Array.Copy(BitConverter.GetBytes(unchecked((ulong)file.DangerousGetHandle().ToInt64())), 0, input, 8, 8);
            }
            hr = FilterSendMessage(port, input, (uint)input.Length, output, (uint)output.Length, out returned);
        } finally {
            if (fileReference) file.DangerousRelease();
        }
        if (hr != 0) throw new COMException("Write fault control message", hr);
        if (returned != output.Length || BitConverter.ToUInt32(output, 0) != 2 || BitConverter.ToUInt32(output, 84) != 0)
            throw new InvalidOperationException("Write fault reply schema mismatch");
        return new WriteState {
            Version=BitConverter.ToUInt32(output,0), Mode=BitConverter.ToUInt32(output,4),
            CurrentHeld=BitConverter.ToUInt32(output,8), PostFlags=BitConverter.ToUInt32(output,12),
            ArmGeneration=BitConverter.ToUInt64(output,16), Matched=BitConverter.ToUInt64(output,24),
            Held=BitConverter.ToUInt64(output,32), Released=BitConverter.ToUInt64(output,40),
            LowerPosts=BitConverter.ToUInt64(output,48), Canceled=BitConverter.ToUInt64(output,56),
            TimedOut=BitConverter.ToUInt64(output,64), ArmedFileObject=BitConverter.ToUInt64(output,72),
            LowerStatus=BitConverter.ToInt32(output,80), LowerInformation=BitConverter.ToUInt64(output,88),
            LowerCallbackData=BitConverter.ToUInt64(output,96), SyntheticFailures=BitConverter.ToUInt64(output,104),
            WriteOffset=BitConverter.ToUInt64(output,112), WriteLength=BitConverter.ToUInt32(output,120),
            IrpFlags=BitConverter.ToUInt32(output,124) };
    }
    public WriteState ArmNoncachedWrite(SafeFileHandle file) { return SendWrite(WriteArm, file); }
    public WriteState ReleaseHeldWrite() { return SendWrite(WriteRelease); }
    public WriteState FailHeldWriteBeforeDispatch() { return SendWrite(WriteSyntheticFailure); }
    public WriteState ReadWriteStatus() { return SendWrite(WriteStatus); }
    public WriteState DisarmWrite() { return SendWrite(WriteDisarm); }
    public void Dispose() { port.Dispose(); }
    // Both commands used while a lower callback is held read resident driver state only.
    public static string Inspector(string executable, string command) {
        ProcessStartInfo start = new ProcessStartInfo(executable, command) {
            UseShellExecute=false, CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true };
        using (Process process = Process.Start(start)) {
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(5000)) {
                process.Kill(); process.WaitForExit(5000);
                throw new InvalidOperationException("Memory inspector timed out: " + command);
            }
            if (!output.Wait(5000) || !error.Wait(5000)) throw new InvalidOperationException("Inspector pipe drain timed out");
            if (process.ExitCode != 0) throw new InvalidOperationException("Inspector failed: " + command + "; " + error.Result + output.Result);
            return output.Result;
        }
    }
}

// Opens and retains a separate writer FILE_OBJECT from a dedicated managed/native thread.
public sealed class SafeUploadSectionFaultRetainedWriter : IDisposable
{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(SafeFileHandle file, byte[] buffer, uint bytesToWrite,
        out uint bytesWritten, IntPtr overlapped);
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();

    public sealed class WriteResult
    {
        public bool Succeeded;
        public int Win32Error;
        public uint BytesWritten;
    }

    readonly ManualResetEvent ready = new ManualResetEvent(false);
    readonly ManualResetEvent release = new ManualResetEvent(false);
    readonly Thread thread;
    SafeFileHandle file;
    Exception workerError;
    int openError;
    uint openThreadId;

    public uint OpenThreadId { get { return openThreadId; } }
    public int OpenError { get { return openError; } }
    public Exception WorkerError { get { return workerError; } }
    public bool IsOpen { get { return file != null && !file.IsInvalid && !file.IsClosed; } }

    public SafeUploadSectionFaultRetainedWriter(string path)
    {
        thread = new Thread(delegate()
        {
            try
            {
                openThreadId = GetCurrentThreadId();
                SafeFileHandle opened = CreateFileW(path, 0x40000000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                if (opened.IsInvalid)
                {
                    openError = Marshal.GetLastWin32Error();
                    opened.Dispose();
                }
                else file = opened;
            }
            catch (Exception error) { workerError = error; }
            finally { ready.Set(); }

            if (file != null) release.WaitOne();
            if (file != null) file.Dispose();
        });
        thread.IsBackground = true;
        thread.Start();
        if (!ready.WaitOne(10000))
        {
            release.Set();
            if (thread.Join(10000))
            {
                ready.Dispose();
                release.Dispose();
            }
            throw new InvalidOperationException("Retained writer open timed out.");
        }
        if (workerError != null)
        {
            release.Set();
            thread.Join(10000);
            ready.Dispose();
            release.Dispose();
            throw new InvalidOperationException("Retained writer open failed.", workerError);
        }
        if (openError != 0 || !IsOpen)
        {
            release.Set();
            thread.Join(10000);
            ready.Dispose();
            release.Dispose();
            if (openError != 0) throw new System.ComponentModel.Win32Exception(openError);
            throw new InvalidOperationException("Retained writer did not keep a valid handle.");
        }
    }

    public static uint CurrentThreadId() { return GetCurrentThreadId(); }

    public static WriteResult TryWrite(SafeFileHandle handle, byte[] bytes)
    {
        if (handle == null || handle.IsInvalid || handle.IsClosed) throw new ArgumentException("Invalid file handle.");
        if (bytes == null || bytes.Length == 0) throw new ArgumentException("Write payload must not be empty.");
        bool retained = false;
        try
        {
            handle.DangerousAddRef(ref retained);
            uint written = 0;
            bool succeeded = WriteFile(handle, bytes, (uint)bytes.Length, out written, IntPtr.Zero);
            return new WriteResult {
                Succeeded=succeeded,
                Win32Error=succeeded ? 0 : Marshal.GetLastWin32Error(),
                BytesWritten=written
            };
        }
        finally { if (retained) handle.DangerousRelease(); }
    }

    public WriteResult AttemptWrite(byte[] bytes)
    {
        if (!IsOpen) throw new InvalidOperationException("Retained writer handle is closed.");
        return TryWrite(file, bytes);
    }

    public void Dispose()
    {
        release.Set();
        if (!thread.Join(10000)) throw new InvalidOperationException("Retained writer thread did not stop.");
        ready.Dispose();
        release.Dispose();
    }
}

public sealed class SafeUploadSectionFaultMapping
{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protection,
        uint highSize, uint lowSize, string name);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    readonly Thread thread;
    public bool Created;
    public int Error;
    public Exception WorkerError;
    public SafeUploadSectionFaultMapping(SafeFileHandle file) {
        thread = new Thread(delegate() {
            bool retained = false;
            try {
                file.DangerousAddRef(ref retained);
                IntPtr mapping = CreateFileMappingW(file.DangerousGetHandle(), IntPtr.Zero, 4, 0, 4096, null);
                Error = mapping == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
                Created = mapping != IntPtr.Zero;
                if (Created && !CloseHandle(mapping)) throw new InvalidOperationException("Mapping close failed");
            } catch (Exception error) { WorkerError = error; }
            finally { if (retained) file.DangerousRelease(); }
        });
        thread.IsBackground = true;
        thread.Start();
    }
    public bool Wait(int timeoutMilliseconds) { return thread.Join(timeoutMilliseconds); }
}

// One persistent native worker per simulated caller. Reusing the thread matters because
// SafeUpload pairs release callbacks by (thread, FILE_OBJECT), newest slot first.
public sealed class SafeUploadSectionFaultThreadMapping : IDisposable
{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileMappingW(IntPtr file, IntPtr attributes, uint protection,
        uint highSize, uint lowSize, string name);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();

    readonly SafeFileHandle file;
    readonly AutoResetEvent command = new AutoResetEvent(false);
    readonly ManualResetEvent completed = new ManualResetEvent(true);
    readonly Thread thread;
    volatile bool stopping;
    uint protection;
    uint nativeThreadId;
    bool created;
    int error;
    Exception workerError;

    public SafeUploadSectionFaultThreadMapping(SafeFileHandle sharedFile)
    {
        file = sharedFile;
        thread = new Thread(Worker);
        thread.IsBackground = true;
        thread.Start();
    }

    public uint NativeThreadId { get { return nativeThreadId; } }
    public bool Created { get { return created; } }
    public int Error { get { return error; } }
    public Exception WorkerError { get { return workerError; } }
    public bool Pending { get { return !completed.WaitOne(0); } }

    public void Start(uint pageProtection)
    {
        if (!completed.WaitOne(0)) throw new InvalidOperationException("Section worker already has an operation.");
        protection = pageProtection;
        nativeThreadId = 0;
        created = false;
        error = 0;
        workerError = null;
        completed.Reset();
        command.Set();
    }

    void Worker()
    {
        for (;;)
        {
            command.WaitOne();
            if (stopping) return;
            bool retained = false;
            try
            {
                nativeThreadId = GetCurrentThreadId();
                file.DangerousAddRef(ref retained);
                IntPtr mapping = CreateFileMappingW(file.DangerousGetHandle(), IntPtr.Zero,
                    protection, 0, 4096, null);
                error = mapping == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
                created = mapping != IntPtr.Zero;
                if (created && !CloseHandle(mapping))
                {
                    error = Marshal.GetLastWin32Error();
                    created = false;
                }
            }
            catch (Exception exception) { workerError = exception; }
            finally
            {
                if (retained) file.DangerousRelease();
                completed.Set();
            }
        }
    }

    public bool Wait(int timeoutMilliseconds) { return completed.WaitOne(timeoutMilliseconds); }

    public void Dispose()
    {
        stopping = true;
        command.Set();
        if (!thread.Join(10000)) throw new InvalidOperationException("Persistent section worker did not stop.");
        command.Dispose();
        completed.Dispose();
    }
}

/* Writes through a view whose backing volume was dismounted fault with an in-page/access exception that .NET 4
 * does not deliver to managed handlers by default (section-teardown run 4 crashed the exercise). Catch it here so
 * the outcome is recorded instead of terminating the process. Raw address = view base + PointerOffset + offset. */
public static class SafeUploadGuardedView
{
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FlushViewOfFile(IntPtr address, UIntPtr bytes);

    [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
    [System.Security.SecurityCritical]
    public static string Write(IntPtr address, byte value)
    {
        try { Marshal.WriteByte(address, value); return "returned"; }
        catch (Exception e) { return "faulted:" + e.GetType().FullName + ":0x" + e.HResult.ToString("X8"); }
    }

    [System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
    [System.Security.SecurityCritical]
    public static string Flush(IntPtr address)
    {
        try {
            if (FlushViewOfFile(address, new UIntPtr(1))) return "returned";
            return "failed:win32:" + Marshal.GetLastWin32Error();
        }
        catch (Exception e) { return "faulted:" + e.GetType().FullName + ":0x" + e.HResult.ToString("X8"); }
    }
}
