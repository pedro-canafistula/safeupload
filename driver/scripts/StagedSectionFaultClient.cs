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
