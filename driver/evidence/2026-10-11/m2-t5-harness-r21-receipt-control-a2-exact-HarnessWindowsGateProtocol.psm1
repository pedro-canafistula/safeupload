Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$nativeType = 'SafeUpload.HarnessGate.Native'
if ($null -eq ($nativeType -as [type])) {
    $nativeSource = @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SafeUpload.HarnessGate {
    public sealed class ChildProcess {
        public IntPtr ProcessHandle;
        public IntPtr ThreadHandle;
        public uint ProcessId;
        public long StartFileTime;
    }

    public static class Native {
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
        private const uint PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint CREATE_NEW = 1;
        private const uint OPEN_EXISTING = 3;
        private const uint DUPLICATE_SAME_ACCESS = 2;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint INFINITE = 0xffffffff;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const uint PIPE_ACCESS_INBOUND = 0x00000001;
        private const uint PIPE_TYPE_BYTE = 0x00000000;
        private const uint PIPE_READMODE_BYTE = 0x00000000;
        private const uint PIPE_WAIT = 0x00000000;
        private const uint PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
        private const uint ERROR_IO_PENDING = 997;
        private const uint ERROR_PIPE_CONNECTED = 535;
        private const uint ERROR_BROKEN_PIPE = 109;
        private const uint ERROR_OPERATION_ABORTED = 995;
        private const int STD_OUTPUT_HANDLE = -11;
        private const int STD_ERROR_HANDLE = -12;
        private const int OUTPUT_CHUNK_BYTES = 65536;
        private const int PIPE_DRAIN_MILLISECONDS = 1500;
        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint SYNCHRONIZE = 0x00100000;

        [StructLayout(LayoutKind.Sequential)]
        private struct BasicLimitInformation {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct IoCounters {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ExtendedLimitInformation {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct BasicAccountingInformation {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct StartupInfoEx {
            public StartupInfo StartupInfo;
            public IntPtr AttributeList;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime {
            public uint Low;
            public uint High;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeOverlapped {
            public IntPtr Internal;
            public IntPtr InternalHigh;
            public uint Offset;
            public uint OffsetHigh;
            public IntPtr EventHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out BasicAccountingInformation info, uint length, out uint returned);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, out uint returned);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenJobObject(uint access, bool inherit, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")]
        private static extern void SetLastError(uint errorCode);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(string name, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcess(string application, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string currentDirectory,
            ref StartupInfoEx startup, out ProcessInformation information);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount,
            uint flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute,
            IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetHandleInformation(IntPtr handle, out uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateNamedPipe(string name, uint openMode, uint pipeMode,
            uint maxInstances, uint outBufferSize, uint inBufferSize, uint defaultTimeout, IntPtr securityAttributes);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(IntPtr file, IntPtr buffer, uint bytesToRead, IntPtr bytesRead, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetOverlappedResult(IntPtr file, IntPtr overlapped, out uint bytesTransferred, bool wait);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CancelIoEx(IntPtr file, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateEvent(IntPtr attributes, bool manualReset, bool initialState, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ResetEvent(IntPtr eventHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetEvent(IntPtr eventHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int standardHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(IntPtr file, IntPtr buffer, uint bytesToWrite, out uint bytesWritten, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        private static void Check(bool ok, string operation) {
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }
        private static long ToLong(FileTime value) {
            return unchecked((long)(((ulong)value.High << 32) | value.Low));
        }
        private static double ElapsedMilliseconds(long startTicks) {
            return ((double)(Stopwatch.GetTimestamp() - startTicks) * 1000.0) / Stopwatch.Frequency;
        }
        private static string QuoteArgument(string value) {
            if (value == null) return "\"\"";
            StringBuilder result = new StringBuilder();
            result.Append('"');
            int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('"');
                    slashes = 0;
                    continue;
                }
                result.Append('\\', slashes);
                slashes = 0;
                result.Append(c);
            }
            result.Append('\\', slashes * 2);
            result.Append('"');
            return result.ToString();
        }
        private sealed class AttributeListResources {
            public IntPtr AttributeList;
            public IntPtr HandleList;
            public IntPtr JobList;
            public IntPtr[] Handles;
            public uint[] OriginalHandleFlags;
            public int FlagsCaptured;
            public bool Initialized;
            public int RestoreError;
            public void Release() {
                int restoreError = 0;
                if (Handles != null && OriginalHandleFlags != null) {
                    for (int index = 0; index < FlagsCaptured; index++) {
                        if (Handles[index] != IntPtr.Zero && Handles[index] != new IntPtr(-1)) {
                            if (!SetHandleInformation(Handles[index], HANDLE_FLAG_INHERIT,
                                OriginalHandleFlags[index] & HANDLE_FLAG_INHERIT) && restoreError == 0) {
                                restoreError = Marshal.GetLastWin32Error();
                            }
                        }
                    }
                }
                if (Initialized && AttributeList != IntPtr.Zero) DeleteProcThreadAttributeList(AttributeList);
                if (AttributeList != IntPtr.Zero) Marshal.FreeHGlobal(AttributeList);
                if (HandleList != IntPtr.Zero) Marshal.FreeHGlobal(HandleList);
                if (JobList != IntPtr.Zero) Marshal.FreeHGlobal(JobList);
                AttributeList = IntPtr.Zero;
                HandleList = IntPtr.Zero;
                JobList = IntPtr.Zero;
                Handles = null;
                OriginalHandleFlags = null;
                FlagsCaptured = 0;
                Initialized = false;
                RestoreError = restoreError;
            }
        }
        private static AttributeListResources CreateHandleAttributeList(IntPtr[] handles, IntPtr[] jobs) {
            if (handles == null || handles.Length == 0) throw new ArgumentException("An explicit child handle list is required.");
            if (jobs == null) jobs = new IntPtr[0];
            if (jobs.Length > 1) throw new ArgumentException("Only the exact single diagnostic job may be assigned at process creation.");
            for (int index = 0; index < jobs.Length; index++) {
                if (jobs[index] == IntPtr.Zero || jobs[index] == new IntPtr(-1)) {
                    throw new ArgumentException("A process-creation job handle is invalid.");
                }
            }
            int attributeCount = jobs.Length == 0 ? 1 : 2;
            IntPtr size = IntPtr.Zero;
            bool first = InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, 0, ref size);
            int firstError = Marshal.GetLastWin32Error();
            if (first || firstError != 122 || size == IntPtr.Zero) {
                throw new Win32Exception(firstError, "Query process handle-list attribute size");
            }
            AttributeListResources resources = new AttributeListResources();
            try {
                resources.AttributeList = Marshal.AllocHGlobal(size);
                resources.HandleList = Marshal.AllocHGlobal(new IntPtr(handles.Length * IntPtr.Size));
                resources.Handles = (IntPtr[])handles.Clone();
                resources.OriginalHandleFlags = new uint[handles.Length];
                if (jobs.Length != 0) resources.JobList = Marshal.AllocHGlobal(new IntPtr(jobs.Length * IntPtr.Size));
                if (!InitializeProcThreadAttributeList(resources.AttributeList, attributeCount, 0, ref size)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Initialize process handle-list attributes");
                }
                resources.Initialized = true;
                for (int index = 0; index < handles.Length; index++) {
                    if (handles[index] == IntPtr.Zero || handles[index] == new IntPtr(-1)) {
                        throw new ArgumentException("An inherited child handle is invalid.");
                    }
                    uint oldFlags;
                    if (!GetHandleInformation(handles[index], out oldFlags)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Read inherited handle flags");
                    }
                    resources.OriginalHandleFlags[index] = oldFlags;
                    resources.FlagsCaptured = index + 1;
                    if (!SetHandleInformation(handles[index], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Mark allow-listed child handle inheritable");
                    }
                    Marshal.WriteIntPtr(resources.HandleList, index * IntPtr.Size, handles[index]);
                }
                IntPtr listSize = new IntPtr(handles.Length * IntPtr.Size);
                if (!UpdateProcThreadAttribute(resources.AttributeList, 0,
                    new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST), resources.HandleList, listSize,
                    IntPtr.Zero, IntPtr.Zero)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Set explicit child handle allow-list");
                }
                if (jobs.Length != 0) {
                    Marshal.WriteIntPtr(resources.JobList, 0, jobs[0]);
                    if (!UpdateProcThreadAttribute(resources.AttributeList, 0,
                        new IntPtr(PROC_THREAD_ATTRIBUTE_JOB_LIST), resources.JobList,
                        new IntPtr(jobs.Length * IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Set exact job-at-process-creation list");
                    }
                }
                return resources;
            } catch {
                resources.Release();
                throw;
            }
        }

        private static readonly object OutputGate = new object();
        private static long OutputLimitBytes;
        private static long StdoutBytesReserved;
        private static long StderrBytesReserved;
        private static bool OutputLimitExceeded;
        private static IntPtr BoundedStdoutHandle;
        private static IntPtr BoundedStderrHandle;

        private sealed class ChildCapture {
            public readonly long MaxStdoutBytes;
            public readonly long MaxStderrBytes;
            public readonly bool ProbeT5Sentinel;
            public readonly ManualResetEvent Signal = new ManualResetEvent(false);
            public long StdoutBytesReserved;
            public long StderrBytesReserved;
            public volatile bool OutputLimitExceeded;
            public volatile bool ReaderFailed;
            public volatile bool ReaderTimedOut;
            public volatile bool NativeIoOutstanding;
            public volatile bool SawStderr;
            public string ReaderFailure;
            public readonly T5SentinelProbe T5Probe;
            public ChildCapture(long stdoutLimit, long stderrLimit, bool probeT5) {
                MaxStdoutBytes = stdoutLimit;
                MaxStderrBytes = stderrLimit;
                ProbeT5Sentinel = probeT5;
                T5Probe = probeT5 ? new T5SentinelProbe() : null;
            }
        }
        public sealed class BoundedChildResult {
            public uint ExitCode;
            public long StdoutBytes;
            public long StderrBytes;
            public bool ProcessTerminal;
            public bool ReadersTerminal;
            public bool OutputLimitExceeded;
            public bool ReaderFailed;
            public bool ReaderTimedOut;
            public bool SawStderr;
            public bool T5SentinelComplete;
            public bool Success;
        }
        private sealed class T5SentinelProbe {
            private const string Token = "T5 coordinator schema self-check";
            private const string Pattern = "^T5 coordinator schema self-check PASS \\([1-9][0-9]* assertions\\)\\.$";
            private readonly byte[] line = new byte[512];
            private int lineLength;
            private int sentinelCount;
            private bool finalLineIsSentinel;
            private bool malformed;
            private bool endedWithLf;
            public void Append(byte[] buffer, int count) {
                for (int index = 0; index < count; index++) {
                    byte value = buffer[index];
                    if (value == 10) {
                        ProcessLine();
                        lineLength = 0;
                        endedWithLf = true;
                    } else {
                        endedWithLf = false;
                        if (lineLength >= line.Length) { malformed = true; continue; }
                        line[lineLength++] = value;
                    }
                }
            }
            private void ProcessLine() {
                int count = lineLength;
                if (count > 0 && line[count - 1] == 13) count--;
                for (int index = 0; index < count; index++) if (line[index] == 13) malformed = true;
                string text = Encoding.ASCII.GetString(line, 0, count);
                bool tokenPresent = text.IndexOf(Token, StringComparison.Ordinal) >= 0;
                bool complete = Regex.IsMatch(text, Pattern, RegexOptions.CultureInvariant);
                if (tokenPresent) {
                    if (!complete || sentinelCount != 0) malformed = true;
                    sentinelCount++;
                }
                if (complete && !tokenPresent) malformed = true;
                finalLineIsSentinel = complete && tokenPresent && sentinelCount == 1;
                if (sentinelCount > 0 && !finalLineIsSentinel) malformed = true;
            }
            public bool IsComplete() {
                if (lineLength != 0 || !endedWithLf) return false;
                return !malformed && sentinelCount == 1 && finalLineIsSentinel;
            }
        }
        private sealed class PipeResource {
            public IntPtr Server;
            public IntPtr Client;
            public bool Connected;
        }
        private sealed class ReaderState {
            public PipeResource Pipe;
            public ChildCapture Capture;
            public IntPtr ProcessHandle;
            public bool IsStderr;
            public Thread Thread;
        }

        public static void InitializeBoundedOutput(long maximumBytesPerStream) {
            if (maximumBytesPerStream < 65536 || maximumBytesPerStream > 15728640) {
                throw new ArgumentOutOfRangeException("maximumBytesPerStream", "Worker output budget must leave supervisor metadata headroom.");
            }
            lock (OutputGate) {
                OutputLimitBytes = maximumBytesPerStream;
                StdoutBytesReserved = 0;
                StderrBytesReserved = 0;
                OutputLimitExceeded = false;
                BoundedStdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
                BoundedStderrHandle = GetStdHandle(STD_ERROR_HANDLE);
                if (BoundedStdoutHandle == IntPtr.Zero || BoundedStdoutHandle == new IntPtr(-1) ||
                    BoundedStderrHandle == IntPtr.Zero || BoundedStderrHandle == new IntPtr(-1)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Open bounded worker standard handles");
                }
            }
        }
        public static bool WriteStdoutLine(string value) {
            byte[] bytes = Encoding.UTF8.GetBytes(value + "\r\n");
            return TryWriteBounded(false, bytes, bytes.Length, null);
        }
        public static bool WriteStderrLine(string value) {
            byte[] bytes = Encoding.UTF8.GetBytes(value + "\r\n");
            return TryWriteBounded(true, bytes, bytes.Length, null);
        }
        public static bool HasOutputLimitExceeded() {
            lock (OutputGate) return OutputLimitExceeded;
        }
        private static bool TryWriteBounded(bool isStderr, byte[] bytes, int count, ChildCapture capture) {
            if (bytes == null || count <= 0) return true;
            if (count > bytes.Length) throw new ArgumentOutOfRangeException("count");
            lock (OutputGate) {
                if (OutputLimitBytes <= 0 || OutputLimitExceeded) {
                    if (capture != null) { capture.OutputLimitExceeded = true; capture.Signal.Set(); }
                    return false;
                }
                long streamReserved = isStderr ? StderrBytesReserved : StdoutBytesReserved;
                long childReserved = capture == null ? 0 : (isStderr ? capture.StderrBytesReserved : capture.StdoutBytesReserved);
                long childMaximum = capture == null ? 0 : (isStderr ? capture.MaxStderrBytes : capture.MaxStdoutBytes);
                if ((capture != null && childReserved + count > childMaximum) ||
                    streamReserved + count > OutputLimitBytes) {
                    if (capture != null) { capture.OutputLimitExceeded = true; capture.Signal.Set(); }
                    if (streamReserved + count > OutputLimitBytes) OutputLimitExceeded = true;
                    return false;
                }
                if (isStderr) StderrBytesReserved += count; else StdoutBytesReserved += count;
                if (capture != null) {
                    if (isStderr) capture.StderrBytesReserved += count; else capture.StdoutBytesReserved += count;
                }
                IntPtr handle = isStderr ? BoundedStderrHandle : BoundedStdoutHandle;
                GCHandle pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                try {
                    IntPtr address = Marshal.UnsafeAddrOfPinnedArrayElement(bytes, 0);
                    int writtenTotal = 0;
                    while (writtenTotal < count) {
                        uint written;
                        IntPtr next = IntPtr.Add(address, writtenTotal);
                        uint remaining = (uint)(count - writtenTotal);
                        if (!WriteFile(handle, next, remaining, out written, IntPtr.Zero) || written == 0) {
                            OutputLimitExceeded = true;
                            if (capture != null) { capture.ReaderFailed = true; capture.Signal.Set(); }
                            return false;
                        }
                        writtenTotal += (int)written;
                    }
                    return true;
                } finally {
                    pinned.Free();
                }
            }
        }

        private static PipeResource CreateConnectedOutputPipe() {
            PipeResource result = new PipeResource();
            string name = @"\\.\pipe\SafeUpload.HarnessGate." + Guid.NewGuid().ToString("N");
            result.Server = CreateNamedPipe(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1, OUTPUT_CHUNK_BYTES, OUTPUT_CHUNK_BYTES, 0, IntPtr.Zero);
            if (result.Server == IntPtr.Zero || result.Server == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Create private local output pipe");
            }
            if (!SetHandleInformation(result.Server, HANDLE_FLAG_INHERIT, 0)) {
                CloseHandle(result.Server); result.Server = IntPtr.Zero;
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Make parent output pipe non-inheritable");
            }
            IntPtr eventHandle = IntPtr.Zero;
            IntPtr overlappedMemory = IntPtr.Zero;
            bool connectPending = false;
            try {
                eventHandle = CreateEvent(IntPtr.Zero, true, false, null);
                if (eventHandle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Create output-pipe connect event");
                NativeOverlapped overlapped = new NativeOverlapped();
                overlapped.EventHandle = eventHandle;
                overlappedMemory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeOverlapped)));
                Marshal.StructureToPtr(overlapped, overlappedMemory, false);
                bool connected = ConnectNamedPipe(result.Server, overlappedMemory);
                if (!connected) {
                    int error = Marshal.GetLastWin32Error();
                    if (error != (int)ERROR_IO_PENDING && error != (int)ERROR_PIPE_CONNECTED) {
                        throw new Win32Exception(error, "Connect private local output pipe");
                    }
                    if (error == (int)ERROR_PIPE_CONNECTED) SetEvent(eventHandle);
                    else connectPending = true;
                }
                SecurityAttributes security = new SecurityAttributes();
                security.nLength = Marshal.SizeOf(typeof(SecurityAttributes));
                security.bInheritHandle = true;
                result.Client = CreateFile(name, GENERIC_WRITE, 0, ref security, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (result.Client == IntPtr.Zero || result.Client == new IntPtr(-1)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Open private local child output handle");
                }
                if (!SetHandleInformation(result.Client, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Make allow-listed output handle inheritable");
                }
                if (connectPending) {
                    uint transferred;
                    if (!GetOverlappedResult(result.Server, overlappedMemory, out transferred, true)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Complete private local output-pipe connection");
                    }
                    connectPending = false;
                }
                result.Connected = true;
                return result;
            } catch {
                if (connectPending && result.Server != IntPtr.Zero && overlappedMemory != IntPtr.Zero) {
                    CancelIoEx(result.Server, overlappedMemory);
                    uint cancelled = eventHandle == IntPtr.Zero ? WAIT_TIMEOUT : WaitForSingleObject(eventHandle, 1000);
                    if (cancelled == WAIT_OBJECT_0) {
                        uint ignored;
                        GetOverlappedResult(result.Server, overlappedMemory, out ignored, false);
                        connectPending = false;
                    }
                }
                if (!connectPending) {
                    if (result.Client != IntPtr.Zero && result.Client != new IntPtr(-1)) CloseHandle(result.Client);
                    result.Client = IntPtr.Zero;
                    if (result.Server != IntPtr.Zero) CloseHandle(result.Server);
                    result.Server = IntPtr.Zero;
                } else {
                    // Keep the native pipe, event, and OVERLAPPED allocation live until process exit.
                    overlappedMemory = IntPtr.Zero;
                    eventHandle = IntPtr.Zero;
                    result.Server = IntPtr.Zero;
                }
                throw;
            } finally {
                if (overlappedMemory != IntPtr.Zero) Marshal.FreeHGlobal(overlappedMemory);
                if (eventHandle != IntPtr.Zero) CloseHandle(eventHandle);
            }
        }

        private static void ReadBoundedPipe(object value) {
            ReaderState reader = (ReaderState)value;
            IntPtr eventHandle = IntPtr.Zero;
            IntPtr overlappedMemory = IntPtr.Zero;
            byte[] buffer = new byte[OUTPUT_CHUNK_BYTES];
            GCHandle pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            long childExitedAt = 0;
            bool requestOutstanding = false;
            bool nativeResourcesSafeToRelease = true;
            try {
                eventHandle = CreateEvent(IntPtr.Zero, true, false, null);
                if (eventHandle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Create output-pipe read event");
                overlappedMemory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeOverlapped)));
                while (true) {
                    if (WaitForSingleObject(reader.ProcessHandle, 0) == WAIT_OBJECT_0 && childExitedAt == 0) {
                        childExitedAt = Stopwatch.GetTimestamp();
                    }
                    if (childExitedAt != 0 && ElapsedMilliseconds(childExitedAt) >= PIPE_DRAIN_MILLISECONDS) {
                        reader.Capture.ReaderTimedOut = true;
                        return;
                    }
                    if (!ResetEvent(eventHandle)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Reset output-pipe read event");
                    NativeOverlapped overlapped = new NativeOverlapped();
                    overlapped.EventHandle = eventHandle;
                    Marshal.StructureToPtr(overlapped, overlappedMemory, false);
                    IntPtr bufferAddress = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, 0);
                    bool immediate = ReadFile(reader.Pipe.Server, bufferAddress, (uint)buffer.Length, IntPtr.Zero, overlappedMemory);
                    int readError = immediate ? 0 : Marshal.GetLastWin32Error();
                    requestOutstanding = !immediate && readError == (int)ERROR_IO_PENDING;
                    if (!immediate && !requestOutstanding) {
                        if (readError == (int)ERROR_BROKEN_PIPE) return;
                        throw new Win32Exception(readError, "Read private child output pipe");
                    }
                    if (requestOutstanding) {
                        while (true) {
                            uint wait = WaitForSingleObject(eventHandle, 100);
                            if (wait == WAIT_OBJECT_0) break;
                            if (wait != WAIT_TIMEOUT) throw new Win32Exception(Marshal.GetLastWin32Error(), "Wait for child output pipe");
                            if (WaitForSingleObject(reader.ProcessHandle, 0) == WAIT_OBJECT_0 && childExitedAt == 0) {
                                childExitedAt = Stopwatch.GetTimestamp();
                            }
                            if (childExitedAt != 0 && ElapsedMilliseconds(childExitedAt) >= PIPE_DRAIN_MILLISECONDS) {
                                CancelIoEx(reader.Pipe.Server, overlappedMemory);
                                uint cancelled = WaitForSingleObject(eventHandle, 1000);
                                if (cancelled == WAIT_OBJECT_0) {
                                    uint ignored;
                                    GetOverlappedResult(reader.Pipe.Server, overlappedMemory, out ignored, false);
                                    requestOutstanding = false;
                                } else {
                                    nativeResourcesSafeToRelease = false;
                                    reader.Capture.NativeIoOutstanding = true;
                                }
                                reader.Capture.ReaderTimedOut = true;
                                return;
                            }
                        }
                    }
                    uint bytesRead;
                    if (!GetOverlappedResult(reader.Pipe.Server, overlappedMemory, out bytesRead, false)) {
                        int error = Marshal.GetLastWin32Error();
                        requestOutstanding = false;
                        if (error == (int)ERROR_BROKEN_PIPE || error == (int)ERROR_OPERATION_ABORTED) return;
                        throw new Win32Exception(error, "Complete child output-pipe read");
                    }
                    requestOutstanding = false;
                    if (bytesRead == 0) return;
                    int count = (int)bytesRead;
                    if (reader.IsStderr) reader.Capture.SawStderr = true;
                    else if (reader.Capture.T5Probe != null) reader.Capture.T5Probe.Append(buffer, count);
                    if (!TryWriteBounded(reader.IsStderr, buffer, count, reader.Capture)) {
                        reader.Capture.OutputLimitExceeded = true;
                        reader.Capture.Signal.Set();
                        return;
                    }
                }
            } catch (Exception exception) {
                reader.Capture.ReaderFailed = true;
                reader.Capture.ReaderFailure = exception.GetType().Name;
                reader.Capture.Signal.Set();
                if (requestOutstanding && overlappedMemory != IntPtr.Zero) {
                    CancelIoEx(reader.Pipe.Server, overlappedMemory);
                    uint cancelled = eventHandle == IntPtr.Zero ? WAIT_TIMEOUT : WaitForSingleObject(eventHandle, 1000);
                    if (cancelled == WAIT_OBJECT_0) {
                        uint ignored;
                        GetOverlappedResult(reader.Pipe.Server, overlappedMemory, out ignored, false);
                        requestOutstanding = false;
                    }
                    else {
                        nativeResourcesSafeToRelease = false;
                        reader.Capture.NativeIoOutstanding = true;
                    }
                }
            } finally {
                if (nativeResourcesSafeToRelease) {
                    if (pinnedBuffer.IsAllocated) pinnedBuffer.Free();
                    if (overlappedMemory != IntPtr.Zero) Marshal.FreeHGlobal(overlappedMemory);
                    if (eventHandle != IntPtr.Zero) CloseHandle(eventHandle);
                }
            }
        }
        private static IntPtr OpenChildOutput(string path) {
            SecurityAttributes security = new SecurityAttributes();
            security.nLength = Marshal.SizeOf(typeof(SecurityAttributes));
            security.bInheritHandle = true;
            IntPtr handle = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, ref security, CREATE_NEW, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Create child output file");
            return handle;
        }
        private static IntPtr OpenNullInput() {
            SecurityAttributes security = new SecurityAttributes();
            security.nLength = Marshal.SizeOf(typeof(SecurityAttributes));
            security.bInheritHandle = true;
            IntPtr handle = CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref security, OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Open NUL input");
            return handle;
        }

        public static IntPtr CreateKillOnCloseJob(string name) {
            SetLastError(0);
            IntPtr job = CreateJobObject(IntPtr.Zero, name);
            int createError = Marshal.GetLastWin32Error();
            if (job == IntPtr.Zero) throw new Win32Exception(createError, "CreateJobObject");
            if (createError == 183) { CloseHandle(job); throw new InvalidOperationException("Named job already exists."); }
            ExtendedLimitInformation limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
            IntPtr memory = Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(limits, memory, false);
                Check(SetInformationJobObject(job, 9, memory, (uint)size), "SetInformationJobObject");
                uint returned;
                Check(QueryInformationJobObject(job, 9, memory, (uint)size, out returned), "Verify exact kill-on-close job limits");
                ExtendedLimitInformation observed = (ExtendedLimitInformation)Marshal.PtrToStructure(
                    memory, typeof(ExtendedLimitInformation));
                if (returned < (uint)size || observed.BasicLimitInformation.LimitFlags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) {
                    throw new InvalidOperationException("Named job did not retain the exact kill-on-close-only configuration.");
                }
            } catch { CloseHandle(job); throw; }
            finally { Marshal.FreeHGlobal(memory); }
            return job;
        }
        public static IntPtr OpenNamedJob(string name, out int error) {
            IntPtr job = OpenJobObject(0x0001 | 0x0004 | 0x0008, false, name);
            error = job == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
            return job;
        }
        public static uint ActiveProcessCount(IntPtr job) {
            BasicAccountingInformation info;
            uint returned;
            Check(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(BasicAccountingInformation)), out returned), "QueryInformationJobObject");
            return info.ActiveProcesses;
        }
        public static void VerifyKillOnCloseJob(IntPtr job) {
            if (job == IntPtr.Zero || job == new IntPtr(-1)) throw new ArgumentException("Exact job handle is required.");
            int size = Marshal.SizeOf(typeof(ExtendedLimitInformation));
            IntPtr memory = Marshal.AllocHGlobal(size);
            try {
                uint returned;
                Check(QueryInformationJobObject(job, 9, memory, (uint)size, out returned), "Query exact job limits");
                ExtendedLimitInformation limits = (ExtendedLimitInformation)Marshal.PtrToStructure(memory, typeof(ExtendedLimitInformation));
                if (returned < (uint)size || limits.BasicLimitInformation.LimitFlags != JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) {
                    throw new InvalidOperationException("Named job limit flags differ from the exact kill-on-close-only configuration.");
                }
            } finally { Marshal.FreeHGlobal(memory); }
        }
        public static bool IsProcessHandleInJob(IntPtr process, IntPtr job) {
            if (process == IntPtr.Zero || job == IntPtr.Zero) throw new ArgumentException("Exact process and job handles are required.");
            bool member;
            Check(IsProcessInJob(process, job, out member), "Verify exact process-handle job membership");
            return member;
        }
        public static ChildProcess OpenExactProcessHandle(uint processId, long expectedStart) {
            int error;
            bool exact;
            IntPtr process = OpenExactProcess(processId, expectedStart, out error, out exact);
            if (process == IntPtr.Zero) {
                if (error == 0 && !exact) throw new InvalidOperationException("Process creation FILETIME differs from the expected exact identity.");
                throw new Win32Exception(error, "Open exact process identity");
            }
            ChildProcess result = new ChildProcess();
            result.ProcessHandle = process;
            result.ProcessId = processId;
            result.StartFileTime = expectedStart;
            return result;
        }
        public static ChildProcess OpenExactProcessFromJob(uint processId, IntPtr job) {
            int error;
            IntPtr process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, processId);
            error = process == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
            if (process == IntPtr.Zero) throw new Win32Exception(error, "Open exact job-listed process");
            try {
                FileTime creation, exit, kernel, user;
                Check(GetProcessTimes(process, out creation, out exit, out kernel, out user), "Read job-listed process creation FILETIME");
                bool member;
                Check(IsProcessInJob(process, job, out member), "Verify job-listed process membership");
                if (!member) throw new InvalidOperationException("Job PID list and native process membership disagree.");
                ChildProcess result = new ChildProcess();
                result.ProcessHandle = process;
                result.ProcessId = processId;
                result.StartFileTime = ToLong(creation);
                return result;
            } catch { CloseHandle(process); throw; }
        }
        public static uint[] ExactJobProcessIds(IntPtr job) {
            if (job == IntPtr.Zero || job == new IntPtr(-1)) throw new ArgumentException("Exact job handle is required.");
            const int capacity = 256;
            const int headerBytes = 8;
            int bufferBytes = headerBytes + capacity * IntPtr.Size;
            IntPtr memory = Marshal.AllocHGlobal(bufferBytes);
            try {
                for (int offset = 0; offset < bufferBytes; offset += IntPtr.Size) {
                    Marshal.WriteIntPtr(memory, offset, IntPtr.Zero);
                }
                uint returned;
                Check(QueryInformationJobObject(job, 3, memory, (uint)bufferBytes, out returned),
                    "Query exact job process ID list");
                uint assigned = unchecked((uint)Marshal.ReadInt32(memory, 0));
                uint available = unchecked((uint)Marshal.ReadInt32(memory, 4));
                if (assigned != available || available > capacity) {
                    throw new InvalidOperationException("Exact job process ID list was incomplete; membership remains unknown.");
                }
                uint[] ids = new uint[(int)available];
                for (int index = 0; index < ids.Length; index++) {
                    long value = Marshal.ReadIntPtr(memory, headerBytes + index * IntPtr.Size).ToInt64();
                    if (value <= 0 || value > UInt32.MaxValue) throw new InvalidOperationException("Exact job returned an invalid process ID.");
                    ids[index] = (uint)value;
                }
                return ids;
            } finally {
                Marshal.FreeHGlobal(memory);
            }
        }
        public static bool IsExactProcessInJob(uint processId, long expectedStart, IntPtr job) {
            int error;
            bool exact;
            IntPtr process = OpenExactProcess(processId, expectedStart, out error, out exact);
            if (process == IntPtr.Zero) {
                if (error == 0 && !exact) return false;
                throw new Win32Exception(error, "Open exact process for job membership verification");
            }
            try {
                bool member;
                Check(IsProcessInJob(process, job, out member), "Verify exact process membership in named job");
                return member;
            } finally {
                CloseHandle(process);
            }
        }
        public static void TerminateJob(IntPtr job, uint exitCode) {
            Check(TerminateJobObject(job, exitCode), "TerminateJobObject");
        }
        public static void Close(IntPtr handle) {
            if (handle != IntPtr.Zero) Check(CloseHandle(handle), "CloseHandle");
        }
        private static ProcessInformation CreateSuspendedProcess(string executable, string[] arguments, string currentDirectory,
            IntPtr stdin, IntPtr stdout, IntPtr stderr, IntPtr[] extraInheritedHandles, IntPtr[] jobList, string operation,
            out int inheritFlagRestoreError) {
            inheritFlagRestoreError = 0;
            int extraCount = extraInheritedHandles == null ? 0 : extraInheritedHandles.Length;
            IntPtr[] inherited = new IntPtr[3 + extraCount];
            inherited[0] = stdin;
            inherited[1] = stdout;
            inherited[2] = stderr;
            for (int index = 0; index < extraCount; index++) inherited[3 + index] = extraInheritedHandles[index];
            AttributeListResources attributes = CreateHandleAttributeList(inherited, jobList);
            ProcessInformation process = new ProcessInformation();
            try {
                StartupInfoEx startup = new StartupInfoEx();
                startup.StartupInfo.cb = (uint)Marshal.SizeOf(typeof(StartupInfoEx));
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = stdin;
                startup.StartupInfo.hStdOutput = stdout;
                startup.StartupInfo.hStdError = stderr;
                startup.AttributeList = attributes.AttributeList;
                StringBuilder command = new StringBuilder(QuoteArgument(executable));
                foreach (string argument in arguments) { command.Append(' '); command.Append(QuoteArgument(argument)); }
                Check(CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero, currentDirectory, ref startup, out process), operation);
                return process;
            } finally {
                attributes.Release();
                inheritFlagRestoreError = attributes.RestoreError;
            }
        }
        public static ChildProcess StartSuspendedInJob(IntPtr job, string executable, string[] arguments, string currentDirectory,
            string stdoutPath, string stderrPath) {
            return StartSuspendedInJob(job, executable, arguments, currentDirectory, stdoutPath, stderrPath, new IntPtr[0]);
        }
        public static ChildProcess StartSuspendedInJob(IntPtr job, string executable, string[] arguments, string currentDirectory,
            string stdoutPath, string stderrPath, IntPtr[] additionalInheritedJobHandles) {
            IntPtr stdout = IntPtr.Zero, stderr = IntPtr.Zero, stdin = IntPtr.Zero;
            ProcessInformation process = new ProcessInformation();
            bool created = false;
            int inheritFlagRestoreError = 0;
            try {
                stdout = OpenChildOutput(stdoutPath);
                stderr = OpenChildOutput(stderrPath);
                stdin = OpenNullInput();
                int additionalCount = additionalInheritedJobHandles == null ? 0 : additionalInheritedJobHandles.Length;
                IntPtr[] inheritedJobs = new IntPtr[1 + additionalCount];
                inheritedJobs[0] = job;
                if (additionalCount != 0) Array.Copy(additionalInheritedJobHandles, 0, inheritedJobs, 1, additionalCount);
                process = CreateSuspendedProcess(executable, arguments, currentDirectory, stdin, stdout, stderr,
                    inheritedJobs, new IntPtr[] { job },
                    "CreateProcess suspended worker with exact creation-time job and explicit handle allow-list",
                    out inheritFlagRestoreError);
                created = true;
                bool inExpectedJob;
                Check(IsProcessInJob(process.hProcess, job, out inExpectedJob), "Verify suspended worker creation-time job membership");
                if (!inExpectedJob) throw new InvalidOperationException("Suspended worker was not created inside the exact diagnostic job.");
                FileTime creation, exit, kernel, user;
                Check(GetProcessTimes(process.hProcess, out creation, out exit, out kernel, out user), "GetProcessTimes child");
                if (inheritFlagRestoreError != 0) {
                    if (!TerminateProcess(process.hProcess, 0xe506)) {
                        int terminateError = Marshal.GetLastWin32Error();
                        if (WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0) {
                            throw new Win32Exception(terminateError, "Terminate child after inherited-handle restoration failure");
                        }
                    }
                    if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) {
                        throw new InvalidOperationException("Could not prove child terminal after inherited-handle restoration failure.");
                    }
                    throw new Win32Exception(inheritFlagRestoreError, "Restore inherited-handle flags after suspended child creation");
                }
                ChildProcess result = new ChildProcess();
                result.ProcessHandle = process.hProcess;
                result.ThreadHandle = process.hThread;
                result.ProcessId = process.dwProcessId;
                result.StartFileTime = ToLong(creation);
                process.hProcess = IntPtr.Zero;
                process.hThread = IntPtr.Zero;
                return result;
            } catch {
                if (created && process.hProcess != IntPtr.Zero) {
                    if (!TerminateProcess(process.hProcess, 0xe501) && Marshal.GetLastWin32Error() != 5) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Terminate suspended worker after launch failure");
                    }
                    uint stopped = WaitForSingleObject(process.hProcess, 5000);
                    if (stopped != WAIT_OBJECT_0) {
                        throw new InvalidOperationException("Failed to prove the suspended worker process terminal after launch failure.");
                    }
                }
                throw;
            } finally {
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                if (stdin != IntPtr.Zero) CloseHandle(stdin);
                if (stdout != IntPtr.Zero) CloseHandle(stdout);
                if (stderr != IntPtr.Zero) CloseHandle(stderr);
            }
        }
        public static void ResumeChild(ChildProcess child) {
            if (child == null || child.ProcessHandle == IntPtr.Zero || child.ThreadHandle == IntPtr.Zero) {
                throw new ArgumentException("A live suspended child process and thread handle are required.");
            }
            uint previousCount = ResumeThread(child.ThreadHandle);
            if (previousCount == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread exact child");
            if (previousCount != 1) throw new InvalidOperationException("Child thread was not in the expected single suspended state.");
        }
        public static bool TerminateAndWait(ChildProcess child, uint exitCode, uint timeoutMilliseconds) {
            if (child == null || child.ProcessHandle == IntPtr.Zero) throw new ArgumentException("Exact process handle is required.");
            uint existing = WaitForSingleObject(child.ProcessHandle, 0);
            if (existing == WAIT_OBJECT_0) return true;
            if (existing != WAIT_TIMEOUT) throw new Win32Exception(Marshal.GetLastWin32Error(), "Check exact child before termination");
            if (!TerminateProcess(child.ProcessHandle, exitCode)) {
                int error = Marshal.GetLastWin32Error();
                if (error != 5) throw new Win32Exception(error, "Terminate exact child process");
            }
            return WaitForSingleObject(child.ProcessHandle, timeoutMilliseconds) == WAIT_OBJECT_0;
        }
        public static bool IsExactChildInJob(ChildProcess child, IntPtr job) {
            if (child == null || child.ProcessHandle == IntPtr.Zero || job == IntPtr.Zero) throw new ArgumentException("Exact child and job handles are required.");
            bool inJob;
            Check(IsProcessInJob(child.ProcessHandle, job, out inJob), "Verify exact process job membership");
            return inJob;
        }
        public static bool CurrentProcessInJob(IntPtr job) {
            if (job == IntPtr.Zero || job == new IntPtr(-1)) throw new ArgumentException("Exact job handle is required.");
            bool inJob;
            Check(IsProcessInJob(GetCurrentProcess(), job, out inJob), "Verify current process membership in exact job");
            return inJob;
        }
        public static void CloseChild(ChildProcess child) {
            if (child == null) return;
            if (child.ThreadHandle != IntPtr.Zero) { CloseHandle(child.ThreadHandle); child.ThreadHandle = IntPtr.Zero; }
            if (child.ProcessHandle != IntPtr.Zero) { CloseHandle(child.ProcessHandle); child.ProcessHandle = IntPtr.Zero; }
        }
        public static BoundedChildResult RunBoundedChild(string executable, string[] arguments, string currentDirectory,
            string runToken, long maximumPerChildStreamBytes, int timeoutMilliseconds, bool probeT5Sentinel) {
            if (String.IsNullOrEmpty(runToken) || maximumPerChildStreamBytes <= 0 || timeoutMilliseconds <= 0) {
                throw new ArgumentException("Bounded child identity, output, and deadline parameters are required.");
            }
            IntPtr job = IntPtr.Zero, stdin = IntPtr.Zero;
            PipeResource stdoutPipe = null, stderrPipe = null;
            ProcessInformation process = new ProcessInformation();
            ReaderState stdoutReader = null, stderrReader = null;
            bool processCreated = false;
            bool processTerminal = false;
            bool readersTerminal = false;
            bool retainPipeResources = false;
            int inheritFlagRestoreError = 0;
            ChildCapture capture = new ChildCapture(maximumPerChildStreamBytes, maximumPerChildStreamBytes, probeT5Sentinel);
            BoundedChildResult result = new BoundedChildResult();
            try {
                string jobName = "Global\\SafeUpload.HarnessGate." + runToken;
                int jobError;
                job = OpenNamedJob(jobName, out jobError);
                if (job == IntPtr.Zero) throw new Win32Exception(jobError, "Open the exact diagnostic job for child containment");
                stdoutPipe = CreateConnectedOutputPipe();
                stderrPipe = CreateConnectedOutputPipe();
                stdin = OpenNullInput();
                process = CreateSuspendedProcess(executable, arguments, currentDirectory,
                    stdin, stdoutPipe.Client, stderrPipe.Client, new IntPtr[0], new IntPtr[] { job },
                    "CreateProcess diagnostic child with bounded output pipes, exact job membership, and explicit handle allow-list",
                    out inheritFlagRestoreError);
                processCreated = true;
                if (inheritFlagRestoreError != 0) {
                    if (!TerminateProcess(process.hProcess, 0xe506) && WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "Terminate diagnostic child after inherited-handle restoration failure");
                    }
                    if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) {
                        throw new InvalidOperationException("Could not prove diagnostic child terminal after inherited-handle restoration failure.");
                    }
                    throw new Win32Exception(inheritFlagRestoreError, "Restore inherited-handle flags after diagnostic child creation");
                }
                FileTime creation, exit, kernel, user;
                Check(GetProcessTimes(process.hProcess, out creation, out exit, out kernel, out user), "GetProcessTimes diagnostic child");
                bool inExpectedJob;
                Check(IsProcessInJob(process.hProcess, job, out inExpectedJob), "Verify diagnostic child job membership");
                if (!inExpectedJob) throw new InvalidOperationException("Diagnostic child did not inherit the exact active job.");

                CloseHandle(stdin); stdin = IntPtr.Zero;
                CloseHandle(stdoutPipe.Client); stdoutPipe.Client = IntPtr.Zero;
                CloseHandle(stderrPipe.Client); stderrPipe.Client = IntPtr.Zero;

                stdoutReader = new ReaderState();
                stdoutReader.Pipe = stdoutPipe;
                stdoutReader.Capture = capture;
                stdoutReader.ProcessHandle = process.hProcess;
                stdoutReader.IsStderr = false;
                stdoutReader.Thread = new Thread(new ParameterizedThreadStart(ReadBoundedPipe));
                stdoutReader.Thread.IsBackground = true;
                stdoutReader.Thread.Start(stdoutReader);
                stderrReader = new ReaderState();
                stderrReader.Pipe = stderrPipe;
                stderrReader.Capture = capture;
                stderrReader.ProcessHandle = process.hProcess;
                stderrReader.IsStderr = true;
                stderrReader.Thread = new Thread(new ParameterizedThreadStart(ReadBoundedPipe));
                stderrReader.Thread.IsBackground = true;
                stderrReader.Thread.Start(stderrReader);

                uint resume = ResumeThread(process.hThread);
                if (resume == 0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error(), "Resume diagnostic child");
                CloseHandle(process.hThread); process.hThread = IntPtr.Zero;

                Stopwatch deadline = Stopwatch.StartNew();
                bool mustStop = false;
                while (true) {
                    if (capture.OutputLimitExceeded || capture.ReaderFailed || HasOutputLimitExceeded()) {
                        mustStop = true;
                    }
                    if (mustStop) {
                        TerminateExactProcess(process.hProcess, 0xe501);
                        uint stopped = WaitForSingleObject(process.hProcess, 5000);
                        if (stopped != WAIT_OBJECT_0) throw new InvalidOperationException("Output-overflow child did not become terminal on its pinned handle.");
                        processTerminal = true;
                        break;
                    }
                    uint wait = WaitForSingleObject(process.hProcess, 100);
                    if (wait == WAIT_OBJECT_0) { processTerminal = true; break; }
                    if (wait != WAIT_TIMEOUT) throw new Win32Exception(Marshal.GetLastWin32Error(), "Wait for diagnostic child process handle");
                    if (deadline.ElapsedMilliseconds >= timeoutMilliseconds) {
                        capture.ReaderTimedOut = true;
                        TerminateExactProcess(process.hProcess, 0xe502);
                        uint stopped = WaitForSingleObject(process.hProcess, 5000);
                        if (stopped != WAIT_OBJECT_0) throw new InvalidOperationException("Timed-out diagnostic child did not become terminal on its pinned handle.");
                        processTerminal = true;
                        break;
                    }
                }

                bool stdoutJoined = stdoutReader.Thread.Join(PIPE_DRAIN_MILLISECONDS + 1200);
                bool stderrJoined = stderrReader.Thread.Join(PIPE_DRAIN_MILLISECONDS + 1200);
                readersTerminal = stdoutJoined && stderrJoined && !capture.NativeIoOutstanding;
                if (!readersTerminal) {
                    capture.ReaderTimedOut = true;
                    retainPipeResources = true;
                }
                result.ProcessTerminal = processTerminal && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0;
                result.ReadersTerminal = readersTerminal;
                result.ExitCode = ExitCode(new ChildProcess { ProcessHandle = process.hProcess });
                result.StdoutBytes = capture.StdoutBytesReserved;
                result.StderrBytes = capture.StderrBytesReserved;
                result.OutputLimitExceeded = capture.OutputLimitExceeded || HasOutputLimitExceeded();
                result.ReaderFailed = capture.ReaderFailed;
                result.ReaderTimedOut = capture.ReaderTimedOut;
                result.SawStderr = capture.SawStderr;
                result.T5SentinelComplete = capture.T5Probe != null && capture.T5Probe.IsComplete();
                result.Success = result.ProcessTerminal && result.ReadersTerminal && !result.OutputLimitExceeded &&
                    !result.ReaderFailed && !result.ReaderTimedOut && !result.SawStderr && result.ExitCode == 0 &&
                    (!probeT5Sentinel || result.T5SentinelComplete);
                return result;
            } catch {
                if (processCreated && process.hProcess != IntPtr.Zero) {
                    try {
                        TerminateExactProcess(process.hProcess, 0xe503);
                        processTerminal = WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0;
                    } catch { processTerminal = false; }
                }
                if (stdoutReader != null && stdoutReader.Thread != null && stdoutReader.Thread.IsAlive) {
                    CancelIoEx(stdoutReader.Pipe.Server, IntPtr.Zero);
                    if (!stdoutReader.Thread.Join(1000)) retainPipeResources = true;
                }
                if (stderrReader != null && stderrReader.Thread != null && stderrReader.Thread.IsAlive) {
                    CancelIoEx(stderrReader.Pipe.Server, IntPtr.Zero);
                    if (!stderrReader.Thread.Join(1000)) retainPipeResources = true;
                }
                if (capture.NativeIoOutstanding) retainPipeResources = true;
                throw;
            } finally {
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero && !retainPipeResources) CloseHandle(process.hProcess);
                if (stdin != IntPtr.Zero) CloseHandle(stdin);
                if (job != IntPtr.Zero) CloseHandle(job);
                if (!retainPipeResources) {
                    ClosePipeResource(stdoutPipe);
                    ClosePipeResource(stderrPipe);
                    capture.Signal.Close();
                }
            }
        }
        private static void ClosePipeResource(PipeResource pipe) {
            if (pipe == null) return;
            if (pipe.Client != IntPtr.Zero && pipe.Client != new IntPtr(-1)) CloseHandle(pipe.Client);
            if (pipe.Server != IntPtr.Zero && pipe.Server != new IntPtr(-1)) CloseHandle(pipe.Server);
            pipe.Client = IntPtr.Zero;
            pipe.Server = IntPtr.Zero;
        }
        public static uint Wait(ChildProcess child, uint milliseconds) {
            return WaitForSingleObject(child.ProcessHandle, milliseconds);
        }
        public static IntPtr OpenExactProcess(uint processId, long expectedStart, out int error, out bool exact) {
            IntPtr handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false, processId);
            error = handle == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
            exact = false;
            if (handle == IntPtr.Zero) return IntPtr.Zero;
            try {
                FileTime creation, exit, kernel, user;
                Check(GetProcessTimes(handle, out creation, out exit, out kernel, out user), "GetProcessTimes exact process");
                if (ToLong(creation) != expectedStart) { CloseHandle(handle); return IntPtr.Zero; }
                exact = true;
                return handle;
            } catch { CloseHandle(handle); throw; }
        }
        public static void TerminateExactProcess(IntPtr process, uint exitCode) {
            if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return;
            if (!TerminateProcess(process, exitCode)) {
                int error = Marshal.GetLastWin32Error();
                if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) return;
                throw new Win32Exception(error, "TerminateProcess exact process handle");
            }
        }
        public static uint WaitHandle(IntPtr process, uint milliseconds) {
            return WaitForSingleObject(process, milliseconds);
        }
        public static uint ExitCode(ChildProcess child) {
            uint code;
            Check(GetExitCodeProcess(child.ProcessHandle, out code), "GetExitCodeProcess");
            return code;
        }
    }
}
'@
    Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
}

$script:HarnessGateBuilderName = 'DESKTOP-O1LP5DG'
$script:HarnessGateBuilderUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$script:HarnessGateBuilderMac = '52-54-00-63-87-7A'
$script:HarnessGateVikaSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$script:HarnessGateManifestLeaf = 'HarnessWindowsGate.manifest.json'
$script:HarnessGateRunnerLeaf = 'HarnessWindowsGateRemote.ps1'
$script:HarnessGateWorkerLeaf = 'HarnessWindowsGateWorker.ps1'
$script:HarnessGateKeeperLeaf = 'HarnessWindowsGateLeaseKeeper.ps1'
$script:HarnessGateFixtureLeaf = 'HarnessWindowsGateLifecycleFixture.ps1'
$script:HarnessGateControlLeaf = 'HarnessWindowsGateRemoteControl.ps1'
$script:HarnessGateProtocolLeaf = 'HarnessWindowsGateProtocol.psm1'

function Assert-HarnessGateEnvironment {
    if ($env:COMPUTERNAME -cne $script:HarnessGateBuilderName -or
        (Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 10).UUID -ine $script:HarnessGateBuilderUuid -or
        -not @(Get-NetAdapter | Where-Object { $_.MacAddress -ieq $script:HarnessGateBuilderMac }).Count) {
        throw 'Required builder name, UUID, or MAC does not match.'
    }
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
        $PSVersionTable.PSEdition -cne 'Desktop' -or -not [Environment]::Is64BitProcess) {
        throw 'Windows PowerShell 5.1 Desktop x64 is required.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -cne $script:HarnessGateVikaSid -or $identity.IsSystem -or
        $env:USERPROFILE -ine 'C:\Users\vika') {
        throw 'The ordinary Vika identity is required.'
    }
}

function Assert-HarnessGateFiles {
    param(
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$ExpectedManifestSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedRunnerSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkerSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedKeeperSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedFixtureSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedControlSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedProtocolSha256
    )
    $destination = Get-Item -LiteralPath $DestinationPath -ErrorAction Stop
    if (-not $destination.PSIsContainer -or ($destination.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Gate destination is not a plain directory.'
    }
    $manifestPath = Join-Path $DestinationPath $script:HarnessGateManifestLeaf
    $manifestItem = Get-Item -LiteralPath $manifestPath -ErrorAction Stop
    if ($manifestItem.PSIsContainer -or ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Manifest is not a plain file.'
    }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedManifestSha256) {
        throw 'Manifest SHA-256 differs from the gate pin.'
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.schema -cne 'safeupload-harness-windows-gate-v1' -or
        $manifest.builder.computerName -cne $script:HarnessGateBuilderName -or
        $manifest.builder.uuid -ine $script:HarnessGateBuilderUuid -or
        $manifest.builder.macAddress -ine '52:54:00:63:87:7a' -or
        $manifest.builder.userSid -cne $script:HarnessGateVikaSid -or
        $manifest.powershell.version -cne '5.1' -or $manifest.powershell.edition -cne 'Desktop' -or
        $manifest.powershell.architecture -cne 'x64' -or
        $manifest.gateRunner.path -cne $script:HarnessGateRunnerLeaf -or
        $manifest.gateWorker.path -cne $script:HarnessGateWorkerLeaf -or
        $manifest.gateKeeper.path -cne $script:HarnessGateKeeperLeaf -or
        $manifest.gateFixture.path -cne $script:HarnessGateFixtureLeaf -or
        $manifest.gateControl.path -cne $script:HarnessGateControlLeaf -or
        $manifest.gateProtocol.path -cne $script:HarnessGateProtocolLeaf -or
        $manifest.gateRunner.sha256 -cne $ExpectedRunnerSha256 -or
        $manifest.gateWorker.sha256 -cne $ExpectedWorkerSha256 -or
        $manifest.gateKeeper.sha256 -cne $ExpectedKeeperSha256 -or
        $manifest.gateFixture.sha256 -cne $ExpectedFixtureSha256 -or
        $manifest.gateControl.sha256 -cne $ExpectedControlSha256 -or
        $manifest.gateProtocol.sha256 -cne $ExpectedProtocolSha256) {
        throw 'Manifest environment or support-file identity differs from the gate pins.'
    }

    $main = @($manifest.mainFiles)
    $rootChecks = @($manifest.rootSelfchecks)
    $t5 = [string]$manifest.t5Selfcheck
    $records = @($manifest.sourceFiles)
    if ($main.Count -ne 15 -or $rootChecks.Count -ne 17 -or
        $t5 -cne 't5/notepad-coordinator.SelfCheck.ps1' -or $records.Count -ne 33) {
        throw 'Manifest inventory counts differ from the closed review set.'
    }
    $expectedSources = @($main) + @($rootChecks) + @($t5)
    $paths = @(); $hashes = @{}
    foreach ($record in $records) {
        $relative = [string]$record.path
        $digest = [string]$record.sha256
        if ($relative -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or $relative.Contains('..') -or
            $relative.Contains('\') -or $digest -cnotmatch '^[0-9a-f]{64}$' -or $hashes.ContainsKey($relative)) {
            throw 'Manifest contains an unsafe, duplicate, or malformed source record.'
        }
        $paths += $relative; $hashes[$relative] = $digest
    }
    if ($paths.Count -ne 33 -or $expectedSources.Count -ne 33) { throw 'Closed source list is incomplete.' }
    foreach ($relative in $expectedSources) {
        if (-not ($paths -ccontains [string]$relative)) { throw ('Manifest omits reviewed source: ' + $relative) }
    }
    foreach ($relative in $paths) {
        if (-not ($expectedSources -ccontains $relative)) { throw ('Manifest adds unreviewed source: ' + $relative) }
    }

    $supportRecords = @(
        @{ Path = $script:HarnessGateRunnerLeaf; Hash = $ExpectedRunnerSha256 },
        @{ Path = $script:HarnessGateWorkerLeaf; Hash = $ExpectedWorkerSha256 },
        @{ Path = $script:HarnessGateKeeperLeaf; Hash = $ExpectedKeeperSha256 },
        @{ Path = $script:HarnessGateFixtureLeaf; Hash = $ExpectedFixtureSha256 },
        @{ Path = $script:HarnessGateControlLeaf; Hash = $ExpectedControlSha256 },
        @{ Path = $script:HarnessGateProtocolLeaf; Hash = $ExpectedProtocolSha256 }
    )
    $expectedFiles = @($expectedSources) + $script:HarnessGateManifestLeaf + @($supportRecords | ForEach-Object { $_.Path })
    $expectedDirectories = @('t4', 't6', 't10', 't5')
    $actual = @(Get-ChildItem -LiteralPath $DestinationPath -Force -Recurse -ErrorAction Stop)
    $actualFiles = @(); $actualDirectories = @()
    foreach ($item in $actual) {
        $relative = $item.FullName.Substring(($DestinationPath.TrimEnd('\')).Length + 1).Replace('\', '/')
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Reparse point in gate tree: ' + $relative) }
        if ($item.PSIsContainer) { $actualDirectories += $relative } else { $actualFiles += $relative }
    }
    if ($actualFiles.Count -ne 40 -or $actualDirectories.Count -ne 4) { throw 'Remote membership count is not exact.' }
    foreach ($relative in $actualFiles) { if (-not ($expectedFiles -ccontains $relative)) { throw ('Unreviewed remote file: ' + $relative) } }
    foreach ($relative in $expectedFiles) { if (-not ($actualFiles -ccontains $relative)) { throw ('Missing remote file: ' + $relative) } }
    foreach ($relative in $actualDirectories) { if (-not ($expectedDirectories -ccontains $relative)) { throw ('Unreviewed remote directory: ' + $relative) } }
    foreach ($relative in $expectedDirectories) { if (-not ($actualDirectories -ccontains $relative)) { throw ('Missing remote directory: ' + $relative) } }

    foreach ($record in $records) {
        $relative = [string]$record.path
        $path = Join-Path $DestinationPath $relative.Replace('/', '\')
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Source is not a plain file: ' + $relative) }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$record.sha256) { throw ('Source SHA-256 mismatch: ' + $relative) }
    }
    foreach ($support in $supportRecords) {
        $path = Join-Path $DestinationPath $support.Path
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Support is not a plain file: ' + $support.Path) }
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $support.Hash) { throw ('Support SHA-256 mismatch: ' + $support.Path) }
    }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedManifestSha256) { throw 'Manifest changed while verifying the remote tree.' }
    return $manifest
}

function Get-HarnessGateJobName([string]$RunToken) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParseExact($RunToken, 'D', [ref]$guid) -or $guid.ToString() -cne $RunToken) { throw 'Run token is not a canonical GUID.' }
    return ('Global\SafeUpload.HarnessGate.' + $RunToken)
}

function Get-HarnessGateKeeperJobName([string]$RunToken) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParseExact($RunToken, 'D', [ref]$guid) -or $guid.ToString() -cne $RunToken) { throw 'Run token is not a canonical GUID.' }
    return ('Global\SafeUpload.HarnessGate.Lease.' + $RunToken)
}

function Get-HarnessGateLifecycleMutexName([string]$RunToken) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParseExact($RunToken, 'D', [ref]$guid) -or $guid.ToString() -cne $RunToken) {
        throw 'Run token is not canonical for lifecycle mutex.'
    }
    return ('Global\SafeUpload.HarnessGate.Lifecycle.' + $RunToken)
}

function Enter-HarnessGateLifecycleMutex([string]$RunToken, [int]$TimeoutMilliseconds = 15000) {
    if ($TimeoutMilliseconds -le 0 -or $TimeoutMilliseconds -gt 120000) {
        throw 'Lifecycle mutex wait must be within the fixed bounded interval.'
    }
    $name = Get-HarnessGateLifecycleMutexName $RunToken
    $mutex = [Threading.Mutex]::new($false, $name)
    $acquired = $false
    $abandoned = $false
    try {
        try {
            $acquired = $mutex.WaitOne($TimeoutMilliseconds)
        } catch [Threading.AbandonedMutexException] {
            # The caller owns the mutex now, but the prior critical-section proof is lost.
            $acquired = $true
            $abandoned = $true
        }
        if (-not $acquired) { throw 'Timed out waiting for the exact per-run lifecycle mutex.' }
        return ,([pscustomobject]@{
            Name = $name
            Mutex = $mutex
            Acquired = $true
            Abandoned = $abandoned
            OwnerThreadId = [Threading.Thread]::CurrentThread.ManagedThreadId
            Released = $false
        })
    } catch {
        if ($acquired) { try { $mutex.ReleaseMutex() } catch { } }
        $mutex.Dispose()
        throw
    }
}

function Exit-HarnessGateLifecycleMutex($Lease) {
    if ($null -eq $Lease -or -not $Lease.Acquired -or $Lease.Released) { return }
    if ([Threading.Thread]::CurrentThread.ManagedThreadId -ne [int]$Lease.OwnerThreadId) {
        throw 'Lifecycle mutex must be released by the thread that acquired it.'
    }
    try {
        $Lease.Mutex.ReleaseMutex()
        $Lease.Released = $true
    } finally {
        $Lease.Mutex.Dispose()
    }
}

function Write-HarnessGateBoundedBytes($Budget, $Stream, [byte[]]$Bytes, [int]$Count, [bool]$ToError, [bool]$Metadata) {
    if ($null -eq $Budget -or $null -eq $Stream -or $null -eq $Bytes -or $Count -lt 0 -or $Count -gt $Bytes.Length) {
        throw 'Bounded output write arguments are invalid.'
    }
    $byteKey = if ($ToError) { 'StderrBytes' } else { 'StdoutBytes' }
    $metadataKey = if ($ToError) { 'StderrMetadataBytes' } else { 'StdoutMetadataBytes' }
    $failedKey = if ($ToError) { 'StderrWriteFailed' } else { 'StdoutWriteFailed' }
    if ([bool]$Budget[$failedKey]) { throw ('Bounded output stream is already failed: ' + $byteKey) }
    if ([long]$Budget[$byteKey] + $Count -gt [long]$Budget['MaximumStreamBytes']) {
        throw ('Bounded output stream limit exceeded: ' + $byteKey)
    }
    if ($Metadata -and [long]$Budget[$metadataKey] + $Count -gt [long]$Budget['MaximumMetadataBytes']) {
        throw ('Bounded output metadata reserve exceeded: ' + $metadataKey)
    }
    # Commit the full attempted chunk before Write or Flush. Exceptions never refund it.
    $Budget[$byteKey] = [long]$Budget[$byteKey] + $Count
    if ($Metadata) { $Budget[$metadataKey] = [long]$Budget[$metadataKey] + $Count }
    try {
        if ($Count -gt 0) { $Stream.Write($Bytes, 0, $Count); $Stream.Flush() }
    } catch {
        $Budget[$failedKey] = $true
        throw
    }
}

function Get-HarnessGateStateRoot {
    $fixedAncestors = @(
        'C:\Users\vika',
        'C:\Users\vika\AppData',
        'C:\Users\vika\AppData\Local',
        'C:\Users\vika\AppData\Local\Temp'
    )
    foreach ($ancestor in $fixedAncestors) {
        $ancestorItem = Get-Item -LiteralPath $ancestor -ErrorAction Stop
        if (-not $ancestorItem.PSIsContainer -or ($ancestorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('Gate state ancestor is not a plain directory: ' + $ancestor)
        }
    }
    $root = 'C:\Users\vika\AppData\Local\Temp\SafeUpload-HarnessGate'
    if (-not (Test-Path -LiteralPath $root)) { $null = New-Item -ItemType Directory -Path $root -ErrorAction Stop }
    $item = Get-Item -LiteralPath $root -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Gate state root is not a plain directory.' }
    return $root
}

function Get-HarnessGateStatePath([string]$RunToken) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParseExact($RunToken, 'D', [ref]$guid) -or $guid.ToString() -cne $RunToken) { throw 'Run token is not canonical for state path.' }
    return (Join-Path (Get-HarnessGateStateRoot) ($RunToken + '.json'))
}

function Get-HarnessGateKeeperReadyPath([string]$RunToken) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParseExact($RunToken, 'D', [ref]$guid) -or $guid.ToString() -cne $RunToken) { throw 'Run token is not canonical for keeper receipt path.' }
    return (Join-Path (Get-HarnessGateStateRoot) ($RunToken + '.keeper-ready.json'))
}

function Get-HarnessGateLifecycleBarrierPath([string]$RunToken, [string]$Barrier) {
    $guid = [guid]::Empty
    if (-not [guid]::TryParseExact($RunToken, 'D', [ref]$guid) -or $guid.ToString() -cne $RunToken -or
        $Barrier -cnotin @('BeforeKeeperPublication', 'BeforeKeeperResume')) {
        throw 'Lifecycle barrier identity is not an allowed exact run/mode pair.'
    }
    return (Join-Path (Get-HarnessGateStateRoot) ($RunToken + '.' + $Barrier + '.barrier.json'))
}

function Write-HarnessGateLifecycleBarrier([string]$RunToken, [string]$Barrier, [uint32]$SupervisorPid,
    [long]$SupervisorStartFiletime, [string]$Path) {
    $expected = Get-HarnessGateLifecycleBarrierPath $RunToken $Barrier
    if ($SupervisorPid -eq 0 -or $SupervisorStartFiletime -le 0 -or
        -not [string]::Equals($Path, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lifecycle barrier marker is not bound to this exact supervisor and deterministic path.'
    }
    $marker = [ordered]@{
        schema = 'safeupload-harness-gate-lifecycle-barrier-v1'
        runToken = $RunToken
        barrier = $Barrier
        supervisorPid = $SupervisorPid
        supervisorStartFiletime = $SupervisorStartFiletime
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $marker -Depth 4 -Compress))
    $stream = $null
    try {
        $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Write-HarnessGateKeeperReadyReceipt([string]$RunToken, [uint32]$KeeperPid, [long]$KeeperStartFiletime,
    [string]$MainJobName, [string]$KeeperJobName, [string]$Path) {
    if ($KeeperPid -eq 0 -or $KeeperStartFiletime -le 0 -or
        $MainJobName -cne (Get-HarnessGateJobName $RunToken) -or
        $KeeperJobName -cne (Get-HarnessGateKeeperJobName $RunToken) -or
        $Path -cne (Get-HarnessGateKeeperReadyPath $RunToken)) {
        throw 'Keeper readiness receipt identity is incomplete or not bound to the deterministic run objects.'
    }
    $receipt = [ordered]@{
        schema = 'safeupload-harness-gate-keeper-ready-v1'
        runToken = $RunToken
        keeperPid = $KeeperPid
        keeperStartFiletime = $KeeperStartFiletime
        mainJobName = $MainJobName
        keeperJobName = $KeeperJobName
        mainJobQuery = 'EXACT_HANDLE_QUERY_SUCCEEDED'
        keeperJobMembership = 'CURRENT_PROCESS_MEMBER'
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $receipt -Depth 4 -Compress))
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $readySha = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    # Stage under the protected state root with an exclusive, one-use name.
    # RUN observes only the deterministic final path, which appears after the
    # complete bytes are flushed and the staging handle is closed.
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $stream = $null
    $temporaryCreated = $false
    try {
        $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $temporaryCreated = $true
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        # Same-directory Move is an atomic publish and fails if the final name
        # already exists; no partial receipt is ever created at the ready path.
        [IO.File]::Move($temporary, $Path)
        $temporaryCreated = $false
        return $readySha
    } catch {
        if ($null -ne $stream) {
            try { $stream.Dispose() } catch { }
            $stream = $null
        }
        if ($temporaryCreated) {
            try {
                if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
            } catch { }
        }
        throw
    } finally {
        if ($null -ne $stream) {
            try { $stream.Dispose() } catch { }
        }
    }
}

function New-HarnessGateState([string]$Path, $State) {
    $json = ConvertTo-Json -InputObject $State -Depth 8 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.claim'
    $stream = $null
    try {
        $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    try {
        # Same-directory Move is atomic and fails if another one-use claim already exists.
        [IO.File]::Move($temporary, $Path)
    } catch {
        [IO.File]::Delete($temporary)
        throw
    }
}

function Write-HarnessGateState([string]$Path, $State) {
    $leaf = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($leaf.PSIsContainer -or ($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Run state is not a plain file.' }
    $current = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($current.schema -cne 'safeupload-harness-gate-run-v2' -or
        [string]$current.runToken -cne [string]$State.runToken -or
        [string]$current.jobName -cne [string]$State.jobName -or
        [string]$current.keeperJobName -cne [string]$State.keeperJobName -or
        [string]$current.keeperPath -cne [string]$State.keeperPath -or
        [string]$current.keeperReadyPath -cne [string]$State.keeperReadyPath -or
        [uint32]$current.supervisorPid -ne [uint32]$State.supervisorPid -or
        [long]$current.supervisorStartFiletime -ne [long]$State.supervisorStartFiletime -or
        [string]$current.workerPath -cne [string]$State.workerPath -or
        ([uint32]$current.keeperPid -gt 0 -and [uint32]$current.keeperPid -ne [uint32]$State.keeperPid) -or
        ([uint32]$current.workerPid -gt 0 -and [uint32]$current.workerPid -ne [uint32]$State.workerPid) -or
        (-not [string]::IsNullOrEmpty([string]$current.keeperReadySha256) -and
            [string]$current.keeperReadySha256 -cne [string]$State.keeperReadySha256)) {
        throw 'Run state update does not preserve the exact one-use owner identity.'
    }
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $json = ConvertTo-Json -InputObject $State -Depth 8 -Compress
    $stream = $null
    try {
        $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    [IO.File]::Replace($temporary, $Path, $null)
}

function Read-HarnessGateState([string]$RunToken) {
    $path = Get-HarnessGateStatePath $RunToken
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $leaf = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($leaf.PSIsContainer -or ($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Run state path exists but is not a plain file.' }
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
}

function Get-HarnessGateProcessStartFiletime([uint32]$ProcessId) {
    try {
        $process = Get-Process -Id ([int]$ProcessId) -ErrorAction Stop
        return [long]$process.StartTime.ToFileTimeUtc()
    } catch [System.ArgumentException] { return $null }
    catch [System.InvalidOperationException] { return $null }
}

function Get-HarnessGateCimRowStartFiletime($CimProcess) {
    $processId = [uint32]$CimProcess.ProcessId
    $liveStart = Get-HarnessGateProcessStartFiletime $processId
    if ($null -eq $liveStart) { return $null }
    try {
        $reportedStart = [long][Management.ManagementDateTimeConverter]::ToDateTime([string]$CimProcess.CreationDate).ToFileTimeUtc()
    } catch {
        throw ('Could not decode the WMI creation time for matching process ' + [string]$processId)
    }
    # Win32_Process exposes microsecond precision while GetProcessTimes is 100 ns.
    # A disagreement outside that representation loss means the PID row raced a reuse;
    # fail closed rather than pairing a stale command line with the new process identity.
    if ([Math]::Abs([long]$liveStart - $reportedStart) -gt 10) {
        throw ('WMI process creation identity changed while inspecting PID ' + [string]$processId)
    }
    return [long]$liveStart
}

function Get-HarnessGateCommandLineMatches([string]$RunToken, [string]$ScriptPath) {
    $foundProcesses = @()
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -OperationTimeoutSec 5 -ErrorAction Stop)
    foreach ($process in $processes) {
        $commandLine = [string]$process.CommandLine
        $executablePath = [string]$process.ExecutablePath
        if (-not [string]::Equals($executablePath, (Join-Path $PSHOME 'powershell.exe'), [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ([string]::IsNullOrEmpty($commandLine) -or $commandLine -notmatch '(?i)-EncodedCommand\s+(?:"([A-Za-z0-9+/=]+)"|([A-Za-z0-9+/=]+))') { continue }
        $encodedMatch = $Matches
        $encoded = if ($encodedMatch[1]) { $encodedMatch[1] } else { $encodedMatch[2] }
        try { $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)) } catch { continue }
        $tokenArgument = "-RunToken '" + $RunToken + "'"
        $expectedDestination = Split-Path -Parent $ScriptPath
        $expectedLeaf = Split-Path -Leaf $ScriptPath
        $destinationBinding = '$destination=' + "'" + $expectedDestination + "'"
        $runnerBinding = '$runnerPath=Join-Path $destination ' + "'" + $expectedLeaf + "'"
        if ($decoded.IndexOf($tokenArgument, [StringComparison]::Ordinal) -lt 0 -or
            $decoded.IndexOf($destinationBinding, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $decoded.IndexOf($runnerBinding, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $decoded.IndexOf('& $runnerPath -DestinationPath $destination', [StringComparison]::Ordinal) -lt 0) { continue }
        $start = Get-HarnessGateCimRowStartFiletime $process
        if ($null -ne $start) {
            $foundProcesses += [pscustomobject]@{ ProcessId = [uint32]$process.ProcessId; StartFiletime = [long]$start; CommandLine = $commandLine }
        }
    }
    return $foundProcesses
}

function Get-HarnessGateFileProcessMatches([string]$RunToken, [string]$ScriptPath) {
    $foundProcesses = @()
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -OperationTimeoutSec 5 -ErrorAction Stop)
    foreach ($process in $processes) {
        $commandLine = [string]$process.CommandLine
        $executablePath = [string]$process.ExecutablePath
        if (-not [string]::Equals($executablePath, (Join-Path $PSHOME 'powershell.exe'), [StringComparison]::OrdinalIgnoreCase) -or
            [string]::IsNullOrEmpty($commandLine) -or
            $commandLine.IndexOf('-File "' + $ScriptPath + '"', [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $commandLine.IndexOf('-RunToken "' + $RunToken + '"', [StringComparison]::Ordinal) -lt 0) { continue }
        $start = Get-HarnessGateCimRowStartFiletime $process
        if ($null -ne $start) {
            $foundProcesses += [pscustomobject]@{ ProcessId = [uint32]$process.ProcessId; StartFiletime = [long]$start; CommandLine = $commandLine }
        }
    }
    return $foundProcesses
}

function Test-HarnessGateProcessIdentityPresent([uint32]$ProcessId, [long]$StartFiletime) {
    $current = Get-HarnessGateProcessStartFiletime $ProcessId
    return ($null -ne $current -and [long]$current -eq $StartFiletime)
}

function Stop-HarnessGateExactProcessIdentity([uint32]$ProcessId, [long]$StartFiletime, [int]$TimeoutMilliseconds = 5000) {
    $openError = 0
    $exact = $false
    $handle = [SafeUpload.HarnessGate.Native]::OpenExactProcess($ProcessId, $StartFiletime, [ref]$openError, [ref]$exact)
    if ($handle -eq [IntPtr]::Zero) {
        if (-not $exact -and $openError -eq 0) { return $false }
        $current = Get-HarnessGateProcessStartFiletime $ProcessId
        if ($null -eq $current -or [long]$current -ne $StartFiletime) { return $false }
        throw ('Could not open the exact PID/start FILETIME; Win32Error=' + [string]$openError)
    }
    try {
        [SafeUpload.HarnessGate.Native]::TerminateExactProcess($handle, [uint32]0xE505)
        $watch = [Diagnostics.Stopwatch]::StartNew()
        while ($watch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
            $wait = [SafeUpload.HarnessGate.Native]::WaitHandle($handle, [uint32]50)
            if ($wait -eq 0) { return $true }
            if ($wait -ne 258) { throw ('Exact process wait failed with result ' + [string]$wait) }
        }
        if ([SafeUpload.HarnessGate.Native]::WaitHandle($handle, [uint32]0) -eq 0) { return $true }
        throw 'Exact original PID/start FILETIME did not become terminal before the bounded stop deadline.'
    } finally {
        [SafeUpload.HarnessGate.Native]::Close($handle)
    }
}

function Wait-HarnessGateJobEmpty([IntPtr]$Job, [int]$TimeoutMilliseconds) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        if ([SafeUpload.HarnessGate.Native]::ActiveProcessCount($Job) -eq 0) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return ([SafeUpload.HarnessGate.Native]::ActiveProcessCount($Job) -eq 0)
}

function Stop-HarnessGateMatchingWorkers([string]$RunToken, [string]$WorkerPath, [int]$TimeoutMilliseconds) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $stableEmpty = 0
    while ($watch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        $matches = @(Get-HarnessGateFileProcessMatches $RunToken $WorkerPath)
        foreach ($match in $matches) {
            if (-not (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime))) { continue }
            $current = @(Get-HarnessGateFileProcessMatches $RunToken $WorkerPath | Where-Object {
                $_.ProcessId -eq [uint32]$match.ProcessId -and $_.StartFiletime -eq [long]$match.StartFiletime
            })
            if ($current.Count -ne 1) { throw 'Refusing to stop an ambiguous late worker identity.' }
            if (-not (Stop-HarnessGateExactProcessIdentity ([uint32]$match.ProcessId) ([long]$match.StartFiletime) 5000) -and
                (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime))) {
                throw 'Exact late worker PID/start FILETIME changed before it could be safely stopped.'
            }
            $waitWatch = [Diagnostics.Stopwatch]::StartNew()
            while ($waitWatch.ElapsedMilliseconds -lt 5000 -and
                (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime))) {
                Start-Sleep -Milliseconds 50
            }
            if (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime)) {
                throw 'Exact late worker PID/start FILETIME remained active after stop.'
            }
        }
        if ($matches.Count -eq 0) { $stableEmpty++ } else { $stableEmpty = 0 }
        if ($stableEmpty -ge 3) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Stop-HarnessGateMatchingSupervisors([string]$RunToken, [string]$RunnerPath, [int]$TimeoutMilliseconds) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $stableEmpty = 0
    while ($watch.ElapsedMilliseconds -lt $TimeoutMilliseconds) {
        $matches = @(Get-HarnessGateCommandLineMatches $RunToken $RunnerPath)
        foreach ($match in $matches) {
            if (-not (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime))) { continue }
            $current = @(Get-HarnessGateCommandLineMatches $RunToken $RunnerPath | Where-Object {
                $_.ProcessId -eq [uint32]$match.ProcessId -and $_.StartFiletime -eq [long]$match.StartFiletime
            })
            if ($current.Count -ne 1) { throw 'Refusing to stop an ambiguous late supervisor identity.' }
            if (-not (Stop-HarnessGateExactProcessIdentity ([uint32]$match.ProcessId) ([long]$match.StartFiletime) 5000) -and
                (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime))) {
                throw 'Exact late supervisor PID/start FILETIME changed before it could be safely stopped.'
            }
            $waitWatch = [Diagnostics.Stopwatch]::StartNew()
            while ($waitWatch.ElapsedMilliseconds -lt 5000 -and
                (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime))) {
                Start-Sleep -Milliseconds 50
            }
            if (Test-HarnessGateProcessIdentityPresent ([uint32]$match.ProcessId) ([long]$match.StartFiletime)) {
                throw 'Exact late supervisor PID/start FILETIME remained active after stop.'
            }
        }
        if ($matches.Count -eq 0) { $stableEmpty++ } else { $stableEmpty = 0 }
        if ($stableEmpty -ge 3) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

Export-ModuleMember -Function Assert-HarnessGateEnvironment, Assert-HarnessGateFiles, Get-HarnessGateJobName, Get-HarnessGateKeeperJobName, Get-HarnessGateKeeperReadyPath, Write-HarnessGateKeeperReadyReceipt, Get-HarnessGateLifecycleBarrierPath, Write-HarnessGateLifecycleBarrier, Get-HarnessGateLifecycleMutexName, Enter-HarnessGateLifecycleMutex, Exit-HarnessGateLifecycleMutex, Write-HarnessGateBoundedBytes, Get-HarnessGateStateRoot, Get-HarnessGateStatePath, New-HarnessGateState, Write-HarnessGateState, Read-HarnessGateState, Get-HarnessGateProcessStartFiletime, Get-HarnessGateCommandLineMatches, Get-HarnessGateFileProcessMatches, Test-HarnessGateProcessIdentityPresent, Stop-HarnessGateExactProcessIdentity, Wait-HarnessGateJobEmpty, Stop-HarnessGateMatchingWorkers, Stop-HarnessGateMatchingSupervisors
