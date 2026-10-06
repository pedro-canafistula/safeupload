// Source-only RV4-W01 stimulus draft. Requires Windows 10 x64 / .NET Framework 4.x.
// This executable never asserts a lower hold, W ticket, raw bytes, or case PASS.
using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

public static class Rv4W01Stimulus
{
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_ALL = 7, FILE_SHARE_READ_DELETE = 5, OPEN_EXISTING = 3;
    const uint FILE_FLAG_NO_BUFFERING = 0x20000000, FILE_FLAG_OVERLAPPED = 0x40000000;
    const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const uint FILE_ATTRIBUTE_DIRECTORY = 0x10, FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    const int ERROR_IO_PENDING = 997, WAIT_TIMEOUT = 258;
    const int PAGE = 4096;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, MEM_RELEASE = 0x8000, PAGE_READWRITE = 4;

    [StructLayout(LayoutKind.Sequential)]
    struct NativeOverlapped {
        public IntPtr Internal, InternalHigh;
        public uint Offset, OffsetHigh;
        public IntPtr Event;
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateDirectoryW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateDirectoryExclusive(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileW")]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, byte[] buffer, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="GetFinalPathNameByHandleW")]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="GetVolumeInformationW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumeInformation(string root, StringBuilder name, uint nameLength,
        out uint serial, out uint maxComponent, out uint flags, StringBuilder fileSystem, uint fsLength);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="GetDriveTypeW")]
    static extern uint GetDriveType(string root);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="GetVolumePathNameW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetVolumePathName(string fileName, StringBuilder volumePath, uint capacity);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateIoCompletionPort(SafeFileHandle file, IntPtr existingPort, UIntPtr key, uint threads);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool WriteFile(SafeFileHandle handle, IntPtr buffer, uint bytes, IntPtr written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetQueuedCompletionStatus(IntPtr port, out uint bytes, out UIntPtr key,
        out IntPtr overlapped, uint timeoutMs);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CancelIoEx(SafeFileHandle handle, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool VirtualFree(IntPtr address, UIntPtr size, uint freeType);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);

    static string runDir, runGuid;
    static bool issued, completed, rootOwned, completionSuccess, completionReceiptDurable, recoveryRequired;
    static IntPtr aligned = IntPtr.Zero, ovPointer = IntPtr.Zero, port = IntPtr.Zero;
    static SafeFileHandle file;

    static void Receipt(string name, string body)
    {
        // All filenames are fixed literals; CreateNew preserves collision evidence.
        string path = Path.Combine(runDir, name + ".receipt");
        byte[] data = new UTF8Encoding(false).GetBytes(
            "Schema=Rv4W01StimulusDraft/1\nRunGuid=" + runGuid + "\nUtc=" +
            DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + "\n" + body);
        using (FileStream s = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
            FileShare.Read, 4096, FileOptions.WriteThrough)) { s.Write(data, 0, data.Length); s.Flush(true); }
    }
    static void BestEffortReceipt(string name, string body)
    {
        try { Receipt(name, body); } catch (Exception ex) { Console.Error.WriteLine("ReceiptFailure=" + name + ";" + ex.Message); }
    }

    static bool WaitRequest(string leaf, int timeoutMs)
    {
        string path = Path.Combine(runDir, leaf + ".request");
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        do {
            if (File.Exists(path)) {
                try { if (File.ReadAllText(path, Encoding.ASCII) == runGuid + "\n") return true; }
                catch (IOException) { /* Retry an incomplete request until the deadline. */ }
            }
            Thread.Sleep(25);
        } while (DateTime.UtcNow < deadline);
        return false;
    }

    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", ""); }
    static string Sha256(byte[] bytes)
    {
        using (SHA256 sha = SHA256.Create()) return Hex(sha.ComputeHash(bytes));
    }

    static string FinalPath(SafeFileHandle handle)
    {
        StringBuilder result = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandle(handle, result, (uint)result.Capacity, 0);
        if (length == 0 || length >= result.Capacity)
            throw new IOException("GetFinalPathNameByHandle failed; Win32=" + Marshal.GetLastWin32Error());
        return result.ToString();
    }

    static uint HandleAttributes(SafeFileHandle handle)
    {
        byte[] info = new byte[8]; // FILE_ATTRIBUTE_TAG_INFO
        if (!GetFileInformationByHandleEx(handle, 9, info, 8))
            throw new IOException("FileAttributeTagInfo failed; Win32=" + Marshal.GetLastWin32Error());
        return BitConverter.ToUInt32(info, 0);
    }

    static void RequireTestPlatform(string finalPath)
    {
        if (!finalPath.StartsWith(@"\\?\C:\", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("Expected boot-attached C: volume");
        using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", false)) {
            if (key == null || Convert.ToString(key.GetValue("CurrentBuildNumber"), CultureInfo.InvariantCulture) != "19045" ||
                Convert.ToInt32(key.GetValue("UBR"), CultureInfo.InvariantCulture) != 2965)
                throw new NotSupportedException("Expected Windows 10 build 19045.2965");
        }
        const string root = @"C:\";
        if (GetDriveType(root) != 3) throw new NotSupportedException("Boot volume is not a fixed drive");
        StringBuilder fs = new StringBuilder(64), volume = new StringBuilder(256);
        uint serial, maximum, flags;
        if (!GetVolumeInformation(root, volume, (uint)volume.Capacity, out serial, out maximum,
            out flags, fs, (uint)fs.Capacity))
            throw new IOException("GetVolumeInformation failed; Win32=" + Marshal.GetLastWin32Error());
        if (fs.ToString() != "NTFS") throw new NotSupportedException("Boot volume is not NTFS");
    }

    static void RequireBootVolumePath(string path)
    {
        StringBuilder volumePath = new StringBuilder(32768);
        if (!GetVolumePathName(path, volumePath, (uint)volumePath.Capacity))
            throw new IOException("GetVolumePathName failed; Win32=" + Marshal.GetLastWin32Error());
        if (!String.Equals(volumePath.ToString(), @"C:\", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("Fixture path is on a mounted volume other than C:");
    }

    static void CloseWriter()
    {
        if (file == null) return;
        IntPtr native = file.DangerousGetHandle();
        bool closed = CloseHandle(native);
        int error = closed ? 0 : Marshal.GetLastWin32Error();
        if (closed) file.SetHandleAsInvalid();
        file.Dispose(); file = null;
        if (!closed) throw new IOException("Native writer CloseHandle failed; Win32=" + error);
    }

    static void WaitForMatchingCompletion(int timeoutMs)
    {
        bool deadlineReported = false;
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        for (;;) {
            uint bytes; UIntPtr key; IntPtr returned;
            bool ok = GetQueuedCompletionStatus(port, out bytes, out key, out returned, 1000);
            int error = ok ? 0 : Marshal.GetLastWin32Error();
            if (returned != IntPtr.Zero) {
                if (returned != ovPointer || key.ToUInt64() != 1UL) {
                    if (!File.Exists(Path.Combine(runDir, "foreign-completion.receipt")))
                        BestEffortReceipt("foreign-completion", "PointerMismatch=True\nNativeError=" + error + "\n");
                    // An unrelated packet cannot discharge this OVERLAPPED's lifetime.
                    continue;
                }
                completed = true; // The matching packet ends native OVERLAPPED/buffer lifetime.
                completionSuccess = ok && bytes == PAGE && !recoveryRequired;
                Receipt("completed", "CompletionSource=IOCP\nSuccess=" + ok + "\nNativeError=" + error +
                    "\nBytes=" + bytes + "\nDeadlineExceeded=" + deadlineReported + "\n");
                completionReceiptDurable = true;
                return;
            }
            if (!ok && error != WAIT_TIMEOUT) {
                recoveryRequired = true;
                if (!File.Exists(Path.Combine(runDir, "recovery-required.receipt")))
                    BestEffortReceipt("recovery-required", "Reason=CompletionPortError\nNativeError=" + error +
                        "\nNativeStorageRetained=True\nProcessMustRemainLive=True\n");
                Thread.Sleep(1000);
            }
            if (!deadlineReported && DateTime.UtcNow >= deadline) {
                deadlineReported = true;
                recoveryRequired = true;
                if (!File.Exists(Path.Combine(runDir, "recovery-required.receipt")))
                    BestEffortReceipt("recovery-required", "Reason=MatchingIocpCompletionNotObservedByDeadline\n" +
                        "NativeStorageRetained=True\nProcessMustRemainLive=True\n");
                // Continue bounded 1-second waits. The coordinator must release/cancel the lower hold;
                // exiting or freeing the buffer/OVERLAPPED here would invalidate a live IRP.
            }
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length != 7) {
            Console.Error.WriteLine("Usage: Rv4W01Stimulus.exe <owned-fixture-root> <owned-control-parent> <32-hex-run-guid> <4096-aligned-offset> <timeout-ms> <volume-serial-16hex> <file-id-32hex>");
            return 2;
        }
        int timeoutMs = 30000, outcome = 4;
        try {
            if (!Environment.Is64BitProcess) throw new InvalidOperationException("x64 process required");
            Guid parsed;
            if (args[2].Length != 32 || !Guid.TryParseExact(args[2], "N", out parsed))
                throw new ArgumentException("run GUID must be 32 hex digits");
            runGuid = parsed.ToString("N");
            if (!System.Text.RegularExpressions.Regex.IsMatch(args[5], "\\A[0-9a-fA-F]{16}\\z") ||
                !System.Text.RegularExpressions.Regex.IsMatch(args[6], "\\A[0-9a-fA-F]{32}\\z"))
                throw new ArgumentException("Expected volume serial/file ID must be exact hex");
            long offset = long.Parse(args[3], CultureInfo.InvariantCulture);
            timeoutMs = int.Parse(args[4], CultureInfo.InvariantCulture);
            if (offset < 0 || offset > long.MaxValue - PAGE || offset % PAGE != 0 ||
                timeoutMs < 1000 || timeoutMs > 600000)
                throw new ArgumentOutOfRangeException("offset/timeout");
            string parent = Path.GetFullPath(args[1]);
            string controlLeaf = "SafeUpload-rv4-w01-control-" + runGuid;
            string runLeaf = "SafeUpload-rv4-w01-" + runGuid;
            if (Path.GetFileName(parent.TrimEnd('\\')) != controlLeaf)
                throw new ArgumentException("Control parent is not the GUID-owned fixture control root");
            using (SafeFileHandle controlHandle = CreateFile(parent, 0x80, FILE_SHARE_ALL, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero)) {
                if (controlHandle.IsInvalid)
                    throw new IOException("Open control parent failed; Win32=" + Marshal.GetLastWin32Error());
                uint controlAttributes = HandleAttributes(controlHandle);
                if ((controlAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                    (controlAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    throw new InvalidDataException("Control parent is not an ordinary directory");
                string controlFinal = FinalPath(controlHandle).TrimEnd('\\');
                RequireTestPlatform(controlFinal);
                RequireBootVolumePath(parent);
                if (Path.GetFileName(controlFinal) != controlLeaf)
                    throw new InvalidDataException("Resolved control parent leaf mismatch");
                runDir = Path.Combine(parent, runLeaf);
                if (!CreateDirectoryExclusive(runDir, IntPtr.Zero))
                    throw new IOException("Exclusive run directory creation failed; Win32=" + Marshal.GetLastWin32Error());
                using (SafeFileHandle runHandle = CreateFile(runDir, 0x80, FILE_SHARE_ALL, IntPtr.Zero,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero)) {
                    if (runHandle.IsInvalid)
                        throw new IOException("Open created run directory failed; Win32=" + Marshal.GetLastWin32Error());
                    uint runAttributes = HandleAttributes(runHandle);
                    if ((runAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                        (runAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                        !String.Equals(FinalPath(runHandle).TrimEnd('\\'), controlFinal + "\\" + runLeaf,
                            StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Created run directory is not the exact nonreparse control child");
                }
                rootOwned = true;
            }
            string fixtureRoot = Path.GetFullPath(args[0]);
            if (Path.GetFileName(fixtureRoot.TrimEnd('\\')) != "SafeUpload-rv4-w01-files-" + runGuid)
                throw new ArgumentException("Fixture root is not the GUID-owned file root");
            string leaf = "rv4-w01-target-" + runGuid + ".bin";
            string target = Path.Combine(fixtureRoot, leaf);
            string rootFinal;
            using (SafeFileHandle rootHandle = CreateFile(fixtureRoot, 0x80, FILE_SHARE_ALL, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero)) {
                if (rootHandle.IsInvalid) throw new IOException("Open fixture root failed; Win32=" + Marshal.GetLastWin32Error());
                uint rootAttributes = HandleAttributes(rootHandle);
                if ((rootAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                    (rootAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    throw new InvalidDataException("Fixture root is not an ordinary directory");
                rootFinal = FinalPath(rootHandle).TrimEnd('\\');
            }
            RequireTestPlatform(rootFinal);
            RequireBootVolumePath(fixtureRoot);
            file = CreateFile(target, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ_DELETE, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED |
                FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (file.IsInvalid) throw new IOException("CreateFile failed; Win32=" + Marshal.GetLastWin32Error());
            uint targetAttributes = HandleAttributes(file);
            if ((targetAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                throw new InvalidDataException("Target is a directory or reparse point");
            string targetFinal = FinalPath(file);
            if (!String.Equals(targetFinal, rootFinal + "\\" + leaf, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Opened target escapes the GUID-owned fixture root or is an ADS");
            RequireTestPlatform(targetFinal);
            byte[] identity = new byte[24], alignment = new byte[4];
            if (!GetFileInformationByHandleEx(file, 18, identity, 24))
                throw new IOException("FILE_ID_INFO failed; Win32=" + Marshal.GetLastWin32Error());
            string serialHex = Hex(Subarray(identity, 0, 8)), fileIdHex = Hex(Subarray(identity, 8, 16));
            if (!String.Equals(serialHex, args[5], StringComparison.OrdinalIgnoreCase) ||
                !String.Equals(fileIdHex, args[6], StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Controller-approved volume serial/file ID mismatch");
            if (!GetFileInformationByHandleEx(file, 17, alignment, 4))
                throw new IOException("FileAlignmentInfo failed; Win32=" + Marshal.GetLastWin32Error());
            uint requiredAlignment = BitConverter.ToUInt32(alignment, 0) + 1;
            if (requiredAlignment > PAGE || PAGE % requiredAlignment != 0)
                throw new NotSupportedException("4KiB alignment insufficient for device: " + requiredAlignment);
            port = CreateIoCompletionPort(file, IntPtr.Zero, new UIntPtr(1), 1);
            if (port == IntPtr.Zero) throw new IOException("IOCP bind failed; Win32=" + Marshal.GetLastWin32Error());
            Receipt("opened", "ProcessId=" + System.Diagnostics.Process.GetCurrentProcess().Id +
                "\nWriterHandleHex=" + file.DangerousGetHandle().ToInt64().ToString("X", CultureInfo.InvariantCulture) +
                "\nVolumeSerialHex=" + serialHex +
                "\nFileId128Hex=" + fileIdHex + "\nOffset=" + offset +
                "\nLength=4096\nAlignment=" + requiredAlignment + "\n");
            Console.WriteLine("Opened=True;RunGuid=" + runGuid + ";RunDir=" + runDir);
            Console.Out.Flush();
            if (!WaitRequest("write", timeoutMs)) {
                Receipt("unexercised", "Reason=WriteRequestTimeout\n");
                return 3;
            }
            byte[] payload = new byte[PAGE];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(payload);
            byte[] tag = parsed.ToByteArray();
            Array.Copy(tag, 0, payload, 0, tag.Length);
            aligned = VirtualAlloc(IntPtr.Zero, new UIntPtr(PAGE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (aligned == IntPtr.Zero || (aligned.ToInt64() & (PAGE - 1)) != 0)
                throw new IOException("Aligned VirtualAlloc failed; Win32=" + Marshal.GetLastWin32Error());
            Marshal.Copy(payload, 0, aligned, PAGE);
            NativeOverlapped ov = new NativeOverlapped();
            ov.Offset = (uint)(offset & 0xffffffffL); ov.OffsetHigh = (uint)((ulong)offset >> 32);
            ovPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeOverlapped)));
            Marshal.StructureToPtr(ov, ovPointer, false);
            bool sync = WriteFile(file, aligned, PAGE, IntPtr.Zero, ovPointer);
            int writeError = sync ? 0 : Marshal.GetLastWin32Error();
            issued = sync || writeError == ERROR_IO_PENDING;
            Receipt("issued", "PayloadSha256=" + Sha256(payload) + "\nOffset=" + offset +
                "\nLength=4096\nWriteCall=" + (sync ? "SYNCHRONOUS" : issued ? "PENDING" : "ERROR") +
                "\nWriteCallError=" + writeError + "\nByteCountSource=MatchingIocpOnly\n");
            Console.WriteLine("Issued=True;NativePending=" + (!sync && issued)); Console.Out.Flush();
            bool closeRequested = WaitRequest("close", timeoutMs);
            if (!closeRequested && issued) {
                bool cancel = CancelIoEx(file, ovPointer);
                int cancelError = cancel ? 0 : Marshal.GetLastWin32Error();
                Receipt("close-request-timeout", "CancelIoEx=" + cancel + "\nCancelError=" + cancelError + "\n");
            }
            // No duplicated user handle is retained here. A controller must close its arm duplicate
            // before requesting this close; the lower filter must retain an independent kernel FO ref.
            Receipt("close-entered", "CloseRequested=" + closeRequested + "\nWasNativePending=" + (!sync && issued) + "\n");
            CloseWriter();
            Receipt("closed", "CloseRequested=" + closeRequested + "\nNativeCloseSucceeded=True\nWasNativePending=" + (!sync && issued) + "\n");
            if (issued) WaitForMatchingCompletion(timeoutMs);
            else Receipt("completed", "CompletionSource=None\nNativeError=" + writeError +
                "\nBytes=0\nStatus=UNEXERCISED\n");
            Console.WriteLine("StimulusComplete=True;CaseQualified=False;RecoveryRequired=" + File.Exists(Path.Combine(runDir, "recovery-required.receipt")));
            outcome = (!closeRequested || !issued || sync || !completionSuccess ||
                !completionReceiptDurable || recoveryRequired) ? 3 : 0;
        } catch (Exception ex) {
            try { if (rootOwned && runDir != null && Directory.Exists(runDir)) Receipt("error", "Type=" + ex.GetType().FullName + "\nMessage=" + ex.Message.Replace("\n", " ").Replace("\r", " ") + "\n"); } catch { }
            Console.Error.WriteLine(ex.ToString());
            if (issued && !completed && port != IntPtr.Zero) {
                // An exception is not completion. Request cancellation while the user handle exists,
                // close it, then retain this process and its native allocations until the IOCP packet.
                if (file != null) {
                    try { CancelIoEx(file, ovPointer); } catch { }
                    try { CloseWriter(); } catch (Exception closeError) {
                        if (rootOwned) BestEffortReceipt("close-error", "NativeClose=" + closeError.Message + "\n");
                    }
                }
                WaitForMatchingCompletion(timeoutMs);
            }
            outcome = 4;
        } finally {
            // A pending request owns the unmanaged buffer and OVERLAPPED until the matching IOCP packet.
            if (file != null) {
                try { CloseWriter(); } catch (Exception closeError) {
                    outcome = 4;
                    if (rootOwned) BestEffortReceipt("cleanup-error", "CloseWriter=" + closeError.Message + "\n");
                }
            }
            if (!issued || completed) {
                if (ovPointer != IntPtr.Zero) Marshal.FreeHGlobal(ovPointer);
                if (aligned != IntPtr.Zero && !VirtualFree(aligned, UIntPtr.Zero, MEM_RELEASE)) {
                    outcome = 4;
                    int freeError = Marshal.GetLastWin32Error();
                    if (rootOwned) BestEffortReceipt("cleanup-error", "VirtualFreeWin32=" + freeError + "\n");
                }
            }
            if (port != IntPtr.Zero && !CloseHandle(port)) {
                outcome = 4;
                int portError = Marshal.GetLastWin32Error();
                if (rootOwned) BestEffortReceipt("cleanup-error", "CloseIocpWin32=" + portError + "\n");
            }
        }
        return outcome;
    }

    static byte[] Subarray(byte[] a, int start, int count)
    {
        byte[] b = new byte[count]; Array.Copy(a, start, b, 0, count); return b;
    }
}
