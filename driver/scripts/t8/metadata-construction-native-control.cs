// Standalone unprotected NTFS feasibility control. Never used by product code.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class T8MetadataConstructionControl {
    static string progressPath;
    static void Log(string line) { if (progressPath != null) File.AppendAllText(progressPath, line + Environment.NewLine, new UTF8Encoding(false)); }
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public uint Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Security, Qos; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] struct Privilege { public uint Count; public Luid Id; public uint Attributes; }
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool OpenThreadToken(IntPtr thread, uint access, [MarshalAs(UnmanagedType.Bool)] bool self, out IntPtr token);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attributes, int level, int type, out IntPtr copy);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool CreateRestrictedToken(IntPtr token, uint flags, uint disabledCount, IntPtr disabled, uint deletedCount, IntPtr deleted, uint restrictedCount, IntPtr restricted, out IntPtr copy);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool SetThreadToken(IntPtr thread, IntPtr token);
    [DllImport("advapi32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool LookupPrivilegeValueW(string system, string name, out Luid id);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool AdjustTokenPrivileges(IntPtr token, [MarshalAs(UnmanagedType.Bool)] bool all, ref Privilege state, uint bytes, IntPtr previous, IntPtr returned);
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetTokenInformation(IntPtr token, int kind, byte[] bytes, uint length, out uint needed);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes, out IoStatus io, IntPtr allocation, uint flags, uint share, uint disposition, uint options, IntPtr ea, uint eaBytes);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtQueryObject(SafeFileHandle file, int kind, byte[] bytes, uint length, out uint needed);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtQuerySecurityObject(SafeFileHandle file, uint information, byte[] bytes, uint length, out uint needed);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtSetSecurityObject(SafeFileHandle file, uint information, byte[] bytes);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtWriteFile(SafeFileHandle file, IntPtr wait, IntPtr apc, IntPtr context, out IoStatus io, byte[] bytes, uint length, ref long offset, IntPtr key);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtFlushBuffersFile(SafeFileHandle file, out IoStatus io);
    [DllImport("ntdll.dll", ExactSpelling=true)] static extern int NtSetInformationFile(SafeFileHandle file, out IoStatus io, byte[] bytes, uint length, int kind);
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, byte[] bytes, uint length);

    public const uint ServiceMask = 0x011F01FF; // internal only: FILE_ALL_ACCESS | ACCESS_SYSTEM_SECURITY
    public const uint CallerWriteMask = 0x00100002; // exact original in-place write grant
    public const uint BackupSecurity = 0x00010000;
    public sealed class Row {
        public string Case, Operation, Status, Identity, ExpectedHex, ActualHex, SubjectSid, Detail;
        public uint Requested, Granted;
        public bool Passed, Exact;
    }
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static void CheckStatus(int status, string operation) { if (status != 0) throw new IOException(operation + ": 0x" + status.ToString("X8")); }
    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", ""); }
    static byte[] Descriptor(string sddl) { var raw = new RawSecurityDescriptor(sddl); byte[] bytes = new byte[raw.BinaryLength]; raw.GetBinaryForm(bytes, 0); return bytes; }
    static byte[] Privileges(IntPtr token) {
        uint needed; GetTokenInformation(token, 3, null, 0, out needed);
        if (needed < 4 || needed > 65536) throw new IOException("Invalid token privilege inventory.");
        byte[] data = new byte[needed]; Check(GetTokenInformation(token, 3, data, needed, out needed)); return data;
    }
    static byte[] ProcessPrivileges() {
        IntPtr token; Check(OpenProcessToken(new IntPtr(-1), 8, out token));
        try { return Privileges(token); } finally { Check(CloseHandle(token)); }
    }
    sealed class Subject : IDisposable {
        IntPtr previous; bool attached;
        public Subject(IntPtr token) {
            if (!OpenThreadToken(new IntPtr(-2), 0xC, true, out previous) && Marshal.GetLastWin32Error() != 1008) Check(false);
            try { Check(SetThreadToken(IntPtr.Zero, token)); attached = true; }
            catch { Dispose(); throw; }
        }
        public void Dispose() {
            try { if (attached) { Check(SetThreadToken(IntPtr.Zero, previous)); attached = false; } }
            finally { if (previous != IntPtr.Zero) { Check(CloseHandle(previous)); previous = IntPtr.Zero; } }
        }
    }
    static IntPtr ServiceToken() {
        IntPtr source = IntPtr.Zero, result = IntPtr.Zero;
        try {
            Check(OpenProcessToken(new IntPtr(-1), 0xA, out source));
            Check(DuplicateTokenEx(source, 0x2E, IntPtr.Zero, 2, 2, out result));
            foreach (string name in new string[] { "SeRestorePrivilege", "SeSecurityPrivilege", "SeBackupPrivilege" }) {
                Luid id; Check(LookupPrivilegeValueW(null, name, out id));
                var state = new Privilege { Count = 1, Id = id, Attributes = 2 };
                Check(AdjustTokenPrivileges(result, false, ref state, 0, IntPtr.Zero, IntPtr.Zero));
                if (Marshal.GetLastWin32Error() == 1300) throw new IOException("Service privilege unavailable: " + name);
            }
            IntPtr owned = result; result = IntPtr.Zero; return owned;
        } finally { if (source != IntPtr.Zero) CloseHandle(source); if (result != IntPtr.Zero) CloseHandle(result); }
    }
    static IntPtr CallerToken(int pid, long started, string sid) {
        IntPtr process = IntPtr.Zero, source = IntPtr.Zero, restricted = IntPtr.Zero, result = IntPtr.Zero;
        try {
            process = OpenProcess(0x1000, false, pid); if (process == IntPtr.Zero) Check(false);
            long created, exited, kernel, user;
            Check(GetProcessTimes(process, out created, out exited, out kernel, out user));
            if (DateTime.FromFileTimeUtc(created).Ticks != started) throw new IOException("Caller PID/start mismatch.");
            Check(OpenProcessToken(process, 0xA, out source));
            using (var identity = new WindowsIdentity(source)) {
                if (identity.IsSystem || identity.User.Value != sid) throw new IOException("Caller token SID mismatch/SYSTEM token forbidden.");
            }
            // Real caller token, LUA restrictions + disabled maximum privileges; not a SYSTEM-derived SID probe.
            Check(CreateRestrictedToken(source, 5, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted));
            Check(DuplicateTokenEx(restricted, 0xE, IntPtr.Zero, 2, 2, out result));
            byte[] privileges = Privileges(result);
            for (int i = 0; i < BitConverter.ToUInt32(privileges, 0); i++) {
                int offset = 4 + i * 12;
                if ((BitConverter.ToUInt32(privileges, offset + 8) & 2) != 0) {
                    Luid traverse; Check(LookupPrivilegeValueW(null, "SeChangeNotifyPrivilege", out traverse));
                    if (BitConverter.ToUInt32(privileges, offset) != traverse.Low || BitConverter.ToInt32(privileges, offset + 4) != traverse.High)
                        throw new IOException("Restricted caller retains a non-traverse enabled privilege.");
                }
            }
            IntPtr owned = result; result = IntPtr.Zero; return owned;
        } finally { if (result != IntPtr.Zero) CloseHandle(result); if (restricted != IntPtr.Zero) CloseHandle(restricted); if (source != IntPtr.Zero) CloseHandle(source); if (process != IntPtr.Zero) CloseHandle(process); }
    }
    sealed class OpenResult : IDisposable {
        public int Status; public uint Granted; public ulong Information; public SafeFileHandle File;
        public bool Accepted { get { return Status == 0 && File != null && !File.IsInvalid; } }
        public void Dispose() { if (File != null) File.Dispose(); }
    }
    static OpenResult Open(string path, uint access, uint disposition, bool directory, uint share = 7) {
        byte[] bytes = Encoding.Unicode.GetBytes("\\??\\" + Path.GetFullPath(path));
        IntPtr name = Marshal.AllocHGlobal(bytes.Length + 2), value = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
        try {
            Marshal.Copy(bytes, 0, name, bytes.Length); Marshal.WriteInt16(name, bytes.Length, 0);
            Marshal.StructureToPtr(new UnicodeString { Length = (ushort)bytes.Length, MaximumLength = (ushort)(bytes.Length + 2), Buffer = name }, value, false);
            var attributes = new ObjectAttributes { Length = 48, Name = value, Attributes = 0x1040 }; // DONT_REPARSE | CASE_INSENSITIVE
            SafeFileHandle file; IoStatus io;
            uint options = directory ? 0x00200021u : 0x00200060u;
            // Only the finite internal service request uses backup intent. Caller checks never do.
            if (access == ServiceMask) options |= 0x4000;
            int status = NtCreateFile(out file, access, ref attributes, out io, IntPtr.Zero, 0x80, share, disposition,
                options, IntPtr.Zero, 0);
            var result = new OpenResult { Status = status, File = file, Information = io.Information.ToUInt64() };
            if (status == 0) {
                if (io.Status != IntPtr.Zero || result.Information != (disposition == 2 ? 2UL : 1UL)) { result.Dispose(); throw new IOException("Unexpected native open result."); }
                byte[] basic = new byte[56]; uint returned;
                CheckStatus(NtQueryObject(file, 0, basic, 56, out returned), "Granted access");
                if (returned < 8) { result.Dispose(); throw new IOException("Short granted-access query."); }
                result.Granted = BitConverter.ToUInt32(basic, 4);
            }
            return result;
        } finally { Marshal.FreeHGlobal(value); Marshal.FreeHGlobal(name); }
    }
    static string Id(SafeFileHandle file) {
        byte[] bytes = new byte[24]; Check(GetFileInformationByHandleEx(file, 18, bytes, 24)); return Hex(bytes);
    }
    static byte[] Security(SafeFileHandle file) {
        uint needed; int status = NtQuerySecurityObject(file, BackupSecurity, null, 0, out needed);
        if (status != unchecked((int)0xC0000023) || needed < 20 || needed > 65536) throw new IOException("Security measurement size/status invalid.");
        byte[] bytes = new byte[needed]; CheckStatus(NtQuerySecurityObject(file, BackupSecurity, bytes, needed, out needed), "Full security query");
        new RawSecurityDescriptor(bytes, 0); return bytes;
    }
    static void Write(SafeFileHandle file, string text) {
        byte[] bytes = Encoding.UTF8.GetBytes(text); long offset = 0; IoStatus io;
        CheckStatus(NtWriteFile(file, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out io, bytes, (uint)bytes.Length, ref offset, IntPtr.Zero), "Native write");
        if (io.Status != IntPtr.Zero || io.Information.ToUInt64() != (ulong)bytes.Length) throw new IOException("Incomplete write.");
        CheckStatus(NtFlushBuffersFile(file, out io), "Native flush");
    }
    static void Rename(SafeFileHandle file, string path) {
        byte[] name = Encoding.Unicode.GetBytes("\\??\\" + Path.GetFullPath(path));
        byte[] bytes = new byte[20 + name.Length]; BitConverter.GetBytes(3u).CopyTo(bytes, 0);
        BitConverter.GetBytes(name.Length).CopyTo(bytes, 16); name.CopyTo(bytes, 20); IoStatus io;
        CheckStatus(NtSetInformationFile(file, out io, bytes, (uint)bytes.Length, 65), "Native replace rename");
        if (io.Status != IntPtr.Zero) throw new IOException("Incomplete rename.");
    }
    static void Need(bool ok, string message) { if (!ok) throw new IOException(message); }
    static void Record(ICollection<Row> rows, Row row) {
        rows.Add(row); Log("T8Progress=" + row.Case + "/" + row.Operation + " Passed=" + row.Passed + " Requested=0x" + row.Requested.ToString("X8") + " Granted=0x" + row.Granted.ToString("X8") + " Status=" + row.Status + " Identity=" + row.Identity);
        if (row.ExpectedHex != null) Log("T8Expected=" + row.Case + "/" + row.Operation + ":" + row.ExpectedHex);
        if (row.ActualHex != null) Log("T8Actual=" + row.Case + "/" + row.Operation + ":" + row.ActualHex);
    }
    public static Row[] Run(int callerPid, long callerStarted, string callerSid, string root, string progressFile) {
        Need(!File.Exists(progressFile), "Fresh progress evidence required."); progressPath = progressFile;
        using (var identity = WindowsIdentity.GetCurrent()) { Need(identity.IsSystem, "SYSTEM worker required."); }
        Need(!Directory.Exists(root), "Fresh fixture root required.");
        byte[] processBefore = ProcessPrivileges(); IntPtr caller = IntPtr.Zero, service = IntPtr.Zero;
        var rows = new List<Row>(); var inventory = new Dictionary<string, string>();
        try {
            caller = CallerToken(callerPid, callerStarted, callerSid); service = ServiceToken();
            using (var subject = new Subject(service)) {
                Directory.CreateDirectory(root);
                Register(inventory, root, true);
                ApplyPath(root, true, Descriptor("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;;0x001000A1;;;" + callerSid + ")"));
                foreach (string shape in new string[] { "Protected", "Inherited", "NullDacl", "EmptyDacl" }) {
                    string parent = Path.Combine(root, shape), target = Path.Combine(parent, "target.txt"), temporary = Path.Combine(root, shape + ".private");
                    Directory.CreateDirectory(parent); Register(inventory, parent, true);
                    ApplyPath(parent, true, Descriptor("O:SYG:BAD:P(A;OICI;FA;;;SY)(A;;0x001000A1;;;" + callerSid + ")(A;OIIO;0x00100002;;;" + callerSid + ")S:P(AU;OICISAFA;FW;;;WD)(ML;OICI;NW;;;LW)"));
                    using (var created = Open(target, ServiceMask, 2, false)) { Need(created.Accepted && created.Granted == ServiceMask, "Fixture create grant failed."); Register(inventory, target, false, created.File); Write(created.File, "original-native-bytes"); }
                    if (shape != "Inherited") {
                        string dacl = shape == "NullDacl" ? "D:NO_ACCESS_CONTROL" : shape == "EmptyDacl" ? "D:P" : "D:P(A;;FA;;;SY)(A;;0x00100002;;;" + callerSid + ")";
                        ApplyPath(target, false, Descriptor("O:SYG:BA" + dacl + "S:P(AU;SAFA;FW;;;WD)(ML;;NW;;;LW)"));
                    }
                    byte[] expected; using (var observation = Open(target, ServiceMask, 1, false)) { Need(observation.Accepted, "Target observation failed."); expected = Security(observation.File); }
                    if (shape == "Protected" || shape == "Inherited") {
                        using (var subjectCaller = new Subject(caller)) {
                            using (var writer = Open(target, CallerWriteMask, 1, false)) {
                                Need(writer.Accepted && writer.Granted == CallerWriteMask, "Original caller write must succeed exactly."); Write(writer.File, "caller-native-bytes");
                                Record(rows, new Row { Case = shape, Operation = "OriginalWrite", Requested = CallerWriteMask, Granted = writer.Granted, Status = "0x00000000", Identity = Id(writer.File), SubjectSid = callerSid, Passed = true });
                            }
                            foreach (uint denied in new uint[] { 0x00140000, 0x00180000, 0x01100000 }) {
                                using (var probe = Open(target, denied, 1, false)) { bool refused = probe.Status == unchecked((int)0xC0000022) || probe.Status == unchecked((int)0xC0000061); Need(!probe.Accepted && refused, "Caller security grant unexpectedly succeeded or failed for another reason."); Record(rows, new Row { Case = shape, Operation = "DeniedSecurityGrant", Requested = denied, Granted = probe.Granted, Status = "0x" + probe.Status.ToString("X8"), Passed = refused, SubjectSid = callerSid }); }
                            }
                            using (var probe = Open(Path.Combine(parent, "caller-must-not-create.txt"), CallerWriteMask, 2, false)) { Need(!probe.Accepted && probe.Status == unchecked((int)0xC0000022), "Caller parent-create denial failed."); Record(rows, new Row { Case = shape, Operation = "DeniedParentCreate", Requested = CallerWriteMask, Status = "0x" + probe.Status.ToString("X8"), Passed = true, SubjectSid = callerSid }); }
                        }
                    }
                    Clone(rows, inventory, shape, target, temporary, expected);
                    if (shape == "Protected" || shape == "Inherited") using (var subjectCaller = new Subject(caller)) {
                        using (var writer = Open(target, CallerWriteMask, 1, false)) {
                            Need(writer.Accepted && writer.Granted == CallerWriteMask, "Publication changed caller write grant.");
                            Record(rows, new Row { Case = shape, Operation = "PublishedCallerGrant", Requested = CallerWriteMask, Granted = writer.Granted, Status = "0x00000000", Identity = Id(writer.File), SubjectSid = callerSid, Passed = true });
                        }
                    }
                }
                string creates = Path.Combine(root, "new-and-app-temp"); Directory.CreateDirectory(creates); Register(inventory, creates, true);
                ApplyPath(creates, true, Descriptor("O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;0x001301BF;;;" + callerSid + ")S:P(AU;OICISAFA;FW;;;WD)(ML;OICI;NW;;;LW)"));
                string nativeNew = Path.Combine(creates, "native-new.txt");
                using (var subjectCaller = new Subject(caller)) using (var created = Open(nativeNew, 0x00110002, 2, false)) {
                    Need(created.Accepted && created.Granted == 0x00110002, "Native new-file grant failed.");
                    Register(inventory, nativeNew, false, created.File); Write(created.File, "native-new-bytes");
                }
                byte[] newExpected; using (var observed = Open(nativeNew, ServiceMask, 1, false)) { Need(observed.Accepted, "New observation failed."); newExpected = Security(observed.File); }
                Clone(rows, inventory, "NativeNew", nativeNew, Path.Combine(root, "new.private"), newExpected);
                string appTemp = Path.Combine(creates, "actual-app-temp.txt");
                string previousId = inventory[nativeNew];
                using (var subjectCaller = new Subject(caller)) using (var created = Open(appTemp, 0x00110002, 2, false)) {
                    Need(created.Accepted && created.Granted == 0x00110002, "Actual app-temp grant failed.");
                    Register(inventory, appTemp, false, created.File); Write(created.File, "app-temp-bytes"); Rename(created.File, nativeNew);
                    inventory[nativeNew] = inventory[appTemp]; inventory.Remove(appTemp);
                }
                // Ordinary native app-temp rename is measured separately; it is not inferred from initial CREATE.
                Need(inventory[nativeNew] != previousId, "App-temp rename must replace the old object.");
                using (var observed = Open(nativeNew, ServiceMask, 1, false)) { Need(observed.Accepted, "App-temp observation failed."); newExpected = Security(observed.File); }
                Clone(rows, inventory, "ActualAppTempRename", nativeNew, Path.Combine(root, "apptemp.private"), newExpected);
            }
        } finally {
            if (service != IntPtr.Zero) {
                using (var subject = new Subject(service)) {
                    var paths = new List<string>(inventory.Keys); paths.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
                    foreach (string path in paths) {
                        bool directory = Directory.Exists(path);
                        using (var observed = Open(path, ServiceMask, 1, directory)) { Need(observed.Accepted && Id(observed.File) == inventory[path], "Fixture cleanup identity changed: " + path); Need((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "Fixture became reparse."); CheckStatus(NtSetSecurityObject(observed.File, 0x80000004, Descriptor("D:P(A;;FA;;;SY)")), "Cleanup DACL"); }
                        if (directory) Directory.Delete(path); else File.Delete(path);
                    }
                    Need(!Directory.Exists(root), "Fixture root remains."); Log("FixtureRemoved=True");
                }
            }
            if (caller != IntPtr.Zero) CloseHandle(caller); if (service != IntPtr.Zero) CloseHandle(service);
            Need(Hex(processBefore) == Hex(ProcessPrivileges()), "Process privileges changed."); Log("ProcessPrivilegesUnchanged=True");
        }
        return rows.ToArray();
    }
    static void Register(IDictionary<string, string> inventory, string path, bool directory, SafeFileHandle held) { inventory.Add(path, Id(held)); }
    static void Register(IDictionary<string, string> inventory, string path, bool directory) { using (var file = Open(path, ServiceMask, 1, directory)) { Need(file.Accepted, "Register fixture failed."); Register(inventory, path, directory, file.File); } }
    static void ApplyPath(string path, bool directory, byte[] security) { using (var file = Open(path, ServiceMask, 1, directory)) { Need(file.Accepted, "Fixture security open failed."); CheckStatus(NtSetSecurityObject(file.File, BackupSecurity, security), "Fixture full security apply"); } }
    static void Clone(ICollection<Row> rows, IDictionary<string, string> inventory, string shape, string target, string temporary, byte[] expected) {
        using (var output = Open(temporary, ServiceMask, 2, false, 0)) {
            Need(output.Accepted && output.Granted == ServiceMask, "Private service output grant mismatch."); Register(inventory, temporary, false, output.File);
            Write(output.File, "approved-output-bytes");
            Log("T8ApplyInput=" + shape + ":" + Hex(expected));
            CheckStatus(NtSetSecurityObject(output.File, BackupSecurity, expected), "Exact private output security apply");
            byte[] actual = Security(output.File); bool exact = Hex(expected) == Hex(actual);
            Record(rows, new Row { Case = shape, Operation = "ServicePrivateApply", Requested = ServiceMask, Granted = output.Granted, Status = "0x00000000", Identity = Id(output.File), ExpectedHex = Hex(expected), ActualHex = Hex(actual), Exact = exact, Passed = exact, Detail = "BACKUP_SECURITY_INFORMATION; service-only broad handle never exported to caller" });
            string oldTarget = inventory[target], outputId = inventory[temporary];
            Rename(output.File, target); inventory.Remove(temporary); inventory[target] = outputId;
            actual = Security(output.File); exact = Hex(expected) == Hex(actual);
            Record(rows, new Row { Case = shape, Operation = "AfterNativeRename", Requested = ServiceMask, Granted = output.Granted, Status = "0x00000000", Identity = Id(output.File), ExpectedHex = Hex(expected), ActualHex = Hex(actual), Exact = exact, Passed = exact && outputId != oldTarget && Id(output.File) == outputId });
        }
    }
    public static void SelfCheck() {
        Need(IntPtr.Size == 8 && Marshal.SizeOf(typeof(ObjectAttributes)) == 48 && Marshal.SizeOf(typeof(UnicodeString)) == 16 && Marshal.SizeOf(typeof(IoStatus)) == 16 && Marshal.SizeOf(typeof(Privilege)) == 16, "Native packing mismatch.");
        Need(ServiceMask == (0x001F01FFu | 0x01000000u) && CallerWriteMask == (0x00100000u | 2u) && BackupSecurity == 0x10000, "Native masks changed.");
        int signatures = 0;
        foreach (var method in typeof(T8MetadataConstructionControl).GetMethods(BindingFlags.NonPublic | BindingFlags.Static)) {
            var dll = (DllImportAttribute)Attribute.GetCustomAttribute(method, typeof(DllImportAttribute)); if (dll == null) continue; signatures++;
            bool nt = method.Name.StartsWith("Nt", StringComparison.Ordinal), kernel = method.Name == "OpenProcess" || method.Name == "GetProcessTimes" || method.Name == "CloseHandle" || method.Name == "GetFileInformationByHandleEx";
            Need(dll.Value == (nt ? "ntdll.dll" : kernel ? "kernel32.dll" : "advapi32.dll") && dll.ExactSpelling && dll.SetLastError == !nt && dll.CallingConvention == CallingConvention.Winapi, "Native import metadata: " + method.Name);
            if (method.ReturnType == typeof(bool)) Need(((MarshalAsAttribute)Attribute.GetCustomAttribute(method.ReturnParameter, typeof(MarshalAsAttribute))).Value == UnmanagedType.Bool, "Native return BOOL packing.");
            foreach (var arg in method.GetParameters()) if (arg.ParameterType == typeof(bool)) Need(((MarshalAsAttribute)Attribute.GetCustomAttribute(arg, typeof(MarshalAsAttribute))).Value == UnmanagedType.Bool, "Native argument BOOL packing.");
        }
        Need(signatures == 19, "Native signature inventory changed.");
        Type ip = typeof(IntPtr), u = typeof(uint), i = typeof(int), b = typeof(bool), s = typeof(string), a = typeof(byte[]), f = typeof(SafeFileHandle);
        Signature("OpenProcess", ip, u, b, i);
        Signature("GetProcessTimes", b, ip, typeof(long).MakeByRefType(), typeof(long).MakeByRefType(), typeof(long).MakeByRefType(), typeof(long).MakeByRefType());
        Signature("CloseHandle", b, ip);
        Signature("OpenProcessToken", b, ip, u, ip.MakeByRefType());
        Signature("OpenThreadToken", b, ip, u, b, ip.MakeByRefType());
        Signature("DuplicateTokenEx", b, ip, u, ip, i, i, ip.MakeByRefType());
        Signature("CreateRestrictedToken", b, ip, u, u, ip, u, ip, u, ip, ip.MakeByRefType());
        Signature("SetThreadToken", b, ip, ip);
        Signature("LookupPrivilegeValueW", b, s, s, typeof(Luid).MakeByRefType());
        Signature("AdjustTokenPrivileges", b, ip, b, typeof(Privilege).MakeByRefType(), u, ip, ip);
        Signature("GetTokenInformation", b, ip, i, a, u, u.MakeByRefType());
        Signature("NtCreateFile", i, f.MakeByRefType(), u, typeof(ObjectAttributes).MakeByRefType(), typeof(IoStatus).MakeByRefType(), ip, u, u, u, u, ip, u);
        Signature("NtQueryObject", i, f, i, a, u, u.MakeByRefType());
        Signature("NtQuerySecurityObject", i, f, u, a, u, u.MakeByRefType());
        Signature("NtSetSecurityObject", i, f, u, a);
        Signature("NtWriteFile", i, f, ip, ip, ip, typeof(IoStatus).MakeByRefType(), a, u, typeof(long).MakeByRefType(), ip);
        Signature("NtFlushBuffersFile", i, f, typeof(IoStatus).MakeByRefType());
        Signature("NtSetInformationFile", i, f, typeof(IoStatus).MakeByRefType(), a, u, i);
        Signature("GetFileInformationByHandleEx", b, f, i, a, u);
    }
    static void Signature(string name, Type result, params Type[] parameters) {
        var method = typeof(T8MetadataConstructionControl).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static);
        Need(method != null && method.ReturnType == result, "Native result signature: " + name);
        var actual = method.GetParameters(); Need(actual.Length == parameters.Length, "Native arity: " + name);
        for (int index = 0; index < actual.Length; index++) Need(actual[index].ParameterType == parameters[index], "Native parameter: " + name + "/" + index);
    }
}
