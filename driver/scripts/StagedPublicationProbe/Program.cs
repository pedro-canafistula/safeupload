using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

// Disposable-VM controller for the existing authenticated publication protocol.
// It deliberately substitutes for the trusted service and writes only benign
// fixture bytes. Actual inspection/UI acceptance uses Test-StagedApprovalFlow.
internal static unsafe class Program
{
    static readonly string Root = @"C:\SafeUpload\Escopo Monitorado";
    static string Prefix;
    static string PathFor(string suffix) => Path.Combine(Root, Prefix + suffix);
    static void Require(bool value, string message)
    { if (!value) throw new InvalidOperationException(message); }
    static void Denied(Action action, string name)
    {
        try { action(); }
        catch (Win32Exception error) when (error.NativeErrorCode == 5)
        { Console.WriteLine(name + "Denied=True"); return; }
        throw new InvalidOperationException(name + " was not denied with access denied.");
    }
    static SafeFileHandle Create(string path) => StagedIdentityProbe.NativeDisposition(path, 2, out _);

    static int Main(string[] args)
    {
        Contract.Verify();
        if (args.Length == 1 && args[0] == "user-connect")
        {
            Require(!WindowsIdentity.GetCurrent().IsSystem, "User fixture unexpectedly runs as SYSTEM.");
            int result = NativePort.Connect(out var handle);
            handle?.Dispose();
            Console.WriteLine($"NonSystemPortConnectHresult=0x{result:X8}");
            Require(result == unchecked((int)0x80070005), "Non-SYSTEM client connected.");
            return 0;
        }
        if (args.Length == 3 && args[0] == "duplicate")
        {
            using var process = OpenProcess(0x40, false, int.Parse(args[1]));
            Require(!process.IsInvalid, "Cannot open controller for handle duplication.");
            Require(DuplicateHandle(process, new IntPtr(long.Parse(args[2])), GetCurrentProcess(),
                out var duplicate, 0, false, 2), "Cannot duplicate communication handle.");
            using (duplicate)
            {
                var grant = Message(Guid.NewGuid(), @"C:\wrong-process.pending", @"C:\wrong-process.txt");
                int result = NativePort.Send(duplicate, ref grant);
                Console.WriteLine($"DuplicatedPortWrongProcessHresult=0x{result:X8}");
                Require(result == unchecked((int)0x80070005), "Other process used publication connection.");
            }
            return 0;
        }
        Require(args.Length == 2 && Guid.TryParseExact(args[0], "N", out _), "Expected fixture GUID and mode.");
        Require(WindowsIdentity.GetCurrent().IsSystem, "Controller must run as LocalSystem.");
        Prefix = "permit-" + args[0];
        int exitCode = 1;
        try
        {
            using var port = new NativePort();
            Console.WriteLine($"ControllerPid={Environment.ProcessId}; Session={System.Diagnostics.Process.GetCurrentProcess().SessionId}; LocalSystem=True");
            string temporary = PathFor(".pending"), destination = PathFor(".txt");
            var grant = Message(Guid.NewGuid(), temporary, destination);
            Require(port.Send(ref grant) == 0, "Valid control permit refused.");
            using (var file = Create(temporary))
            {
                StagedIdentityProbe.Write(file, "BENIGN APPROVED CONTROL");
                StagedIdentityProbe.Rename(file, destination, true);
            }
            int replay = port.Send(ref grant);
            Console.WriteLine($"ExactConsumedMessageReplayHresult=0x{replay:X8}");
            if (args[1] == "before")
            {
                Require(replay == 0, "Recorded consumed-grant gap did not reproduce.");
                using (var file = Create(temporary)) StagedIdentityProbe.Write(file, "BENIGN REPLAY CONTROL");
                Console.WriteLine("ConsumedGrantReactivatedAndSecondTemporaryCreated=True");
                port.Revoke(grant.TransferId);
                foreach (bool zeroId in new[] { false, true })
                {
                    var malformed = Message(zeroId ? Guid.Empty : Guid.NewGuid(), PathFor("-invalid.pending"), PathFor("-invalid.txt"));
                    if (!zeroId) malformed.Control.Reserved = 1;
                    int malformedResult = port.Send(ref malformed);
                    Console.WriteLine($"BeforeMalformedPermit={(zeroId ? "EmptyTransferId" : "ControlReserved")}; Hresult=0x{malformedResult:X8}");
                    Require(malformedResult == 0, "Recorded malformed-message gap did not reproduce.");
                    port.Revoke(malformed.TransferId);
                }
            }
            else
            {
                Require(replay != 0, "Consumed grant reactivated.");
                Denied(() => { using var file = Create(temporary); }, "ConsumedTemporaryRecreate");
                port.Revoke(grant.TransferId);
                FullMatrix(port);
                Console.WriteLine("PublicationPermitNegativeMatrix=True");
            }
            exitCode = 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); }
        finally
        {
            string done = Path.Combine(@"C:\Users\vika\Documents", Prefix + ".result");
            using var stream = new FileStream(done, FileMode.Create, FileAccess.Write, FileShare.Read,
                4096, FileOptions.WriteThrough);
            byte[] result = System.Text.Encoding.UTF8.GetBytes(exitCode.ToString());
            stream.Write(result); stream.Flush(true);
        }
        return exitCode;
    }

    static void FullMatrix(NativePort port)
    {
        var invalid = Message(Guid.NewGuid(), PathFor("-invalid.pending"), PathFor("-invalid.txt"));
        for (int test = 0; test < 10; ++test)
        {
            var message = invalid;
            switch (test)
            {
                case 0: message.Control.Version--; break;
                case 1: message.Control.StructSize--; break;
                case 2: message.Control.Reserved = 1; break;
                case 3: message.TransferId = Guid.Empty; break;
                case 4: message.Reserved = 1; break;
                case 5: message.Revoke = 2; break;
                case 6: message.TemporaryPathLength = 1; break;
                case 7: message.DestinationPathLength = 0; break;
                case 8: message.TemporaryPathLength = 1026; break;
            }
            int result = test == 9 ? NativePort.Send(port.Handle, ref message, 2127) : port.Send(ref message);
            Console.WriteLine($"MalformedPermitCase={test}; Hresult=0x{result:X8}");
            Require(result != 0, "Malformed permit accepted.");
        }
        Denied(() => { using var file = Create(PathFor("-invalid.pending")); }, "MalformedPermitOutput");
        using (var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            Environment.ProcessPath, $"duplicate {Environment.ProcessId} {port.Handle.DangerousGetHandle().ToInt64()}")
            { UseShellExecute = false }))
        {
            Require(child.WaitForExit(10000) && child.ExitCode == 0, "Duplicated-handle wrong-process fixture failed.");
        }

        string temporary = PathFor("-path.pending"), destination = PathFor("-path.txt");
        var grant = Message(Guid.NewGuid(), temporary, destination);
        Require(port.Send(ref grant) == 0, "Path control permit refused.");
        Require(port.Send(ref grant) != 0, "Active grant reset.");
        Denied(() => { using var file = Create(PathFor("-wrong.pending")); }, "WrongTemporary");
        Denied(() => { using var file = StagedIdentityProbe.NativeDisposition(temporary, 3, out _); }, "WrongCreateDisposition");
        string outside = Path.Combine(@"C:\Users\vika\Documents", Prefix + "-wrong-source.txt");
        try
        {
            using var source = Create(outside);
            StagedIdentityProbe.Write(source, "BENIGN WRONG SOURCE CONTROL");
            Denied(() => StagedIdentityProbe.Rename(source, destination, true), "WrongSource");
        }
        finally { File.Delete(outside); }
        using (var file = Create(temporary))
        {
            StagedIdentityProbe.Write(file, "BENIGN PATH CONTROL");
            Denied(() => { using var second = Create(temporary); }, "SecondWriterCreate");
            Denied(() => StagedIdentityProbe.Rename(file, PathFor("-wrong.txt"), true), "WrongDestination");
            StagedIdentityProbe.Rename(file, destination, true);
        }
        port.Revoke(grant.TransferId);

        grant = Message(Guid.NewGuid(), PathFor("-revoked.pending"), PathFor("-revoked.txt"));
        Require(port.Send(ref grant) == 0, "Revocation control permit refused.");
        using (var file = Create(PathFor("-revoked.pending")))
        {
            StagedIdentityProbe.Write(file, "BENIGN REVOKED CONTROL");
            port.Revoke(grant.TransferId);
            Denied(() => StagedIdentityProbe.Rename(file, PathFor("-revoked.txt"), true), "RevokedRename");
        }
        // Explicit revocation ends the attempt; existing publisher retries need
        // to authorize the same transfer again after their journal transition.
        Require(port.Send(ref grant) == 0, "Explicitly revoked attempt could not be authorized again.");
        port.Revoke(grant.TransferId);

        var expiredCreate = Message(Guid.NewGuid(), PathFor("-expired-create.pending"), PathFor("-expired-create.txt"));
        var expiredRename = Message(Guid.NewGuid(), PathFor("-expired-rename.pending"), PathFor("-expired-rename.txt"));
        Require(port.Send(ref expiredCreate) == 0 && port.Send(ref expiredRename) == 0, "Expiry control permits refused.");
        using (var file = Create(PathFor("-expired-rename.pending")))
        {
            StagedIdentityProbe.Write(file, "BENIGN EXPIRY CONTROL");
            System.Threading.Thread.Sleep(31500);
            Denied(() => { using var output = Create(PathFor("-expired-create.pending")); }, "ExpiredCreate");
            Denied(() => StagedIdentityProbe.Rename(file, PathFor("-expired-rename.txt"), true), "ExpiredRename");
        }
        port.Revoke(expiredCreate.TransferId); port.Revoke(expiredRename.TransferId);

        var capacity = new Guid[64];
        for (int i = 0; i < capacity.Length; ++i)
        {
            capacity[i] = Guid.NewGuid();
            var item = Message(capacity[i], PathFor($"-capacity-{i}.pending"), PathFor($"-capacity-{i}.txt"));
            Require(port.Send(ref item) == 0, "Bounded permit table refused an available slot.");
        }
        var overflow = Message(Guid.NewGuid(), PathFor("-overflow.pending"), PathFor("-overflow.txt"));
        Require(port.Send(ref overflow) != 0, "Permit table overflow accepted.");
        port.Revoke(capacity[0]);
        Require(port.Send(ref overflow) == 0, "Revoked permit slot not reusable.");
        foreach (var id in capacity) port.Revoke(id);
        port.Revoke(overflow.TransferId);
        Console.WriteLine("PermitTableBoundedAndReclaimed=True");

        grant = Message(Guid.NewGuid(), PathFor("-disconnect.pending"), PathFor("-disconnect.txt"));
        Require(port.Send(ref grant) == 0, "Disconnect control permit refused.");
        port.Dispose();
        using var reconnected = new NativePort();
        Denied(() => { using var file = Create(PathFor("-disconnect.pending")); }, "DisconnectedOldPermit");
    }

    static SafeUploadPublicationMessage Message(Guid id, string temporary, string destination)
    {
        temporary = PolicyBuilder.ToNtPath(temporary); destination = PolicyBuilder.ToNtPath(destination);
        Require(temporary.Length < Contract.MaxPathChars && destination.Length < Contract.MaxPathChars, "Fixture path too long.");
        var message = new SafeUploadPublicationMessage
        {
            Control = new() { Version = Contract.Version, StructSize = 2128, Command = ControlCommand.StagePublication },
            TransferId = id, TemporaryPathLength = (uint)temporary.Length * 2,
            DestinationPathLength = (uint)destination.Length * 2
        };
        byte[] digest = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("BENIGN FIXTURE"));
        for (int i = 0; i < digest.Length; ++i) message.Digest[i] = digest[i];
        for (int i = 0; i < temporary.Length; ++i) message.TemporaryPath[i] = temporary[i];
        for (int i = 0; i < destination.Length; ++i) message.DestinationPath[i] = destination[i];
        return message;
    }
    sealed class NativePort : IDisposable
    {
        public SafeFileHandle Handle;
        public NativePort() { int result = Connect(out Handle); Require(result == 0, $"System connection refused: 0x{result:X8}"); }
        public static int Connect(out SafeFileHandle handle) => FilterConnectCommunicationPort(Contract.PortName, 0, IntPtr.Zero, 0, IntPtr.Zero, out handle);
        public int Send(ref SafeUploadPublicationMessage message) => Send(Handle, ref message);
        public static int Send(SafeFileHandle handle, ref SafeUploadPublicationMessage message, uint size = 2128)
        { fixed (SafeUploadPublicationMessage* input = &message) return FilterSendMessage(handle, (IntPtr)input, size, IntPtr.Zero, 0, out _); }
        public void Revoke(Guid id)
        { var message = new SafeUploadPublicationMessage { Control = new() { Version = Contract.Version, StructSize = 2128, Command = ControlCommand.StagePublication }, TransferId = id, Revoke = 1 }; Require(Send(ref message) == 0, "Permit revocation failed."); }
        public void Dispose() => Handle.Dispose();
        [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
        static extern int FilterConnectCommunicationPort(string name, uint options, IntPtr context, ushort contextSize, IntPtr security, out SafeFileHandle port);
        [DllImport("fltlib.dll")]
        static extern int FilterSendMessage(SafeFileHandle port, IntPtr input, uint size, IntPtr output, uint outputSize, out uint returned);
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern SafeFileHandle OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(SafeFileHandle sourceProcess, IntPtr source, IntPtr targetProcess, out SafeFileHandle target, uint access, bool inherit, uint options);
}
