using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

// A disposable LocalSystem gate for the production journal class. It neither
// loads a filter nor edits the live service journal or any existing user file.
internal static class Program
{
    private static readonly CancellationToken None = CancellationToken.None;
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier UsersSid = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly List<string> Passed = [];
    private const string RootPrefix = "SafeUpload-JournalProbe-";
    private static string Root = "";

    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 3) return 2;
        Root = Path.GetFullPath(args[0]);
        string result = Path.GetFullPath(args[1]), ready = Path.GetFullPath(args[2]);
        int exitCode = 1;
        string? failure = null;
        try
        {
            Require(OperatingSystem.IsWindows(), "Windows is required.");
            using var identity = WindowsIdentity.GetCurrent();
            Require(identity.User?.Equals(SystemSid) == true, "Probe must run as LocalSystem.");
            string parent = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            Require(Path.GetDirectoryName(Root)!.Equals(parent, StringComparison.OrdinalIgnoreCase) &&
                    Path.GetFileName(Root).StartsWith(RootPrefix, StringComparison.Ordinal) &&
                    Guid.TryParseExact(Path.GetFileName(Root)[RootPrefix.Length..], "N", out _), "Invalid disposable root.");
            Require(!Directory.Exists(Root), "Refusing to reuse a fixture root.");
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (!File.Exists(ready) && DateTime.UtcNow < deadline) await Task.Delay(50);
            Require(File.Exists(ready), "Launcher did not acknowledge the process.");
            PrivateDirectory(Root);
            Console.WriteLine($"UTC={DateTimeOffset.UtcNow:O}; Identity={identity.User}; ProcessId={Environment.ProcessId}");
            Console.WriteLine($"OS={Environment.OSVersion.Version}; ServiceAssemblySHA256={Digest(typeof(StagedTransferJournal).Assembly.Location)}");

            foreach (bool hard in new[] { false, true })
            foreach (bool restart in new[] { false, true })
                await Case($"{(hard ? "hardlink" : "symlink")}-{(restart ? "restart" : "read")}", async f =>
                {
                    string outside = Path.Combine(f.Directory, "outside.json");
                    File.Copy(f.Manifest, outside);
                    var info = new FileInfo(outside);
                    var security = info.GetAccessControl();
                    security.AddAccessRule(new FileSystemAccessRule(UsersSid, FileSystemRights.Read, AccessControlType.Allow));
                    info.SetAccessControl(security);
                    string acl = Descriptor(info), bytes = Digest(outside);
                    File.Delete(f.Manifest);
                    if (hard)
                    {
                        if (!CreateHardLink(f.Manifest, outside, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    else File.CreateSymbolicLink(f.Manifest, outside);
                    if (restart) await Reject<IOException>(() => { _ = f.Restart(); return Task.CompletedTask; });
                    else await Reject<IOException>(() => f.Journal.ReadAsync(f.Transfer.TransferId, None));
                    Require(Digest(outside) == bytes && Descriptor(info) == acl, "Redirected external object changed.");
                    File.Delete(f.Manifest); // Delete only the fixture link.
                });

            foreach (bool link in new[] { false, true })
                await Case(link ? "directory-link" : "unexpected-directory", async f =>
                {
                    string outside = Path.Combine(f.Directory, "outside-folder");
                    PrivateDirectory(outside);
                    string content = Path.Combine(outside, "retained.txt");
                    File.WriteAllText(content, "BENIGN EXTERNAL CONTENT");
                    string acl = Descriptor(new DirectoryInfo(outside)), digest = Digest(content);
                    string child = Path.Combine(f.JournalDirectory, "unexpected");
                    if (link) Directory.CreateSymbolicLink(child, outside); else PrivateDirectory(child);
                    await Reject<IOException>(() => { _ = f.Restart(); return Task.CompletedTask; });
                    Require(Descriptor(new DirectoryInfo(outside)) == acl && Digest(content) == digest, "External directory changed.");
                    Directory.Delete(child); // Nonrecursive: never follows the fixture link.
                });

            foreach (var (directory, restart) in new[] { (false, false), (false, true), (true, true) })
                await Case($"unsafe-acl-{(directory ? "directory" : "file")}-{(restart ? "restart" : "read")}", async f =>
                {
                    FileSystemInfo info = directory ? new DirectoryInfo(f.JournalDirectory) : new FileInfo(f.Manifest);
                    AddUsersWrite(info);
                    string acl = Descriptor(info), bytes = Digest(f.Manifest);
                    if (restart) await Reject<UnauthorizedAccessException>(() => { _ = f.Restart(); return Task.CompletedTask; });
                    else await Reject<UnauthorizedAccessException>(() => f.Journal.ReadAsync(f.Transfer.TransferId, None));
                    Require(Descriptor(info) == acl && Digest(f.Manifest) == bytes, "Unsafe ACL or manifest was silently repaired.");
                });

            foreach (string corruption in new[] { "null-transfer", "unknown-state", "negative-generation", "relative-path",
                         "zero-owner", "unsealed-publishing", "zero-rename", "negative-tombstone", "incomplete-json", "oversize" })
                await Case(corruption, async f =>
                {
                    var entry = await f.Journal.ReadAsync(f.Transfer.TransferId, None);
                    entry = corruption switch
                    {
                        "null-transfer" => entry with { Transfer = null! },
                        "unknown-state" => entry with { State = (TransferJournalState)99 },
                        "negative-generation" => entry with { DestinationGeneration = -1 },
                        "relative-path" => entry with { Transfer = f.Transfer with { DestinationPath = "relative.txt" } },
                        "zero-owner" => entry with { Transfer = f.Transfer with { ProcessId = 0 } },
                        "unsealed-publishing" => entry with { State = TransferJournalState.Publishing, Sha256Hex = new string('A', 64) },
                        "zero-rename" => entry with { PendingRename = new StagedRename(0, f.Transfer.DestinationPath, false) },
                        "negative-tombstone" => entry with { NamespaceTombstones = new StagedNameTombstone(f.Transfer.DestinationPath, -1, null) },
                        _ => entry
                    };
                    File.WriteAllText(f.Manifest, corruption == "incomplete-json" ? "{\"Transfer\":" : JsonSerializer.Serialize(entry));
                    if (corruption == "oversize") File.AppendAllText(f.Manifest, new string(' ', 128 * 1024));
                    string bytes = Digest(f.Manifest);
                    await Reject<InvalidDataException>(() => f.Journal.ReadAsync(f.Transfer.TransferId, None));
                    await Reject<InvalidDataException>(() => f.Restart().RetainInterruptedAsync(None));
                    Require(Digest(f.Manifest) == bytes, "Malformed journal bytes were changed by recovery.");
                });

            await Case("legacy-zero-generation", async f =>
            {
                var entry = (await f.Journal.ReadAsync(f.Transfer.TransferId, None)) with { DestinationGeneration = 0 };
                File.WriteAllText(f.Manifest, JsonSerializer.Serialize(entry));
                Require((await f.Restart().ReadAsync(f.Transfer.TransferId, None)).DestinationGeneration == 0, "Legacy generation was rejected.");
                await f.Restart().RetainInterruptedAsync(None);
                Require((await f.Journal.ReadAsync(f.Transfer.TransferId, None)).State == TransferJournalState.Unsealed, "Legacy allocation was implicitly sealed.");
            });

            foreach (var state in new[] { TransferJournalState.Allocated, TransferJournalState.Unsealed,
                         TransferJournalState.Inspecting, TransferJournalState.Approved })
                await Case("recovery-" + state, async f =>
                {
                    if (state == TransferJournalState.Unsealed)
                        await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Allocated, state, null, None);
                    else if (state != TransferJournalState.Allocated)
                    {
                        await f.Journal.SealAsync(f.Transfer.TransferId, f.Transfer.ProcessId, f.Transfer.StagePath, None);
                        await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, null, None);
                        if (state == TransferJournalState.Approved)
                            await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Inspecting, state, Digest(f.Transfer.StagePath), None);
                    }
                    var restarted = f.Restart();
                    await restarted.RetainInterruptedAsync(None);
                    await restarted.ReconcilePublishingAsync(None);
                    var recovered = await restarted.ReadAsync(f.Transfer.TransferId, None);
                    Require(recovered.State == (state is TransferJournalState.Allocated or TransferJournalState.Unsealed
                            ? TransferJournalState.Unsealed : TransferJournalState.Retained), "Recovery inferred a seal or approval.");
                    if (recovered.State == TransferJournalState.Unsealed)
                        await Reject<InvalidOperationException>(() => restarted.TransitionAsync(f.Transfer.TransferId,
                            TransferJournalState.Unsealed, TransferJournalState.Inspecting, null, None));
                });

            await Case("pending-rename-recovery", async f =>
            {
                string destination = Path.Combine(f.Directory, "renamed.txt");
                await f.Journal.PrepareRenameAsync(f.Transfer.TransferId, 1, f.Transfer.ProcessId, destination, false, None);
                string bytes = Digest(f.Manifest);
                await f.Restart().RetainInterruptedAsync(None);
                await f.Restart().ReconcilePublishingAsync(None);
                Require(Digest(f.Manifest) == bytes && !File.Exists(destination), "Recovery inferred a pending rename outcome.");
            });

            foreach (bool matches in new[] { false, true })
                await Case(matches ? "publishing-already-matched" : "publishing-mismatched", async f =>
                {
                    await f.Journal.SealAsync(f.Transfer.TransferId, f.Transfer.ProcessId, f.Transfer.StagePath, None);
                    await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, null, None);
                    await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Approved,
                        matches ? Digest(f.Transfer.DestinationPath) : Digest(f.Transfer.StagePath), None);
                    await f.Journal.TransitionAsync(f.Transfer.TransferId, TransferJournalState.Approved, TransferJournalState.Publishing, null, None);
                    await f.Restart().ReconcilePublishingAsync(None);
                    Require((await f.Journal.ReadAsync(f.Transfer.TransferId, None)).State ==
                        (matches ? TransferJournalState.Released : TransferJournalState.Retained), "Publication recovery ignored the exact destination digest.");
                });

            await Case("cancelled-read", async f =>
            {
                string bytes = Digest(f.Manifest);
                await Reject<OperationCanceledException>(() => f.Journal.ReadAsync(f.Transfer.TransferId, new CancellationToken(true)));
                Require(Digest(f.Manifest) == bytes, "Cancelled read changed the journal.");
            });
            exitCode = 0;
        }
        catch (Exception error) { failure = error.ToString(); Console.Error.WriteLine(error); }
        finally
        {
            // Retain every disposable fixture for inspection; never recursively
            // clean a root that intentionally contains reparse-point fixtures.
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { ExitCode = exitCode, Passed, Failure = failure, FixtureRoot = Root });
            using var file = new FileStream(result, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
            file.Write(bytes); file.Flush(true);
        }
        return exitCode;
    }

    private sealed record Fixture(string Directory, string JournalDirectory, string Manifest,
        StagedTransfer Transfer, StagedTransferJournal Journal)
    {
        internal StagedTransferJournal Restart() => new(JournalDirectory, requireProtectedParent: true);
    }

    private static async Task Case(string name, Func<Fixture, Task> action)
    {
        string directory = Path.Combine(Root, name);
        PrivateDirectory(directory);
        string stage = Path.Combine(directory, "private.txt"), destination = Path.Combine(directory, "public.txt");
        File.WriteAllText(stage, "CPF: 123.456.789-09 PRIVATE VERSION");
        File.WriteAllText(destination, "BENIGN PUBLIC ORIGINAL");
        string stageHash = Digest(stage), destinationHash = Digest(destination);
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, destination, DestinationKind.RemovableDrive,
            "StagedJournalProbe.exe", Environment.ProcessId, 0);
        string journalDirectory = Path.Combine(directory, "journal");
        var journal = new StagedTransferJournal(journalDirectory, requireProtectedParent: true);
        await journal.CreateAsync(transfer, None);
        var fixture = new Fixture(directory, journalDirectory, Path.Combine(journalDirectory, transfer.TransferId.ToString("N") + ".json"), transfer, journal);
        await action(fixture);
        Require(Digest(stage) == stageHash && Digest(destination) == destinationHash, "Recovery changed private or public bytes.");
        Passed.Add(name);
        Console.WriteLine($"JournalCase={name}; PASS; PrivateSHA256={stageHash}; DestinationSHA256={destinationHash}");
    }

    private static void PrivateDirectory(string path)
    {
        var security = new DirectorySecurity();
        security.SetOwner(SystemSid);
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { SystemSid, AdminSid }) security.AddAccessRule(new FileSystemAccessRule(sid,
            FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(path).Create(security);
    }

    private static void AddUsersWrite(FileSystemInfo info)
    {
        var rule = new FileSystemAccessRule(UsersSid, FileSystemRights.Write, AccessControlType.Allow);
        if (info is DirectoryInfo directory) { var acl = directory.GetAccessControl(); acl.AddAccessRule(rule); directory.SetAccessControl(acl); }
        else { var file = (FileInfo)info; var acl = file.GetAccessControl(); acl.AddAccessRule(rule); file.SetAccessControl(acl); }
    }

    private static string Descriptor(FileSystemInfo info) => (info is DirectoryInfo directory
        ? (FileSystemSecurity)directory.GetAccessControl() : ((FileInfo)info).GetAccessControl()).GetSecurityDescriptorSddlForm(AccessControlSections.All);
    private static string Digest(string path) { using var file = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(file)); }
    private static void Require(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static async Task Reject<T>(Func<Task> action) where T : Exception
    {
        try { await action(); } catch (T) { return; }
        throw new InvalidOperationException("Expected rejection: " + typeof(T).Name);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);
}
