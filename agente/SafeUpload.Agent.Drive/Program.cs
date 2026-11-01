using System.Security.AccessControl;
using System.Security.Principal;
using Fsp;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Drive;

/// <summary>
/// Spike host: mounts one SafeUpload drive in front of a backing folder.
///   SafeUpload.Agent.Drive --backing C:\SafeUploadSpike\Envios --private C:\SafeUploadSpike\private --mount S: [--protect-backing]
/// Runs until the file &lt;private&gt;\stop exists or the process is stopped.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        string? Arg(string name)
        {
            int i = Array.IndexOf(args, name);
            return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
        }
        var backing = Arg("--backing");
        var privateRoot = Arg("--private");
        var mount = Arg("--mount") ?? "S:";
        if (backing is null || privateRoot is null)
        {
            Console.Error.WriteLine("usage: SafeUpload.Agent.Drive --backing <dir> --private <dir> [--mount S:] [--protect-backing]");
            return 2;
        }
        Directory.CreateDirectory(privateRoot);
        DriveLog.Open(Path.Combine(privateRoot, "drive.log"));
        Directory.CreateDirectory(backing);
        if (args.Contains("--protect-backing")) ProtectBacking(backing);

        var policy = LocalPolicyStore.CreateStagedDefault();
        policy = policy with
        {
            MonitoredScopes = policy.MonitoredScopes with { DestinationPaths = [mount.TrimEnd('\\') + "\\"] },
        };
        var inspection = new InspectionService(new FixedPolicyStore(policy),
            new LocalQueueAuditSink(Path.Combine(privateRoot, "audit.jsonl")),
            ExtractorRegistry.CreateDefault(), new VerdictCache());

        var fileSystem = new DriveFileSystem(backing, privateRoot, mount, new ContentInspector(inspection));
        var host = new FileSystemHost(fileSystem);
        int status = host.Mount(mount, null, false, 0);
        if (status < 0)
        {
            DriveLog.Write($"mount {mount} failed: NTSTATUS 0x{status:X8}");
            return 1;
        }
        fileSystem.StartBackgroundWork();
        DriveLog.Write($"mounted {host.MountPoint()} -> {backing} (private {privateRoot}), WinFsp {FileSystemHost.Version()}");

        var stopFile = Path.Combine(privateRoot, "stop");
        File.Delete(stopFile);
        using var exit = new ManualResetEventSlim();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; exit.Set(); };
        while (!exit.Wait(500) && !File.Exists(stopFile)) { }
        fileSystem.Stop();
        host.Unmount();
        DriveLog.Write("unmounted");
        return 0;
    }

    /// <summary>Users may read the destination folder but only SYSTEM and administrators may change it.</summary>
    private static void ProtectBacking(string backing)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(backing).SetAccessControl(security);
        DriveLog.Write($"protected {backing}: users read-only");
    }

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
    }
}
