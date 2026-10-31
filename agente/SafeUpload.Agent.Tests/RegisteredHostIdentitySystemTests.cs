using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Domain;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

/// <summary>Explicit SYSTEM phases, each executed in a separate process by CI or the matrix.</summary>
public sealed class RegisteredHostIdentitySystemTests(ITestOutputHelper output)
{
    [IdentitySystemFact("provision")]
    public Task Provisiona_arquivo_protegido_SYSTEM() => VerifyPhase("provision");

    [IdentitySystemFact("restore")]
    public Task Recupera_arquivo_protegido_em_outro_processo_SYSTEM() => VerifyPhase("restore");

    private async Task VerifyPhase(string expectedPhase)
    {
        Assert.True(WindowsIdentity.GetCurrent().IsSystem);
        string phase = Environment.GetEnvironmentVariable("SAFEUPLOAD_IDENTITY_PHASE")!;
        Assert.Equal(expectedPhase, phase);
        using var process = Process.GetCurrentProcess();
        output.WriteLine($"HOST_IDENTITY_PROCESS={phase}|{process.Id}|{process.StartTime.ToUniversalTime().Ticks}");
        string root = Path.GetFullPath(Environment.GetEnvironmentVariable("SAFEUPLOAD_IDENTITY_TEST_ROOT")!);
        string runnerTemp = Path.GetFullPath(Environment.GetEnvironmentVariable("RUNNER_TEMP")!);
        Assert.StartsWith(Path.TrimEndingDirectorySeparator(runnerTemp) + Path.DirectorySeparatorChar, root,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(root.StartsWith(AgentPaths.RootDirectory, StringComparison.OrdinalIgnoreCase));
        string file = Path.Combine(root, "protected", "host-registration.json");
        var server = new Uri("https://identity-test.example/agent/");
        var store = new RegisteredHostIdentityStore(file);
        if (phase == "provision")
        {
            Assert.False(Directory.Exists(root));
            Assert.Equal(23, store.Resolve(server, 23));
        }
        else
        {
            Assert.Equal("restore", phase);
            var before = File.ReadAllBytes(file);
            Assert.Equal(23, store.Resolve(server, null));
            Assert.Equal("server_mismatch", Assert.Throws<HostIdentityException>(() =>
                store.Resolve(new Uri("https://another-test.example/agent/"), null)).Code);
            Assert.Equal(before, File.ReadAllBytes(file));
        }
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var fileAcl = new FileInfo(file).GetAccessControl();
        var directoryAcl = new DirectoryInfo(Path.GetDirectoryName(file)!).GetAccessControl();
        Assert.Equal(system, fileAcl.GetOwner(typeof(SecurityIdentifier)));
        Assert.Equal(system, directoryAcl.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(fileAcl.AreAccessRulesProtected);
        Assert.True(directoryAcl.AreAccessRulesProtected);
        Assert.Equal(2, fileAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
        Assert.Equal(2, directoryAcl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
        await VerifyQueuePhase(root, phase, system);
    }

    private async Task VerifyQueuePhase(string root, string phase, SecurityIdentifier system)
    {
        // Same production trust policy, redirected only to the runner-owned fixture.
        string file = Path.Combine(root, "protected", "queue.jsonl");
        var protection = new QueueStorageProtection(file);
        LocalQueueAuditSink Reopen() => new(file, protection);
        var id = Guid.Parse("00000000-0000-0000-0000-000000000023");
        var occurred = DateTimeOffset.Parse("2026-10-31T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        var requested = new AuditOverride(id, "synthetic business reason", occurred, "SYNTHETIC", "SYNTHETIC");
        if (phase == "provision")
        {
            Assert.False(File.Exists(file));
            await Reopen().WriteAsync(new AuditEvent(id, occurred, "SYNTHETIC", "SYNTHETIC", "ordinary.txt", ".txt",
                1, Verdict.Approved, [], [], "synthetic", 42, "synthetic", null, 1, 0, false), default);
            await Reopen().RecordOverrideAsync(requested, default);
        }
        Assert.Equal(id, Assert.Single(await Reopen().ReadPendingAsync(10, default)).EventId);
        Assert.Equal(requested, Assert.Single(await Reopen().ReadPendingOverridesAsync(10, default)));
        if (phase == "restore")
        {
            await Reopen().MarkDispatchedAsync([id], default);
            await Reopen().MarkOverridesDispatchedAsync([requested], default);
            Assert.Empty(await Reopen().ReadPendingAsync(10, default));
            Assert.Empty(await Reopen().ReadPendingOverridesAsync(10, default));
            Assert.True(Assert.Single(await Reopen().ReadRecentAsync(10, default)).Dispatched);
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(file)!, "queue.jsonl.*.tmp"));
        }
        var acl = new FileInfo(file).GetAccessControl();
        protection.Verify(acl, directory: false);
        Assert.Equal(system, acl.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(acl.AreAccessRulesProtected);
        Assert.Equal(2, acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count);
        output.WriteLine($"AUDIT_QUEUE_SYSTEM={phase}|production-two-trustees|passed");
    }
}

public sealed class IdentitySystemFactAttribute : FactAttribute
{
    public IdentitySystemFactAttribute(string expectedPhase)
    {
        if (!OperatingSystem.IsWindows() || !WindowsIdentity.GetCurrent().IsSystem ||
            Environment.GetEnvironmentVariable("SAFEUPLOAD_IDENTITY_PHASE") != expectedPhase)
            Skip = "Exige a fase explícita correspondente e execução SYSTEM em fixture isolada.";
    }
}
