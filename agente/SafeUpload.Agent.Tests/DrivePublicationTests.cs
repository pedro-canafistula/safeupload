using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Drive;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Gate;

namespace SafeUpload.Agent.Tests;

// Exercise the real filesystem reconciler and Windows file sharing without mounting a drive or loading a driver.
public sealed partial class DrivePublicationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Approval_does_not_audit_success_until_the_destination_is_replaced()
    {
        using var f = Create("Clean new bytes");
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.True(decision.Approved);
        await f.Service.HandleDecisionAsync(decision, f.Policy, null);
        Assert.Empty(await f.Pending());
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));

        f.Reconcile();
        var publication = Assert.Single(f.Observer.Publications);
        Assert.True(publication.Succeeded);
        Assert.Equal("Clean new bytes", File.ReadAllText(f.Target));
        Assert.Equal("Clean new bytes", Assert.Single(f.Observer.BytesAtPublication));
        await f.Service.HandlePublicationAsync(publication);
        var audit = Assert.Single(await f.Pending());
        Assert.Equal(Verdict.Approved, audit.Verdict);
        Assert.Equal(publication.EventId, audit.EventId);
        Assert.Equal(f.Target, audit.DestinationPath);
        f.Reconcile();
        Assert.Single(f.Observer.Publications);
    }

    [Theory]
    [InlineData("clean")]
    [InlineData("alert")]
    [InlineData("justified")]
    public async Task Locked_destination_reports_one_failure_preserves_original_and_retries_same_snapshot(string mode)
    {
        var bytes = mode == "clean" ? "Clean retry bytes" : "CPF: 529.982.247-25";
        using var f = Create(bytes, alert: mode == "alert");
        f.Inspect();
        if (mode != "clean") Assert.True(f.FileSystem.Approve(Assert.Single(f.Observer.Decisions).VersionId));
        long previousVersion = f.Content.PublishedVersion;
        using (var held = new FileStream(f.Target, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                var error = Assert.Throws<TargetInvocationException>(f.Reconcile).InnerException;
                Assert.True(error is IOException or UnauthorizedAccessException, error?.ToString());
            }
            var failed = Assert.Single(f.Observer.Publications);
            Assert.False(failed.Succeeded);
            Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
            Assert.True(File.Exists(f.Content.ApprovedSnapshot));
            Assert.Equal(previousVersion, f.Content.PublishedVersion);
            Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.Target)!, ".~su-*"));
            await f.Service.HandlePublicationAsync(failed);
            var audit = Assert.Single(await f.Pending());
            Assert.Equal(Verdict.Blocked, audit.Verdict);
            Assert.Equal("publication_failed", audit.NotInspectedReason);
        }
        f.Reconcile();
        var success = f.Observer.Publications[1];
        Assert.True(success.Succeeded);
        Assert.NotEqual(f.Observer.Publications[0].EventId, success.EventId);
        Assert.Equal(f.Observer.Publications[0].Decision.VersionId, success.Decision.VersionId);
        Assert.Equal(bytes, File.ReadAllText(f.Target));
        await f.Service.HandlePublicationAsync(success);
        var events = await f.Pending();
        Assert.Equal(2, events.Count);
        Assert.Equal(Verdict.Blocked, events[0].Verdict);
        Assert.Equal(Verdict.Approved, events[1].Verdict);
        Assert.Null(events[1].NotInspectedReason);
        f.Reconcile();
        Assert.Equal(2, f.Observer.Publications.Count);
    }

    [Fact]
    public void Missing_snapshot_never_reports_success_and_a_restored_snapshot_can_be_published()
    {
        using var f = Create("Snapshot bytes");
        f.Inspect();
        var snapshot = f.Content.ApprovedSnapshot!;
        File.Delete(snapshot);
        Assert.IsAssignableFrom<IOException>(Assert.Throws<TargetInvocationException>(f.Reconcile).InnerException);
        Assert.False(Assert.Single(f.Observer.Publications).Succeeded);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.Target)!, ".~su-*"));
        File.WriteAllText(snapshot, "Snapshot bytes");
        f.Reconcile();
        Assert.True(f.Observer.Publications[1].Succeeded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Justification_and_alertar_report_success_only_after_copying_the_exact_blocked_version(bool alert)
    {
        const string bytes = "CPF: 529.982.247-25";
        using var f = Create(bytes, alert);
        f.Inspect();
        var blocked = Assert.Single(f.Observer.Decisions);
        Assert.False(blocked.Approved);
        Assert.Equal(Verdict.Blocked, blocked.Result!.Verdict);
        await f.Service.HandleDecisionAsync(blocked, f.Policy, kind => f.FileSystem.Approve(blocked.VersionId, kind));
        if (alert)
            Assert.Empty(await f.Pending());
        else
        {
            Assert.Equal(blocked.VersionId, Assert.Single(await f.Pending()).EventId);
            Assert.True(f.Justifications.TryConsume(blocked.VersionId.ToString(), 7, "S-1-5-21-111-222-333-1001", PolicyContentFingerprint.Compute(f.Policy), out var approve));
            await f.Sink.RecordOverrideAsync(blocked.VersionId.ToString(), "Authorized synthetic test", CancellationToken.None);
            Assert.True(approve!());
            Assert.False(approve());
        }
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
        f.Reconcile();
        var publication = Assert.Single(f.Observer.Publications);
        Assert.True(publication.Succeeded);
        Assert.Equal(blocked.VersionId, publication.Decision.VersionId);
        Assert.NotEqual(blocked.VersionId, publication.EventId);
        Assert.Equal(bytes, File.ReadAllText(f.Target));
        await f.Service.HandlePublicationAsync(publication);
        var events = await f.Pending();
        Assert.Equal(alert ? 1 : 2, events.Count);
        Assert.Equal(Verdict.Approved, events[^1].Verdict);
        Assert.Contains(Category.Cpf, events[^1].Categories);
        if (!alert)
        {
            Assert.Equal(Verdict.Blocked, events[0].Verdict);
            Assert.Equal(blocked.VersionId, Assert.Single(await f.Sink.ReadPendingOverridesAsync(10, CancellationToken.None)).EventId);
        }
    }

    [Fact]
    public async Task Alertar_with_stale_authorization_stays_blocked_without_a_success_event()
    {
        using var f = Create("CPF: 529.982.247-25", alert: true);
        f.Inspect();
        await f.Service.HandleDecisionAsync(Assert.Single(f.Observer.Decisions), f.Policy, _ => false);
        Assert.Equal(Verdict.Blocked, Assert.Single(await f.Pending()).Verdict);
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        Assert.Equal("Previous bytes", File.ReadAllText(f.Target));
    }

    [Fact]
    public async Task Alertar_does_not_release_a_failed_inspection()
    {
        using var f = Create("PK\u0003\u0004broken zip", alert: true);
        File.WriteAllBytes(f.Content.Path, System.Text.Encoding.UTF8.GetBytes("PK\u0003\u0004broken zip"));
        f.Content.Size = new FileInfo(f.Content.Path).Length;
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.False(decision.Approved);
        Assert.NotNull(decision.Result!.Reason);
        bool called = false;
        await f.Service.HandleDecisionAsync(decision, f.Policy, _ => { called = true; return true; });
        Assert.False(called);
        Assert.Equal(Verdict.Blocked, Assert.Single(await f.Pending()).Verdict);
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
    }

    [Fact]
    public async Task Publication_after_explicit_justification_preserves_the_initial_inspection_failure_reason()
    {
        using var f = Create("Unused bytes");
        File.WriteAllBytes(f.Content.Path, "PK\u0003\u0004broken zip"u8.ToArray());
        f.Content.Size = new FileInfo(f.Content.Path).Length;
        f.Inspect();
        var decision = Assert.Single(f.Observer.Decisions);
        Assert.NotNull(decision.Result!.Reason);
        Assert.True(f.FileSystem.Approve(decision.VersionId));
        f.Reconcile();
        await f.Service.HandlePublicationAsync(Assert.Single(f.Observer.Publications));
        var audit = Assert.Single(await f.Pending());
        Assert.Equal(Verdict.Approved, audit.Verdict);
        Assert.Equal(decision.Result.Reason, audit.NotInspectedReason);
    }

    [Fact]
    public async Task Rename_before_publication_reports_the_final_name_and_destination()
    {
        using var f = Create("Final-name bytes");
        f.Inspect();
        Assert.Equal(0, f.FileSystem.Open(@"\report.txt", 0, 0, out var node, out var handle, out _, out _));
        try { Assert.Equal(0, f.FileSystem.Rename(node, handle, @"\report.txt", @"\final.txt", true)); }
        finally { f.FileSystem.Close(node, handle); }
        f.Reconcile();
        Assert.Empty(f.Observer.Publications);
        f.Inspect(); // The new name is a new publication context.
        f.Reconcile();
        var publication = Assert.Single(f.Observer.Publications);
        Assert.EndsWith(@"\final.txt", publication.DestinationPath);
        Assert.Equal(@"S:\final.txt", publication.Decision.DrivePath);
        await f.Service.HandlePublicationAsync(publication);
        var audit = Assert.Single(await f.Pending());
        Assert.Equal("final.txt", audit.FileName);
        Assert.Equal(publication.DestinationPath, audit.DestinationPath);
    }

    private Fixture Create(string bytes, bool alert = false, Func<IPolicyStore, IPolicyStore>? wrapPolicy = null)
    {
        var backing = Path.Combine(_workspace.Root, "backing");
        Directory.CreateDirectory(backing);
        var target = Path.Combine(backing, "report.txt");
        File.WriteAllText(target, "Previous bytes");
        var policy = new Policy(1, new HashSet<Category> { Category.Cpf },
            new MonitoredScopes(new HashSet<string> { ".txt", ".zip" }, [], true, false), 10, 5, true,
            new HashSet<string>(), AuditOnly: alert, OverrideAllowed: true);
        var policies = new Policies(policy);
        var effectivePolicies = wrapPolicy?.Invoke(policies) ?? policies;
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var engine = new InspectionService(effectivePolicies, sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var observer = new Observer();
        var fs = new DriveFileSystem(backing, Path.Combine(_workspace.Root, "private"), "S:",
            new ContentInspector(engine, effectivePolicies), observer, DestinationKind.RemovableDrive, "Synthetic", () => 123);
        Assert.Equal(0, fs.Open(@"\report.txt", 0, 0, out var node, out var handle, out _, out _));
        var content = ((Handle)handle).Node.Content!;
        fs.Close(node, handle);
        content.Path = Path.Combine(_workspace.Root, "private", "stage", Guid.NewGuid().ToString("N"));
        File.WriteAllText(content.Path, bytes);
        content.IsStage = true;
        content.Size = new FileInfo(content.Path).Length;
        content.Version = 1;
        content.Writer = new DriveWriter(123, "explorer.exe", 7, "S-1-5-21-111-222-333-1001", "synthetic-writer");
        var gate = new GateClient(NullLogger<GateClient>.Instance);
        var justifications = new DriveJustifications();
        var service = new DriveService(effectivePolicies, engine, NotificationTestHub.Create(), justifications,
            gate, new ConfigurationBuilder().Build(), NullLogger<DriveService>.Instance);
        return new Fixture(fs, content, observer, target, policies, sink, service, gate, justifications, effectivePolicies as IDisposable);
    }

    private sealed record Fixture(DriveFileSystem FileSystem, Content Content, Observer Observer, string Target,
        Policies Store, LocalQueueAuditSink Sink, DriveService Service, GateClient Gate, DriveJustifications Justifications,
        IDisposable? OwnedPolicy) : IDisposable
    {
        public Policy Policy => Store.Current;
        // No worker is started: deterministic calls exercise the same inspection and reconciler used by it.
        public void Inspect() => Invoke("InspectOne", Content);
        public void Reconcile() => Invoke("Reconcile");
        private void Invoke(string method, params object[] arguments) => typeof(DriveFileSystem)
            .GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(FileSystem, arguments);
        public Task<IReadOnlyList<AuditEvent>> Pending() => Sink.ReadPendingAsync(10, CancellationToken.None);
        public void Dispose() { Service.Dispose(); Gate.Dispose(); FileSystem.Stop(); OwnedPolicy?.Dispose(); }
    }

    private sealed class Policies(Policy policy) : IPolicyStore
    {
        public Policy Current { get; set; } = policy;
        public Exception? Failure { get; set; }
        public Action? BeforeLoad { get; set; }
        public Task<Policy> LoadAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            BeforeLoad?.Invoke();
            if (Failure is { } error) throw error;
            return Task.FromResult(Current);
        }
    }

    private sealed class Observer : IDriveObserver
    {
        public List<DriveDecision> Decisions { get; } = [];
        public List<DrivePublication> Publications { get; } = [];
        public List<string> BytesAtPublication { get; } = [];
        public DriveWriter? IdentifyWriter(int processId) =>
            new(123, "explorer.exe", 7, "S-1-5-21-111-222-333-1001", "synthetic-writer");
        public void OnDecision(DriveDecision decision) => Decisions.Add(decision);
        public void OnPublication(DrivePublication publication)
        {
            Publications.Add(publication);
            BytesAtPublication.Add(File.ReadAllText(publication.DestinationPath));
        }
    }
}
