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

public sealed class DriveShutdownTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Service_stop_waits_for_queued_report_and_reopened_queue_keeps_its_id(bool publication)
    {
        using var work = new TestWorkspace();
        var sink = new HeldSink(new LocalQueueAuditSink(work.QueueFile));
        using var fixture = new Fixture(work, sink);
        var decision = fixture.Decision(publication);
        fixture.Report(decision, publication);
        await sink.Entered.Task.WaitAsync(Deadline);
        var stopping = fixture.Service.StopAsync(default);
        try
        {
            await Task.WhenAny(stopping, Task.Delay(100));
            Assert.False(stopping.IsCompleted);
        }
        finally { sink.Release.TrySetResult(); await stopping.WaitAsync(Deadline); }
        var audit = Assert.Single(await new LocalQueueAuditSink(work.QueueFile).ReadPendingAsync(10, default));
        Assert.Equal(publication ? fixture.PublicationId : decision.VersionId, audit.EventId);
        Assert.Equal(publication ? Verdict.Approved : Verdict.Blocked, audit.Verdict);
    }

    [Fact]
    public async Task Service_stop_deadline_reports_incomplete_drain_and_can_wait_again()
    {
        using var work = new TestWorkspace();
        var sink = new HeldSink(new LocalQueueAuditSink(work.QueueFile));
        using var fixture = new Fixture(work, sink);
        fixture.Report(fixture.Decision(true), true);
        await sink.Entered.Task.WaitAsync(Deadline);
        using var stop = new CancellationTokenSource();
        var stopping = fixture.Service.StopAsync(stop.Token);
        stop.Cancel();
        try { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stopping.WaitAsync(Deadline)); }
        finally { sink.Release.TrySetResult(); await fixture.Service.StopAsync(default).WaitAsync(Deadline); }
        Assert.Equal(fixture.PublicationId,
            Assert.Single(await new LocalQueueAuditSink(work.QueueFile).ReadPendingAsync(10, default)).EventId);
    }

    [Fact]
    public async Task Filesystem_stop_waits_for_the_active_worker_and_keeps_private_bytes()
    {
        using var work = new TestWorkspace();
        var policy = new HeldPolicy(ignoreCancellation: true);
        using var fixture = new Fixture(work, new LocalQueueAuditSink(work.QueueFile), policy);
        fixture.FileSystem.StartBackgroundWork();
        await policy.Entered.Task.WaitAsync(Deadline);
        var stopping = Task.Run(fixture.FileSystem.Stop);
        try
        {
            await Task.WhenAny(stopping, Task.Delay(100));
            Assert.False(stopping.IsCompleted);
        }
        finally
        {
            policy.Release.TrySetResult();
            await stopping.WaitAsync(Deadline);
            // Also allow the pre-fix worker to finish before disposing its temporary directory.
            await Task.WhenAny(fixture.Observer.Completed.Task, Task.Delay(100));
        }
        Assert.Empty(fixture.Observer.Decisions);
        Assert.False(fixture.Content.Inspecting);
        Assert.Equal("Private version", File.ReadAllText(fixture.Content.Path));
        Assert.Equal("Published version", File.ReadAllText(fixture.Target));
    }

    [Fact]
    public async Task Cancelled_inspection_is_not_reported_as_a_new_block()
    {
        using var work = new TestWorkspace();
        var policy = new HeldPolicy(ignoreCancellation: false);
        using var fixture = new Fixture(work, new LocalQueueAuditSink(work.QueueFile), policy);
        var inspecting = Task.Run(() => Invoke(fixture.FileSystem, "InspectOne", fixture.Content));
        await policy.Entered.Task.WaitAsync(Deadline);
        fixture.FileSystem.Stop();
        try
        {
            var error = await Assert.ThrowsAsync<TargetInvocationException>(() => inspecting.WaitAsync(Deadline));
            Assert.IsAssignableFrom<OperationCanceledException>(error.InnerException);
        }
        finally { policy.Release.TrySetResult(); await Task.WhenAny(inspecting, Task.Delay(100)); }
        Assert.Empty(fixture.Observer.Decisions);
        Assert.False(fixture.Content.Inspecting);
        Assert.True(File.Exists(fixture.Content.Path));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(work.Root, "private", "snapshots")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_worker_cannot_be_started_twice_or_after_stop(bool stopped)
    {
        using var work = new TestWorkspace();
        using var fixture = new Fixture(work, new LocalQueueAuditSink(work.QueueFile));
        if (stopped) fixture.FileSystem.Stop();
        else fixture.FileSystem.StartBackgroundWork();
        Assert.Throws<InvalidOperationException>(fixture.FileSystem.StartBackgroundWork);
    }

    [Fact]
    public void Remount_does_not_publish_or_delete_private_bytes_without_recovered_authority()
    {
        using var work = new TestWorkspace();
        using var fixture = new Fixture(work, new LocalQueueAuditSink(work.QueueFile));
        var snapshot = Path.Combine(work.Root, "private", "snapshots", Guid.NewGuid().ToString("N"));
        File.WriteAllText(snapshot, "Previously retained snapshot");
        fixture.FileSystem.Stop();
        var policies = new FixedPolicy(LocalPolicyStore.CreateDefault());
        var engine = new InspectionService(policies, new LocalQueueAuditSink(work.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        var observer = new Observer();
        var remounted = new DriveFileSystem(Path.GetDirectoryName(fixture.Target)!, Path.Combine(work.Root, "private"),
            "T:", new ContentInspector(engine, policies), observer, DestinationKind.Cloud, "Synthetic");
        try
        {
            Invoke(remounted, "Reconcile");
            Assert.Equal("Published version", File.ReadAllText(fixture.Target));
            Assert.Equal("Private version", File.ReadAllText(fixture.Content.Path));
            Assert.Equal("Previously retained snapshot", File.ReadAllText(snapshot));
            Assert.Empty(observer.Decisions);
        }
        finally { remounted.Stop(); }
    }

    private static void Invoke(object target, string name, params object[] arguments) =>
        target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, arguments);

    private sealed class Fixture : IDisposable
    {
        private readonly GateClient _gate = new(NullLogger<GateClient>.Instance);
        public DriveFileSystem FileSystem { get; }
        public DriveService Service { get; }
        public Content Content { get; }
        public Observer Observer { get; } = new();
        public Guid PublicationId { get; } = Guid.NewGuid();
        public string Target { get; }
        private readonly Policy _policy = LocalPolicyStore.CreateDefault();
        public Fixture(TestWorkspace work, IAuditSink sink, IPolicyStore? policies = null)
        {
            policies ??= new FixedPolicy(_policy);
            var backing = Path.Combine(work.Root, "backing");
            Directory.CreateDirectory(backing);
            Target = Path.Combine(backing, "report.txt");
            File.WriteAllText(Target, "Published version");
            var engine = new InspectionService(policies, sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
            FileSystem = new DriveFileSystem(backing, Path.Combine(work.Root, "private"), "S:",
                new ContentInspector(engine, policies), Observer, DestinationKind.Cloud, "Synthetic");
            Assert.Equal(0, FileSystem.Open(@"\report.txt", 0, 0, out var node, out var handle, out _, out _));
            Content = ((Handle)handle).Node.Content!;
            FileSystem.Close(node, handle);
            Content.Path = Path.Combine(work.Root, "private", "stage", Guid.NewGuid().ToString("N"));
            File.WriteAllText(Content.Path, "Private version");
            Content.IsStage = true;
            Content.Version = 1;
            Content.Size = new FileInfo(Content.Path).Length;
            var dirty = (HashSet<Content>)typeof(DriveFileSystem).GetField("_dirty", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(FileSystem)!;
            dirty.Add(Content);
            Service = new DriveService(policies, engine, NotificationTestHub.Create(), new DriveJustifications(),
                _gate, new ConfigurationBuilder().Build(), NullLogger<DriveService>.Instance);
        }
        public DriveDecision Decision(bool approved) => new(Guid.NewGuid(), @"S:\report.txt", "report.txt", null,
            TestWorkspace.Operation(Content.Path, DestinationKind.Cloud, destinationPath: Target),
            new InspectionResult(approved ? Verdict.Approved : Verdict.Blocked, [], null, 1, false, 1, true)
                { PolicyContentFingerprint = PolicyContentFingerprint.Compute(_policy) },
            approved, "Synthetic", Content.Path);
        public void Report(DriveDecision decision, bool publication)
        {
            if (publication) Invoke(Service, "OnPublication", new DrivePublication(PublicationId, decision, Target, true));
            else Invoke(Service, "OnDecision", Path.GetDirectoryName(Target)!, decision);
        }
        public void Dispose() { FileSystem.Stop(); Service.Dispose(); _gate.Dispose(); }
    }

    private sealed class Observer : IDriveObserver
    {
        public List<DriveDecision> Decisions { get; } = [];
        public TaskCompletionSource Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public DriveWriter? IdentifyWriter(int pid) => null;
        public void OnDecision(DriveDecision decision) { Decisions.Add(decision); Completed.TrySetResult(); }
        public void OnPublication(DrivePublication publication) { }
    }
    private sealed class FixedPolicy(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
    }
    private sealed class HeldPolicy(bool ignoreCancellation) : IPolicyStore
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<Policy> LoadAsync(CancellationToken token)
        {
            Entered.TrySetResult();
            await Release.Task.WaitAsync(ignoreCancellation ? CancellationToken.None : token);
            return LocalPolicyStore.CreateDefault();
        }
    }
    private sealed class HeldSink(LocalQueueAuditSink inner) : IAuditSink
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task WriteAsync(AuditEvent audit, CancellationToken token)
        {
            Entered.TrySetResult();
            await Release.Task;
            await inner.WriteAsync(audit, token);
        }
        public Task RecordOverrideAsync(string id, string reason, CancellationToken token) => inner.RecordOverrideAsync(id, reason, token);
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int count, CancellationToken token) => inner.ReadRecentAsync(count, token);
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int count, CancellationToken token) => inner.ReadPendingAsync(count, token);
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) => inner.MarkDispatchedAsync(ids, token);
    }
}
