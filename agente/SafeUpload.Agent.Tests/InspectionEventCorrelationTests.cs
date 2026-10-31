using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionEventCorrelationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private InspectionService Engine(IAuditSink sink, VerdictCache? cache = null) => new(
        new LocalPolicyStore(_workspace.PolicyFile), sink, ExtractorRegistry.CreateDefault(), cache ?? new VerdictCache());

    [Fact]
    public async Task Cached_decision_records_a_new_event_for_each_invocation()
    {
        var sink = new Sink(); var engine = Engine(sink);
        var operation = TestWorkspace.Operation(_workspace.WriteText("same.txt", "ordinary text"));
        var first = await engine.InspectAsync(operation, default);
        var second = await engine.InspectAsync(operation, default);
        Assert.False(first.FromCache); Assert.True(second.FromCache);
        Assert.Same(sink.Written[0], first.RecordedEvent);
        Assert.Same(sink.Written[1], second.RecordedEvent);
        Assert.NotEqual(first.RecordedEvent!.EventId, second.RecordedEvent!.EventId);
        Assert.Equal(0, sink.HistoryReads);
    }

    [Fact]
    public async Task Failed_write_does_not_reuse_the_previous_successful_event()
    {
        var sink = new Sink(); var engine = Engine(sink);
        var operation = TestWorkspace.Operation(_workspace.WriteText("same.txt", "ordinary text"));
        Assert.NotNull((await engine.InspectAsync(operation, default)).RecordedEvent);
        sink.Fail = true;
        var failed = await engine.InspectAsync(operation, default);
        Assert.True(failed.FromCache);
        Assert.Equal(Verdict.Approved, failed.Verdict);
        Assert.Null(failed.RecordedEvent);
    }

    [Fact]
    public async Task Event_in_memory_does_not_change_the_serialized_result_contract()
    {
        var result = await Engine(new Sink()).InspectAsync(
            TestWorkspace.Operation(_workspace.WriteText("ordinary.txt", "ordinary text")), default);
        Assert.NotNull(result.RecordedEvent);
        string json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("RecordedEvent", json);
        Assert.DoesNotContain("EventId", json);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task Out_of_scope_and_staged_classification_do_not_claim_an_outcome_event(bool staged)
    {
        var sink = new Sink(); var engine = Engine(sink);
        string path = _workspace.WriteText(staged ? "staged.txt" : "outside.png", "ordinary text");
        var operation = TestWorkspace.Operation(path);
        var result = staged ? await engine.InspectStagedAsync(operation, default) : await engine.InspectAsync(operation, default);
        Assert.Null(result.RecordedEvent);
        Assert.Empty(sink.Written);
    }

    [Fact]
    public async Task Watcher_announces_the_written_event_despite_a_newer_same_name_event()
    {
        string scope = Path.Combine(_workspace.Root, "scope");
        Directory.CreateDirectory(scope);
        var policy = LocalPolicyStore.CreateDefault() with { MonitoredScopes = new(new HashSet<string> { ".txt" }, [scope], false, false) };
        File.WriteAllText(_workspace.PolicyFile, JsonSerializer.Serialize(PolicyDocument.FromPolicy(policy)));
        var policies = new LocalPolicyStore(_workspace.PolicyFile);
        var sink = new Sink();
        var hub = new NotificationHub(new Record(), NullLogger<NotificationHub>.Instance);
        using var subscription = hub.Subscribe();
        using var service = new FileSystemInterceptor(Engine(sink), policies, sink, hub,
            NullLogger<FileSystemInterceptor>.Instance, Path.Combine(_workspace.Root, "quarantine"), _workspace.PolicyFile);
        await service.StartAsync(default);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try
        {
            while (hub.CurrentStatus?.ProtectionActive != true) await Task.Delay(20, stop.Token);
            await File.WriteAllTextAsync(Path.Combine(scope, "ordinary.txt"), "ordinary text", stop.Token);
            EventNotification? received = null;
            while (received is null)
                if (await subscription.Reader.ReadAsync(stop.Token) is EventNotification notification) received = notification;
            Assert.Equal(sink.Written[0].EventId, received.Event.EventId);
            Assert.NotEqual(sink.Foreign!.EventId, received.Event.EventId);
            Assert.Equal(0, sink.HistoryReads);
        }
        finally { await service.StopAsync(default).WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    private sealed class Record : INotificationRecord { public void Append(AgentNotification notification, uint? targetSessionId) { } }
    private sealed class Sink : IAuditSink
    {
        public readonly List<AuditEvent> Written = [];
        public AuditEvent? Foreign;
        public int HistoryReads;
        public bool Fail;
        public Task WriteAsync(AuditEvent item, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (Fail) throw new IOException("synthetic queue failure");
            Written.Add(item);
            Foreign = item with { EventId = Guid.NewGuid(), ProcessId = 999, PolicyVersion = 99 };
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken token)
        { HistoryReads++; return Task.FromResult<IReadOnlyList<AuditEvent>>([Foreign!, .. Written]); }
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken token) => Task.FromResult<IReadOnlyList<AuditEvent>>([]);
        public Task RecordOverrideAsync(string id, string reason, CancellationToken token) => throw new NotSupportedException();
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) => Task.CompletedTask;
    }
    public void Dispose() => _workspace.Dispose();
}
