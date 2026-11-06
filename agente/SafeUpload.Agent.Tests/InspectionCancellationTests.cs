using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionCancellationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Already_cancelled_inspection_does_not_read_policy_or_attempt_audit(bool staged)
    {
        using var workspace = new TestWorkspace();
        using var cancel = new CancellationTokenSource();
        var policies = new Policies();
        var sink = new Sink();
        var engine = Engine(policies, sink);
        var operation = TestWorkspace.Operation(workspace.WriteText("cancelled.txt", "clean"));
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => staged
            ? engine.InspectStagedAsync(operation, cancel.Token) : engine.InspectAsync(operation, cancel.Token));
        Assert.Equal(0, policies.Reads);
        Assert.Equal(0, sink.Writes);
    }

    [Fact]
    public async Task Ordinary_audit_io_failure_still_preserves_the_verdict_and_its_cache()
    {
        using var workspace = new TestWorkspace();
        var sink = new Sink { OnWrite = () => throw new IOException("Synthetic audit failure") };
        var engine = Engine(new Policies(), sink);
        var operation = TestWorkspace.Operation(workspace.WriteText("audit-io.txt", "clean"));
        var first = await engine.InspectAsync(operation, default);
        Assert.Equal(Verdict.Approved, first.Verdict);
        Assert.Null(first.RecordedEvent);
        sink.OnWrite = null;
        var second = await engine.InspectAsync(operation, default);
        Assert.True(second.FromCache);
        Assert.NotNull(second.RecordedEvent);
        Assert.Equal(2, sink.Writes);
    }

    [Theory]
    [InlineData(false, "excluded")]
    [InlineData(true, "excluded")]
    [InlineData(false, "scope")]
    [InlineData(true, "scope")]
    [InlineData(false, "size")]
    [InlineData(true, "size")]
    [InlineData(false, "format")]
    [InlineData(true, "format")]
    public async Task Cancellation_during_policy_read_stops_fast_decisions_before_audit(bool staged, string decision)
    {
        using var workspace = new TestWorkspace();
        using var cancel = new CancellationTokenSource();
        var policies = new Policies { OnRead = cancel.Cancel };
        var sink = new Sink();
        var engine = Engine(policies, sink);
        var operation = TestWorkspace.Operation(workspace.WriteText("fixture.txt", "clean"));
        operation = decision switch
        {
            "excluded" => operation with { ProcessName = "System" },
            "scope" => operation with { Destination = DestinationKind.Cloud, DestinationPath = @"C:\outside" },
            "size" => operation with { SizeBytes = 100 * 1024 * 1024 },
            _ => operation with { Extension = ".unsupported" }
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => staged
            ? engine.InspectStagedAsync(operation, cancel.Token) : engine.InspectAsync(operation, cancel.Token));
        Assert.Equal(0, sink.Writes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_during_authority_read_cannot_confirm_approval_or_justification(bool justification)
    {
        using var workspace = new TestWorkspace();
        using var cancel = new CancellationTokenSource();
        var policies = new Policies();
        var engine = Engine(policies, new Sink());
        var operation = TestWorkspace.Operation(workspace.WriteText("fixture.txt",
            justification ? "CPF: 529.982.247-25" : "clean"));
        var result = await engine.InspectStagedAsync(operation, default);
        Assert.Equal(justification ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        policies.OnRead = cancel.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => justification
            ? engine.IsCurrentStagedJustificationAllowedAsync(operation, result, cancel.Token)
            : engine.IsCurrentStagedApprovalAsync(operation, result, cancel.Token));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_during_audit_does_not_install_a_new_cached_decision(bool sinkThrows)
    {
        using var workspace = new TestWorkspace();
        using var cancel = new CancellationTokenSource();
        var sink = new Sink { OnWrite = () => { cancel.Cancel(); if (sinkThrows) cancel.Token.ThrowIfCancellationRequested(); } };
        var engine = Engine(new Policies(), sink);
        var operation = TestWorkspace.Operation(workspace.WriteText("fixture.txt", "clean"));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.InspectAsync(operation, cancel.Token));
        sink.OnWrite = null;
        var recovered = await engine.InspectAsync(operation, default);
        Assert.Equal(Verdict.Approved, recovered.Verdict);
        Assert.False(recovered.FromCache);
        Assert.NotNull(recovered.RecordedEvent);
        Assert.Equal(2, sink.Writes);
    }

    [Fact]
    public async Task Cancellation_after_durable_audit_keeps_the_event_and_requires_a_new_inspection()
    {
        using var workspace = new TestWorkspace();
        using var cancel = new CancellationTokenSource();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var sink = new Sink { Store = queue.WriteAsync, OnWrite = cancel.Cancel };
        var engine = Engine(new Policies(), sink);
        var operation = TestWorkspace.Operation(workspace.WriteText("fixture.txt", "clean"));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.InspectAsync(operation, cancel.Token));
        var retained = Assert.Single(await queue.ReadPendingAsync(10, default));
        sink.OnWrite = null;
        var retried = await engine.InspectAsync(operation, default);
        Assert.False(retried.FromCache);
        var pending = await queue.ReadPendingAsync(10, default);
        Assert.Equal(2, pending.Count);
        Assert.Contains(pending, item => item.EventId == retained.EventId);
        Assert.NotEqual(retained.EventId, retried.RecordedEvent!.EventId);
    }

    [Fact]
    public async Task Cancellation_during_cached_hit_audit_does_not_return_a_successful_decision()
    {
        using var workspace = new TestWorkspace();
        using var cancel = new CancellationTokenSource();
        var sink = new Sink();
        var engine = Engine(new Policies(), sink);
        var operation = TestWorkspace.Operation(workspace.WriteText("fixture.txt", "clean"));
        Assert.False((await engine.InspectAsync(operation, default)).FromCache);
        sink.OnWrite = cancel.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.InspectAsync(operation, cancel.Token));
        sink.OnWrite = null;
        // A completed earlier invocation remains valid; cancellation does not delete its cache entry.
        Assert.True((await engine.InspectAsync(operation, default)).FromCache);
        Assert.Equal(3, sink.Writes);
    }

    private static InspectionService Engine(IPolicyStore policies, IAuditSink sink) =>
        new(policies, sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
    private sealed class Policies : IPolicyStore
    {
        public Action? OnRead;
        public int Reads;
        public Task<Policy> LoadAsync(CancellationToken token)
        { Interlocked.Increment(ref Reads); OnRead?.Invoke(); return Task.FromResult(LocalPolicyStore.CreateDefault() with { OverrideAllowed = true }); }
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
    }
    private sealed class Sink : IAuditSink
    {
        public int Writes;
        public Action? OnWrite;
        public Func<AuditEvent, CancellationToken, Task>? Store;
        public async Task WriteAsync(AuditEvent record, CancellationToken token)
        { Writes++; if (Store is not null) await Store(record, token); OnWrite?.Invoke(); }
        public Task RecordOverrideAsync(string id, string justification, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int count, CancellationToken token) => throw new NotSupportedException();
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int count, CancellationToken token) => throw new NotSupportedException();
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) => throw new NotSupportedException();
    }
}
