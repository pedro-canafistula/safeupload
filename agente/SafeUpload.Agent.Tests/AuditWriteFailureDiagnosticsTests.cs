using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service;
using SafeUpload.Agent.Service.Audit;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class AuditWriteFailureDiagnosticsTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "TEST", "private-user",
        "private-file.txt", ".txt", 10, Verdict.Blocked, [], ["private-snippet"], "test", 1,
        @"C:\private-destination", null, 7, 1, false);
    private static AuditOverride Override(Guid id) => new(id, "private-justification", DateTimeOffset.UtcNow,
        "S-1-5-21-123-456-789-1001", "private-endpoint");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unconfirmed_append_keeps_original_error_and_reports_no_record_or_exception_content(bool justification)
    {
        var logger = new CaptureLogger();
        var diagnostics = new AuditWriteFailureDiagnostics(logger);
        var original = new IOException("private-path and 529.982.247-25");
        var sink = new LocalQueueAuditSink(_workspace.QueueFile, _ => throw original, diagnostics);
        var audit = Event();
        var error = await Assert.ThrowsAsync<IOException>(() => justification
            ? sink.RecordOverrideAsync(Override(audit.EventId), default) : sink.WriteAsync(audit, default));
        Assert.Same(original, error);
        var snapshot = diagnostics.Read();
        Assert.Equal(1, snapshot.FailureCount);
        Assert.Equal(justification ? AuditWriteKind.Override : AuditWriteKind.Event, snapshot.LastKind);
        Assert.Equal("io", snapshot.LastErrorClass);
        var warning = Assert.Single(logger.Entries);
        Assert.Equal(4101, warning.Id.Id);
        Assert.Equal(LogLevel.Error, warning.Level);
        Assert.Null(warning.Error);
        foreach (string secret in new[] { "private-", "529.982.247-25", audit.EventId.ToString(), "S-1-5-21" })
            Assert.DoesNotContain(secret, warning.Message);
        // The append may have reached disk before a failed flush: never retry
        // automatically or equate the warning with proof of absent bytes.
        Assert.Single(await File.ReadAllLinesAsync(_workspace.QueueFile));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Broken_observer_cannot_mask_original_failure_or_keep_the_queue_lock(bool justification)
    {
        var observer = new BrokenObserver();
        var original = new IOException("original persistence failure");
        var failing = new LocalQueueAuditSink(_workspace.QueueFile, _ => throw original, observer);
        var audit = Event();
        var error = await Assert.ThrowsAsync<IOException>(() => justification
            ? failing.RecordOverrideAsync(Override(audit.EventId), default) : failing.WriteAsync(audit, default));
        Assert.Same(original, error);
        Assert.Equal(1, observer.Calls);
        await Assert.ThrowsAsync<IOException>(() => failing.WriteAsync(Event(), default).WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(2, observer.Calls);
    }

    [Fact]
    public async Task Successful_writes_and_confirmations_keep_event_and_override_queue_contracts()
    {
        var logger = new CaptureLogger();
        var diagnostics = new AuditWriteFailureDiagnostics(logger);
        var sink = new LocalQueueAuditSink(_workspace.QueueFile, diagnostics);
        var audit = Event();
        var reason = Override(audit.EventId);
        await sink.WriteAsync(audit, default);
        await sink.RecordOverrideAsync(reason, default);
        var queued = Assert.Single(await sink.ReadPendingAsync(100, default));
        Assert.Equal(audit.EventId, queued.EventId);
        Assert.Equal(audit.FileName, queued.FileName);
        Assert.Equal(audit.MaskedSnippets, queued.MaskedSnippets);
        IOverrideQueue overrides = sink;
        Assert.Equal(reason, Assert.Single(await overrides.ReadPendingOverridesAsync(100, default)));
        await sink.MarkDispatchedAsync([audit.EventId], default);
        await overrides.MarkOverridesDispatchedAsync([reason], default);
        Assert.Empty(await sink.ReadPendingAsync(100, default));
        Assert.Empty(await overrides.ReadPendingOverridesAsync(100, default));
        Assert.Equal(0, diagnostics.Read().FailureCount);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task Caller_cancellation_does_not_report_a_disk_failure()
    {
        var logger = new CaptureLogger();
        var diagnostics = new AuditWriteFailureDiagnostics(logger);
        var sink = new LocalQueueAuditSink(_workspace.QueueFile, diagnostics);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.WriteAsync(Event(), cancellation.Token));
        Assert.False(File.Exists(_workspace.QueueFile));
        Assert.Equal(0, diagnostics.Read().FailureCount);
        Assert.Empty(logger.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Inspection_decision_stays_blocked_while_failed_audit_becomes_observable(bool staged)
    {
        var logger = new CaptureLogger();
        var diagnostics = new AuditWriteFailureDiagnostics(logger);
        var sink = new LocalQueueAuditSink(_workspace.QueueFile, _ => throw new IOException("disk failure"), diagnostics);
        var inspection = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), sink,
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(_workspace.WriteText("private-file.txt", "CPF: 529.982.247-25"));
        var result = staged ? await inspection.InspectStagedAsync(operation, default)
            : await inspection.InspectAsync(operation, default);
        if (staged)
            await inspection.RecordTransferOutcomeAsync(operation, result, Verdict.Blocked, result.Reason, default);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal(1, diagnostics.Read().FailureCount);
        Assert.Single(logger.Entries);
    }

    [Fact]
    public async Task Verified_justification_failure_remains_visible_and_propagates()
    {
        var diagnostics = new AuditWriteFailureDiagnostics(new CaptureLogger());
        var original = new IOException("disk failure");
        var sink = new LocalQueueAuditSink(_workspace.QueueFile, _ => throw original, diagnostics);
        using var server = new JustificationPipeServer(new PendingOverrides(), new LocalPolicyStore(_workspace.PolicyFile),
            sink, new OverrideGrantDispatcher(), new StagedJustifications(), NullLogger<JustificationPipeServer>.Instance);
        var error = await Assert.ThrowsAsync<IOException>(() => server.RecordJustificationAsync(
            new JustificationRequest(Guid.NewGuid().ToString(), "private reason"), "S-1-5-21-123-456-789-1001", default));
        Assert.Same(original, error);
        Assert.Equal(AuditWriteKind.Override, diagnostics.Read().LastKind);
    }

    [Fact]
    public async Task Repeated_concurrent_failures_are_counted_but_log_at_most_once_per_record_kind()
    {
        var logger = new CaptureLogger();
        var diagnostics = new AuditWriteFailureDiagnostics(logger);
        Parallel.For(0, 200, i => diagnostics.OnWriteFailure(i % 2 == 0 ? AuditWriteKind.Event : AuditWriteKind.Override,
            new UnauthorizedAccessException("private error")));
        Assert.Equal(200, diagnostics.Read().FailureCount);
        Assert.Equal("access_denied", diagnostics.Read().LastErrorClass);
        Assert.Equal(2, logger.Entries.Count);
        await new LocalQueueAuditSink(_workspace.QueueFile, diagnostics).WriteAsync(Event(), default);
        Assert.Equal(200, diagnostics.Read().FailureCount);
        Assert.Equal(2, logger.Entries.Count);
    }

    [Fact]
    public async Task Unavailable_logger_cannot_change_the_original_persistence_outcome()
    {
        var logger = new CaptureLogger { Throw = true };
        var diagnostics = new AuditWriteFailureDiagnostics(logger);
        var original = new IOException("disk failure");
        var sink = new LocalQueueAuditSink(_workspace.QueueFile, _ => throw original, diagnostics);
        Assert.Same(original, await Assert.ThrowsAsync<IOException>(() => sink.WriteAsync(Event(), default)));
        Assert.Equal(1, diagnostics.Read().FailureCount);
        await new LocalQueueAuditSink(_workspace.QueueFile, diagnostics).WriteAsync(Event(), default);
        Assert.Equal(1, diagnostics.Read().FailureCount);
    }

    [Fact]
    public void Service_graph_shares_failure_observer_without_starting_the_host_or_opening_the_queue()
    {
        var builder = Program.CreateConfiguredServiceBuilder(["--CentroAdministracao:BaseUrl=", "--InspecaoTls:Habilitada=false"]);
        using var provider = builder.Services.BuildServiceProvider();
        Assert.Same(provider.GetRequiredService<AuditWriteFailureDiagnostics>(),
            provider.GetRequiredService<IAuditWriteFailureObserver>());
        Assert.IsType<LocalQueueAuditSink>(provider.GetRequiredService<IAuditSink>());
        Assert.IsAssignableFrom<IOverrideQueue>(provider.GetRequiredService<IAuditSink>());
    }

    private sealed class BrokenObserver : IAuditWriteFailureObserver
    {
        public int Calls;
        public void OnWriteFailure(AuditWriteKind kind, Exception error)
        { Calls++; throw new InvalidOperationException("observer failure"); }
    }

    private sealed class CaptureLogger : ILogger<AuditWriteFailureDiagnostics>
    {
        public ConcurrentQueue<(LogLevel Level, EventId Id, string Message, Exception? Error)> Entries = new();
        public bool Throw;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error,
            Func<TState, Exception?, string> formatter)
        {
            if (Throw) throw new InvalidOperationException("logger failure");
            Entries.Enqueue((level, id, formatter(state, error), error));
        }
    }
}
