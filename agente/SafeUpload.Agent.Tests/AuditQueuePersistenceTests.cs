using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueuePersistenceTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "TEST", "writer",
        "synthetic.txt", ".txt", 10, Verdict.Blocked, [], [], "test", 1,
        @"C:\Synthetic", null, 7, 1, false);

    private static AuditOverride Override(Guid id) => new(id, "Synthetic purpose", DateTimeOffset.UtcNow,
        "S-1-5-21-123-456-789-1001", "TEST");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Append_flush_failure_reaches_the_caller_without_losing_previous_records(bool justification)
    {
        var normal = new LocalQueueAuditSink(_workspace.QueueFile);
        var previous = Event();
        await normal.WriteAsync(previous, default);
        int flushAttempts = 0;
        var failing = new LocalQueueAuditSink(_workspace.QueueFile, stream =>
        {
            Assert.True(stream.Length > 0);
            flushAttempts++;
            throw new IOException("Synthetic disk flush failure");
        });
        var next = Event();
        await Assert.ThrowsAsync<IOException>(() => justification
            ? failing.RecordOverrideAsync(Override(next.EventId), default)
            : failing.WriteAsync(next, default));
        Assert.Equal(1, flushAttempts);
        // A failed flush is an uncertain write, never a promise that the bytes
        // are absent. Keep the existing history and permit subsequent writes.
        var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
        Assert.Contains(await reopened.ReadPendingAsync(100, default), e => e.EventId == previous.EventId);
        var subsequent = Event();
        await reopened.WriteAsync(subsequent, default);
        Assert.Contains(await reopened.ReadPendingAsync(100, default), e => e.EventId == subsequent.EventId);
        Assert.Empty(Directory.GetFiles(_workspace.Root, "*.tmp"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_confirmation_flush_keeps_original_pending_and_retry_preserves_later_records(bool justification)
    {
        var normal = new LocalQueueAuditSink(_workspace.QueueFile);
        var audit = Event();
        var reason = Override(audit.EventId);
        await normal.WriteAsync(audit, default);
        await normal.RecordOverrideAsync(reason, default);
        byte[] before = await File.ReadAllBytesAsync(_workspace.QueueFile);
        var failing = new LocalQueueAuditSink(_workspace.QueueFile, _ => throw new IOException("Synthetic disk flush failure"));
        await Assert.ThrowsAsync<IOException>(() => Confirm(failing, audit, reason, justification));
        Assert.Equal(before, await File.ReadAllBytesAsync(_workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(_workspace.Root, "*.tmp"));
        var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
        Assert.Single(await reopened.ReadPendingAsync(100, default));
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, default));
        var later = Event();
        await reopened.WriteAsync(later, default);
        await Confirm(reopened, audit, reason, justification);
        Assert.Contains(await reopened.ReadPendingAsync(100, default), e => e.EventId == later.EventId);
        Assert.Equal(justification ? 0 : 1, (await reopened.ReadPendingOverridesAsync(100, default)).Count);
        Assert.Equal(justification ? 2 : 1, (await reopened.ReadPendingAsync(100, default)).Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancellation_after_temporary_flush_keeps_original_pending(bool justification)
    {
        var normal = new LocalQueueAuditSink(_workspace.QueueFile);
        var audit = Event();
        var reason = Override(audit.EventId);
        await normal.WriteAsync(audit, default);
        await normal.RecordOverrideAsync(reason, default);
        byte[] before = await File.ReadAllBytesAsync(_workspace.QueueFile);
        using var cancellation = new CancellationTokenSource();
        var cancelled = new LocalQueueAuditSink(_workspace.QueueFile, stream =>
        {
            stream.Flush(flushToDisk: true);
            cancellation.Cancel();
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Confirm(cancelled, audit, reason, justification, cancellation.Token));
        Assert.Equal(before, await File.ReadAllBytesAsync(_workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(_workspace.Root, "*.tmp"));
        var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
        Assert.Single(await reopened.ReadPendingAsync(100, default));
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Windows_refusing_replacement_preserves_queue_and_allows_retry(bool justification)
    {
        var normal = new LocalQueueAuditSink(_workspace.QueueFile);
        var audit = Event();
        var reason = Override(audit.EventId);
        await normal.WriteAsync(audit, default);
        await normal.RecordOverrideAsync(reason, default);
        byte[] before = await File.ReadAllBytesAsync(_workspace.QueueFile);
        using (var held = new FileStream(_workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            // Windows reports ERROR_ACCESS_DENIED when overwrite cannot delete
            // the destination held without FILE_SHARE_DELETE.
            var denied = await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Confirm(normal, audit, reason, justification));
            Assert.Equal(unchecked((int)0x80070005), denied.HResult);
        }
        Assert.Equal(before, await File.ReadAllBytesAsync(_workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(_workspace.Root, "*.tmp"));
        await Confirm(new LocalQueueAuditSink(_workspace.QueueFile), audit, reason, justification);
        Assert.Equal(justification ? 1 : 0, (await normal.ReadPendingAsync(100, default)).Count);
        Assert.Equal(justification ? 0 : 1, (await normal.ReadPendingOverridesAsync(100, default)).Count);
    }

    private static Task Confirm(LocalQueueAuditSink sink, AuditEvent audit, AuditOverride reason,
        bool justification, CancellationToken token = default) => justification
        ? sink.MarkOverridesDispatchedAsync([reason], token)
        : sink.MarkDispatchedAsync([audit.EventId], token);
}
