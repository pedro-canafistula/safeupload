using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

internal sealed class ClipboardAuditSink : IAuditSink
{
    public List<AuditEvent> Events { get; } = [];
    public Exception? Failure { get; set; }

    public Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Failure is not null) throw Failure;
        Events.Add(auditEvent);
        return Task.CompletedTask;
    }

    public Task RecordOverrideAsync(string eventId, string justification, CancellationToken cancellationToken) =>
        throw new NotSupportedException();

    public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<AuditEvent>>(Events.TakeLast(maxEvents).ToArray());

    public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<AuditEvent>>(Events.Where(item => !item.Dispatched).Take(maxEvents).ToArray());

    public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> eventIds, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}
