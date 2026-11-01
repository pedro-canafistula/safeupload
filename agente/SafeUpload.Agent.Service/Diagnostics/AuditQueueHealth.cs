using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Diagnostics;

public enum AuditQueueOperation { WriteEvent, WriteOverride, ReadRecent, ReadPending, ReadPendingOverrides, ConfirmEvents, ConfirmOverrides }
public sealed record AuditQueueOperationHealth(string Operation, bool Degraded, long Failures, long Successes,
    DateTimeOffset? LastFailureUtc, DateTimeOffset? LastSuccessUtc, string? FailureKind, int? FailureHResult);
public sealed record AuditQueueHealthSnapshot(DateTimeOffset SinceUtc, bool Degraded, long FailedWriteAttempts,
    IReadOnlyList<AuditQueueOperationHealth> Operations);

/// <summary>Process-local counters only: never stores events, paths, accounts or exception messages.</summary>
public sealed class AuditQueueHealth
{
    private readonly object _gate = new();
    private readonly DateTimeOffset _sinceUtc = DateTimeOffset.UtcNow;
    private readonly Dictionary<AuditQueueOperation, AuditQueueOperationHealth> _states =
        Enum.GetValues<AuditQueueOperation>().ToDictionary(op => op,
            op => new AuditQueueOperationHealth(op.ToString(), false, 0, 0, null, null, null, null));

    internal bool Failure(AuditQueueOperation operation, Exception exception)
    {
        lock (_gate)
        {
            var old = _states[operation];
            _states[operation] = old with { Degraded = true, Failures = old.Failures + 1,
                LastFailureUtc = DateTimeOffset.UtcNow, FailureKind = Classify(exception), FailureHResult = exception.HResult };
            return !old.Degraded;
        }
    }

    internal bool Success(AuditQueueOperation operation)
    {
        lock (_gate)
        {
            var old = _states[operation];
            _states[operation] = old with { Degraded = false, Successes = old.Successes + 1, LastSuccessUtc = DateTimeOffset.UtcNow };
            return old.Degraded;
        }
    }

    public AuditQueueHealthSnapshot Read()
    {
        lock (_gate)
        {
            var values = _states.Values.ToArray();
            return new(_sinceUtc, values.Any(v => v.Degraded),
                _states[AuditQueueOperation.WriteEvent].Failures + _states[AuditQueueOperation.WriteOverride].Failures, values);
        }
    }

    internal static string Classify(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "access_denied",
        IOException when exception.HResult is unchecked((int)0x80070070) or unchecked((int)0x80070027) => "disk_full",
        IOException => "io_error",
        OperationCanceledException => "unexpected_cancellation",
        _ => "unexpected_error"
    };
}

/// <summary>
/// Observes the real queue without swallowing errors or changing delivery semantics.
/// The original caller keeps its existing verdict/error policy. Logging is independent
/// of queue storage; one failure/recovery log per operation transition avoids storms.
/// </summary>
public sealed class MonitoredAuditSink : IAuditSink, IOverrideQueue
{
    private readonly IAuditSink _inner;
    private readonly IOverrideQueue _overrides;
    private readonly AuditQueueHealth _health;
    private readonly ILogger<MonitoredAuditSink> _logger;

    public MonitoredAuditSink(IAuditSink inner, AuditQueueHealth health, ILogger<MonitoredAuditSink> logger)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _overrides = inner as IOverrideQueue ?? throw new ArgumentException("An override-capable queue is required.", nameof(inner));
        _health = health ?? throw new ArgumentNullException(nameof(health));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task WriteAsync(AuditEvent item, CancellationToken token) =>
        Observe(AuditQueueOperation.WriteEvent, () => _inner.WriteAsync(item, token), token);
    public Task RecordOverrideAsync(string eventId, string justification, CancellationToken token) =>
        Observe(AuditQueueOperation.WriteOverride, () => _inner.RecordOverrideAsync(eventId, justification, token), token);
    public Task RecordOverrideAsync(AuditOverride record, CancellationToken token) =>
        Observe(AuditQueueOperation.WriteOverride, () => _inner.RecordOverrideAsync(record, token), token);
    public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int maxEvents, CancellationToken token) =>
        Observe(AuditQueueOperation.ReadRecent, () => _inner.ReadRecentAsync(maxEvents, token), token);
    public Task<IReadOnlyList<AuditEvent>> ReadRecentMatchingAsync(int maxEvents, Func<AuditEvent, bool> visible, CancellationToken token) =>
        Observe(AuditQueueOperation.ReadRecent, () => _inner.ReadRecentMatchingAsync(maxEvents, visible, token), token);
    public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int maxEvents, CancellationToken token) =>
        Observe(AuditQueueOperation.ReadPending, () => _inner.ReadPendingAsync(maxEvents, token), token);
    public Task<IReadOnlyList<AuditOverride>> ReadPendingOverridesAsync(int maxEvents, CancellationToken token) =>
        Observe(AuditQueueOperation.ReadPendingOverrides, () => _overrides.ReadPendingOverridesAsync(maxEvents, token), token);
    public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) =>
        Observe(AuditQueueOperation.ConfirmEvents, () => _inner.MarkDispatchedAsync(ids, token), token);
    public Task MarkOverridesDispatchedAsync(IReadOnlyCollection<AuditOverride> records, CancellationToken token) =>
        Observe(AuditQueueOperation.ConfirmOverrides, () => _overrides.MarkOverridesDispatchedAsync(records, token), token);

    private Task Observe(AuditQueueOperation operation, Func<Task> action, CancellationToken token) =>
        Observe(operation, async () => { await action().ConfigureAwait(false); return true; }, token);

    private async Task<T> Observe<T>(AuditQueueOperation operation, Func<Task<T>> action, CancellationToken token)
    {
        T value;
        try { value = await action().ConfigureAwait(false); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            // Never attach the exception or its Message: paths/content may be embedded.
            try
            {
                if (_health.Failure(operation, exception))
                    _logger.LogError(new EventId(3101, "AuditQueueFailure"),
                        "Audit queue operation {Operation} failed ({FailureKind}, HRESULT {HResult}). Inspect audit-health; counters are since service start.",
                        operation.ToString(), AuditQueueHealth.Classify(exception), exception.HResult);
            }
            catch { /* A failing logging provider must not replace the queue's original exception. */ }
            throw;
        }
        try
        {
            if (_health.Success(operation))
                _logger.LogWarning(new EventId(3102, "AuditQueueResumed"),
                    "Audit queue operation {Operation} resumed. Earlier failed attempts remain in audit-health counters; no lost-event recovery is implied.", operation.ToString());
        }
        catch { /* Observability must not turn a completed write into a failed inspection. */ }
        return value;
    }
}
