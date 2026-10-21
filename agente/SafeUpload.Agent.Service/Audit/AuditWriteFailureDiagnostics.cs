using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Audit;

/// <summary>Historical failures, not a health/coverage signal or a replacement audit trail.</summary>
public sealed class AuditWriteFailureDiagnostics(ILogger<AuditWriteFailureDiagnostics> logger)
    : IAuditWriteFailureObserver
{
    private readonly object _gate = new();
    private readonly HashSet<AuditWriteKind> _announced = [];
    private AuditWriteFailureSnapshot _state = new(0, null, null);

    internal AuditWriteFailureSnapshot Read() { lock (_gate) return _state; }

    internal AuditWriteStatus ForNotification()
    {
        var state = Read();
        return new(state.FailureCount, state.LastKind switch
        {
            AuditWriteKind.Event => "event",
            AuditWriteKind.Override => "override",
            _ => null
        }, state.LastErrorClass);
    }

    public void OnWriteFailure(AuditWriteKind kind, Exception error)
    {
        kind = kind == AuditWriteKind.Override ? AuditWriteKind.Override : AuditWriteKind.Event;
        string errorClass = error switch
        {
            UnauthorizedAccessException => "access_denied",
            IOException => "io",
            OperationCanceledException => "interrupted",
            _ => "unexpected"
        };
        bool announce;
        lock (_gate)
        {
            _state = new(_state.FailureCount == long.MaxValue ? long.MaxValue : _state.FailureCount + 1,
                kind, errorClass);
            // At most one warning for events and one for overrides per process.
            // Never reset this historical observation after a later success.
            announce = _announced.Add(kind);
        }
        if (!announce) return;
        try
        {
            logger.LogError(new EventId(4101, "AuditLocalWriteFailed"),
                "Persistência de auditoria local não confirmada. Tipo: {RecordKind}; classe: {FailureClass}. " +
                "Verifique espaço em disco e permissões. Escritas posteriores não recuperam este registro automaticamente.",
                kind == AuditWriteKind.Override ? "justificativa" : "evento", errorClass);
        }
        catch (Exception) { /* Logging cannot change the persistence outcome. */ }
    }
}

internal sealed record AuditWriteFailureSnapshot(long FailureCount, AuditWriteKind? LastKind, string? LastErrorClass);
