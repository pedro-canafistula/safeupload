namespace SafeUpload.Agent.Core.Application;

public enum AuditWriteKind { Event, Override }

/// <summary>Diagnostic observation only; it cannot confirm, retry or authorize a write.</summary>
public interface IAuditWriteFailureObserver
{
    void OnWriteFailure(AuditWriteKind kind, Exception error);
}
