using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>Strict durable delivery for a publication journal; failures must propagate to retain the journal.</summary>
public interface IRecoverableAuditSink
{
    /// <summary>Bind a new event before writing its immutable publication journal.</summary>
    AuditEvent BindNewPublication(AuditEvent item);

    /// <param name="replay">False only for a newly generated event's first delivery; true for every retry/restart.</param>
    Task WritePublicationAsync(AuditEvent item, bool replay, CancellationToken token);
}
