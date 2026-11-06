using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>Strict durable delivery for a publication journal; failures must propagate to retain the journal.</summary>
public interface IRecoverableAuditSink
{
    /// <param name="replay">False only for a newly generated event's first delivery; true for every retry/restart.</param>
    Task WritePublicationAsync(AuditEvent item, bool replay, CancellationToken token);
}
