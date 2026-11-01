using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Dispatch;

/// <summary>Explicit network contract. Future local event fields are not sent automatically.</summary>
internal sealed record AgentAuditPayload(
    int SchemaVersion,
    string Hostname,
    string AgentVersion,
    IReadOnlyList<AgentAuditEvent> Events,
    IReadOnlyList<AgentAuditOverride> Overrides);

internal sealed record AgentAuditOverride(Guid EventId, string Justification,
    DateTimeOffset OccurredAtUtc, string UserName, string EndpointId)
{
    public static AgentAuditOverride FromLocal(AuditOverride item) => new(item.EventId,
        item.Justification, item.OccurredAtUtc.ToUniversalTime(), item.UserName, item.EndpointId);
}

internal sealed record AgentAuditEvent(
    Guid EventId,
    DateTimeOffset OccurredAtUtc,
    string EndpointId,
    string UserName,
    string FileName,
    string Extension,
    long SizeBytes,
    Verdict Verdict,
    IReadOnlyList<Category> Categories,
    IReadOnlyList<string> MaskedSnippets,
    string ProcessName,
    int ProcessId,
    string DestinationPath,
    string? NotInspectedReason,
    int PolicyVersion,
    long ElapsedMs,
    bool Dispatched,
    string? PublishedSha256Hex,
    AuditChannel Channel)
{
    public static AgentAuditEvent FromLocal(AuditEvent item) => new(
        item.EventId, item.OccurredAtUtc.ToUniversalTime(), item.EndpointId, item.UserName,
        // Preserve fields used by the server's persisted payload comparison. A lost receipt
        // can leave an already accepted event pending through an agent upgrade.
        item.FileName, item.Extension, item.SizeBytes, item.Verdict, item.Categories, [],
        item.ProcessName, item.ProcessId, item.DestinationPath, item.NotInspectedReason,
        item.PolicyVersion, item.ElapsedMs, false, item.PublishedSha256Hex, item.Channel);
}
