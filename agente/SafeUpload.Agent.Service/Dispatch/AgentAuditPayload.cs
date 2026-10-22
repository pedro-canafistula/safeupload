using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Dispatch;

/// <summary>
/// Contrato de saída separado da fila local. Novos campos no domínio não passam
/// automaticamente a trafegar pela rede. Os trechos inspecionados ficam locais.
/// </summary>
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
        // Also defend against old producers that accidentally stored a full path.
        item.FileName.Replace('\\', '/').Split('/').Last(),
        item.Extension, item.SizeBytes, item.Verdict, item.Categories, [],
        item.ProcessName, item.ProcessId,
        item.Channel == AuditChannel.Web ? WebOrigin(item.DestinationPath) : item.DestinationPath,
        item.NotInspectedReason, item.PolicyVersion, item.ElapsedMs, false,
        item.PublishedSha256Hex, item.Channel);

    private static string WebOrigin(string destination)
    {
        // Paths can contain tokens too. Only the HTTP(S) origin is needed to
        // identify the destination; never send credentials, query or fragment.
        if (!Uri.TryCreate(destination, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            return string.Empty;
        return new UriBuilder(uri.Scheme, uri.Host, uri.Port).Uri.GetLeftPart(UriPartial.Authority);
    }
}
