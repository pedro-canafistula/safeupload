namespace SafeUpload.Agent.Core.Domain;

/// <summary>Justificativa persistida, identificada pelo conteúdo para confirmar apenas o registro enviado.</summary>
public sealed record AuditOverride(Guid EventId, string Justification, DateTimeOffset OccurredAtUtc,
    string UserName, string EndpointId);
