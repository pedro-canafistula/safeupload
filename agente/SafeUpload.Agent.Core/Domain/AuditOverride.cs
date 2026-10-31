namespace SafeUpload.Agent.Core.Domain;

/// <summary>Justificativa persistida, identificada pelo conteúdo para confirmar apenas o registro enviado.</summary>
public sealed record AuditOverride(Guid EventId, string Justification, DateTimeOffset OccurredAtUtc,
    string UserName, string EndpointId)
{
    /// <summary>New user submission only. Existing queue records retain their canonical text on replay.</summary>
    public static AuditOverride FromNewSubmission(Guid eventId, string justification, DateTimeOffset occurredAtUtc,
        string userName, string endpointId) => new(eventId, AuditTextPrivacy.Sanitize(justification), occurredAtUtc, userName, endpointId);
}
