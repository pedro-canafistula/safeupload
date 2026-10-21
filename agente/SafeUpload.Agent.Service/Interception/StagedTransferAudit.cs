using System.Security.Principal;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferPublisher
{
    // Attribution only: this must never grant publication, hand-back or UI access.
    // Use the allocation's persisted token SID, not the service account or the
    // current occupant of a possibly reused/logged-off Windows session.
    internal Task RecordTransferAuditAsync(StagedTransfer transfer, FileOperation operation,
        InspectionResult inspection, Verdict outcome, string? reason,
        CancellationToken cancellationToken, Guid? eventId = null, string? publishedSha256Hex = null)
        => _inspection.RecordTransferOutcomeAsync(operation, inspection, outcome, reason,
            cancellationToken, eventId, publishedSha256Hex, AuditUser(transfer.RequestorSid));

    private static string AuditUser(string? requestorSid)
    {
        if (string.IsNullOrWhiteSpace(requestorSid) || requestorSid.Length > 184)
            return "Não identificado";
        try { return new SecurityIdentifier(requestorSid).Value; }
        catch (ArgumentException) { return "Não identificado"; }
    }
}
