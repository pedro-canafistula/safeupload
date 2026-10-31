using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Clipboard;

/// <summary>
/// Grava na fila de auditoria o que o canal de clipboard observou num destino de saída.
///
/// <para>Dois fatos viram evento: a sonda de foco da Fase 1 (o usuário foi para
/// uma saída com o clipboard sujo) e o Ctrl+V de verdade da Fase 3. A colagem
/// bloqueada sai como <see cref="Verdict.Blocked"/>, sem motivo, como um arquivo
/// bloqueado. A colagem que o modo Audit deixou passar e a sonda de foco saem
/// como <see cref="Verdict.AllowedWithoutInspection"/>, com o motivo dizendo qual
/// das duas foi. O texto copiado nunca entra no evento (RN-006).</para>
/// </summary>
public static class ClipboardAudit
{
    /// <summary>Motivo da sonda de foco.</summary>
    public const string FocusObserved = "clipboard_focus_observed";

    /// <summary>Motivo da colagem que o modo Audit deixou passar.</summary>
    public const string PasteAuditOnly = "clipboard_paste_audit_only";

    public static async Task<ClipboardResponse> WriteAsync(ClipboardOutcome outcome,
        IAuditSink sink, ILogger logger, string? userName, CancellationToken cancellationToken,
        string? endpointId = null, string? ownerSid = null)
    {
        if (outcome.Observation is not { Kind: ClipboardObservationKind.EgressFocusWhileDirty
                or ClipboardObservationKind.EgressPasteWhileDirty } observation)
            return outcome.Response;

        var (verdict, reason) = observation.Kind == ClipboardObservationKind.EgressFocusWhileDirty
            ? (Verdict.AllowedWithoutInspection, FocusObserved)
            : observation.Verdict == ClipboardPasteVerdict.Block
                ? (Verdict.Blocked, (string?)null)
                : (Verdict.AllowedWithoutInspection, PasteAuditOnly);

        var auditEvent = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow,
            endpointId ?? Environment.MachineName,
            string.IsNullOrWhiteSpace(userName) ? "Não informado" : userName,
            "", "", observation.SizeBytes, verdict,
            observation.Categories ?? [], [], observation.SourceProcess ?? "", 0,
            observation.DestinationProcess ?? "", reason,
            observation.PolicyVersion, 0, false, Channel: AuditChannel.Clipboard) { OwnerSid = ownerSid };
        try
        {
            await sink.WriteAsync(auditEvent, cancellationToken).ConfigureAwait(false);
            return outcome.Response with { EventId = auditEvent.EventId.ToString() };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogWarning("Falha ao registrar observacao de clipboard ({Tipo}).",
                exception.GetType().Name);
            return outcome.Response;
        }
    }
}
