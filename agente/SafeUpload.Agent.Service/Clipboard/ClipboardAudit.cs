using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Clipboard;

public static class ClipboardAudit
{
    public static async Task<ClipboardResponse> WriteAsync(ClipboardOutcome outcome,
        IAuditSink sink, ILogger logger, string? userName, CancellationToken cancellationToken,
        string? endpointId = null)
    {
        if (outcome.Observation is not { Kind: ClipboardObservationKind.EgressFocusWhileDirty } observation)
            return outcome.Response;

        var auditEvent = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow,
            endpointId ?? Environment.MachineName,
            string.IsNullOrWhiteSpace(userName) ? "Não informado" : userName,
            "", "", observation.SizeBytes, Verdict.AllowedWithoutInspection,
            observation.Categories ?? [], [], observation.SourceProcess ?? "", 0,
            observation.DestinationProcess ?? "", "clipboard_focus_observed",
            observation.PolicyVersion, 0, false, Channel: AuditChannel.Clipboard);
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
