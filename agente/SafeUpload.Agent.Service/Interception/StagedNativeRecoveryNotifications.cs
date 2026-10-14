using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Interception;

// Emit only from the live recovery dispatcher after reading the exact durable
// destination head. This records a diagnosis and guidance, never clears a hold
// or offers an override. Startup and live last-close reconciliation share the
// same owner-scoped guidance; no notification grants publication authority.
internal static class StagedNativeRecoveryNotifications
{
    internal static void PublishRelay(NotificationHub hub, ILogger logger, StagedDestinationHead head,
        StagedPublicRelayReceipt receipt, StagedRecoveryAdvice advice, string reason)
    {
        if (!(head.PublicRelayReceipts ?? []).Contains(receipt) || !Enum.IsDefined(advice) || string.IsNullOrWhiteSpace(reason))
            throw new InvalidOperationException("Ordinary recovery guidance requires the exact retained receipt.");
        logger.LogWarning("Native disposition recovery holds {Destination}: transfer {TransferId}, operation {OperationId}, " +
            "generation {Generation}, native status {NativeStatus}, reason {Reason}, advice {Advice}",
            head.Locator, receipt.Binding.TransferId, receipt.OperationId, receipt.Generation, receipt.NativeStatus, reason, advice);
        var notice = new TransferNotification(receipt.Binding.TransferId, head.Locator, TransferPhase.Retained, RecoveryAdvice: advice);
        if (receipt.Binding.OwnerSessionId == 0) hub.RecordOnly(notice, 0);
        else hub.Publish(notice, receipt.Binding.OwnerSessionId, receipt.Binding.OwnerSid);
    }

    internal static bool Publish(NotificationHub hub, ILogger logger, StagedDestinationHead head,
        StagedPublicDeleteRecord delete, StagedRecoveryAdvice advice, string diagnosticReason)
    {
        ArgumentNullException.ThrowIfNull(hub);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(head);
        ArgumentNullException.ThrowIfNull(delete);
        ArgumentException.ThrowIfNullOrWhiteSpace(diagnosticReason);
        bool legacyVolumeUnknown = head.Destination.MountManagerVolumeId is null || delete.Binding.MountManagerVolumeId is null;
        if (!Enum.IsDefined(advice) || delete.Kind != StagedPublicDeleteKind.NativeOnClose ||
            (delete.State != StagedPublicDeleteState.AcceptedUnresolved &&
             !(legacyVolumeUnknown && delete.State == StagedPublicDeleteState.Admitted)) ||
            !head.Deletes.Contains(delete) || (legacyVolumeUnknown && advice != StagedRecoveryAdvice.CollectDiagnostics))
            throw new InvalidOperationException("Recovery guidance requires the exact unresolved native intent.");
        var binding = delete.Binding;
        logger.LogWarning("Native delete recovery holds {Destination}: transfer {TransferId}, generation {Generation}, " +
            "operation {OperationId}, volume {VolumeSerial}, file {FileIdHigh}:{FileIdLow}, accepted {Accepted}, " +
            "driver {DriverInstance}, connection {ConnectionEpoch}, mount volume {MountVolumeId}, reason {Reason}, advice {Advice}",
            head.Locator, binding.TransferId, delete.Generation, delete.OperationId,
            binding.PublicIdentity.VolumeSerialNumber, binding.PublicIdentity.FileIdHigh, binding.PublicIdentity.FileIdLow,
            delete.NativeCreateAccepted, binding.DriverInstanceId, binding.ConnectionEpoch, binding.MountManagerVolumeId, diagnosticReason, advice);
        var notification = new TransferNotification(binding.TransferId, head.Locator, TransferPhase.Retained,
            RecoveryAdvice: advice);
        if (binding.OwnerSessionId == 0)
        {
            hub.RecordOnly(notification, binding.OwnerSessionId);
            return false; // No interactive recipient in session 0.
        }
        return hub.Publish(notification, binding.OwnerSessionId, binding.OwnerSid);
    }
}
