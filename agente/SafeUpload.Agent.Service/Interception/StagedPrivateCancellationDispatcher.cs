#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed class StagedPrivateCancellationDispatcher(StagedTransferJournal journal,
    Func<StagedAllocationBindingV23, CancellationToken, StagedDestinationNameObservation> observe, Func<bool> ready)
{
    internal async Task<PrivateCancellationReplyV28> ProcessAsync(PrivateCancellationRequestV28 request,
        Guid driver, CancellationToken token)
    {
        if (!ready() || !PrivateCancellationV28.Valid(request) || request.DriverInstanceId != driver)
            throw new IOException("private_cancellation_not_ready");
        var entry = await journal.ReadAsync(request.TransferId, token).ConfigureAwait(false);
        if (entry.DriverInstanceId != driver) throw new IOException("private_cancellation_binding_unproved");
        if (entry.BoundAllocation is not { } binding)
        {
            var canceled = await journal.CancelUnboundPrivateAsync(request.OperationId,
                new(request.TransferId, checked((long)request.Generation),
                    new(request.StageIdentity.VolumeSerialNumber, request.StageIdentity.FileIdHigh, request.StageIdentity.FileIdLow)),
                driver, checked((int)request.OwnerProcessId), request.OwnerCreationTime, token).ConfigureAwait(false);
            return new() { Request = request, CancellationGeneration = checked((ulong)canceled.Generation),
                Result = canceled.RequiresPublicDelete ? PrivateCancellationV28.RequiresPublicDelete : PrivateCancellationV28.Canceled };
        }
        using var turn = await journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        if (!ready()) throw new IOException("private_cancellation_channel_changed");
        var result = await journal.CancelSealedPrivateAsync(turn, request.OperationId,
            new(request.TransferId, checked((long)request.Generation),
                new(request.StageIdentity.VolumeSerialNumber, request.StageIdentity.FileIdHigh, request.StageIdentity.FileIdLow)),
            checked((int)request.OwnerProcessId), request.OwnerCreationTime, observe(binding, token), token).ConfigureAwait(false);
        return new() { Request = request, CancellationGeneration = checked((ulong)result.Generation),
            Result = result.RequiresPublicDelete ? PrivateCancellationV28.RequiresPublicDelete : PrivateCancellationV28.Canceled };
    }
}

public sealed partial class MinifilterInterceptor
{
    private async Task ReplyPrivateCancellationAsync(FilterPort port, SafeUploadRequest request, ulong messageId,
        Guid? driver, CancellationToken token)
    {
        try
        {
            if (!_stageV20Ready || !_stagingRecoveryReady || _stageJournal is not { } journal ||
                driver is not { } current || _activeDriverInstanceId != current ||
                !request.TryReadPrivateCancellationV28(out var payload))
                throw new IOException("private_cancellation_not_ready");
            var dispatcher = new StagedPrivateCancellationDispatcher(journal, (binding, cancellation) =>
            {
                if (!_stageBoundHeadReady) throw new IOException("private_cancellation_not_ready");
                using var directory = StagedDestinationDirectory.Open(binding);
                return StagedDestinationNameObserver.Observe(directory.VolumeRoot, directory.Parent, binding.Destination, cancellation);
            }, () => _stageV20Ready && _stagingRecoveryReady && _activeDriverInstanceId == current && !token.IsCancellationRequested);
            var reply = await dispatcher.ProcessAsync(payload, current, token).ConfigureAwait(false);
            port.ReplyPrivateCancellationV28(messageId, request.RequestId, reply);
            Interlocked.Increment(ref _answered);
        }
        catch (Exception error)
        {
            _boundReadiness.Invalidate(StagedBoundBlocker.UnresolvedPrerequisite);
            _logger.LogWarning(error, "Private cancellation {RequestId} retains its exact version.", request.RequestId);
            try { port.Reply(messageId, request.RequestId, Verdict.Deny); }
            catch (Exception delivery) { _logger.LogWarning(delivery, "Private cancellation reply was lost."); }
        }
    }
}
#endif
