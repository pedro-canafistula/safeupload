using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class MinifilterInterceptor
{
    private Task ExecuteDispatchedRequestAsync(FilterPort port, SafeUploadRequest request, ulong messageId,
        StagedRequestTrace trace, StagedRequestDispatcher dispatcher, Guid cookie, StagedDispatchLane lane,
        bool validHeader, Task<Guid?> precedingDriver, CancellationToken token, long boundTicket)
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (lane != StagedDispatchLane.Ordered) return ReplyAfterOrderedAsync();

        async Task ReplyAfterOrderedAsync()
        {
            Guid? driver = await AwaitDispatchDriverAsync(precedingDriver, dispatcher, cookie, token).ConfigureAwait(false);
            await ReplyContinuationAsync(port, request, messageId, driver, token).ConfigureAwait(false);
        }
#endif
        if (!validHeader) ReplyDispatchFailure(port, request, messageId, null);
        else ProcessOrderedRequest(port, request, messageId, trace, dispatcher, cookie, token, boundTicket);
        return Task.CompletedTask;
    }

    internal static async Task<Guid?> AwaitDispatchDriverAsync(Task<Guid?> precedingDriver,
        StagedRequestDispatcher dispatcher, Guid cookie, CancellationToken token)
    {
        Guid? driver = await precedingDriver.WaitAsync(token).ConfigureAwait(false);
        if (token.IsCancellationRequested || !dispatcher.IsCurrent(cookie)) throw new OperationCanceledException(token);
        return driver;
    }

    internal static bool HasDispatchHeader(SafeUploadRequest request) =>
        request.Version == Contract.Version && request.StructSize == Contract.RequestSize &&
        (request.Operation == Operation.StageDiagnostic || request.HasKnownFlags);

    internal static StagedDispatchLane DispatchLane(SafeUploadRequest request)
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (request.Operation == Operation.StageSeal ||
            request.Operation == PrivateCancellationV28.Operation || request.Reserved == PrivateCancellationV28.Version ||
            request.Operation == PublicDispositionV25.Operation || request.Reserved == PublicDispositionV25.Version ||
            request.Operation == NativeLifecycleV24.Operation || request.Reserved == NativeLifecycleV24.Version)
            return StagedDispatchLane.Continuation;
        if (request.Reserved == Contract.StageBoundAllocationVersion && request.Operation == Operation.StageAllocate)
            return StagedDispatchLane.Allocation;
#endif
        return StagedDispatchLane.Ordered;
    }

    private void ReplyDispatchFailure(FilterPort port, SafeUploadRequest request, ulong messageId, Exception? error)
    {
        if (error is not null)
            _logger.LogWarning(error, "Request {RequestId} failed in the bounded dispatcher.", request.RequestId);
        try
        {
            var failure = CreateDispatchFailure(request);
            if (failure.AllocationResolution is { } resolution)
                _ = port.ReplyAllocationResolutionV20(messageId, request, resolution);
            else if (failure.Lifecycle is { } lifecycle)
                _ = port.ReplyStageLifecycleV20(messageId, lifecycle);
            else if (failure.Rename is { } rename)
                _ = port.ReplyStageRenameCommitV20(messageId, rename);
            else port.Reply(messageId, request.RequestId, Verdict.Deny);
        }
        catch (Exception replyError)
        {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            _boundReadiness.Invalidate(StagedBoundBlocker.ProtocolChanged);
#endif
            _logger.LogWarning(replyError, "Falha ao responder o veredito {RequestId}.", request.RequestId);
        }
    }

    internal static (uint? AllocationResolution, SafeUploadStageLifecycleV20? Lifecycle,
        SafeUploadStageRenameReplyV20? Rename) CreateDispatchFailure(SafeUploadRequest request)
    {
        if (!HasDispatchHeader(request)) return default;
        // Preserve the operation's existing transient resource failure. In
        // particular saturation is never proof of NoAllocationCommitted:
        // another duplicate may already have committed the same intent.
        if (request.Operation == Operation.StageAllocate &&
            request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out _))
        {
            try
            {
                _ = FilterPort.CreateAllocationResolutionReplyV20(request, StageV20Result.RetryableFailure);
                return (StageV20Result.RetryableFailure, null, null);
            }
            catch (ArgumentException) { return default; }
        }
        if (request.Operation is Operation.StageAttachCommit or Operation.StageCompletionPermit or Operation.StageHandleObserved &&
            request.TryReadStagePayload<SafeUploadStageLifecycleV20>(request.Operation, out var lifecycle) &&
            lifecycle.Operation == request.Operation && lifecycle.Result == 0 && lifecycle.RequestId == request.RequestId &&
            lifecycle.RequestId != 0 && request.RequestorProcessId != 0 && lifecycle.TransferId != Guid.Empty &&
            lifecycle.DestinationGeneration is > 0 and <= long.MaxValue && lifecycle.StageIdentity.HasNonzeroFileId &&
            lifecycle.DriverInstanceId != Guid.Empty && lifecycle.ParentDirectoryIdentity.HasNonzeroFileId)
        {
            lifecycle.Result = StageV20Result.RetryableFailure;
            return (null, lifecycle, null);
        }
        if (request.Operation == Operation.StageRenameCommit &&
            request.TryReadStagePayload<SafeUploadStageRenameV20>(request.Operation, out var rename) &&
            rename.RequestId == request.RequestId && rename.OwnerProcessId == request.RequestorProcessId)
        {
            try
            {
                return (null, null, FilterPort.CreateStageRenameReplyV20(rename, 0,
                    request.GetPath(), StageV20Result.RetryableFailure));
            }
            catch (ArgumentException) { return default; }
        }
        return default;
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    private Task ReplyContinuationAsync(FilterPort port, SafeUploadRequest request, ulong messageId,
        Guid? driver, CancellationToken token)
    {
        if (request.Operation == Operation.StageSeal)
            return ReplySealAsync(port, request, messageId, driver, token);
        if (request.Operation == PrivateCancellationV28.Operation || request.Reserved == PrivateCancellationV28.Version)
            return ReplyPrivateCancellationAsync(port, request, messageId, driver, token);
        if (request.Operation == PublicDispositionV25.Operation || request.Reserved == PublicDispositionV25.Version)
            return ReplyPublicOpenAsync(port, request, messageId, driver, token);
        if (request.Operation == NativeLifecycleV24.Operation || request.Reserved == NativeLifecycleV24.Version)
            return ReplyNativeLifecycleAsync(port, request, messageId, driver, token);
        return ReplyBoundAllocationAsync(port, request, messageId, driver, token);
    }
#endif
}
