#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Diagnostics;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Notifications;
using PortVerdict = SafeUpload.Agent.Minifilter.Verdict;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class MinifilterInterceptor
{
    private readonly StagedBoundReadiness _boundReadiness = new();
    private bool _stageBoundHeadReady => _stageV20Ready && _stagingRecoveryReady &&
        _boundReadiness.Snapshot.IsReady;
    internal static bool BoundAllocationImplemented => StagedBoundReadiness.NativeHolds == StagedBoundBlocker.None;

    private NativeRecordReplay ReadBoundNativeReplay(FilterPort port)
    {
        try
        {
            var replay = port.ReadNativeRecordReplay();
            _boundReadiness.ObserveReplay("native", replay.DriverInstanceId, replay.ConnectionEpoch,
                replay.OsBootSequence, replay.Revision);
            return replay;
        }
        catch { _boundReadiness.Invalidate(StagedBoundBlocker.ReplayInvalidated); throw; }
    }

    private PublicOpenReplay ReadBoundPublicReplay(FilterPort port)
    {
        try
        {
            var replay = port.ReadPublicOpenReplayV25();
            _boundReadiness.ObserveReplay("native", replay.DriverInstanceId, replay.ConnectionEpoch,
                replay.OsBootSequence, replay.Revision);
            return replay;
        }
        catch { _boundReadiness.Invalidate(StagedBoundBlocker.ReplayInvalidated); throw; }
    }

    private async Task ReplyBoundAllocationAsync(FilterPort port, SafeUploadRequest request,
        ulong messageId, Guid? capturedDriver, CancellationToken token)
    {
        try
        {
            StagedAllocationReply? reply = await AllocateStageV23Async(port, request, capturedDriver, token)
                .ConfigureAwait(false);
            if (reply is not null && !token.IsCancellationRequested && BoundAllocationImplemented && _stageBoundHeadReady &&
                _stageV20Ready && _stagingRecoveryReady && _activeDriverInstanceId == capturedDriver)
            {
                var identity = ToWireStageIdentity(reply.StageIdentity);
                port.ReplyStageCreateV19(messageId, request.RequestId, Path.GetFileName(reply.Transfer.StagePath),
                    checked((ulong)reply.DestinationGeneration), in identity);
            }
            else port.Reply(messageId, request.RequestId, PortVerdict.Deny);
            Interlocked.Increment(ref _answered);
        }
        catch (Exception error)
        {
            _boundReadiness.Invalidate(StagedBoundBlocker.UnresolvedPrerequisite);
            _logger.LogWarning(error, "Bound allocation/reply failed for request {RequestId}.", request.RequestId);
            try { port.Reply(messageId, request.RequestId, PortVerdict.Deny); }
            catch (Exception replyError)
            { _logger.LogWarning(replyError, "Bound allocation denial delivery failed for {RequestId}.", request.RequestId); }
        }
    }

    private async Task<StagedAllocationReply?> AllocateStageV23Async(FilterPort port, SafeUploadRequest request,
        Guid? capturedDriver, CancellationToken token)
    {
        using var ownerPolicy = StagedRequestTiming.Measure("policy-and-owner");
        if (!BoundAllocationImplemented || !_stageBoundHeadReady || !_stagingEnabled || !_stageV20Ready || !_stagingRecoveryReady ||
            capturedDriver is not { } driver || _activeDriverInstanceId != driver ||
            _stageAllocator is not { } allocator || _stageJournal is not { } journal ||
            !request.TryReadBoundAllocationV23(out var payload, out string leaf) ||
            request.TypedFlags.HasFlag(RequestFlags.StageNetwork) ||
            request.TypedFlags.HasFlag(RequestFlags.StageRemovable))
            return null;
        try
        {
            string? destination = NtPathTranslator.ToDosPath(request.GetPath());
            if (destination is null) return null; // Locator only; no authority reconstructed here.
            int processId = checked((int)request.RequestorProcessId);
            var parent = new StagedStageIdentity(payload.ParentIdentity.VolumeSerialNumber,
                payload.ParentIdentity.FileIdHigh, payload.ParentIdentity.FileIdLow);
            var binding = new StagedAllocationBindingV23(payload.AllocationReservationId, driver,
                payload.ParentTransferId, payload.Disposition, payload.ReferenceKind, payload.MountManagerVolumeId,
                new(parent.VolumeSerialNumber, payload.VolumeRootIdHigh, payload.VolumeRootIdLow), parent,
                payload.ParentCaseSensitive == 1, leaf, payload.PublicTargetPresent
                    ? new(parent.VolumeSerialNumber, payload.PublicTargetIdHigh, payload.PublicTargetIdLow) : null);
            var metadata = port.ReadWriterMetadata(driver, binding.ReservationId, request.RequestId, token);
            var security = StagedAllocationSecuritySnapshot.FromWriterMetadata(metadata);
            security.RequireBinding(binding);
            DestinationKind kind = ClassifyStagedDestination(request.TypedFlags);
            var requestor = SessionResolver.GetRequiredProcessIdentity(processId);
            TransferJournalEntry? saved = await journal.FindBoundAllocationAsync(binding.ReservationId, token)
                .ConfigureAwait(false);
            if (saved is not null)
            {
                if (saved.BoundAllocation != binding || saved.Transfer.ProcessId != processId ||
                    saved.Transfer.Destination != kind ||
                    !string.Equals(saved.Transfer.DestinationPath, Path.GetFullPath(destination), StringComparison.Ordinal))
                    throw new IOException("The bound reservation belongs to a different request.");
                var writer = saved.Transfer;
                RequireBoundWriterIdentity(writer, processId);
                ownerPolicy?.Dispose();
                var replay = await allocator.AllocateV23Async(destination, kind, writer.ProcessName, processId,
                    writer.SessionId ?? throw new IOException("The saved bound writer has no session."),
                    writer.RequestorSid ?? throw new IOException("The saved bound writer has no SID."),
                    writer.RequestorProcessCreationTime ?? throw new IOException("The saved writer has no process lifetime."),
                    binding, token, security).ConfigureAwait(false);
                RequireBoundWriterIdentity(writer, processId);
                return replay;
            }
            string processName = Process.GetProcessById(processId).ProcessName;
            Policy policy = await _policyStore.LoadCurrentAsync(token).ConfigureAwait(false);
            var operation = new FileOperation(destination, Path.GetFileName(destination), Path.GetExtension(destination),
                0, DateTime.MinValue, processName, processId, destination, kind);
            if (!policy.IsMonitoredDestination(operation)) return null;
            ownerPolicy?.Dispose();
            var reply = await allocator.AllocateV23Async(destination, kind, processName, processId,
                requestor.SessionId, requestor.UserSid.Value, requestor.CreationTimeFileTime, binding, token, security)
                .ConfigureAwait(false);
            var after = SessionResolver.GetRequiredProcessIdentity(processId);
            if (after.SessionId != requestor.SessionId || after.CreationTimeFileTime != requestor.CreationTimeFileTime ||
                !after.UserSid.Equals(requestor.UserSid))
                throw new IOException("The original bound writer changed during allocation.");
            return reply;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return null; }
        catch (Exception error)
        {
            _logger.LogWarning(error, "Bound allocation refused for request {RequestId}.", request.RequestId);
            return null;
        }
    }

    internal static void RequireBoundWriterIdentity(StagedTransfer writer, int processId)
    {
        using var ownerTiming = StagedRequestTiming.Measure("policy-and-owner");
        var current = SessionResolver.GetRequiredProcessIdentity(processId);
        if (writer.ProcessId != processId || writer.SessionId != current.SessionId ||
            writer.RequestorProcessCreationTime != current.CreationTimeFileTime ||
            !string.Equals(writer.RequestorSid, current.UserSid.Value, StringComparison.Ordinal))
            throw new IOException("The original bound writer changed before allocation replay.");
    }
}
#endif
