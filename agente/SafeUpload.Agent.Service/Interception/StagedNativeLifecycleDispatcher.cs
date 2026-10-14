#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Interception;

// One authenticated connection supplies these reads. No second public-file
// open or service DELETE authority is obtained by this dispatcher.
internal sealed class StagedNativeLifecycleDispatcher(
    StagedTransferJournal journal, Func<NativeRecordReplay> readReplay,
    Func<NativeNameObservationRequest, NativeNameObservation> observeName,
    Func<NativeRecordReplayRow, string> resolveLocator,
    Action<NativeRecordReplayRow> checkLiveCreator,
    Action<StagedDestinationHead, StagedPublicDeleteRecord, StagedRecoveryAdvice, string>? reportUnresolved = null)
{
    internal async Task<NativeLifecycleReplyV24> ProcessAsync(NativeLifecycleRequestV24 request,
        uint requestorPid, Guid expectedDriver, CancellationToken token)
    {
        if (!NativeLifecycleV24.Valid(request) || expectedDriver == Guid.Empty || requestorPid == 0)
            throw new IOException("Invalid native lifecycle request.");
        NativeRecordReplay replay = RequireReplay(request, expectedDriver);
        var matches = replay.Records.Where(r => r.TransferId == request.TransferId ||
            r.RequestNonce == request.RequestNonce || r.OperationId == request.OperationId).ToArray();
        if (matches.Length == 0 && request.Phase == NativeLifecycleV24.FactsChanged)
            return await ConfirmRemovalAsync(request, requestorPid, replay, token).ConfigureAwait(false);
        if (matches.Length != 1) throw new IOException("Native lifecycle requires one exact retained record.");
        NativeRecordReplayRow row = matches[0];
        if (row.TransferId != request.TransferId || row.RequestNonce != request.RequestNonce ||
            row.OperationId != request.OperationId || row.DriverInstanceId != expectedDriver ||
            row.CallerProcessId != requestorPid || row.OsBootSequence != replay.OsBootSequence ||
            row.OriginalConnectionEpoch == 0 || row.OriginalConnectionEpoch > replay.ConnectionEpoch)
            throw new IOException("Native lifecycle changed its original binding.");
        var destination = StagedNativeStartupRecovery.Destination(row);
        var binding = StagedNativeStartupRecovery.Binding(row);
        var intentFacts = new StagedNativeCreateIntent(row.CreateOptions, row.OriginalDesiredAccess, row.OriginalShareAccess);
        StagedPublicDeleteRecord saved;
        if (request.Phase == NativeLifecycleV24.Prepare)
        {
            if (row.OriginalConnectionEpoch != replay.ConnectionEpoch || row.JournalGeneration != 0 ||
                row.Facts != 0) throw new IOException("Native preparation is no longer an unforwarded CREATE.");
            checkLiveCreator(row); // PID/lifetime; effective filesystem subject remains in the original CREATE.
            string locator = resolveLocator(row); // The held parent's diagnostic name, never open authority.
            using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                StagedDestinationTurnPurpose.Allocation, token).ConfigureAwait(false);
            RequireSameReplay(request, replay);
            // A publication may have finished while this original CREATE was
            // queued. Its pre-open identity must still name the exact link;
            // a stale capture cannot schedule deletion of a replacement.
            var expected = new NativeNameObservationRequest(replay.DriverInstanceId, replay.ConnectionEpoch,
                replay.Revision, replay.OsBootSequence, row.MountManagerVolumeId, row.VolumeRootIdentity,
                row.ParentIdentity, row.ParentCaseSensitive, row.CanonicalLeaf);
            var name = observeName(expected);
            if (name.Binding != expected || name.ChildIdentity is not { } child ||
                child.VolumeSerialNumber != row.PublicIdentity.VolumeSerialNumber ||
                child.FileIdHigh != row.PublicIdentity.FileIdHigh || child.FileIdLow != row.PublicIdentity.FileIdLow)
                throw new IOException("Native CREATE's captured public link changed while awaiting its destination turn.");
            RequireSameReplay(request, replay);
            saved = await journal.BeginNativeDeleteOnCloseCreateAsync(turn, binding, row.OperationId,
                locator, 0, token, intentFacts).ConfigureAwait(false);
            checkLiveCreator(row);
            RequireSameReplay(request, replay);
            return Reply(request, saved.Generation, NativeLifecycleV24.Prepared);
        }

        using var recoveryTurn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        RequireSameReplay(request, replay);
        var heads = await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        var candidates = heads.SelectMany(h => h.Deletes.Select(d => (Head: h, Delete: d)))
            .Where(p => p.Delete.Binding.TransferId == row.TransferId || p.Delete.Binding.RequestNonce == row.RequestNonce ||
                p.Delete.OperationId == row.OperationId).ToArray();
        if (candidates.Length != 1 || candidates[0].Head.Destination != destination ||
            candidates[0].Delete.Binding != binding || candidates[0].Delete.OperationId != row.OperationId ||
            candidates[0].Delete.NativeIntent != intentFacts)
            throw new IOException("Native progress has no exact durable pre-CREATE intent.");
        saved = candidates[0].Delete;
        bool forwarded = row.Facts.HasFlag(NativeRecordFacts.Forwarded);
        bool outcomeKnown = row.Facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown);
        if (forwarded && row.JournalGeneration != checked((ulong)saved.Generation))
            throw new IOException("Native progress changed its journal generation.");
        if (outcomeKnown)
        {
            bool accepted = row.Facts.HasFlag(NativeRecordFacts.CreateAccepted);
            bool checkedIdentity = accepted && row.Facts.HasFlag(NativeRecordFacts.IdentityChecked);
            var outcome = new StagedNativeCreateOutcome((uint)row.Facts & 0x0f, row.CreateStatus, row.IdentityStatus);
            saved = await journal.RecordNativeDeleteOnCloseCreateResultAsync(recoveryTurn, binding,
                row.OperationId, accepted, checkedIdentity, outcome).ConfigureAwait(false);
        }
        if (row.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost) && saved.State == StagedPublicDeleteState.Admitted)
            saved = await journal.RetainNativeReconciliationHoldAsync(recoveryTurn, binding, row.OperationId, token)
                .ConfigureAwait(false);
        RequireSameReplay(request, replay);
        heads = await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        var records = StagedNativeStartupRecovery.ReconcileRecords(replay, heads);
        var session = new StagedNativeRecoverySession(replay.DriverInstanceId, replay.ConnectionEpoch, replay.OsBootSequence);
        try
        {
            var proof = session.ReconcileReplay(replay.DriverInstanceId, replay.ConnectionEpoch,
                complete: true, reconciled: true, records, nativeMapRevision: replay.Revision);
            bool lifetimeEnded;
            try { proof.RequireExactLifetimeEnded(binding, row.OperationId); lifetimeEnded = true; }
            catch (IOException) { lifetimeEnded = false; }
            if (!lifetimeEnded && saved.State == StagedPublicDeleteState.AcceptedUnresolved &&
                row.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost))
                reportUnresolved?.Invoke(AssertExactHead(heads, destination),
                    saved, StagedRecoveryAdvice.RestartWindows, "NativeCleanupCoverageLost");
            if (lifetimeEnded && saved.State is StagedPublicDeleteState.AcceptedUnresolved or StagedPublicDeleteState.Admitted)
            {
                var expected = new NativeNameObservationRequest(replay.DriverInstanceId, replay.ConnectionEpoch,
                    replay.Revision, replay.OsBootSequence, row.MountManagerVolumeId, row.VolumeRootIdentity,
                    row.ParentIdentity, row.ParentCaseSensitive, row.CanonicalLeaf);
                try
                {
                    NativeNameObservation name = observeName(expected);
                    if (name.Binding != expected) throw new IOException("Native name observation changed its exact replay.");
                    RequireSameReplay(request, replay);
                    var observation = new StagedDestinationNameObservation(destination, destination.Parent,
                        destination.Parent, true, name.ChildIdentity is { } child ? Identity(child) : null);
                    if (saved.State == StagedPublicDeleteState.AcceptedUnresolved)
                        saved = await journal.ReconcileNativeDeleteOnCloseAsync(recoveryTurn, binding, row.OperationId,
                            proof, observation, token).ConfigureAwait(false);
                    if (saved.State == StagedPublicDeleteState.Admitted)
                        saved = await journal.CompleteNativeDeleteOnCloseAsync(recoveryTurn, binding, row.OperationId,
                            proof, observation, token).ConfigureAwait(false);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    // Only a durable exceptional hold produces recovery guidance;
                    // publication progress is never a reason to grant an override.
                    var currentHead = AssertExactHead(await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false), destination);
                    var currentDelete = currentHead.Deletes.Single(d => d.Binding == binding && d.OperationId == row.OperationId);
                    if (currentDelete.State == StagedPublicDeleteState.Admitted)
                    {
                        currentDelete = await journal.RetainNativeReconciliationHoldAsync(recoveryTurn, binding,
                            row.OperationId, token).ConfigureAwait(false);
                        currentHead = AssertExactHead(await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false), destination);
                    }
                    if (currentDelete.State == StagedPublicDeleteState.AcceptedUnresolved)
                        reportUnresolved?.Invoke(currentHead, currentDelete, StagedRecoveryAdvice.CollectDiagnostics,
                            "NativeAnchoredReconciliationUnresolved");
                    throw;
                }
            }
            if (saved.State is StagedPublicDeleteState.Failed or StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded)
            {
                RequireSameReplay(request, replay);
                await journal.ArmNativeAcknowledgementAsync(recoveryTurn, binding, row.OperationId,
                    replay.Revision, token).ConfigureAwait(false);
                RequireSameReplay(request, replay);
                return Reply(request, saved.Generation, NativeLifecycleV24.Terminal);
            }
            return Reply(request, saved.Generation, NativeLifecycleV24.Progress);
        }
        finally { session.Invalidate(); }
    }

    private NativeRecordReplay RequireReplay(NativeLifecycleRequestV24 request, Guid driver)
    {
        var replay = readReplay();
        if (replay.DriverInstanceId != driver || replay.ConnectionEpoch == 0 || replay.Revision != request.NativeMapRevision)
            throw new IOException("Native lifecycle replay is stale or belongs to another channel.");
        return replay;
    }

    private async Task<NativeLifecycleReplyV24> ConfirmRemovalAsync(NativeLifecycleRequestV24 request,
        uint pid, NativeRecordReplay replay, CancellationToken token)
    {
        var heads = await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        var candidates = heads.SelectMany(h => h.Deletes.Select(d => (Head: h, Delete: d)))
            .Where(p => p.Delete.Binding.TransferId == request.TransferId || p.Delete.Binding.RequestNonce == request.RequestNonce ||
                p.Delete.OperationId == request.OperationId).ToArray();
        if (candidates.Length != 1 || candidates[0].Delete.Kind != StagedPublicDeleteKind.NativeOnClose ||
            candidates[0].Delete.Binding.TransferId != request.TransferId ||
            candidates[0].Delete.Binding.RequestNonce != request.RequestNonce ||
            candidates[0].Delete.OperationId != request.OperationId || candidates[0].Delete.Binding.OwnerProcessId != pid)
            throw new IOException("Absent native record has no exact retained terminal receipt.");
        var saved = candidates[0];
        using var turn = await journal.EnterDestinationCommitTurnAsync(saved.Head.Destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        RequireSameReplay(request, replay);
        heads = await journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        var session = new StagedNativeRecoverySession(replay.DriverInstanceId, replay.ConnectionEpoch, replay.OsBootSequence);
        try
        {
            var proof = session.ReconcileReplay(replay.DriverInstanceId, replay.ConnectionEpoch, true, true,
                StagedNativeStartupRecovery.ReconcileRecords(replay, heads), nativeMapRevision: replay.Revision);
            await journal.RetireNativeDeleteReceiptAsync(turn, saved.Delete.Binding, request.OperationId,
                proof, saved.Delete.NativeAcknowledgementRevision ?? 0, token).ConfigureAwait(false);
            return Reply(request, saved.Delete.Generation, NativeLifecycleV24.Progress);
        }
        finally { session.Invalidate(); }
    }

    private void RequireSameReplay(NativeLifecycleRequestV24 request, NativeRecordReplay expected)
    {
        var current = RequireReplay(request, expected.DriverInstanceId);
        if (current.ConnectionEpoch != expected.ConnectionEpoch || current.OsBootSequence != expected.OsBootSequence ||
            !current.Records.SequenceEqual(expected.Records))
            throw new IOException("Native facts changed while the lifecycle request was pending.");
    }

    private static NativeLifecycleReplyV24 Reply(NativeLifecycleRequestV24 request, long generation, uint result) =>
        new() { Request = request, JournalGeneration = checked((ulong)generation), Result = result };
    private static StagedStageIdentity Identity(SafeUploadStageIdentityV19 value) =>
        new(value.VolumeSerialNumber, value.FileIdHigh, value.FileIdLow);
    private static StagedDestinationHead AssertExactHead(IReadOnlyList<StagedDestinationHead> heads,
        StagedDestinationIdentity destination) => heads.Single(h => h.Destination == destination);
}

public sealed partial class MinifilterInterceptor
{
    private async Task ReplyNativeLifecycleAsync(FilterPort port, SafeUploadRequest request, ulong messageId,
        Guid? driver, CancellationToken token)
    {
        try
        {
            if (!_stageBoundHeadReady || !_stageV20Ready || !_stagingRecoveryReady || _stageJournal is not { } journal ||
                driver is not { } current || _activeDriverInstanceId != current ||
                !request.TryReadNativeLifecycleV24(out var payload))
                throw new IOException("The integrated native publication pipeline is not ready.");
            var dispatcher = new StagedNativeLifecycleDispatcher(journal, () => ReadBoundNativeReplay(port),
                port.ObserveNativeName, row =>
                {
                    var destination = StagedNativeStartupRecovery.Destination(row);
                    var allocation = new StagedAllocationBindingV23(row.TransferId, row.DriverInstanceId, Guid.Empty,
                        1, StageV19AllocationReferenceKind.None, row.MountManagerVolumeId,
                        destination.VolumeRoot, destination.Parent, destination.CaseSensitive, destination.CanonicalLeaf,
                        new(row.PublicIdentity.VolumeSerialNumber, row.PublicIdentity.FileIdHigh, row.PublicIdentity.FileIdLow));
                    using var parent = StagedDestinationDirectory.Open(allocation);
                    return parent.ReadLocator();
                }, row =>
                {
                    var process = SessionResolver.GetRequiredProcessIdentity(checked((int)row.CallerProcessId));
                    if (process.CreationTimeFileTime != row.CallerProcessCreationTime)
                        throw new IOException("The native CREATE caller lifetime changed.");
                }, (head, delete, advice, reason) =>
                    StagedNativeRecoveryNotifications.Publish(_hub, _logger, head, delete, advice, reason));
            var reply = await dispatcher.ProcessAsync(payload, request.RequestorProcessId, current, token).ConfigureAwait(false);
            if (token.IsCancellationRequested || !_stageBoundHeadReady || _activeDriverInstanceId != current)
                throw new IOException("Native lifecycle completion belongs to a revoked channel.");
            port.ReplyNativeLifecycleV24(messageId, request.RequestId, reply);
            Interlocked.Increment(ref _answered);
        }
        catch (Exception error)
        {
            _boundReadiness.Invalidate(StagedBoundBlocker.UnresolvedPrerequisite);
            _logger.LogWarning(error, "Native lifecycle request {RequestId} retained its private intent.", request.RequestId);
            try { port.Reply(messageId, request.RequestId, Verdict.Deny); }
            catch (Exception replyError) { _logger.LogWarning(replyError, "Native lifecycle denial was not delivered."); }
        }
    }
}
#endif
