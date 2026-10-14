#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

// Per authenticated FilterPort connection. Preparation runs away from the
// receive loop; reconciliation requests get the existing EpochBusy reply until
// conservative recovery has completed. This object grants no DELETE permit.
internal sealed class StagedNativeStartupRecovery
{
    private readonly object _sync = new();
    private readonly StagedTransferJournal _journal;
    private readonly Func<NativeRecordReplay> _readAuthenticatedReplay;
    private readonly Func<CancellationToken, Task> _recoverPrivateStages;
    private readonly Action<StagedDestinationHead, StagedPublicDeleteRecord>? _reportUnresolved;
    private readonly StagedNativeRecoveryDispatcher? _nativeRecovery;
    private bool _active = true;
    private StagedNativeRecoverySession? _session;
    private StagedBoundRecoveryReceipt? _boundReceipt;
    private readonly Action? _invalidateReadiness;
    private Task<(Guid Driver, StagedDriverEpochReconcileV20 Result)>? _preparation;

    internal StagedNativeStartupRecovery(StagedTransferJournal journal,
        Func<NativeRecordReplay> readAuthenticatedReplay, Func<CancellationToken, Task> recoverPrivateStages,
        Action<StagedDestinationHead, StagedPublicDeleteRecord>? reportUnresolved = null,
        Func<NativeNameObservationRequest, NativeNameObservation>? observeName = null,
        Action<StagedDestinationHead, StagedPublicDeleteRecord, SafeUpload.Agent.Core.Contracts.StagedRecoveryAdvice, string>? reportRecovery = null,
        Action? invalidateReadiness = null)
    {
        (_journal, _readAuthenticatedReplay, _recoverPrivateStages, _reportUnresolved) =
            (journal, readAuthenticatedReplay, recoverPrivateStages, reportUnresolved);
        _invalidateReadiness = invalidateReadiness;
        if (observeName is not null)
            _nativeRecovery = new(journal, readAuthenticatedReplay, observeName,
                reportRecovery ?? ((head, delete, _, _) => reportUnresolved?.Invoke(head, delete)));
    }

    internal Task Start(CancellationToken token)
    {
        lock (_sync)
        {
            if (!_active || _preparation is not null)
                throw new InvalidOperationException("Startup recovery belongs to one live connection.");
            return _preparation = Task.Run(() => PrepareAsync(token), token);
        }
    }

    internal bool TryGetResult(Guid driver, out StagedDriverEpochReconcileV20 result)
    {
        lock (_sync)
        {
            result = StagedDriverEpochReconcileV20.Rejected;
            if (!_active || _preparation is not { IsCompletedSuccessfully: true } done || done.Result.Driver != driver)
                return false;
            result = done.Result.Result;
            return true;
        }
    }

    internal void Invalidate()
    {
        lock (_sync) { _active = false; _boundReceipt = null; _session?.Invalidate(); }
        _invalidateReadiness?.Invoke();
    }

    internal bool TryGetBoundResult(Guid driver, out StagedBoundRecoveryReceipt? receipt)
    {
        lock (_sync)
        {
            receipt = null;
            if (!_active || _preparation is not { IsCompletedSuccessfully: true } done ||
                done.Result.Driver != driver || done.Result.Result != StagedDriverEpochReconcileV20.Active)
                return false;
            receipt = _boundReceipt;
            return receipt is not null;
        }
    }

    internal bool HasFailed
    {
        get
        {
            lock (_sync)
                return _preparation is { IsFaulted: true } or { IsCanceled: true } ||
                    (_preparation is { IsCompletedSuccessfully: true } done &&
                     done.Result.Result == StagedDriverEpochReconcileV20.Rejected);
        }
    }

    private async Task<(Guid, StagedDriverEpochReconcileV20)> PrepareAsync(CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            NativeRecordReplay replay = _readAuthenticatedReplay();
            var heads = await _journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
            StagedNativeRecordReplay[] records = ReconcileRecords(replay, heads);
            StagedNativeRecoverySession session;
            lock (_sync)
            {
                if (!_active) throw new IOException("Startup replay belongs to a disconnected service connection.");
                session = _session = new(replay.DriverInstanceId, replay.ConnectionEpoch, replay.OsBootSequence);
            }
            var proof = session.ReconcileReplay(replay.DriverInstanceId, replay.ConnectionEpoch,
                complete: true, reconciled: true, records, nativeMapRevision: replay.Revision);
            StagedBoundRecoveryReceipt? completed = null;
            var result = await _journal.ReconcileDriverStartupAsync(replay.DriverInstanceId, 0xbf, proof,
                async recoveryToken =>
                {
                    await _recoverPrivateStages(recoveryToken).ConfigureAwait(false);
                    if (_nativeRecovery is not null && heads.Any(h => h.Deletes.Any(d =>
                            d.Kind == StagedPublicDeleteKind.NativeOnClose)))
                        await _nativeRecovery.ReconcileAsync(replay, proof, recoveryToken).ConfigureAwait(false);
                    // A completed pass can retain explicitly diagnosed per-name
                    // barriers. The shared head still bars physical publication;
                    // accepting the epoch permits subsequent exact close events.
                    // Global bound readiness separately refuses every unresolved prerequisite.
                    var recoveredHeads = await _journal.ReadDestinationHeadsAsync(recoveryToken).ConfigureAwait(false);
                    var held = recoveredHeads.Where(h => h.Deletes.Any(d => d.State == StagedPublicDeleteState.AcceptedUnresolved ||
                        (d.Kind == StagedPublicDeleteKind.NativeOnClose && d.State == StagedPublicDeleteState.Admitted &&
                         (h.Destination.MountManagerVolumeId is null || d.Binding.MountManagerVolumeId is null))))
                        .ToArray();
                    if (held.Length != 0 && _nativeRecovery is null)
                    {
                        // Report exact durable native holds through the live
                        // connection's owner-scoped tray/diagnostic delivery.
                        // Reporting can neither accept an epoch nor mutate a
                        // destination head. No resolving trigger is promised
                        // before the shared physical dispatcher is connected.
                        foreach (var head in held)
                            foreach (var delete in head.Deletes.Where(d => d.Kind == StagedPublicDeleteKind.NativeOnClose &&
                                (d.State == StagedPublicDeleteState.AcceptedUnresolved ||
                                 (d.State == StagedPublicDeleteState.Admitted &&
                                  (head.Destination.MountManagerVolumeId is null || d.Binding.MountManagerVolumeId is null)))))
                                _reportUnresolved?.Invoke(head, delete);
                        throw new IOException("Native publication recovery remains unresolved: " +
                            string.Join(", ", held.Select(h => h.Locator)));
                    }

                    NativeRecordReplay final = _readAuthenticatedReplay();
                    if (final.DriverInstanceId != replay.DriverInstanceId || final.ConnectionEpoch != replay.ConnectionEpoch ||
                        final.OsBootSequence != replay.OsBootSequence || final.Revision != replay.Revision)
                        throw new IOException("Authenticated native replay changed during private startup recovery.");
                    ReconcileRecords(final, recoveredHeads);
                    bool unresolved = recoveredHeads.Any(h => h.PendingCommit is not null ||
                        h.Deletes.Any(d => d.State is StagedPublicDeleteState.Admitted or StagedPublicDeleteState.Intent or
                            StagedPublicDeleteState.Accepted or StagedPublicDeleteState.AcceptedUnresolved) ||
                        (h.PublicRelayReceipts?.Length ?? 0) != 0 || (h.PublicationAttempts?.Length ?? 0) != 0 ||
                        (h.PublicationNativeReceipts?.Length ?? 0) != 0);
                    completed = new(final.DriverInstanceId, final.ConnectionEpoch, final.OsBootSequence,
                        final.Revision, unresolved);
                }, token).ConfigureAwait(false);
            lock (_sync)
            {
                if (!_active) throw new IOException("Startup completion belongs to invalidated replay.");
                if (result == StagedDriverEpochReconcileV20.Active) _boundReceipt = completed;
            }
            return (replay.DriverInstanceId, result);
        }
        catch { Invalidate(); throw; }
    }

    internal static StagedNativeRecordReplay[] ReconcileRecords(NativeRecordReplay replay,
        IReadOnlyList<StagedDestinationHead> heads)
    {
        if (replay.DriverInstanceId == Guid.Empty || replay.ConnectionEpoch == 0 || replay.Revision == 0)
            throw new IOException("Native startup requires a complete authenticated replay revision.");
        var records = new List<StagedNativeRecordReplay>();
        foreach (NativeRecordReplayRow row in replay.Records)
        {
            if (row.DriverInstanceId != replay.DriverInstanceId || row.OsBootSequence != replay.OsBootSequence ||
                row.OriginalConnectionEpoch == 0 || row.OriginalConnectionEpoch > replay.ConnectionEpoch)
                throw new IOException("Native startup replay changed its original driver/channel/boot.");
            var destination = new StagedDestinationIdentity(Identity(row.VolumeRootIdentity), Identity(row.ParentIdentity),
                row.ParentCaseSensitive, row.CanonicalLeaf, row.MountManagerVolumeId);
            var binding = new StagedPublicDeleteBinding(row.TransferId, row.RequestNonce, row.DriverInstanceId,
                row.OriginalConnectionEpoch, Identity(row.PublicIdentity), checked((int)row.CallerProcessId),
                row.CallerProcessCreationTime, row.CallerSessionId, row.CallerSid, row.OsBootSequence, row.MountManagerVolumeId);
            var candidates = heads.SelectMany(h => h.Deletes.Select(d => (Head: h, Delete: d)))
                .Where(p => p.Delete.Binding.TransferId == row.TransferId || p.Delete.Binding.RequestNonce == row.RequestNonce ||
                    p.Delete.OperationId == row.OperationId).ToArray();
            if (candidates.Length == 0)
            {
                // A reserved, not-forwarded record cannot have performed the
                // original CREATE. It still remains live in the checked map.
                if (row.Facts.HasFlag(NativeRecordFacts.Forwarded))
                    throw new IOException("A forwarded native CREATE has no exact durable intent.");
            }
            else if (candidates.Length != 1 || candidates[0].Head.Destination != destination ||
                     candidates[0].Delete.Binding != binding || candidates[0].Delete.OperationId != row.OperationId ||
                     candidates[0].Delete.Kind != StagedPublicDeleteKind.NativeOnClose ||
                     (row.Facts.HasFlag(NativeRecordFacts.Forwarded) &&
                      candidates[0].Delete.Generation != checked((long)row.JournalGeneration)))
            {
                throw new IOException("The native replay does not match its exact durable destination intent.");
            }
            else
            {
                var saved = candidates[0].Delete;
                if ((saved.NativeIntent is { } intent && intent != new StagedNativeCreateIntent(
                        row.CreateOptions, row.OriginalDesiredAccess, row.OriginalShareAccess)) ||
                    (saved.NativeOutcome is { } outcome && outcome != new StagedNativeCreateOutcome(
                        (uint)row.Facts & 0x0f, row.CreateStatus, row.IdentityStatus)) ||
                    (saved.NativeCreateAccepted is { } accepted &&
                        (!row.Facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown) ||
                         accepted != row.Facts.HasFlag(NativeRecordFacts.CreateAccepted))))
                    throw new IOException("Native CREATE outcome or original request changed during startup replay.");
            }
            records.Add(new(binding, row.OperationId, row.Facts.HasFlag(NativeRecordFacts.LastHandleCleanedUp),
                row.Facts.HasFlag(NativeRecordFacts.CancelledBeforeHandle), row.Facts.HasFlag(NativeRecordFacts.CancelledCloseObserved)));
        }
        return records.ToArray();
    }

    private static StagedStageIdentity Identity(SafeUploadStageIdentityV19 value)
        => new(value.VolumeSerialNumber, value.FileIdHigh, value.FileIdLow);

    internal static StagedDestinationIdentity Destination(NativeRecordReplayRow row) =>
        new(Identity(row.VolumeRootIdentity), Identity(row.ParentIdentity), row.ParentCaseSensitive,
            row.CanonicalLeaf, row.MountManagerVolumeId);
    internal static StagedPublicDeleteBinding Binding(NativeRecordReplayRow row) =>
        new(row.TransferId, row.RequestNonce, row.DriverInstanceId, row.OriginalConnectionEpoch, Identity(row.PublicIdentity),
            checked((int)row.CallerProcessId), row.CallerProcessCreationTime, row.CallerSessionId, row.CallerSid,
            row.OsBootSequence, row.MountManagerVolumeId);
}
#endif
