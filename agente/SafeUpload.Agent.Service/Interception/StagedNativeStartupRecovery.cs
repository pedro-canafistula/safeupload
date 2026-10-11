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
    private bool _active = true;
    private StagedNativeRecoverySession? _session;
    private Task<(Guid Driver, StagedDriverEpochReconcileV20 Result)>? _preparation;

    internal StagedNativeStartupRecovery(StagedTransferJournal journal,
        Func<NativeRecordReplay> readAuthenticatedReplay, Func<CancellationToken, Task> recoverPrivateStages)
        => (_journal, _readAuthenticatedReplay, _recoverPrivateStages) =
            (journal, readAuthenticatedReplay, recoverPrivateStages);

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
        lock (_sync) { _active = false; _session?.Invalidate(); }
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
                complete: true, reconciled: true, records);
            var result = await _journal.ReconcileDriverStartupAsync(replay.DriverInstanceId, 0x3f, proof,
                async recoveryToken =>
                {
                    await _recoverPrivateStages(recoveryToken).ConfigureAwait(false);
                    // Until the anchored live recovery and shared physical
                    // commit dispatcher are integrated, never let the existing
                    // publisher bypass a durable exceptional hold.
                    var recoveredHeads = await _journal.ReadDestinationHeadsAsync(recoveryToken).ConfigureAwait(false);
                    var held = recoveredHeads.Where(h => h.Deletes.Any(d => d.State == StagedPublicDeleteState.AcceptedUnresolved))
                        .Select(h => h.Locator).ToArray();
                    if (held.Length != 0)
                        throw new IOException("Native publication recovery remains unresolved: " + string.Join(", ", held));

                    NativeRecordReplay final = _readAuthenticatedReplay();
                    if (final.DriverInstanceId != replay.DriverInstanceId || final.ConnectionEpoch != replay.ConnectionEpoch ||
                        final.OsBootSequence != replay.OsBootSequence || final.Revision != replay.Revision)
                        throw new IOException("Authenticated native replay changed during private startup recovery.");
                    ReconcileRecords(final, recoveredHeads);
                }, token).ConfigureAwait(false);
            return (replay.DriverInstanceId, result);
        }
        catch { Invalidate(); throw; }
    }

    private static StagedNativeRecordReplay[] ReconcileRecords(NativeRecordReplay replay,
        IReadOnlyList<StagedDestinationHead> heads)
    {
        var records = new List<StagedNativeRecordReplay>();
        foreach (NativeRecordReplayRow row in replay.Records)
        {
            var destination = new StagedDestinationIdentity(Identity(row.VolumeRootIdentity), Identity(row.ParentIdentity),
                row.ParentCaseSensitive, row.CanonicalLeaf);
            var binding = new StagedPublicDeleteBinding(row.TransferId, row.RequestNonce, row.DriverInstanceId,
                row.OriginalConnectionEpoch, Identity(row.PublicIdentity), checked((int)row.CallerProcessId),
                row.CallerProcessCreationTime, row.CallerSessionId, row.CallerSid, row.OsBootSequence);
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
            records.Add(new(binding, row.OperationId, row.Facts.HasFlag(NativeRecordFacts.LastHandleCleanedUp),
                row.Facts.HasFlag(NativeRecordFacts.CancelledBeforeHandle), row.Facts.HasFlag(NativeRecordFacts.CancelledCloseObserved)));
        }
        return records.ToArray();
    }

    private static StagedStageIdentity Identity(SafeUploadStageIdentityV19 value)
        => new(value.VolumeSerialNumber, value.FileIdLow, value.FileIdHigh);
}
#endif
