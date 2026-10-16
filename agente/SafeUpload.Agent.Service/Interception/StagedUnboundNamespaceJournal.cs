namespace SafeUpload.Agent.Service.Interception;

public sealed record StagedUnboundCancellation(Guid OperationId, StagedVersionIdentity Version, long Generation);

public sealed partial class StagedTransferJournal
{
    // Only _gate protects these live facts. A restarted Publishing entry has no
    // receipt: cancellation/retarget must retain that uncertainty, never replay.
    private readonly HashSet<Guid> _unboundPublicationAttempts = [];
    private readonly HashSet<Guid> _unboundCommitted = [];

    internal async Task CommitUnboundPublicationAsync(TransferJournalEntry intent, Action commit, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(intent.Transfer.TransferId, token).ConfigureAwait(false);
            if (current != intent || current.BoundAllocation is not null || current.UnboundCancellation is not null ||
                current.State != TransferJournalState.Publishing || current.PendingRename is not null ||
                _unboundCommitted.Contains(current.Transfer.TransferId))
                throw new IOException("The exact publication intent was cancelled or retargeted.");
            await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            // Reserve the live fact before I/O so no allocation follows a
            // successful mutation. The callback validates metadata before the
            // native rename and performs no work after native success.
            _unboundCommitted.Add(current.Transfer.TransferId);
            try { commit(); }
            catch { _unboundCommitted.Remove(current.Transfer.TransferId); throw; }
        }
        finally { _gate.Release(); }
    }

    internal async Task<(bool RequiresPublicDelete, long Generation)> CancelUnboundPrivateAsync(
        Guid operation, StagedVersionIdentity version, Guid driver, int owner, long ownerCreation, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(version.TransferId, token).ConfigureAwait(false);
            if (operation == Guid.Empty || current.BoundAllocation is not null || VersionIdentity(current) != version ||
                current.DriverInstanceId != driver || current.Transfer.ProcessId != owner ||
                current.Transfer.RequestorProcessCreationTime != ownerCreation || !current.SealedOnce)
                throw new IOException("private_cancellation_owner_changed");
            await RequireRenameEpochV20Async(driver, token).ConfigureAwait(false);
            if (current.UnboundCancellation is { } receipt)
            {
                if (receipt.OperationId != operation || receipt.Version != version)
                    throw new IOException("private_cancellation_replay_changed");
                return (false, receipt.Generation);
            }
            if (_unboundCommitted.Contains(version.TransferId) || current.State == TransferJournalState.Released)
                return (true, 0);
            if (current.PendingRename is not null || current.StageCleanupStarted ||
                current.State == TransferJournalState.Publishing && !_unboundPublicationAttempts.Contains(version.TransferId) ||
                current.State is not (TransferJournalState.Sealed or TransferJournalState.Inspecting or
                    TransferJournalState.Approved or TransferJournalState.Publishing or TransferJournalState.Blocked or
                    TransferJournalState.Retained))
                throw new IOException("private_cancellation_version_unresolved");
            var claims = await DestinationVersionsAsync(current.Transfer.DestinationPath, token).ConfigureAwait(false);
            long generation = checked(Math.Max(version.DestinationGeneration,
                claims.Select(c => c.Generation).DefaultIfEmpty(0).Max()) + 1);
            var history = current.State == TransferJournalState.Retained ? current.StateHistory :
                AppendState(current, TransferJournalState.Retained);
            await ReplaceAsync(ManifestPath(version.TransferId), current with {
                UnboundCancellation = new(operation, version, generation),
                State = TransferJournalState.Retained, StateHistory = history,
                JustificationWindowClosed = true, BlockedDeletionReceipt = null, UpdatedAtUtc = DateTimeOffset.UtcNow
            }, token).ConfigureAwait(false);
            _unboundPublicationAttempts.Remove(version.TransferId);
            return (false, generation);
        }
        finally { _gate.Release(); }
    }
    internal async Task CompleteUnboundCancellationCleanupAsync(TransferJournalEntry expected, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(expected.Transfer.TransferId, token).ConfigureAwait(false);
            if (current.UnboundCancellation is null || current.UnboundCancellation != expected.UnboundCancellation ||
                !StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out _))
                throw new IOException("The cancelled exact stage has no absence receipt.");
            await ReplaceAsync(ManifestPath(current.Transfer.TransferId), current with {
                StageDeleted = true, UpdatedAtUtc = DateTimeOffset.UtcNow
            }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

}
