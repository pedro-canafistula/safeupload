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
                current.StageSpaceFailed || current.State != TransferJournalState.Publishing || current.PendingRename is not null ||
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
            if (current.SupersededByFollowup is not null)
                throw new IOException("private_cancellation_version_unresolved"); // retired; only its stage disposal remains
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
            if (current.StageDeleted) return; // immutable exact completion replay
            await ReplaceAsync(ManifestPath(current.Transfer.TransferId), current with {
                StageDeleted = true, UpdatedAtUtc = DateTimeOffset.UtcNow
            }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// T8 Word drop 2 (owner, 2026-10-30). Word can reopen a document for writing right after a save, before the service
    /// starts inspecting the version it just sealed. The follow-up version seeded from it then supersedes it, so it is
    /// Retained and was kept for ever (mvpWdiagG4). Once that exact follow-up is published, the superseded version is
    /// retired: it never became public, is never inspected or published again, and its stage is disposed of like a
    /// released one. Returns the retired entry, or null while the version or its follow-up does not qualify.
    /// </summary>
    internal async Task<TransferJournalEntry?> RetireSupersededByFollowupAsync(Guid predecessorId,
        IReadOnlyCollection<Guid> hotFollowups, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(predecessorId, token).ConfigureAwait(false);
            if (current.SupersededByFollowup is not null) return current;
            if (current.State != TransferJournalState.Retained || !current.SealedOnce || current.StageIdentity is null ||
                current.BoundAllocation is not null || current.UnboundCancellation is not null ||
                current.PendingRename is not null || current.StageCleanupStarted || current.StageDeleted ||
                current.HandbackState != StagedHandbackState.NotAttempted || current.DiscardKind is not null ||
                // An empty (legacy) history cannot show that the version was never public; it stays Retained.
                !current.StateHistory.Any() ||
                current.StateHistory.Any(change => change.State is TransferJournalState.Publishing or
                    TransferJournalState.Released or TransferJournalState.Blocked))
                return null;
            var version = VersionIdentity(current);
            // Direct follow-ups only, by their durable parent link: hot candidates named by the caller (from its pending
            // snapshot, or the follow-up just released), each reread here, and the archive index (a newer archived save can
            // hide a published follow-up from the destination's claims). No directory-wide scan per predecessor.
            await EnsureArchiveLoadedCoreAsync(token).ConfigureAwait(false);
            var children = new List<TransferJournalEntry>();
            foreach (Guid id in hotFollowups.Distinct())
            {
                if (id == predecessorId || _archived.ContainsKey(id)) continue;
                try { children.Add(await ReadCoreAsync(id, token).ConfigureAwait(false)); }
                catch (FileNotFoundException) { } // archived meanwhile: the index below has it
            }
            if (_archivedFollowups.TryGetValue(predecessorId, out var archivedIds))
                foreach (Guid id in archivedIds)
                    children.Add(await ReadArchivedCoreAsync(id, token).ConfigureAwait(false));
            var followup = children.FirstOrDefault(child =>
                child.ParentVersionIdentity == version && child.State == TransferJournalState.Released &&
                child.SealedOnce && child.BoundAllocation is null && child.PendingRename is null &&
                child.DestinationGeneration > current.DestinationGeneration &&
                string.Equals(child.Transfer.DestinationPath, current.Transfer.DestinationPath, StringComparison.OrdinalIgnoreCase));
            if (followup is null) return null;
            var retired = current with { SupersededByFollowup = VersionIdentity(followup), UpdatedAtUtc = DateTimeOffset.UtcNow };
            await ReplaceAsync(ManifestPath(predecessorId), retired, token).ConfigureAwait(false);
            return retired;
        }
        finally { _gate.Release(); }
    }

    internal async Task<TransferJournalEntry> CompleteSupersededStageDisposalAsync(TransferJournalEntry expected,
        CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(expected.Transfer.TransferId, token).ConfigureAwait(false);
            if (current.SupersededByFollowup is null || current.SupersededByFollowup != expected.SupersededByFollowup ||
                VersionIdentity(current) != VersionIdentity(expected) ||
                !StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out _))
                throw new IOException("The superseded exact stage has no absence receipt.");
            if (current.StageDeleted) return current; // immutable exact completion replay
            var disposed = current with { StageDeleted = true, UpdatedAtUtc = DateTimeOffset.UtcNow };
            await ReplaceAsync(ManifestPath(current.Transfer.TransferId), disposed, token).ConfigureAwait(false);
            return disposed;
        }
        finally { _gate.Release(); }
    }
}
