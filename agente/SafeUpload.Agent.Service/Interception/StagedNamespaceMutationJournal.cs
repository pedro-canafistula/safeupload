namespace SafeUpload.Agent.Service.Interception;

internal sealed record StagedPrivateCancellationResult(bool RequiresPublicDelete, long Generation);

public sealed partial class StagedTransferJournal
{
    // A tombstone is a projection of accepted immutable facts, never admission
    // or a pending/blocked save. The exact observed object prevents an old
    // handle from hiding an already-published replacement. Recovery reads the
    // same projection after restart; there is no second tombstone journal.
    internal static bool HasAcceptedOwnerTombstone(StagedDestinationHead head, StagedStageIdentity observed,
        int ownerPid, long ownerCreation) => head.Deletes.Any(d =>
            d.Binding.PublicIdentity == observed && d.Binding.OwnerProcessId == ownerPid &&
            d.Binding.OwnerProcessCreationTime == ownerCreation &&
            (d.Kind != StagedPublicDeleteKind.NativeOnClose
                ? d.State == StagedPublicDeleteState.Accepted
                : d.NativeCreateAccepted == true &&
                  d.State is StagedPublicDeleteState.Admitted or StagedPublicDeleteState.AcceptedUnresolved));

    // Caller is the authenticated exact-private-view dispatcher, never a path
    // supplied by the application. The head turn precedes _gate, and is held
    // through the single durable cancellation write. No public I/O is issued.
    internal async Task<StagedPrivateCancellationResult> CancelSealedPrivateAsync(DestinationCommitTurn turn,
        Guid operation, StagedVersionIdentity version, int ownerPid, long ownerCreation,
        StagedDestinationNameObservation observation, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (operation == Guid.Empty || ownerPid <= 0 || ownerCreation <= 0 ||
            observation.Destination != turn.Destination || !observation.CompleteEnumeration ||
            observation.ParentBefore != turn.Destination.Parent || observation.ParentAfter != turn.Destination.Parent)
            throw new IOException("private_cancellation_binding_unproved");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            var cancellations = head.PrivateCancellations ?? [];
            if (cancellations.SingleOrDefault(c => c.OperationId == operation || c.Version == version) is { } prior)
            {
                if (prior.OperationId != operation || prior.Version != version || prior.OwnerProcessId != ownerPid ||
                    prior.OwnerProcessCreationTime != ownerCreation)
                    throw new IOException("private_cancellation_replay_changed");
                return new(false, prior.Generation); // No filesystem mutation or generation allocation on replay.
            }
            RequireNoPendingPhysicalCommit(head);
            var entry = await ReadCoreAsync(version.TransferId, token).ConfigureAwait(false);
            if (VersionIdentity(entry) != version || entry.BoundAllocation?.Destination != turn.Destination ||
                entry.Transfer.ProcessId != ownerPid || entry.Transfer.RequestorProcessCreationTime != ownerCreation ||
                !entry.SealedOnce || entry.PendingRename is not null || entry.StageCleanupStarted || entry.StageDeleted)
                throw new IOException("private_cancellation_owner_changed");
            // Publication may have won while the cancellation waited. Never
            // claim that private cancellation removed a public file, even if
            // its manifest's Released bookkeeping was lost.
            if (head.LatestPublished >= version.DestinationGeneration || observation.PublicIdentity is not null)
                return new(true, 0);
            if (head.CurrentSaveTransferId != version.TransferId || head.CurrentSaveGeneration != version.DestinationGeneration ||
                entry.State is not (TransferJournalState.Sealed or TransferJournalState.Inspecting or
                    TransferJournalState.Approved or TransferJournalState.Publishing or TransferJournalState.Blocked or
                    TransferJournalState.Retained))
                throw new IOException("private_cancellation_version_changed");
            long high = head.MaxAllocated;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            high = Math.Max(high, await BoundManifestHighWaterCoreAsync(turn.Destination, token).ConfigureAwait(false));
#endif
            long generation = checked(high + 1);
            await WriteDestinationHeadCoreAsync(head with { MaxAllocated = generation,
                PrivateCancellations = [.. cancellations, new(operation, version, generation, ownerPid, ownerCreation)] },
                token).ConfigureAwait(false);
            // Keep private bytes and their manifest for exact cleanup. An
            // immutable head floor bars inspection/justification/publication;
            // it is not a physical-delete watermark or cleanup receipt.
            return new(false, generation);
        }
        finally { _gate.Release(); }
    }
}
