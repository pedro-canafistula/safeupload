#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Text.Json;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    private static void RequireBoundAllocationSource(TransferJournalEntry entry, CancellationToken token)
    {
        if (entry.BoundAllocation is not { } binding) return;
        using var directory = StagedDestinationDirectory.Open(binding);
        directory.RequirePublicTarget(binding.PublicTarget, token);
    }

    internal async Task<TransferJournalEntry?> FindBoundAllocationAsync(Guid reservation, CancellationToken token)
    {
        if (reservation == Guid.Empty) throw new ArgumentException("An allocation needs a reservation.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            try { return await ReadCoreAsync(reservation, token).ConfigureAwait(false); }
            catch (FileNotFoundException) { return null; }
        }
        finally { _gate.Release(); }
    }

    // The manifest is flushed first. A crash before its head claim leaves an
    // exact, private recovery candidate, not permission to publish. An exact
    // replay completes that claim only if it has not been overtaken. Neither
    // failure rolls a generation back or erases the backing cleanup obligation.
    internal async Task<TransferJournalEntry> CommitBoundAllocationAsync(DestinationCommitTurn turn,
        StagedTransfer transfer, StagedAllocationBindingV23 binding, CancellationToken token,
        StagedAllocationSecuritySnapshot? security = null)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Allocation);
        binding.Validate();
        security?.RequireBinding(binding);
        if (turn.Destination != binding.Destination || transfer.TransferId != binding.ReservationId ||
            transfer.ProcessId <= 0 || transfer.SessionId is null ||
            string.IsNullOrWhiteSpace(transfer.RequestorSid) || transfer.RequestorProcessCreationTime is not > 0 ||
            !binding.Destination.LeafEquals(Path.GetFileName(transfer.DestinationPath)))
            throw new IOException("The bound allocation does not match its destination or original writer.");

        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            TransferJournalEntry? existing;
            try { existing = await ReadCoreAsync(transfer.TransferId, token).ConfigureAwait(false); }
            catch (FileNotFoundException) { existing = null; }
            using StagedStageFile stage = StagedStageFile.Open(transfer.StagePath);
            if (existing is not null)
            {
                if (existing.Transfer != transfer || existing.BoundAllocation != binding ||
                    existing.AllocationSecurity != security?.Reference() ||
                    existing.AllocationExtensionVersion != 23 || existing.StageIdentity != stage.Identity ||
                    existing.SealedOnce || existing.PendingRename is not null ||
                    existing.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed))
                    throw new IOException("The allocation replay changed its committed tuple or version lifetime.");
                StagedVersionIdentity? parent = await RequireBoundAncestryCoreAsync(transfer, binding, token).ConfigureAwait(false);
                if (existing.ParentVersionIdentity != parent)
                    throw new IOException("The allocation replay changed its exact predecessor.");
                await ClaimBoundAllocationHeadCoreAsync(existing, token).ConfigureAwait(false);
                return existing;
            }

            StagedVersionIdentity? parentIdentity = await RequireBoundAncestryCoreAsync(transfer, binding, token).ConfigureAwait(false);
            var head = await ReadDestinationHeadCoreAsync(binding.Destination, token).ConfigureAwait(false)
                ?? NewDestinationHead(binding.Destination, transfer.DestinationPath);
            RequireNoPendingPhysicalCommit(head);
            if (head.CurrentSaveTransferId == transfer.TransferId ||
                head.Deletes.Any(d => d.Binding.TransferId == transfer.TransferId))
                throw new IOException("The allocation reservation already has a different durable claim.");
            long generation = checked(Math.Max(head.MaxAllocated,
                await BoundManifestHighWaterCoreAsync(binding.Destination, token).ConfigureAwait(false)) + 1);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            var entry = new TransferJournalEntry(transfer, TransferJournalState.Allocated, null, now)
            {
                StateHistory = [new(TransferJournalState.Allocated, now)],
                StageIdentity = stage.Identity, DestinationGeneration = generation,
                ParentVersionIdentity = parentIdentity, CreateReservationId = binding.ReservationId,
                AllocationDisposition = binding.Disposition, AllocationReferenceKind = binding.ReferenceKind,
                AllocationReferenceId = binding.ParentTransferId == Guid.Empty ? null : binding.ParentTransferId,
                DriverInstanceId = binding.DriverInstanceId, ParentDirectoryIdentity = binding.Parent,
                AllocationExtensionVersion = 23, BoundAllocation = binding,
                AllocationSecurity = security?.Reference()
            };
            ValidateEntry(entry, transfer.TransferId);
            if (security is not null) await PersistAllocationSecurityCoreAsync(security, token).ConfigureAwait(false);
            string path = ManifestPath(transfer.TransferId);
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await using (FileStream output = CreatePrivateTemporary(temporary))
                {
                    await JsonSerializer.SerializeAsync(output, entry, cancellationToken: token).ConfigureAwait(false);
                    if (output.Length > StagedJournalFile.MaximumManifestBytes)
                        throw new InvalidDataException("The bound allocation manifest exceeds its size bound.");
                    output.Flush(flushToDisk: true);
                }
                File.Move(temporary, path); // A duplicate cannot replace another manifest.
                ForgetScanned(transfer.TransferId);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            await ClaimBoundAllocationHeadCoreAsync(entry, token).ConfigureAwait(false);
            return entry;
        }
        finally { _gate.Release(); }
    }

    private async Task ClaimBoundAllocationHeadCoreAsync(TransferJournalEntry entry, CancellationToken token)
    {
        var destination = entry.BoundAllocation!.Destination;
        var head = await ReadDestinationHeadCoreAsync(destination, token).ConfigureAwait(false)
            ?? NewDestinationHead(destination, entry.Transfer.DestinationPath);
        RequireNoPendingPhysicalCommit(head);
        if (head.CurrentSaveTransferId == entry.Transfer.TransferId &&
            head.CurrentSaveGeneration == entry.DestinationGeneration &&
            entry.DestinationGeneration > PublicationGenerationFloor(head))
            return;
        if (head.MaxAllocated >= entry.DestinationGeneration ||
            await BoundManifestHighWaterCoreAsync(destination, token).ConfigureAwait(false) > entry.DestinationGeneration ||
            head.Deletes.Any(d => d.Binding.TransferId == entry.Transfer.TransferId))
            throw new IOException("The private allocation candidate was overtaken; retain its exact cleanup obligation.");
        await WriteDestinationHeadCoreAsync(head with
        {
            MaxAllocated = entry.DestinationGeneration, CurrentSaveTransferId = entry.Transfer.TransferId,
            CurrentSaveGeneration = entry.DestinationGeneration
        }, token).ConfigureAwait(false);
    }

    private async Task<long> BoundManifestHighWaterCoreAsync(StagedDestinationIdentity destination, CancellationToken token)
    {
        long high = 0;
        foreach (string path in Directory.EnumerateFiles(_directory, "*.json"))
        {
            token.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out Guid id)) continue;
            TransferJournalEntry entry = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (entry.BoundAllocation?.Destination == destination)
                high = Math.Max(high, entry.DestinationGeneration);
            for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
                if (name.AllocationBindingV23?.Destination == destination) high = Math.Max(high, name.Generation);
        }
        return high;
    }

    internal async Task<TransferJournalEntry?> ReadBoundAllocationParentAsync(StagedTransfer transfer,
        StagedAllocationBindingV23 binding, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await RequireBoundAncestryCoreAsync(transfer, binding, token).ConfigureAwait(false);
            return binding.ReferenceKind == 1
                ? await ReadCoreAsync(binding.ParentTransferId, token).ConfigureAwait(false) : null;
        }
        finally { _gate.Release(); }
    }

    private async Task<StagedVersionIdentity?> RequireBoundAncestryCoreAsync(StagedTransfer transfer,
        StagedAllocationBindingV23 binding, CancellationToken token)
    {
        if (binding.ReferenceKind == 0) return null;
        var parent = await ReadCoreAsync(binding.ParentTransferId, token).ConfigureAwait(false);
        if (!SameWriter(parent.Transfer, transfer) || parent.Transfer.Destination != transfer.Destination ||
            parent.DriverInstanceId != binding.DriverInstanceId || parent.BoundAllocation is null)
            throw new IOException("The bound reference does not belong to the original writer and driver.");
        if (binding.ReferenceKind == 1)
        {
            if (parent.BoundAllocation.Destination != binding.Destination || !HasMeasuredSeal(parent) ||
                parent.State is not (TransferJournalState.Sealed or TransferJournalState.Retained) ||
                binding.Disposition == 2)
                throw new IOException("The bound predecessor is not a stable version of this destination.");
            return VersionIdentity(parent);
        }
        var head = await ReadDestinationHeadCoreAsync(binding.Destination, token).ConfigureAwait(false);
        for (var name = parent.NamespaceTombstones; name is not null; name = name.Previous)
            if (name.AllocationBindingV23?.Destination == binding.Destination &&
                (name.Generation == head?.MaxAllocated || head?.CurrentSaveTransferId == binding.ReservationId))
                return null;
        throw new IOException("No current identity-bound tombstone belongs to this writer.");
    }
}
#endif
