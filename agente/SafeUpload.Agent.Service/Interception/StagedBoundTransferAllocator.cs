#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Core.Domain;
using System.Security.AccessControl;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferAllocator
{
    private readonly Dictionary<Guid, BoundReservationCell> _boundReservations = new();
    private readonly SemaphoreSlim _boundAllocationIoSlots = new(4, 4);

    internal async Task<StagedAllocationReply> AllocateV23Async(string destinationPath,
        DestinationKind destination, string processName, int processId, uint sessionId,
        string requestorSid, long requestorProcessCreationTime, StagedAllocationBindingV23 binding,
        CancellationToken token, StagedAllocationSecuritySnapshot? security = null)
    {
        binding.Validate();
        if (security is null) throw new InvalidDataException("writer_metadata_incomplete");
        security.RequireBinding(binding);
        string locator = Path.GetFullPath(destinationPath);
        string extension = Path.GetExtension(binding.CanonicalLeaf);
        if (!binding.Destination.LeafEquals(Path.GetFileName(locator)) ||
            locator.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            extension.Length > 16 || extension.IndexOfAny(['\\', '/', ':']) >= 0 || processId <= 0 ||
            string.IsNullOrWhiteSpace(requestorSid) || requestorProcessCreationTime <= 0)
            throw new ArgumentException("Invalid bound allocation locator or writer.");
        var transfer = new StagedTransfer(binding.ReservationId,
            Path.Combine(_root, binding.ReservationId.ToString("N") + extension), locator, destination,
            processName, processId, sessionId)
        {
            RequestorSid = requestorSid, RequestorProcessCreationTime = requestorProcessCreationTime
        };

        security.RequireWriterMetadata(binding, transfer);

        using var reservation = await EnterBoundReservationAsync(binding.ReservationId, token).ConfigureAwait(false);
        using var turn = await _journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, token).ConfigureAwait(false);
        // Waiting for a destination consumes neither a worker thread nor an
        // I/O slot. Only the admitted disk transaction takes a bounded slot.
        await _boundAllocationIoSlots.WaitAsync(token).ConfigureAwait(false);
        try
        {
        TransferJournalEntry? existing = await _journal.FindBoundAllocationAsync(binding.ReservationId, token)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            TransferJournalEntry replay = await _journal.CommitBoundAllocationAsync(turn, transfer, binding, token, security)
                .ConfigureAwait(false);
            return BoundAllocationReply(replay);
        }

        using var directory = StagedDestinationDirectory.Open(binding);
        directory.RequirePublicTarget(binding.PublicTarget, token);
        TransferJournalEntry? parent = await _journal.ReadBoundAllocationParentAsync(transfer, binding, token)
            .ConfigureAwait(false);
        using StagedStageFile? predecessor = parent is null ? null : StagedStageFile.Open(parent.Transfer.StagePath);
        if (parent is not null && (predecessor!.Identity != parent.StageIdentity ||
            predecessor.Stream.Length != parent.SealedLength))
            throw new IOException("The held private seed changed identity or measured length.");
        bool copy = binding.Disposition is 1 or 3 && (parent is not null || binding.PublicTarget is not null);
        using FileStream? publicSource = copy && parent is null
            ? directory.OpenPublicSource(binding.PublicTarget!, token) : null;
        // Only an object whose journal is absent is eligible for orphan cleanup.
        // Failure after manifest commit must retain that exact candidate.
        if (!StagedStageFile.TryDeleteUnjournaled(transfer.StagePath, out Exception? orphanFailure))
            throw new IOException("An unjournaled reservation cannot be safely recovered.", orphanFailure);
        StagedStageIdentity? createdIdentity = null;
        try
        {
            await StagedBackingFile.CreateFromHeldSourceAsync(null,
                transfer.StagePath, MaximumSeedBytes, token).ConfigureAwait(false);
            if (_fileSecurity is not null) new FileInfo(transfer.StagePath).SetAccessControl(_fileSecurity);
            using (StagedStageFile created = StagedStageFile.Open(transfer.StagePath))
                createdIdentity = created.Identity;
            directory.RequirePublicTarget(binding.PublicTarget, token);
            TransferJournalEntry entry = await _journal.CommitBoundAllocationAsync(turn, transfer, binding, token, security,
                seedPending: copy).ConfigureAwait(false);
            if (copy)
            {
                FileStream source = (predecessor?.Stream ?? publicSource)!;
                long length = source.Length;
                source.Position = 0;
                await StagedBackingFile.CreateFromHeldSourceAsync(source, transfer.StagePath,
                    MaximumSeedBytes, token, createdIdentity).ConfigureAwait(false);
                if (source.Length != length)
                    throw new IOException("The seed source changed length during copying.");
                directory.RequirePublicTarget(binding.PublicTarget, token);
                entry = await _journal.CompleteBoundSeedAsync(StagedTransferJournal.VersionIdentity(entry),
                    length, token).ConfigureAwait(false);
            }
            return BoundAllocationReply(entry);
        }
        catch (Exception allocationFailure)
        {
            // Do not delete on an uncertain journal read. Cleanup evidence is
            // independent of publication, and an interrupted claim stays private.
            TransferJournalEntry? committed = await _journal.FindBoundAllocationAsync(binding.ReservationId,
                CancellationToken.None).ConfigureAwait(false);
            if (committed is null)
            {
                Exception? failure;
                bool removed = createdIdentity is { } exact
                    ? StagedStageFile.TryDeleteExactAndConfirmAbsent(transfer.StagePath, exact, out failure)
                    : StagedStageFile.TryDeleteUnjournaled(transfer.StagePath, out failure);
                if (!removed) throw new IOException("The uncommitted bound stage could not be exactly removed.",
                    new AggregateException(allocationFailure, failure ?? new IOException("Exact stage cleanup failed.")));
            }
            throw;
        }
        }
        finally { _boundAllocationIoSlots.Release(); }
    }

    private static StagedAllocationReply BoundAllocationReply(TransferJournalEntry entry)
    {
        using StagedStageFile stage = StagedStageFile.Open(entry.Transfer.StagePath);
        if (entry.StageIdentity != stage.Identity || entry.BoundAllocation is null ||
            entry.DestinationGeneration <= 0 || entry.SealedOnce || entry.SeedCompletion is null ||
            entry.SeedCompletion.Length != stage.Stream.Length ||
            entry.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed))
            throw new IOException("The bound allocation changed before its typed reply.");
        return new(entry.Transfer, entry.DestinationGeneration, stage.Identity, stage.Stream.Length);
    }

    // A reused GUID with a different destination must not delete another
    // request's backing during the backing-before-manifest interval.
    private sealed class BoundReservationCell
    {
        internal readonly SemaphoreSlim Gate = new(1, 1);
        internal int References;
    }

    private sealed class BoundReservationLease(StagedTransferAllocator allocator,
        Guid id, BoundReservationCell cell) : IDisposable
    {
        public void Dispose()
        {
            cell.Gate.Release();
            allocator.ReleaseBoundReservation(id, cell);
        }
    }

    private async Task<BoundReservationLease> EnterBoundReservationAsync(Guid id, CancellationToken token)
    {
        BoundReservationCell cell;
        lock (_boundReservations)
        {
            if (!_boundReservations.TryGetValue(id, out cell!))
                _boundReservations.Add(id, cell = new());
            cell.References++;
        }
        try
        {
            await cell.Gate.WaitAsync(token).ConfigureAwait(false);
            return new(this, id, cell);
        }
        catch { ReleaseBoundReservation(id, cell); throw; }
    }

    private void ReleaseBoundReservation(Guid id, BoundReservationCell cell)
    {
        lock (_boundReservations)
            if (--cell.References == 0) { _boundReservations.Remove(id); cell.Gate.Dispose(); }
    }
}
#endif
