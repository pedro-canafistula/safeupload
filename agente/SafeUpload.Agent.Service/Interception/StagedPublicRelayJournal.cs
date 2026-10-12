namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    // One reconciliation turn spans intent, the original NTFS operation and
    // its durable result. Admission and intent are flushed together; opening
    // the handle earlier did not allocate this generation.
    internal async Task<StagedPublicRelayReceipt> BeginPublicRelayAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, Guid operationId, StagedPublicRelayIntent original,
        StagedDestinationNameObservation observation, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        ValidatePublicDeleteBinding(binding, turn.Destination);
        ValidateRelayOriginal(original, binding);
        if (operationId == Guid.Empty || operationId == original.OpenOperationId)
            throw new ArgumentException("A disposition needs its own immutable operation ID.");
        if (observation.Destination != turn.Destination || !observation.CompleteEnumeration ||
            observation.ParentBefore != turn.Destination.Parent || observation.ParentAfter != turn.Destination.Parent)
            throw new IOException("Disposition requires an exact stable anchored name observation.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            var receipts = head.PublicRelayReceipts ?? [];
            if (receipts.FirstOrDefault(r => r.Binding.TransferId == binding.TransferId ||
                    r.Binding.RequestNonce == binding.RequestNonce || r.OperationId == operationId) is { } saved)
            {
                if (saved.Binding != binding || saved.OperationId != operationId || saved.Original != original)
                    throw new IOException("Disposition replay changed its original operation or binding.");
                return saved; // A durable replay is never permission to execute NTFS twice.
            }
            RequireNoPendingPhysicalCommit(head);
            bool noNameEffect = observation.PublicIdentity is not null &&
                observation.PublicIdentity != binding.PublicIdentity && head.LatestPublished > original.PublishedGeneration &&
                head.PublishedIdentity == observation.PublicIdentity;
            if (observation.PublicIdentity != binding.PublicIdentity && !noNameEffect)
                throw new IOException("An unexplained name replacement/absence cannot authorize disposition.");
            if (original.PublishedGeneration > head.LatestPublished ||
                (original.PublishedGeneration == head.LatestPublished && original.PublishedIdentity != head.PublishedIdentity))
                throw new IOException("The binding-time Published evidence conflicts with its durable head.");
            bool deleting = (original.DispositionFlags & 1) != 0;
            long generation = 0;
            if (deleting)
            {
                long retained = head.MaxAllocated;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                retained = Math.Max(retained, await BoundManifestHighWaterCoreAsync(turn.Destination, token).ConfigureAwait(false));
#endif
                generation = checked(retained + 1);
                if (head.Deletes.Any(d => d.Binding.TransferId == binding.TransferId || d.Binding.RequestNonce == binding.RequestNonce))
                    throw new IOException("A disposition cannot reuse an existing delete capability.");
                if (!noNameEffect && head.Deletes.Any(d => IsPublicationReservation(d) && d.Binding.PublicIdentity != binding.PublicIdentity))
                    throw new IOException("An accepted native reservation belongs to another public object.");
                var delete = new StagedPublicDeleteRecord(binding, generation,
                    noNameEffect ? StagedPublicDeleteState.Superseded : StagedPublicDeleteState.Intent,
                    DateTimeOffset.UtcNow, operationId);
                head = head with { MaxAllocated = generation, Deletes = [.. head.Deletes, delete] };
            }
            var receipt = new StagedPublicRelayReceipt(binding, operationId, original, generation,
                noNameEffect, StagedPublicDeleteState.Intent);
            var mutation = deleting ? StagedDestinationMutation.DeleteDisposition : StagedDestinationMutation.ClearDisposition;
            head = head with { PendingCommit = new(operationId, mutation,
                deleting ? binding.TransferId : Guid.Empty, generation, binding.PublicIdentity),
                PublicRelayReceipts = [.. receipts, receipt] };
            await WriteDestinationHeadCoreAsync(head, token).ConfigureAwait(false);
            return receipt;
        }
        finally { _gate.Release(); }
    }

    internal async Task<StagedPublicRelayReceipt> RecordPublicRelayResultAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, Guid operationId, StagedPublicRelayIntent original,
        int nativeStatus, bool notForwarded)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (nativeStatus == 259 || (notForwarded && nativeStatus >= 0))
            throw new IOException("A pending/successful status cannot prove no forwarding.");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            var receipts = head.PublicRelayReceipts ?? [];
            var receipt = receipts.SingleOrDefault(r => r.Binding == binding && r.OperationId == operationId)
                ?? throw new IOException("No exact durable disposition intent exists.");
            if (receipt.Original != original) throw new IOException("The native result changed its original operation.");
            if (receipt.NativeStatus is { } recorded)
            {
                if (recorded != nativeStatus || receipt.NotForwarded != notForwarded)
                    throw new IOException("The native result contradicts its durable receipt.");
                return receipt;
            }
            bool deleting = (original.DispositionFlags & 1) != 0;
            var intent = RequirePendingCommit(head, operationId,
                deleting ? StagedDestinationMutation.DeleteDisposition : StagedDestinationMutation.ClearDisposition,
                deleting ? binding.TransferId : Guid.Empty);
            bool accepted = !notForwarded && nativeStatus >= 0;
            if (deleting)
            {
                var delete = RequireExactDelete(head, binding);
                if (!receipt.NoNameEffect)
                    head = ReplaceDelete(head, delete with
                    {
                        State = accepted ? StagedPublicDeleteState.Accepted :
                            notForwarded ? StagedPublicDeleteState.Canceled : StagedPublicDeleteState.Failed,
                        UpdatedAtUtc = DateTimeOffset.UtcNow
                    });
            }
            else if (accepted && !receipt.NoNameEffect)
                head = head with { Deletes = head.Deletes.Select(d => d.Kind == StagedPublicDeleteKind.Ordinary &&
                    d.Binding.PublicIdentity == binding.PublicIdentity &&
                    d.State is (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.Accepted)
                    ? d with { State = StagedPublicDeleteState.Canceled, UpdatedAtUtc = DateTimeOffset.UtcNow } : d).ToArray() };
            receipt = receipt with { NativeStatus = nativeStatus, NotForwarded = notForwarded,
                State = accepted ? StagedPublicDeleteState.Accepted :
                    notForwarded ? StagedPublicDeleteState.Canceled : StagedPublicDeleteState.Failed };
            head = head with { PendingCommit = null, LastMutationResult = new(intent, accepted),
                PublicRelayReceipts = receipts.Select(r => r.OperationId == operationId ? receipt : r).ToArray() };
            await WriteDestinationHeadCoreAsync(head, CancellationToken.None).ConfigureAwait(false);
            return receipt;
        }
        finally { _gate.Release(); }
    }

    internal async Task ArmPublicRelayAcknowledgementAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, Guid operationId, ulong revision, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (revision == 0) throw new ArgumentOutOfRangeException(nameof(revision));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            var saved = (head.PublicRelayReceipts ?? []).Single(r => r.Binding == binding && r.OperationId == operationId);
            if (saved.NativeStatus is null || (saved.AcknowledgedRevision is { } previous && previous > revision))
                throw new IOException("An unresolved/backward native acknowledgement cannot clear the operation slot.");
            if (saved.AcknowledgedRevision == revision) return;
            await WriteDestinationHeadCoreAsync(head with { PublicRelayReceipts = head.PublicRelayReceipts!
                .Select(r => r == saved ? r with { AcknowledgedRevision = revision } : r).ToArray() }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // The dispatcher supplies one authenticated, unchanged original-open
    // replay plus an exact parent observation. The durable operation ACK is
    // distinct from native cleanup: another reader can keep the link pending.
    internal async Task<bool> ReconcilePublicRelayOpenAsync(DestinationCommitTurn turn,
        Guid driver, Guid openTransfer, Guid openNonce, Guid openOperation, ulong epoch,
        StagedStageIdentity publicIdentity, ulong revision, ulong currentSequence,
        bool lifetimeEnded, bool cleanupOutstanding, StagedDestinationNameObservation observation,
        CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (driver == Guid.Empty || openTransfer == Guid.Empty || openNonce == Guid.Empty || openOperation == Guid.Empty ||
            epoch == 0 || revision == 0 || observation.Destination != turn.Destination || !observation.CompleteEnumeration ||
            observation.ParentBefore != turn.Destination.Parent || observation.ParentAfter != turn.Destination.Parent)
            throw new IOException("Relay recovery needs the exact original open and anchored name.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            var receipts = head.PublicRelayReceipts ?? [];
            var matching = receipts.Where(r => r.Original.OpenTransferId == openTransfer &&
                r.Original.OpenNonce == openNonce && r.Original.OpenOperationId == openOperation).ToArray();
            if (matching.Length == 0)
            {
                if (cleanupOutstanding) throw new IOException("Native cleanup lost its durable receipt; retain the hold.");
                return true;
            }
            var retained = receipts.ToList();
            bool ready = true;
            foreach (var receipt in matching)
            {
                if (receipt.Binding.DriverInstanceId != driver || receipt.Binding.ConnectionEpoch != epoch ||
                    receipt.Binding.PublicIdentity != publicIdentity)
                    throw new IOException("Relay recovery changed the original open's immutable binding.");
                bool slotRemoved = receipt.AcknowledgedRevision is { } ack && revision > ack &&
                    (currentSequence == 0 || currentSequence > receipt.Original.Sequence);
                if (receipt.NativeStatus is null || !slotRemoved) { ready = false; continue; }
                bool deleting = (receipt.Original.DispositionFlags & 1) != 0;
                if (deleting)
                {
                    var delete = RequireExactDelete(head, receipt.Binding);
                    if (delete.State == StagedPublicDeleteState.Accepted)
                    {
                        if (!lifetimeEnded) { ready = false; continue; }
                        if (observation.PublicIdentity is null)
                        {
                            delete = delete with { State = StagedPublicDeleteState.Complete, UpdatedAtUtc = DateTimeOffset.UtcNow };
                            head = ReplaceDelete(head, delete) with { CommittedDelete = Math.Max(head.CommittedDelete, delete.Generation) };
                        }
                        else if (head.LatestPublished > delete.Generation && head.PublishedIdentity == observation.PublicIdentity)
                        {
                            delete = delete with { State = StagedPublicDeleteState.Superseded, UpdatedAtUtc = DateTimeOffset.UtcNow };
                            head = ReplaceDelete(head, delete);
                        }
                        else
                        {
                            if (observation.PublicIdentity != publicIdentity)
                                throw new IOException("Unexplained replacement retains the native cleanup hold.");
                            ready = false; continue; // original can still be pending behind another reader
                        }
                    }
                    if (delete.State is not (StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded or
                        StagedPublicDeleteState.Canceled or StagedPublicDeleteState.Failed)) { ready = false; continue; }
                }
                int index = retained.IndexOf(receipt);
                if (cleanupOutstanding)
                    retained[index] = receipt with { CleanupAcknowledgementRevision = revision };
                else if (receipt.CleanupAcknowledgementRevision is not { } cleanupAck || revision > cleanupAck)
                {
                    retained.RemoveAt(index);
                    if (deleting) head = head with { Deletes = head.Deletes.Where(d => d.Binding != receipt.Binding).ToArray() };
                }
                else ready = false;
            }
            await WriteDestinationHeadCoreAsync(head with { PublicRelayReceipts = retained.ToArray() }, token).ConfigureAwait(false);
            return ready;
        }
        finally { _gate.Release(); }
    }

    internal async Task RetirePublicRelayRemovedOpenAsync(DestinationCommitTurn turn,
        Guid driver, Guid openNonce, Guid openOperation, int openPid, uint boot, ulong revision, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            var matching = (head.PublicRelayReceipts ?? []).Where(r => r.Original.OpenNonce == openNonce &&
                r.Original.OpenOperationId == openOperation).ToArray();
            if (matching.Length == 0) throw new IOException("Removed original open has no retained cleanup receipt.");
            foreach (var receipt in matching)
            {
                if (receipt.Binding.DriverInstanceId != driver || receipt.Binding.OsBootSequence != boot ||
                    receipt.Original.OpenProcessId != openPid || receipt.NativeStatus is null ||
                    receipt.AcknowledgedRevision is not { } ack || revision <= ack ||
                    receipt.CleanupAcknowledgementRevision is not { } cleanupAck || revision <= cleanupAck)
                    throw new IOException("Same-revision absence cannot confirm an original open's cleanup ACK.");
                if (receipt.Generation != 0 && RequireExactDelete(head, receipt.Binding).State is not
                    (StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded or StagedPublicDeleteState.Canceled or StagedPublicDeleteState.Failed))
                    throw new IOException("Removed open retains an unresolved delete.");
            }
            await WriteDestinationHeadCoreAsync(head with
            {
                PublicRelayReceipts = head.PublicRelayReceipts!.Except(matching).ToArray(),
                Deletes = head.Deletes.Where(d => !matching.Any(r => r.Binding == d.Binding)).ToArray()
            }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static void ValidateRelayOriginal(StagedPublicRelayIntent original, StagedPublicDeleteBinding binding)
    {
        if (original.OpenTransferId == Guid.Empty || original.OpenNonce == Guid.Empty || original.OpenOperationId == Guid.Empty ||
            original.OpenTransferId == binding.TransferId || original.OpenNonce == binding.RequestNonce || original.Sequence == 0 ||
            original.OpenProcessId <= 0 || original.PublishedGeneration < 0 || ((original.PublishedGeneration == 0) != (original.PublishedIdentity is null)) ||
            original.InformationClass is not (13 or 64) || original.RequestorMode > 1 ||
            (original.InformationClass == 13 ? original.DispositionFlags > 1 : (original.DispositionFlags & ~0x1fu) != 0) ||
            (original.GrantedAccess & 0x10000) == 0)
            throw new InvalidDataException("Invalid original native disposition evidence.");
        if (original.PublishedIdentity is { } published &&
            (published.VolumeSerialNumber != binding.PublicIdentity.VolumeSerialNumber ||
             (published.FileIdHigh | published.FileIdLow) == 0))
            throw new InvalidDataException("Published snapshot changed its captured volume.");
    }

    private static void ValidatePublicRelayReceipts(StagedDestinationHead head)
    {
        var ids = new HashSet<Guid>(); var nonces = new HashSet<Guid>();
        foreach (var receipt in head.PublicRelayReceipts ?? [])
        {
            if (receipt is null) throw new InvalidDataException("Null native disposition receipt.");
            ValidatePublicDeleteBinding(receipt.Binding, head.Destination);
            ValidateRelayOriginal(receipt.Original, receipt.Binding);
            bool deleting = (receipt.Original.DispositionFlags & 1) != 0;
            if (!ids.Add(receipt.OperationId) || !nonces.Add(receipt.Binding.RequestNonce) || receipt.OperationId == Guid.Empty ||
                (deleting ? receipt.Generation <= 0 || receipt.Generation > head.MaxAllocated : receipt.Generation != 0) ||
                receipt.State is not (StagedPublicDeleteState.Intent or StagedPublicDeleteState.Accepted or
                    StagedPublicDeleteState.Failed or StagedPublicDeleteState.Canceled) ||
                ((receipt.State == StagedPublicDeleteState.Intent) != (receipt.NativeStatus is null)) ||
                receipt.NativeStatus == 259 || (receipt.NotForwarded && receipt.NativeStatus is not < 0) ||
                (receipt.State == StagedPublicDeleteState.Accepted && (receipt.NotForwarded || receipt.NativeStatus is not >= 0)) ||
                (receipt.State is StagedPublicDeleteState.Failed or StagedPublicDeleteState.Canceled && receipt.NativeStatus is not < 0) ||
                (receipt.AcknowledgedRevision is { } revision && (revision == 0 || receipt.NativeStatus is null)) ||
                (receipt.CleanupAcknowledgementRevision is { } cleanupRevision &&
                    (receipt.AcknowledgedRevision is not { } armed || cleanupRevision <= armed || receipt.NativeStatus is null)))
                throw new InvalidDataException("Invalid native disposition receipt.");
            if (receipt.State == StagedPublicDeleteState.Intent &&
                (head.PendingCommit?.OperationId != receipt.OperationId ||
                 head.PendingCommit.ExpectedPublicIdentity != receipt.Binding.PublicIdentity))
                throw new InvalidDataException("Native disposition intent lost its physical barrier.");
            if (deleting && !head.Deletes.Any(d => d.Binding == receipt.Binding &&
                    d.OperationId == receipt.OperationId && d.Generation == receipt.Generation))
                throw new InvalidDataException("Native delete result lost its exact generation record.");
        }
    }
}
