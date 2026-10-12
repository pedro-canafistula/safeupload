#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
#endif

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    private static void ValidatePublicationNativeReceipts(StagedDestinationHead head)
    {
        var receipts = head.PublicationNativeReceipts ?? [];
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (receipts.Length > BoundPublicationV26.MaximumRecords) throw new InvalidDataException("Publication receipt bound exceeded.");
        var nonces = new HashSet<Guid>();
        foreach (var receipt in receipts)
        {
            var row = ReadPublicationReceipt(receipt).Facts;
            RequirePublicationDestination(row.Create, head.Destination);
            if (!nonces.Add(row.Create.CreateNonce) || row.Create.DestinationGeneration > head.MaxAllocated ||
                ((receipt.AcknowledgedRevision is null) != (receipt.AcknowledgedConnectionEpoch is null)) ||
                (receipt.AcknowledgedRevision is { } ack && (ack == 0 || ack > receipt.Revision ||
                    receipt.AcknowledgedConnectionEpoch == 0 || receipt.AcknowledgedConnectionEpoch > receipt.ConnectionEpoch ||
                    !ReadPublicationReceipt(receipt).HasTerminalLocalProof)))
                throw new InvalidDataException("Invalid durable publication receipt/ACK.");
        }
        if (head.LastMutationResult?.PublicationCreateNonce is { } nonce)
        {
            var result = head.LastMutationResult;
            var receipt = receipts.SingleOrDefault(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == nonce)
                ?? throw new InvalidDataException("Publication outcome lost its native receipt.");
            var row = ReadPublicationReceipt(receipt).Facts;
            RequirePublicationIntent(row, result.Intent);
            if (!row.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown) ||
                result.Succeeded != row.Flags.HasFlag(BoundPublicationFacts.RenameAccepted))
                throw new InvalidDataException("Publication Boolean contradicts its exact native result.");
        }
        else if (head.LastMutationResult is { Intent.Mutation: StagedDestinationMutation.Publication } untagged &&
            receipts.Any(r => ReadPublicationReceipt(r).Facts.Rename.OperationId == untagged.Intent.OperationId))
            throw new InvalidDataException("Publication result dropped its required native receipt binding.");
#else
        // Normal builds cannot reinterpret a feature receipt as a legacy
        // publication or silently drop an unresolved cleanup obligation.
        if (receipts.Length != 0 || head.LastMutationResult?.PublicationCreateNonce is not null)
            throw new InvalidDataException("Bound native publication recovery needs the feature service.");
#endif
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    private static BoundPublicationReplayRow ReadPublicationReceipt(StagedPublicationNativeReceipt receipt)
    {
        if (receipt is null || receipt.DriverInstanceId == Guid.Empty || receipt.ConnectionEpoch == 0 || receipt.Revision == 0 ||
            receipt.FactsBase64 is null || receipt.FactsBase64.Length != 2816)
            throw new InvalidDataException("Invalid durable publication receipt scope/size.");
        try
        {
            return BoundPublicationV26.DecodeFactRow(Convert.FromBase64String(receipt.FactsBase64),
                receipt.DriverInstanceId, receipt.ConnectionEpoch, receipt.OsBootSequence);
        }
        catch (Exception error) when (error is FormatException or IOException)
        { throw new InvalidDataException("Malformed durable native publication facts.", error); }
    }

    private static StagedStageIdentity? PublicationIdentity(SafeUploadStageIdentityV19 id) =>
        id.HasNonzeroFileId ? new(id.VolumeSerialNumber, id.FileIdHigh, id.FileIdLow) : null;

    private static void RequirePublicationDestination(BoundPublicationRequestV26 request, StagedDestinationIdentity destination)
    {
        if (PublicationIdentity(request.VolumeRootIdentity) != destination.VolumeRoot ||
            PublicationIdentity(request.ParentIdentity) != destination.Parent ||
            request.MountManagerVolumeId != destination.MountManagerVolumeId ||
            (request.ParentCaseSensitive == 1) != destination.CaseSensitive || !destination.LeafEquals(request.GetDestinationLeaf()))
            throw new InvalidDataException("Native publication changed its anchored destination.");
    }

    private static void RequirePublicationIntent(BoundPublicationFactsRowV26 row, StagedDestinationCommitIntent intent)
    {
        if (!row.Flags.HasFlag(BoundPublicationFacts.RenameArmed) || intent.Mutation != StagedDestinationMutation.Publication ||
            row.Rename.OperationId != intent.OperationId || row.Create.TransferId != intent.TransferId ||
            row.Create.DestinationGeneration != intent.Generation || PublicationIdentity(row.TemporaryIdentity) != intent.TemporaryIdentity ||
            PublicationIdentity(row.Rename.ExpectedPublicIdentity) != intent.ExpectedPublicIdentity || row.Create.MeasuredLength != intent.Length ||
            !string.Equals(Convert.ToHexString(row.Create.GetDigest()), intent.Sha256Hex, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Native result changed its exact publication intent.");
    }

    // Called with the shared physical/recovery turn. Unknown results persist
    // their facts but retain PendingCommit. No native I/O is issued here.
    internal async Task RecordBoundPublicationNativeResultAsync(DestinationCommitTurn turn,
        BoundPublicationReplay replay, BoundPublicationReplayRow row)
    {
        turn.Require(this);
        if (turn.Purpose == StagedDestinationTurnPurpose.Allocation)
            throw new InvalidOperationException("Allocation cannot record native publication.");
        byte[] wire = BoundPublicationV26.EncodeFactRow(replay, row);
        var facts = row.Facts;
        RequirePublicationDestination(facts.Create, turn.Destination);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            var receipts = (head.PublicationNativeReceipts ?? []).ToList();
            int index = receipts.FindIndex(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == facts.Create.CreateNonce);
            var oldFacts = index >= 0 ? ReadPublicationReceipt(receipts[index]).Facts : default;
            bool resultReplay = index >= 0 && oldFacts.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown);
            // After a durable result, receipt/cleanup replay is self-contained:
            // compaction of its released manifest must not resurrect a write
            // or prevent acknowledgement of the exact native object.
            if (!resultReplay)
            {
                var entry = await ReadCoreAsync(facts.Create.TransferId, CancellationToken.None).ConfigureAwait(false);
                if (entry.BoundAllocation is not { } allocation || allocation.Destination != turn.Destination ||
                entry.DriverInstanceId != facts.Create.DriverInstanceId || entry.DestinationGeneration != facts.Create.DestinationGeneration ||
                entry.StageIdentity != PublicationIdentity(facts.Create.StageIdentity) || !entry.SealedOnce ||
                entry.SealedLength != facts.Create.MeasuredLength ||
                !string.Equals(entry.Sha256Hex, Convert.ToHexString(facts.Create.GetDigest()), StringComparison.OrdinalIgnoreCase) ||
                entry.State is not (TransferJournalState.Approved or TransferJournalState.Publishing or TransferJournalState.Released))
                    throw new IOException("Native publication does not match an approved bound manifest.");
            }
            var intent = resultReplay ? new StagedDestinationCommitIntent(oldFacts.Rename.OperationId,
                StagedDestinationMutation.Publication, oldFacts.Create.TransferId, oldFacts.Create.DestinationGeneration,
                PublicationIdentity(oldFacts.Rename.ExpectedPublicIdentity), PublicationIdentity(oldFacts.TemporaryIdentity),
                oldFacts.Create.MeasuredLength, Convert.ToHexString(oldFacts.Create.GetDigest())) :
                RequirePendingCommit(head, facts.Rename.OperationId, StagedDestinationMutation.Publication, facts.Create.TransferId);
            RequirePublicationIntent(facts, intent);
            var incoming = new StagedPublicationNativeReceipt(replay.DriverInstanceId, replay.ConnectionEpoch, replay.Revision,
                replay.OsBootSequence, Convert.ToBase64String(wire));
            if (index >= 0)
            {
                RequirePublicationProgress(receipts[index], incoming);
                incoming = incoming with { AcknowledgedRevision = receipts[index].AcknowledgedRevision,
                    AcknowledgedConnectionEpoch = receipts[index].AcknowledgedConnectionEpoch };
                receipts[index] = incoming;
            }
            else receipts.Add(incoming);
            head = head with { PublicationNativeReceipts = receipts.ToArray() };
            if (!facts.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown))
            {
                if (resultReplay) throw new IOException("A final native result cannot become unknown.");
                await WriteDestinationHeadCoreAsync(head, CancellationToken.None).ConfigureAwait(false); return;
            }
            bool committed = facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted);
            if (resultReplay)
            {
                if (oldFacts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) != committed)
                    throw new IOException("Native publication result changed.");
            }
            else
            {
                // Exact native facts and their Boolean projection become
                // durable atomically. Released is a later manifest update.
                head = head with { PendingCommit = null,
                    LatestPublished = committed ? intent.Generation : head.LatestPublished,
                    PublishedIdentity = committed ? intent.TemporaryIdentity : head.PublishedIdentity,
                    LastMutationResult = new(intent, committed, facts.Create.CreateNonce) };
            }
            await WriteDestinationHeadCoreAsync(head, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static void RequirePublicationProgress(StagedPublicationNativeReceipt old, StagedPublicationNativeReceipt next)
    {
        var a = ReadPublicationReceipt(old).Facts; var b = ReadPublicationReceipt(next).Facts;
        byte[] before = Convert.FromBase64String(old.FactsBase64), after = Convert.FromBase64String(next.FactsBase64);
        if (old.DriverInstanceId != next.DriverInstanceId || old.OsBootSequence != next.OsBootSequence ||
            next.ConnectionEpoch < old.ConnectionEpoch || next.Revision < old.Revision ||
            (next.Revision == old.Revision && !before.AsSpan().SequenceEqual(after)) ||
            !before.AsSpan(0, 960).SequenceEqual(after.AsSpan(0, 960)) ||
            !before.AsSpan(1920, 24).SequenceEqual(after.AsSpan(1920, 24)) ||
            (a.Flags & ~BoundPublicationFacts.CallbackOwned & ~b.Flags) != 0 ||
            (a.Flags.HasFlag(BoundPublicationFacts.RenameArmed) && !before.AsSpan(960, 960).SequenceEqual(after.AsSpan(960, 960))) ||
            (a.Flags.HasFlag(BoundPublicationFacts.TemporaryIdentityKnown) && !SamePublicationIdentity(a.TemporaryIdentity, b.TemporaryIdentity)) ||
            (a.Flags.HasFlag(BoundPublicationFacts.TargetObservationKnown) &&
                (!SamePublicationIdentity(a.ObservedPublicIdentity, b.ObservedPublicIdentity) || a.TargetStatus != b.TargetStatus)) ||
            (a.Flags.HasFlag(BoundPublicationFacts.CreateResultKnown) && (a.CreateStatus != b.CreateStatus || a.CreateInformation != b.CreateInformation)) ||
            (a.Flags.HasFlag(BoundPublicationFacts.FlushResultKnown) && a.FlushStatus != b.FlushStatus) ||
            (a.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown) && a.RenameStatus != b.RenameStatus) ||
            (a.Flags.HasFlag(BoundPublicationFacts.CleanupArmed) && (a.CleanupNonce != b.CleanupNonce || a.CleanupOperationId != b.CleanupOperationId)) ||
            (a.Flags.HasFlag(BoundPublicationFacts.CleanupResultKnown) && a.CleanupStatus != b.CleanupStatus))
            throw new IOException("Native publication replay changed immutable or final facts.");
    }

    private static bool SamePublicationIdentity(SafeUploadStageIdentityV19 a, SafeUploadStageIdentityV19 b) =>
        a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIdLow == b.FileIdLow && a.FileIdHigh == b.FileIdHigh;
#endif
}
