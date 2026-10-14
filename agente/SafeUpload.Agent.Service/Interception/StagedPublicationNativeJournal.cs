#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
#endif

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    private static long PublicationReceiptReserve(StagedDestinationHead head)
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        long reserve = 0;
        foreach (var attempt in head.PublicationAttempts ?? [])
        {
            var create = ReadPublicationRequest(attempt.CreateBase64, BoundPublicationPhase.Create);
            // Base64 may require six JSON bytes per character. Include scalar
            // properties, diagnostics, cleanup IDs and future ACK fields.
            if (attempt.RenameBase64 is null) reserve += 1280 * 6 + 256;
            var receipt = (head.PublicationNativeReceipts ?? []).SingleOrDefault(r =>
                ReadPublicationReceipt(r).Facts.Create.CreateNonce == create.CreateNonce);
            reserve += 2816 * 6 + 2048 - (receipt is null ? 0 :
                System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(receipt).Length);
        }
        return reserve;
#else
        return 0;
#endif
    }

    private static void ValidatePublicationNativeReceipts(StagedDestinationHead head)
    {
        var receipts = head.PublicationNativeReceipts ?? [];
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (receipts.Length > BoundPublicationV26.MaximumRecords) throw new InvalidDataException("Publication receipt bound exceeded.");
        var attempts = head.PublicationAttempts ?? [];
        if (attempts.Length > BoundPublicationV26.MaximumRecords) throw new InvalidDataException("Publication attempt bound exceeded.");
        var attemptNonces = new HashSet<Guid>();
        var operations = new HashSet<Guid>();
        foreach (var attempt in attempts)
        {
            if (attempt is null) throw new InvalidDataException("Null publication attempt.");
            var create = ReadPublicationRequest(attempt.CreateBase64, BoundPublicationPhase.Create);
            RequirePublicationDestination(create, head.Destination);
            if (!attemptNonces.Add(create.CreateNonce) || !operations.Add(create.OperationId) ||
                create.DestinationGeneration > head.MaxAllocated || attempt.Diagnostic?.Length > 128 ||
                ((attempt.CleanupNonce is null) != (attempt.CleanupOperationId is null)) ||
                attempt.CleanupNonce == Guid.Empty || attempt.CleanupOperationId == Guid.Empty)
                throw new InvalidDataException("Invalid durable publication attempt.");
            if (attempt.RenameBase64 is { } renameBytes)
            {
                var rename = ReadPublicationRequest(renameBytes, BoundPublicationPhase.Rename);
                RequireLinkedPublicationRequests(create, rename);
                if (!attemptNonces.Add(rename.PermitNonce) || !operations.Add(rename.OperationId))
                    throw new InvalidDataException("Duplicate publication rename intent.");
            }
            if (attempt.HeadPublished)
            {
                var receipt = receipts.SingleOrDefault(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == create.CreateNonce);
                if (receipt is null || !ReadPublicationReceipt(receipt).Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) ||
                    head.LatestPublished < create.DestinationGeneration ||
                    head.LatestPublished == create.DestinationGeneration &&
                        head.PublishedIdentity != PublicationIdentity(ReadPublicationReceipt(receipt).Facts.TemporaryIdentity))
                    throw new InvalidDataException("Publication attempt lost its exact Published projection.");
            }
        }
        var nonces = new HashSet<Guid>();
        foreach (var receipt in receipts)
        {
            var row = ReadPublicationReceipt(receipt).Facts;
            RequirePublicationDestination(row.Create, head.Destination);
            var attempt = RequirePublicationAttempt(head, row.Create.CreateNonce);
            if (attempt.CreateBase64 != PublicationRequestBytes(row.Create) ||
                row.Flags.HasFlag(BoundPublicationFacts.RenameArmed) && attempt.RenameBase64 != PublicationRequestBytes(row.Rename))
                throw new InvalidDataException("Native publication receipt lost its immutable intent.");
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
            if (!(row.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown) || row.Flags.HasFlag(BoundPublicationFacts.RenameNotForwarded)) ||
                result.Succeeded != row.Flags.HasFlag(BoundPublicationFacts.RenameAccepted))
                throw new InvalidDataException("Publication Boolean contradicts its exact native result.");
        }
        else if (head.LastMutationResult is { Intent.Mutation: StagedDestinationMutation.Publication } untagged &&
            receipts.Any(r => ReadPublicationReceipt(r).Facts.Rename.OperationId == untagged.Intent.OperationId))
            throw new InvalidDataException("Publication result dropped its required native receipt binding.");
#else
        // Normal builds cannot reinterpret a feature receipt as a legacy
        // publication or silently drop an unresolved cleanup obligation.
        if (receipts.Length != 0 || (head.PublicationAttempts?.Length ?? 0) != 0 || head.LastMutationResult?.PublicationCreateNonce is not null)
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
            var attempt = RequirePublicationAttempt(head, facts.Create.CreateNonce);
            if (attempt.CreateBase64 != PublicationRequestBytes(facts.Create) ||
                (facts.Flags.HasFlag(BoundPublicationFacts.RenameArmed) && attempt.RenameBase64 != PublicationRequestBytes(facts.Rename)))
                throw new IOException("publication_facts_changed_intent");
            // Existing durable receipts remain self-contained after manifest
            // compaction. A first receipt must still match the exact version.
            if (index < 0)
                RequirePublicationManifest(await ReadCoreAsync(facts.Create.TransferId, CancellationToken.None).ConfigureAwait(false),
                    facts.Create, turn.Destination);
            StagedDestinationCommitIntent? intent = null;
            if (facts.Flags.HasFlag(BoundPublicationFacts.RenameArmed))
            {
                intent = new(facts.Rename.OperationId, StagedDestinationMutation.Publication,
                    facts.Create.TransferId, facts.Create.DestinationGeneration, PublicationIdentity(facts.Rename.ExpectedPublicIdentity),
                    PublicationIdentity(facts.TemporaryIdentity), facts.Create.MeasuredLength, Convert.ToHexString(facts.Create.GetDigest()));
                RequirePublicationIntent(facts, intent);
            }
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
            // Separate durable boundary: exact Facts precede the Published
            // projection. If the second write fails, replay sees PendingCommit
            // and retries only this bookkeeping, never the original rename.
            await WriteDestinationHeadCoreAsync(head, CancellationToken.None).ConfigureAwait(false);
            bool terminalRename = facts.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown) && facts.RenameStatus <= 0 ||
                facts.Flags.HasFlag(BoundPublicationFacts.RenameNotForwarded);
            if (intent is null || !terminalRename || head.PendingCommit?.OperationId != intent.OperationId) return;
            if (head.PendingCommit != intent) throw new IOException("publication_pending_intent_changed");
            bool committed = facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted);
            head = head with { PendingCommit = null,
                LatestPublished = committed ? intent.Generation : head.LatestPublished,
                PublishedIdentity = committed ? intent.TemporaryIdentity : head.PublishedIdentity,
                LastMutationResult = new(intent, committed, facts.Create.CreateNonce),
                PublicationAttempts = head.PublicationAttempts!.Select(a => a == attempt && committed
                    ? a with { HeadPublished = true } : a).ToArray() };
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
