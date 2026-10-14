#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    internal static string PublicationRequestBytes(BoundPublicationRequestV26 request)
    {
        if (!BoundPublicationV26.Valid(request)) throw new IOException("publication_intent_invalid");
        byte[] bytes = new byte[BoundPublicationV26.RequestBytes];
        MemoryMarshal.Write(bytes, in request);
        return Convert.ToBase64String(bytes);
    }

    internal static BoundPublicationRequestV26 ReadPublicationRequest(string bytes, BoundPublicationPhase phase)
    {
        try
        {
            if (bytes is null || bytes.Length != 1280) throw new IOException("publication_intent_invalid");
            var request = MemoryMarshal.Read<BoundPublicationRequestV26>(Convert.FromBase64String(bytes));
            if (!BoundPublicationV26.Valid(request) || request.Phase != phase)
                throw new IOException("publication_intent_invalid");
            return request;
        }
        catch (Exception error) when (error is FormatException or ArgumentException)
        { throw new InvalidDataException("publication_intent_invalid", error); }
    }

    private static StagedPublicationAttempt RequirePublicationAttempt(StagedDestinationHead head, Guid nonce) =>
        (head.PublicationAttempts ?? []).SingleOrDefault(a =>
            ReadPublicationRequest(a.CreateBase64, BoundPublicationPhase.Create).CreateNonce == nonce)
        ?? throw new IOException("publication_create_intent_missing");

    private static void RequirePublicationManifest(TransferJournalEntry entry, BoundPublicationRequestV26 create,
        StagedDestinationIdentity destination)
    {
        if (entry.BoundAllocation?.Destination != destination || entry.DriverInstanceId != create.DriverInstanceId ||
            entry.Transfer.TransferId != create.TransferId || entry.DestinationGeneration != create.DestinationGeneration ||
            entry.StageIdentity != PublicationIdentity(create.StageIdentity) || !entry.SealedOnce ||
            entry.SealedLength != create.MeasuredLength || entry.PendingRename is not null ||
            !string.Equals(entry.Sha256Hex, Convert.ToHexString(create.GetDigest()), StringComparison.OrdinalIgnoreCase) ||
            entry.State is not (TransferJournalState.Approved or TransferJournalState.Publishing or TransferJournalState.Released or TransferJournalState.Retained))
            throw new IOException("publication_manifest_changed");
    }

    private static void RequirePublicationHead(StagedDestinationHead head, BoundPublicationRequestV26 request)
    {
        if (head.CurrentSaveTransferId != request.TransferId || head.CurrentSaveGeneration != request.DestinationGeneration ||
            request.DestinationGeneration <= PublicationGenerationFloor(head) || request.DestinationGeneration <= head.LatestPublished ||
            request.ExpectedLatestPublished != head.LatestPublished || request.ExpectedCommittedDelete != head.CommittedDelete ||
            request.ExpectedMaxAllocated != head.MaxAllocated)
            throw new IOException("publication_generation_changed");
    }

    internal async Task BeginBoundPublicationCreateAsync(StagedDestinationIdentity destination,
        BoundPublicationRequestV26 request, CancellationToken token)
    {
        string wire = PublicationRequestBytes(request);
        if (request.Phase != BoundPublicationPhase.Create) throw new IOException("publication_create_intent_invalid");
        RequirePublicationDestination(request, destination);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(destination, token).ConfigureAwait(false);
            var entry = await ReadCoreAsync(request.TransferId, token).ConfigureAwait(false);
            RequirePublicationManifest(entry, request, destination);
            if (entry.State is not (TransferJournalState.Approved or TransferJournalState.Publishing))
                throw new IOException("publication_not_approved");
            StagedSeedCompletion.Require(entry);
            RequirePublicationHead(head, request);
            var attempts = head.PublicationAttempts ?? [];
            if (attempts.Any(a => ReadPublicationRequest(a.CreateBase64, BoundPublicationPhase.Create).TransferId == request.TransferId))
                throw new IOException("publication_attempt_requires_reconciliation");
            // Reserve journal capacity for this attempt's rename and largest
            // escaped Facts row before a native CREATE can be submitted. Keep
            // the existing 128-KiB head bound, including all other receipts.
            var next = head with { PublicationAttempts = [.. attempts, new(wire)] };
            await WriteDestinationHeadCoreAsync(next, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task BeginBoundPublicationRenameAsync(DestinationCommitTurn turn,
        BoundPublicationRequestV26 request, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.PhysicalCommit);
        string wire = PublicationRequestBytes(request);
        if (request.Phase != BoundPublicationPhase.Rename) throw new IOException("publication_rename_intent_invalid");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            RequirePublicationHead(head, request);
            if (head.Deletes.Any(IsPublicationReservation)) throw new IOException("publication_delete_pending");
            var attempt = RequirePublicationAttempt(head, request.CreateNonce);
            var create = ReadPublicationRequest(attempt.CreateBase64, BoundPublicationPhase.Create);
            RequireLinkedPublicationRequests(create, request);
            RequirePublicationManifest(await ReadCoreAsync(request.TransferId, token).ConfigureAwait(false), create, turn.Destination);
            var receipt = (head.PublicationNativeReceipts ?? []).Single(r =>
                ReadPublicationReceipt(r).Facts.Create.CreateNonce == request.CreateNonce);
            var facts = ReadPublicationReceipt(receipt).Facts;
            if (attempt.RenameBase64 is not null || !facts.Flags.HasFlag(BoundPublicationFacts.TemporaryIdentityKnown) ||
                !SamePublicationIdentity(facts.TemporaryIdentity, request.TemporaryIdentity))
                throw new IOException("publication_temporary_unproved");
            var intent = new StagedDestinationCommitIntent(request.OperationId, StagedDestinationMutation.Publication,
                request.TransferId, request.DestinationGeneration, PublicationIdentity(request.ExpectedPublicIdentity),
                PublicationIdentity(request.TemporaryIdentity), request.MeasuredLength, Convert.ToHexString(request.GetDigest()));
            await WriteDestinationHeadCoreAsync(head with { PendingCommit = intent,
                PublicationAttempts = head.PublicationAttempts!.Select(a => a == attempt ? a with { RenameBase64 = wire } : a).ToArray()
            }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static void RequireLinkedPublicationRequests(BoundPublicationRequestV26 create, BoundPublicationRequestV26 rename)
    {
        // Only the physical turn's observed target and current head fields may
        // differ from pre-CREATE. All original authority and content is fixed.
        var expected = create;
        expected.Phase = BoundPublicationPhase.Rename; expected.PermitNonce = rename.PermitNonce;
        expected.OperationId = rename.OperationId; expected.TemporaryIdentity = rename.TemporaryIdentity;
        expected.ExpectedPublicIdentity = rename.ExpectedPublicIdentity; expected.Flags = rename.Flags;
        expected.ExpectedLatestPublished = rename.ExpectedLatestPublished;
        expected.ExpectedCommittedDelete = rename.ExpectedCommittedDelete;
        expected.ExpectedMaxAllocated = rename.ExpectedMaxAllocated;
        if (rename.OperationId == create.OperationId || PublicationRequestBytes(expected) != PublicationRequestBytes(rename))
            throw new IOException("publication_rename_binding_changed");
    }

    internal async Task HoldBoundPublicationAsync(StagedDestinationIdentity destination, Guid nonce, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 128) throw new ArgumentException(nameof(reason));
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(destination, CancellationToken.None).ConfigureAwait(false);
            var attempt = RequirePublicationAttempt(head, nonce);
            await WriteDestinationHeadCoreAsync(head with { PublicationAttempts = head.PublicationAttempts!
                .Select(a => a == attempt ? a with { Diagnostic = reason } : a).ToArray() }, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task RecordBoundCleanupIntentAsync(DestinationCommitTurn turn, BoundPublicationReplayRow row)
    {
        turn.Require(this);
        var f = row.Facts;
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            var attempt = RequirePublicationAttempt(head, f.Create.CreateNonce);
            var receipt = (head.PublicationNativeReceipts ?? []).Single(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == f.Create.CreateNonce);
            var stored = ReadPublicationReceipt(receipt).Facts;
            if (!stored.Flags.HasFlag(BoundPublicationFacts.CleanupArmed) ||
                stored.CleanupNonce != f.CleanupNonce || stored.CleanupOperationId != f.CleanupOperationId ||
                (stored.Flags & (BoundPublicationFacts.RenameAccepted | BoundPublicationFacts.CleanupForwarded |
                    BoundPublicationFacts.CleanupNotForwarded)) != 0 ||
                (stored.Flags.HasFlag(BoundPublicationFacts.RenameForwarded) && !stored.Flags.HasFlag(BoundPublicationFacts.RenameResultKnown)) ||
                attempt.CleanupNonce is not null)
                throw new IOException("publication_cleanup_unproved");
            await WriteDestinationHeadCoreAsync(head with { PublicationAttempts = head.PublicationAttempts!.Select(a =>
                a == attempt ? a with { CleanupOperationId = f.CleanupOperationId, CleanupNonce = f.CleanupNonce } : a).ToArray()
            }, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // Only bookkeeping: this method never asks for a permit or reopens a public file.
    internal async Task<TransferJournalEntry> CompleteBoundPublicationAsync(Guid transferId, Guid nonce, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var entry = await ReadCoreAsync(transferId, token).ConfigureAwait(false);
            var destination = entry.BoundAllocation?.Destination ?? throw new IOException("publication_binding_missing");
            var head = await RequireDestinationHeadCoreAsync(destination, token).ConfigureAwait(false);
            var receipt = (head.PublicationNativeReceipts ?? []).Single(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == nonce);
            var f = ReadPublicationReceipt(receipt).Facts;
            RequirePublicationManifest(entry, f.Create, destination);
            if (!RequirePublicationAttempt(head, nonce).HeadPublished ||
                !f.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) || head.LatestPublished < entry.DestinationGeneration ||
                head.LatestPublished == entry.DestinationGeneration && head.PublishedIdentity != PublicationIdentity(f.TemporaryIdentity) ||
                head.PendingCommit?.OperationId == f.Rename.OperationId)
                throw new IOException("publication_head_not_published");
            if (entry.State == TransferJournalState.Released) return entry;
            if (entry.State != TransferJournalState.Publishing) throw new IOException("publication_manifest_not_publishing");
            var history = AppendState(entry, TransferJournalState.Released);
            var released = entry with { State = TransferJournalState.Released, StateHistory = history,
                UpdatedAtUtc = history[^1].OccurredAtUtc };
            await ReplaceAsync(ManifestPath(transferId), released, token).ConfigureAwait(false);
            return released;
        }
        finally { _gate.Release(); }
    }

    internal async Task ArmBoundPublicationAckAsync(DestinationCommitTurn turn, BoundPublicationReplay replay, BoundPublicationReplayRow row)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        string wire = Convert.ToBase64String(BoundPublicationV26.EncodeFactRow(replay, row));
        if (!PublicationCleanupComplete(row)) throw new IOException("publication_cleanup_unproved");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            var receipts = head.PublicationNativeReceipts ?? [];
            var receipt = receipts.Single(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == row.Facts.Create.CreateNonce);
            if (receipt.FactsBase64 != wire || receipt.Revision != replay.Revision || receipt.ConnectionEpoch != replay.ConnectionEpoch ||
                head.PendingCommit is { Mutation: StagedDestinationMutation.Publication } pending &&
                    pending.TransferId == row.Facts.Create.TransferId)
                throw new IOException("publication_ack_requires_durable_result");
            if (row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted))
            {
                var entry = await ReadCoreAsync(row.Facts.Create.TransferId, CancellationToken.None).ConfigureAwait(false);
                if (entry.State != TransferJournalState.Released) throw new IOException("publication_ack_before_released");
            }
            else
            {
                var entry = await ReadCoreAsync(row.Facts.Create.TransferId, CancellationToken.None).ConfigureAwait(false);
                RequirePublicationManifest(entry, row.Facts.Create, turn.Destination);
                if (entry.State == TransferJournalState.Publishing)
                {
                    var history = AppendState(entry, TransferJournalState.Retained);
                    await ReplaceAsync(ManifestPath(entry.Transfer.TransferId), entry with {
                        State = TransferJournalState.Retained, StateHistory = history, UpdatedAtUtc = history[^1].OccurredAtUtc
                    }, CancellationToken.None).ConfigureAwait(false);
                }
            }
            await WriteDestinationHeadCoreAsync(head with { PublicationNativeReceipts = receipts.Select(r => r == receipt
                ? r with { AcknowledgedRevision = replay.Revision, AcknowledgedConnectionEpoch = replay.ConnectionEpoch } : r).ToArray()
            }, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task RetireBoundPublicationAsync(DestinationCommitTurn turn, Guid nonce, BoundPublicationReplay replay)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            var receipt = (head.PublicationNativeReceipts ?? []).Single(r => ReadPublicationReceipt(r).Facts.Create.CreateNonce == nonce);
            var row = ReadPublicationReceipt(receipt);
            if (!PublicationCleanupComplete(row) || receipt.AcknowledgedRevision is not { } ack ||
                replay.DriverInstanceId != receipt.DriverInstanceId || replay.OsBootSequence != receipt.OsBootSequence ||
                replay.ConnectionEpoch < receipt.ConnectionEpoch || replay.Revision <= Math.Max(ack, receipt.Revision) ||
                replay.Records.Any(r => r.Facts.Create.CreateNonce == nonce ||
                    r.Facts.Create.TransferId == row.Facts.Create.TransferId ||
                    r.Facts.Create.OperationId == row.Facts.Create.OperationId) || head.PendingCommit is { Mutation: StagedDestinationMutation.Publication } pending &&
                    pending.TransferId == row.Facts.Create.TransferId)
                throw new IOException("publication_ack_removal_unproved");
            var attempt = RequirePublicationAttempt(head, nonce);
            await WriteDestinationHeadCoreAsync(head with {
                PublicationAttempts = head.PublicationAttempts!.Where(a => a != attempt).ToArray(),
                PublicationNativeReceipts = head.PublicationNativeReceipts!.Where(r => r != receipt).ToArray(),
                LastMutationResult = head.LastMutationResult?.PublicationCreateNonce == nonce
                    ? head.LastMutationResult with { PublicationCreateNonce = null } : head.LastMutationResult
            }, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static bool PublicationCleanupComplete(BoundPublicationReplayRow row) => row.HasTerminalLocalProof &&
        (row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) ||
         row.Facts.Flags.HasFlag(BoundPublicationFacts.CreateNotForwarded) ||
         !row.Facts.Flags.HasFlag(BoundPublicationFacts.CreateAccepted) ||
         row.Facts.Flags.HasFlag(BoundPublicationFacts.CleanupAccepted));
}
#endif
