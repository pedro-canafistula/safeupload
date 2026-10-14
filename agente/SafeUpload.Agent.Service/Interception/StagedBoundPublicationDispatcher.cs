#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Diagnostics;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record StagedBoundPublicationResult(bool Released, string? Diagnostic = null, bool ReceiptPending = true);

// Invoked by the publication worker, never the FilterPort receive loop. All
// dependencies are explicit so dormant positive paths can be component-tested.
internal sealed class StagedBoundPublicationDispatcher(StagedTransferJournal journal,
    IStagedBoundPublicationTransport transport, IStagedBoundPublicationNative native, Func<bool> ready)
{
    internal async Task<bool> HasAttemptAsync(TransferJournalEntry entry, CancellationToken token)
    {
        var head = await journal.ReadDestinationHeadAsync(entry.BoundAllocation!.Destination, token).ConfigureAwait(false);
        return (head?.PublicationAttempts ?? []).Any(a => Create(a).TransferId == entry.Transfer.TransferId);
    }

    internal async Task<StagedBoundPublicationResult> PublishAsync(TransferJournalEntry entry, Stream snapshot,
        Func<CancellationToken, Task<bool>> currentApproval, Func<ValueTask> releaseSnapshot, CancellationToken token)
    {
        var binding = entry.BoundAllocation ?? throw new IOException("publication_binding_missing");
        var destination = binding.Destination;
        var head = await journal.ReadDestinationHeadAsync(destination, token).ConfigureAwait(false)
            ?? throw new IOException("publication_head_missing");
        if ((head.PublicationAttempts ?? []).Any(a => Create(a).TransferId == entry.Transfer.TransferId))
            return await ReconcileAsync(entry, token).ConfigureAwait(false);
        if (!ready()) return new(false, "publication_prerequisites_not_ready");
        if (entry.State != TransferJournalState.Publishing || snapshot.Length != entry.SealedLength)
            throw new IOException("publication_inspected_snapshot_missing");
        var security = await journal.ReadBoundAllocationSecurityAsync(entry.Transfer.TransferId, token).ConfigureAwait(false)
            ?? throw new IOException("native_create_security_unproved");
        security.RequireWriterMetadata(binding, entry.Transfer);
        using var directory = native.Open(binding);
        var observed = RequireObservation(directory.Observe(token), destination);
        var create = Request(entry, head, observed, Guid.NewGuid());
        // The only path that forwards CREATE is this new, live invocation. Any
        // loss after this boundary is reconciled from Facts, not from a re-open.
        await journal.BeginBoundPublicationCreateAsync(destination, create, token).ConfigureAwait(false);
        IStagedBoundPublicationFile? temporary = null;
        bool published = false;
        string reason = "publication_create_reply_unknown";
        try
        {
            if (!await currentApproval(token).ConfigureAwait(false)) throw new IOException("publication_policy_changed");
            var permit = await PrepareAsync(create, token).ConfigureAwait(false);
            RequirePrepared(permit, create);
            reason = "publication_create_result_unknown";
            try { temporary = directory.Create(create, security); }
            catch (Exception error) when (IsNativeFailure(error)) { /* Facts own the actual result. */ }
            var row = await CaptureAsync(destination, create, null).ConfigureAwait(false);
            if (temporary is null || !row.Facts.Flags.HasFlag(BoundPublicationFacts.CreateAccepted | BoundPublicationFacts.TemporaryIdentityKnown) ||
                row.Facts.OriginalConnectionEpoch != permit.ConnectionEpoch ||
                row.Facts.Flags.HasFlag(BoundPublicationFacts.DataFenced) || temporary.Identity != Identity(row.Facts.TemporaryIdentity))
                throw new IOException("publication_create_unproved");
            reason = "publication_copy_incomplete";
            snapshot.Position = 0;
            long copied = await temporary.WriteAsync(snapshot, token).ConfigureAwait(false);
            if (copied != create.MeasuredLength || snapshot.Length != create.MeasuredLength)
                throw new IOException("publication_snapshot_length_changed");
            // No inspection snapshot or stage lease waits behind a delete.
            await releaseSnapshot().ConfigureAwait(false);
            reason = "publication_turn_interrupted";
            using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                StagedDestinationTurnPurpose.PhysicalCommit, token).ConfigureAwait(false))
            {
                if (!await currentApproval(token).ConfigureAwait(false)) throw new IOException("publication_policy_changed");
                head = await journal.ReadDestinationHeadAsync(destination, token).ConfigureAwait(false)
                    ?? throw new IOException("publication_head_missing");
                observed = RequireObservation(directory.Observe(token), destination);
                var rename = create;
                rename.Phase = BoundPublicationPhase.Rename; rename.PermitNonce = Guid.NewGuid(); rename.OperationId = Guid.NewGuid();
                rename.TemporaryIdentity = row.Facts.TemporaryIdentity;
                rename.ExpectedPublicIdentity = Wire(observed); rename.Flags = observed is null ? (ushort)0 : (ushort)1;
                rename.ExpectedLatestPublished = head.LatestPublished; rename.ExpectedCommittedDelete = head.CommittedDelete;
                rename.ExpectedMaxAllocated = head.MaxAllocated;
                await journal.BeginBoundPublicationRenameAsync(turn, rename, token).ConfigureAwait(false);
                reason = "publication_rename_reply_unknown";
                var renamePermit = await PrepareAsync(rename, token).ConfigureAwait(false);
                RequirePrepared(renamePermit, rename);
                if (renamePermit.ConnectionEpoch != permit.ConnectionEpoch) throw new IOException("publication_connection_changed");
                // The fence may have waited for I/O. Policy is checked again at
                // the final forwarding boundary; an exception never approves.
                if (!await currentApproval(token).ConfigureAwait(false)) throw new IOException("publication_policy_changed");
                reason = "publication_rename_result_unknown";
                try { directory.Rename(temporary, rename); }
                catch (Exception error) when (IsNativeFailure(error)) { /* Even a lost success reply is reconciled below. */ }
                row = await CaptureAsync(destination, create, turn).ConfigureAwait(false);
                published = row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted);
                if (!published) throw new IOException("publication_rename_unproved");
                // Capture persisted Facts and Published under this same turn.
            }
            reason = "publication_release_pending";
            await journal.CompleteBoundPublicationAsync(entry.Transfer.TransferId, create.CreateNonce, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception error) when (IsNativeFailure(error) || error is OperationCanceledException)
        {
            if (error is IOException && error.Message.StartsWith("publication_", StringComparison.Ordinal)) reason = error.Message;
            await journal.HoldBoundPublicationAsync(destination, create.CreateNonce, reason).ConfigureAwait(false);
        }
        finally
        {
            if (temporary is not null)
            {
                if (!published)
                {
                    try { await CleanupAsync(destination, create, temporary).ConfigureAwait(false); }
                    catch (Exception error) when (IsNativeFailure(error))
                    { await journal.HoldBoundPublicationAsync(destination, create.CreateNonce, "publication_cleanup_unresolved").ConfigureAwait(false); }
                }
                temporary.Dispose(); // No name-based orphan deletion, including error paths.
            }
        }
        // LastCleanup/ACK can lag. Failure cannot change an accepted rename.
        return await ReconcileAsync(entry, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task<BoundPublicationReplyV26> PrepareAsync(BoundPublicationRequestV26 request, CancellationToken token)
    {
        long started = Stopwatch.GetTimestamp();
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var reply = transport.Send(request);
            RequireReply(reply, request);
            if (reply.Result != BoundPublicationResult.NotReady) return reply;
            if (Stopwatch.GetElapsedTime(started) >= TimeSpan.FromSeconds(2))
                throw new IOException("publication_permit_not_ready");
            // Identical permit polling can only obtain the current grant. No
            // original operation has been forwarded and none is retried here.
            await Task.Delay(25, token).ConfigureAwait(false);
        }
    }

    private async Task<BoundPublicationReplayRow> CaptureAsync(StagedDestinationIdentity destination,
        BoundPublicationRequestV26 create, StagedTransferJournal.DestinationCommitTurn? turn)
    {
        var replay = transport.ReadFacts();
        var row = ExactRow(replay, create);
        if (turn is not null)
            await journal.RecordBoundPublicationNativeResultAsync(turn, replay, row).ConfigureAwait(false);
        else
        {
            using var recovery = await journal.EnterDestinationCommitTurnAsync(destination,
                StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None).ConfigureAwait(false);
            await journal.RecordBoundPublicationNativeResultAsync(recovery, replay, row).ConfigureAwait(false);
        }
        return row;
    }

    private async Task CleanupAsync(StagedDestinationIdentity destination, BoundPublicationRequestV26 create,
        IStagedBoundPublicationFile temporary)
    {
        var revoke = create; revoke.Phase = BoundPublicationPhase.Revoke; revoke.TemporaryIdentity = Wire(temporary.Identity);
        var reply = transport.Send(revoke); RequireReply(reply, revoke);
        // Revoke is not a cleanup execution grant. Only captured, locally
        // fenced/drained Facts with the reserved cleanup operation can allow it.
        var replay = transport.ReadFacts(); var row = ExactRow(replay, create);
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None).ConfigureAwait(false);
        await journal.RecordBoundPublicationNativeResultAsync(turn, replay, row).ConfigureAwait(false);
        if (row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted)) return;
        if (!row.Facts.Flags.HasFlag(BoundPublicationFacts.CleanupArmed) || temporary.Identity != Identity(row.Facts.TemporaryIdentity))
            throw new IOException("publication_cleanup_unproved");
        await journal.RecordBoundCleanupIntentAsync(turn, row).ConfigureAwait(false);
        try { temporary.Delete(); }
        catch (Exception error) when (IsNativeFailure(error)) { /* Capture actual disposition, never retry it. */ }
        await CaptureAsync(destination, create, turn).ConfigureAwait(false);
    }

    // Safe for repeated worker calls and service restarts. No mutation permit,
    // CREATE, rename or cleanup is ever issued by this recovery entry point.
    // Durable head publication can finish a lost Released write even after the
    // original driver is gone. That says nothing about cleanup/ACK retirement.
    internal async Task<StagedBoundPublicationResult> ReconcileAsync(TransferJournalEntry entry, CancellationToken token)
    {
        entry = await journal.ReadAsync(entry.Transfer.TransferId, token).ConfigureAwait(false);
        var destination = entry.BoundAllocation?.Destination ?? throw new IOException("publication_binding_missing");
        using var turn = await journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        var head = await journal.ReadDestinationHeadAsync(destination, token).ConfigureAwait(false)
            ?? throw new IOException("publication_head_missing");
        var attempts = (head.PublicationAttempts ?? []).Where(a => Create(a).TransferId == entry.Transfer.TransferId).ToArray();
        if (attempts.Length == 0)
            return new(entry.State == TransferJournalState.Released,
                entry.State == TransferJournalState.Released ? null : "publication_receipt_unavailable", ReceiptPending: false);
        var attempt = attempts.Single(); var create = Create(attempt);
        try
        {
            if (attempt.HeadPublished)
                entry = await journal.CompleteBoundPublicationAsync(entry.Transfer.TransferId, create.CreateNonce, token).ConfigureAwait(false);
            var replay = transport.ReadFacts();
            var rows = replay.Records.Where(r => r.Facts.Create.CreateNonce == create.CreateNonce).ToArray();
            if (rows.Length == 0)
            {
                await journal.RetireBoundPublicationAsync(turn, create.CreateNonce, replay).ConfigureAwait(false);
                entry = await journal.ReadAsync(entry.Transfer.TransferId, token).ConfigureAwait(false);
                return new(entry.State == TransferJournalState.Released,
                    entry.State == TransferJournalState.Released ? null : "publication_not_committed", ReceiptPending: false);
            }
            var row = ExactRow(replay, create);
            if (head.PendingCommit?.OperationId == row.Facts.Rename.OperationId &&
                row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted))
            {
                // A restart cannot promote Publishing from a digest/path
                // match. Pair the exact native receipt with anchored state.
                using var directory = native.Open(entry.BoundAllocation!);
                if (RequireObservation(directory.Observe(token), destination) != Identity(row.Facts.TemporaryIdentity))
                    throw new IOException("publication_recovery_name_changed");
                RequireSameReplay(replay);
            }
            await journal.RecordBoundPublicationNativeResultAsync(turn, replay, row).ConfigureAwait(false);
            bool accepted = row.Facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted);
            if (accepted)
                entry = await journal.CompleteBoundPublicationAsync(entry.Transfer.TransferId, create.CreateNonce, CancellationToken.None).ConfigureAwait(false);
            if (row.HasTerminalLocalProof)
            {
                await journal.ArmBoundPublicationAckAsync(turn, replay, row).ConfigureAwait(false);
                RequireSameReplay(replay);
                var ack = transport.Acknowledge(replay, row);
                RequireAck(ack, replay, create);
                // A later complete replay, never the ACK reply, retires storage.
            }
            if (!accepted) await journal.HoldBoundPublicationAsync(destination, create.CreateNonce,
                attempt.Diagnostic ?? "publication_outcome_unresolved").ConfigureAwait(false);
            return new(accepted, accepted ? null : attempt.Diagnostic ?? "publication_outcome_unresolved");
        }
        catch (Exception error) when (IsNativeFailure(error))
        {
            string diagnostic = error.Message.StartsWith("publication_", StringComparison.Ordinal)
                ? error.Message : "publication_replay_or_ack_pending";
            await journal.HoldBoundPublicationAsync(destination, create.CreateNonce, diagnostic).ConfigureAwait(false);
            entry = await journal.ReadAsync(entry.Transfer.TransferId, CancellationToken.None).ConfigureAwait(false);
            return new(entry.State == TransferJournalState.Released, diagnostic);
        }
    }

    private void RequireSameReplay(BoundPublicationReplay expected)
    {
        var current = transport.ReadFacts();
        if (current.DriverInstanceId != expected.DriverInstanceId || current.ConnectionEpoch != expected.ConnectionEpoch ||
            current.Revision != expected.Revision || current.OsBootSequence != expected.OsBootSequence ||
            current.Records.Count != expected.Records.Count || current.Records.Where((row, index) =>
                !BoundPublicationV26.EncodeFactRow(current, row).AsSpan().SequenceEqual(
                    BoundPublicationV26.EncodeFactRow(expected, expected.Records[index]))).Any())
            throw new IOException("publication_replay_changed");
    }

    private static BoundPublicationRequestV26 Create(StagedPublicationAttempt a) =>
        StagedTransferJournal.ReadPublicationRequest(a.CreateBase64, BoundPublicationPhase.Create);
    private static bool IsNativeFailure(Exception error) => error is IOException or InvalidDataException or UnauthorizedAccessException or
        System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException;
    private static StagedStageIdentity? Identity(SafeUploadStageIdentityV19 id) => id.HasNonzeroFileId
        ? new(id.VolumeSerialNumber, id.FileIdHigh, id.FileIdLow) : null;
    private static SafeUploadStageIdentityV19 Wire(StagedStageIdentity? id) => id is null ? default : new()
        { VolumeSerialNumber = id.VolumeSerialNumber, FileIdHigh = id.FileIdHigh, FileIdLow = id.FileIdLow };
    private static StagedStageIdentity? RequireObservation(StagedDestinationNameObservation observation, StagedDestinationIdentity destination)
    {
        if (observation.Destination != destination || !observation.CompleteEnumeration ||
            observation.ParentBefore != destination.Parent || observation.ParentAfter != destination.Parent)
            throw new IOException("publication_target_unproved");
        return observation.PublicIdentity;
    }
    private static BoundPublicationRequestV26 Request(TransferJournalEntry entry, StagedDestinationHead head,
        StagedStageIdentity? observed, Guid nonce) => BoundPublicationV26.WithPayload(new()
        {
            Phase = BoundPublicationPhase.Create, TransferId = entry.Transfer.TransferId, DriverInstanceId = entry.DriverInstanceId!.Value,
            PermitNonce = nonce, CreateNonce = nonce, OperationId = Guid.NewGuid(), DestinationGeneration = entry.DestinationGeneration,
            MountManagerVolumeId = head.Destination.MountManagerVolumeId!.Value, VolumeRootIdentity = Wire(head.Destination.VolumeRoot),
            ParentIdentity = Wire(head.Destination.Parent), StageIdentity = Wire(entry.StageIdentity), ExpectedPublicIdentity = Wire(observed),
            Flags = observed is null ? (ushort)0 : (ushort)1, ParentCaseSensitive = head.Destination.CaseSensitive ? (ushort)1 : (ushort)0,
            MeasuredLength = entry.SealedLength!.Value, ExpectedMaxAllocated = head.MaxAllocated,
            ExpectedLatestPublished = head.LatestPublished, ExpectedCommittedDelete = head.CommittedDelete
        }, head.Destination.CanonicalLeaf, ".safeupload-" + nonce.ToString("N") + ".pending", Convert.FromHexString(entry.Sha256Hex!));

    private static BoundPublicationReplayRow ExactRow(BoundPublicationReplay replay, BoundPublicationRequestV26 create)
    {
        var rows = replay.Records.Where(r => r.Facts.Create.CreateNonce == create.CreateNonce).ToArray();
        if (rows.Length != 1 || StagedTransferJournal.PublicationRequestBytes(rows[0].Facts.Create) !=
            StagedTransferJournal.PublicationRequestBytes(create)) throw new IOException("publication_exact_facts_unavailable");
        _ = BoundPublicationV26.EncodeFactRow(replay, rows[0]);
        return rows[0];
    }

    internal static void RequireReply(BoundPublicationReplyV26 reply, BoundPublicationRequestV26 request)
    {
        if (reply.ExtensionVersion != BoundPublicationV26.Version || reply.StructSize != BoundPublicationV26.ReplyBytes ||
            reply.Phase != request.Phase || reply.Reserved != 0 || reply.ReservedEnd != 0 || reply.TransferId != request.TransferId ||
            reply.DriverInstanceId != request.DriverInstanceId || reply.CreateNonce != request.CreateNonce ||
            reply.PermitNonce != request.PermitNonce || reply.OperationId != request.OperationId ||
            reply.DestinationGeneration != request.DestinationGeneration || reply.ConnectionEpoch == 0 || reply.AuthorityRevision == 0 ||
            reply.Result is not (BoundPublicationResult.Prepared or BoundPublicationResult.Consumed or BoundPublicationResult.Revoked or
                BoundPublicationResult.Unknown or BoundPublicationResult.Rejected or BoundPublicationResult.NotReady) ||
            (request.Phase == BoundPublicationPhase.Revoke ? reply.Result == BoundPublicationResult.Prepared : reply.Result == BoundPublicationResult.Revoked))
            throw new IOException("publication_reply_binding_changed");
    }
    private static void RequirePrepared(BoundPublicationReplyV26 reply, BoundPublicationRequestV26 request)
    {
        RequireReply(reply, request);
        if (reply.Result != BoundPublicationResult.Prepared) throw new IOException("publication_permit_not_prepared");
    }
    private static void RequireAck(BoundPublicationReplyV26 reply, BoundPublicationReplay replay, BoundPublicationRequestV26 create)
    {
        if (reply.ExtensionVersion != BoundPublicationV26.Version || reply.StructSize != BoundPublicationV26.ReplyBytes ||
            reply.Phase != BoundPublicationPhase.CleanupAck || reply.Reserved != 0 || reply.ReservedEnd != 0 ||
            reply.TransferId != create.TransferId || reply.DriverInstanceId != create.DriverInstanceId ||
            reply.PermitNonce != create.PermitNonce || reply.CreateNonce != create.CreateNonce || reply.OperationId != create.OperationId ||
            reply.DestinationGeneration != create.DestinationGeneration || reply.ConnectionEpoch != replay.ConnectionEpoch ||
            reply.AuthorityRevision == 0 || reply.Result != BoundPublicationResult.Acknowledged)
            throw new IOException("publication_ack_unconfirmed");
    }
}
#endif
