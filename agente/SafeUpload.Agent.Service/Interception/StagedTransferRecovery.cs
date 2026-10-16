using System.Diagnostics;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferPublisher
{
    // An in-process receipt is created only after the exact native rename
    // returns success. Losing it in a crash leaves the durable Publishing
    // reservation unresolved; a pathname/digest match cannot recreate it.
    private sealed record ConfirmedPublication(TransferJournalEntry Intent,
        StagedStageIdentity PublishedObject, FileOperation Operation,
        InspectionResult Inspection, bool Justified);
    private readonly Dictionary<Guid, ConfirmedPublication> _confirmedPublications = new();
    // Known interrupted progress can already be Verified on disk. Keep the
    // worker obligation until its existing notification/justification work
    // also finishes; the durable record is reread before every attempt.
    private readonly Dictionary<Guid, TransferJournalEntry> _pendingJournalProgress = new();
    private readonly SemaphoreSlim _recoveryGate = new(1, 1);
    private readonly Dictionary<Guid, (int Failures, long RetryAt)> _recoveryRetries = new();
#if SAFEUPLOAD_ADMISSION_EVIDENCE
    // Publication ACK/replay and private-stage last close are independent.
    // Neither completion may clear or defer the other obligation's retry.
    private readonly Dictionary<Guid, (int Failures, long RetryAt)> _boundReceiptRetries = new();
#endif
    private readonly HashSet<Guid> _recoveryNotified = new();
    internal Func<long> RecoveryTimestamp { get; set; } = Stopwatch.GetTimestamp;

    private async Task FinishConfirmedPublicationAsync(Guid id, CancellationToken token)
    {
        ConfirmedPublication receipt;
        lock (_confirmedPublications)
            receipt = _confirmedPublications.TryGetValue(id, out var confirmed) ? confirmed :
                throw new IOException("No exact in-process publication receipt is available.");
        TransferJournalEntry released = await _journal.CompleteConfirmedPublicationAsync(receipt.Intent, token)
            .ConfigureAwait(false);
        await _inspection.RecordTransferOutcomeAsync(receipt.Operation, receipt.Inspection,
            Verdict.Approved, receipt.Justified ? "justified_version" : null,
            token, id, released.Sha256Hex).ConfigureAwait(false);
        PublishTransferNotification(released.Transfer, new TransferNotification(id,
            Path.GetFileName(released.Transfer.DestinationPath), TransferPhase.Released,
            PublishedSha256Hex: released.Sha256Hex));
        if (receipt.Justified)
            await ProcessBlockedCleanupAsync(released, token).ConfigureAwait(false);
        else await DisposeReleasedStageAsync(id, token).ConfigureAwait(false);
        lock (_confirmedPublications) _confirmedPublications.Remove(id);
    }

    internal bool HasConfirmedPublication(Guid id)
    {
        lock (_confirmedPublications) return _confirmedPublications.ContainsKey(id);
    }

    internal void QueueJournalProgress(TransferJournalEntry entry)
    {
        lock (_confirmedPublications) _pendingJournalProgress[entry.Transfer.TransferId] = entry;
    }

    internal async Task RecoverJournalProgressAsync(CancellationToken token)
    {
        TransferJournalEntry[] pending;
        lock (_confirmedPublications) pending = _confirmedPublications.Values.Select(r => r.Intent)
            .Concat(_pendingJournalProgress.Values).DistinctBy(e => e.Transfer.TransferId).ToArray();
        foreach (var entry in pending)
            await RecoverPendingTransferAsync(entry, token).ConfigureAwait(false);
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    // Receipts outlive Publishing and even Released-stage disposal. Enumerate
    // the durable heads, not just the publisher's pending-state projection.
    internal async Task RecoverBoundReceiptsAsync(CancellationToken token)
    {
        var heads = await _journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        foreach (Guid id in heads.SelectMany(h => h.PublicationAttempts ?? [])
            .Select(a => StagedTransferJournal.ReadPublicationRequest(a.CreateBase64,
                SafeUpload.Agent.Minifilter.BoundPublicationPhase.Create).TransferId).Distinct())
        {
            var entry = await _journal.ReadAsync(id, token).ConfigureAwait(false);
            await RecoverPendingTransferAsync(entry, token, receiptRecovery: true, cleanupOnly: false).ConfigureAwait(false);
        }
    }
#endif

    // The live worker and startup both call this. No delay is awaited under
    // the journal gate, and a retry for one transfer does not stall another.
    // This dispatcher never invokes PublishAsync or performs a public rename.
    internal Task RecoverPendingTransferAsync(TransferJournalEntry entry, CancellationToken token) =>
        RecoverPendingTransferAsync(entry, token, receiptRecovery: false, cleanupOnly: false);

    // The live pending scan only needs cleanup for a hand-back it has already
    // completed. Startup and interrupted journal progress must also restore
    // notification/justification work, even if Verified reached disk.
    internal Task RecoverPendingTransferAsync(TransferJournalEntry entry, CancellationToken token, bool cleanupOnly) =>
        RecoverPendingTransferAsync(entry, token, receiptRecovery: false, cleanupOnly: cleanupOnly);

    private async Task RecoverPendingTransferAsync(TransferJournalEntry entry, CancellationToken token,
        bool receiptRecovery, bool cleanupOnly)
    {
        // A validated scan snapshot already carries the exact completed
        // receipt. Terminal dispatch must do no per-entry I/O. Any operation
        // which changes authority continues to reread and validate on disk.
        await _recoveryGate.WaitAsync(token).ConfigureAwait(false);
        Guid id = entry.Transfer.TransferId;
        bool boundRecovery = receiptRecovery;
        try
        {
            // Bound publication receipts are a separate obligation. Their
            // explicit dispatcher must still reconcile them after cleanup.
            if (!receiptRecovery && StagedTransferJournal.BlockedCleanupComplete(entry) && !HasConfirmedPublication(id))
            {
                lock (_confirmedPublications) _pendingJournalProgress.Remove(id);
                _recoveryRetries.Remove(id);
                lock (_recoveryNotified) _recoveryNotified.Remove(id);
                return;
            }
            if (RecoveryRetries(receiptRecovery).TryGetValue(id, out var retry) && RecoveryTimestamp() < retry.RetryAt)
                return;
            entry = await _journal.ReadAsync(id, token).ConfigureAwait(false);
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            if ((receiptRecovery || !(entry.State == TransferJournalState.Released &&
                    entry.HandbackState == StagedHandbackState.Verified)) &&
                entry.BoundAllocation is not null && BoundPublication is not null &&
                (entry.State == TransferJournalState.Publishing || await BoundPublication.HasAttemptAsync(entry, token).ConfigureAwait(false)))
            {
                boundRecovery = true;
                if (_boundReceiptRetries.TryGetValue(id, out var boundRetry) && RecoveryTimestamp() < boundRetry.RetryAt)
                    return;
                var bound = await BoundPublication.ReconcileAsync(entry, token).ConfigureAwait(false);
                bool unfinished = bound.ReceiptPending || entry.State == TransferJournalState.Publishing && !bound.Released;
                if (bound.Diagnostic is not null) ReportRecoveryHold(entry, bound.Diagnostic, null);
                if (unfinished)
                {
                    ScheduleRecoveryRetry(id, boundReceipt: true); // bookkeeping only; never forwards a native mutation
                }
                else { _boundReceiptRetries.Remove(id); lock (_recoveryNotified) _recoveryNotified.Remove(id); }
                if (!unfinished) lock (_confirmedPublications) _pendingJournalProgress.Remove(id);
                return;
            }
#endif
            if (entry.UnboundCancellation is not null)
            {
                if (!StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(entry.Transfer.StagePath,
                    entry.StageIdentity, out Exception? failure))
                    throw new IOException("Cancelled stage cleanup is waiting for its exact handles.", failure);
                if (!_publicationGate.DisposeStage(id, SafeUpload.Agent.Minifilter.StageDisposeOutcome.CleanedUp,
                    CommittedRenames(entry))) throw new IOException("Cancelled stage disposal acknowledgement is pending.");
                await _journal.CompleteUnboundCancellationCleanupAsync(entry, token).ConfigureAwait(false);
                return;
            }
            if (HasConfirmedPublication(id))
                await FinishConfirmedPublicationAsync(id, token).ConfigureAwait(false);
            else if (entry.State == TransferJournalState.Publishing)
            {
                ReportRecoveryHold(entry, "publication_receipt_unavailable", null);
                return; // T5 bound records require their existing anchored receipt dispatcher.
            }
            else if (entry.State == TransferJournalState.Blocked ||
                entry.State == TransferJournalState.Released && entry.HandbackState == StagedHandbackState.Verified)
            {
                if (entry.State == TransferJournalState.Blocked &&
                    (!cleanupOnly || entry.HandbackState is StagedHandbackState.NotAttempted or StagedHandbackState.Copying or StagedHandbackState.Failed))
                {
                    TransferJournalEntry? interruptedProgress;
                    lock (_confirmedPublications) _pendingJournalProgress.TryGetValue(id, out interruptedProgress);
                    await RecoverBlockedAsync(entry, token).ConfigureAwait(false);
                    // Hand-back progress has finished, including its UI and
                    // justification registration. Remaining cleanup stays in
                    // durable pending dispatch and keeps its bounded backoff.
                    lock (_confirmedPublications)
                        if (_pendingJournalProgress.TryGetValue(id, out var pending) && ReferenceEquals(pending, interruptedProgress))
                            _pendingJournalProgress.Remove(id);
                }
                else await ProcessBlockedCleanupAsync(entry, token).ConfigureAwait(false);
                entry = await _journal.ReadAsync(id, token).ConfigureAwait(false);
                if (entry.State is (TransferJournalState.Blocked or TransferJournalState.Released) &&
                    !StagedTransferJournal.BlockedCleanupComplete(entry))
                {
                    if (entry.StageDeleted && !StagedTransferJournal.MatchesBlockedDeletionReceipt(entry))
                        ReportRecoveryHold(entry, "blocked_disposition_receipt_unavailable", null);
                    ScheduleRecoveryRetry(id); // includes pending last close and caught cleanup failures
                    return;
                }
            }
            lock (_confirmedPublications) _pendingJournalProgress.Remove(id);
            _recoveryRetries.Remove(id);
            lock (_recoveryNotified) _recoveryNotified.Remove(id);
        }
        catch (StagedJournalPersistenceException error)
        {
            QueueJournalProgress(entry);
            ScheduleRecoveryRetry(id, boundRecovery);
            ReportRecoveryHold(entry, "journal_progress_pending", error);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            // A mismatch or unreadable record is never permission to release
            // or recopy. Keep the obligation, diagnose it, and let unrelated
            // transfers continue. A future attempt must validate from scratch.
            QueueJournalProgress(entry);
            ScheduleRecoveryRetry(id, boundRecovery);
            ReportRecoveryHold(entry, "recovery_evidence_unavailable", error);
        }
        finally { _recoveryGate.Release(); }
    }

    private Dictionary<Guid, (int Failures, long RetryAt)> RecoveryRetries(bool boundReceipt)
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (boundReceipt) return _boundReceiptRetries;
#endif
        return _recoveryRetries;
    }

    private void ScheduleRecoveryRetry(Guid id, bool boundReceipt = false)
    {
        var retries = RecoveryRetries(boundReceipt);
        int failures = retries.TryGetValue(id, out var retry) ? Math.Min(retry.Failures + 1, 6) : 1;
        double seconds = Math.Min(8, .25 * (1 << (failures - 1)));
        retries[id] = (failures, RecoveryTimestamp() + (long)(seconds * Stopwatch.Frequency));
    }

    private void ReportRecoveryHold(TransferJournalEntry entry, string reason, Exception? error)
    {
        bool first;
        lock (_recoveryNotified) first = _recoveryNotified.Add(entry.Transfer.TransferId);
        if (!first && error is null) return;
        _logger?.LogWarning(error, "Staged recovery holds {Destination}: transfer {TransferId}, generation {Generation}, " +
            "state {State}, handback {HandbackState}, reason {Reason}.", entry.Transfer.DestinationPath,
            entry.Transfer.TransferId, entry.DestinationGeneration, entry.State, entry.HandbackState, reason);
        if (!first) return;
        PublishTransferNotification(entry.Transfer, new TransferNotification(entry.Transfer.TransferId,
            entry.Transfer.DestinationPath, TransferPhase.Retained,
            RecoveryAdvice: reason switch
            {
                "publication_receipt_unavailable" => StagedRecoveryAdvice.PublicationUnresolved,
                "blocked_disposition_receipt_unavailable" => StagedRecoveryAdvice.CollectDiagnostics,
                _ => StagedRecoveryAdvice.JournalRecovery
            }));
    }
}

public sealed partial class StagedTransferJournal
{
    // Only the publisher's native-success receipt calls this. It changes
    // bookkeeping, never the public file, and is idempotent after a lost reply.
    internal async Task<TransferJournalEntry> CompleteConfirmedPublicationAsync(
        TransferJournalEntry intent, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(intent.Transfer.TransferId, token).ConfigureAwait(false);
            if (intent.State != TransferJournalState.Publishing || current.BoundAllocation is not null ||
                current.Transfer != intent.Transfer || current.DestinationGeneration != intent.DestinationGeneration ||
                current.NamespaceTombstones != intent.NamespaceTombstones || current.PendingRename is not null ||
                current.StageIdentity != intent.StageIdentity || current.SealedLength != intent.SealedLength ||
                !current.SealedOnce || current.Sha256Hex != intent.Sha256Hex ||
                current.DriverInstanceId != intent.DriverInstanceId || current.AttachmentStateV20 != intent.AttachmentStateV20 ||
                current.State is not (TransferJournalState.Publishing or TransferJournalState.Released))
                throw new IOException("The publication receipt no longer matches the exact journal version.");
            if (current.State == TransferJournalState.Released) return current;
            var history = AppendState(current, TransferJournalState.Released);
            var released = current with { State = TransferJournalState.Released, StateHistory = history,
                UpdatedAtUtc = history.Count == 0 ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc };
            await ReplaceAsync(ManifestPath(current.Transfer.TransferId), released, token).ConfigureAwait(false);
            _unboundPublicationAttempts.Remove(current.Transfer.TransferId);
            _unboundCommitted.Remove(current.Transfer.TransferId);
            return released;
        }
        finally { _gate.Release(); }
    }
}
