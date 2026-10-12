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
    private readonly HashSet<Guid> _recoveryNotified = new();

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

    // The live worker and startup both call this. No delay is awaited under
    // the journal gate, and a retry for one transfer does not stall another.
    // This dispatcher never invokes PublishAsync or performs a public rename.
    internal async Task RecoverPendingTransferAsync(TransferJournalEntry entry, CancellationToken token)
    {
        await _recoveryGate.WaitAsync(token).ConfigureAwait(false);
        Guid id = entry.Transfer.TransferId;
        try
        {
            if (_recoveryRetries.TryGetValue(id, out var retry) && Stopwatch.GetTimestamp() < retry.RetryAt)
                return;
            entry = await _journal.ReadAsync(id, token).ConfigureAwait(false);
            if (HasConfirmedPublication(id))
                await FinishConfirmedPublicationAsync(id, token).ConfigureAwait(false);
            else if (entry.State == TransferJournalState.Publishing)
            {
                ReportRecoveryHold(entry, "publication_receipt_unavailable", null);
                return; // T5 bound records require their existing anchored receipt dispatcher.
            }
            else if (entry.State == TransferJournalState.Blocked)
                await RecoverBlockedAsync(entry, token).ConfigureAwait(false);
            lock (_confirmedPublications) _pendingJournalProgress.Remove(id);
            _recoveryRetries.Remove(id);
            _recoveryNotified.Remove(id);
        }
        catch (StagedJournalPersistenceException error)
        {
            QueueJournalProgress(entry);
            ScheduleRecoveryRetry(id);
            ReportRecoveryHold(entry, "journal_progress_pending", error);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            // A mismatch or unreadable record is never permission to release
            // or recopy. Keep the obligation, diagnose it, and let unrelated
            // transfers continue. A future attempt must validate from scratch.
            QueueJournalProgress(entry);
            ScheduleRecoveryRetry(id);
            ReportRecoveryHold(entry, "recovery_evidence_unavailable", error);
        }
        finally { _recoveryGate.Release(); }
    }

    private void ScheduleRecoveryRetry(Guid id)
    {
        int failures = _recoveryRetries.TryGetValue(id, out var retry) ? Math.Min(retry.Failures + 1, 6) : 1;
        double seconds = Math.Min(8, .25 * (1 << (failures - 1)));
        _recoveryRetries[id] = (failures, Stopwatch.GetTimestamp() + (long)(seconds * Stopwatch.Frequency));
    }

    private void ReportRecoveryHold(TransferJournalEntry entry, string reason, Exception? error)
    {
        bool first = _recoveryNotified.Add(entry.Transfer.TransferId);
        if (!first && error is null) return;
        _logger?.LogWarning(error, "Staged recovery holds {Destination}: transfer {TransferId}, generation {Generation}, " +
            "state {State}, handback {HandbackState}, reason {Reason}.", entry.Transfer.DestinationPath,
            entry.Transfer.TransferId, entry.DestinationGeneration, entry.State, entry.HandbackState, reason);
        if (!first) return;
        PublishTransferNotification(entry.Transfer, new TransferNotification(entry.Transfer.TransferId,
            entry.Transfer.DestinationPath, TransferPhase.Retained,
            RecoveryAdvice: reason == "publication_receipt_unavailable"
                ? StagedRecoveryAdvice.PublicationUnresolved : StagedRecoveryAdvice.JournalRecovery));
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
            return released;
        }
        finally { _gate.Release(); }
    }
}
