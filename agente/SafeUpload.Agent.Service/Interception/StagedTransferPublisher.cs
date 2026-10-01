using System.Security.Cryptography;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Releases a completed local staging file only after its immutable version
/// has received an inspected approval. The minifilter must supply the staging
/// file and must keep every direct write to the destination behind its gate.
/// </summary>
public sealed class StagedTransferPublisher
{
    private readonly InspectionService _inspection;
    private readonly NotificationHub _notifications;
    private readonly StagedTransferJournal _journal;
    private readonly string _stagingRoot;
    private readonly StagedJustifications? _justifications;
    private readonly IStagedPublicationGate _publicationGate;
    private readonly ILogger? _logger;
    private sealed record JustifiedVersion(string Digest, int PolicyVersion);

    public StagedTransferPublisher(
        InspectionService inspection,
        NotificationHub notifications,
        StagedTransferJournal journal,
        string stagingRoot,
        IStagedPublicationGate publicationGate,
        StagedJustifications? justifications = null,
        ILogger? logger = null)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _notifications = notifications ?? throw new ArgumentNullException(nameof(notifications));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _stagingRoot = Path.GetFullPath(stagingRoot);
        _justifications = justifications;
        _publicationGate = publicationGate ?? throw new ArgumentNullException(nameof(publicationGate));
        _logger = logger;
    }

    public Task<StagedTransferOutcome> PublishAsync(
        StagedTransfer transfer,
        CancellationToken cancellationToken)
        => PublishCoreAsync(transfer, null, cancellationToken);

    private async Task<StagedTransferOutcome> PublishCoreAsync(
        StagedTransfer transfer, JustifiedVersion? justified,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transfer);

        string stagePath = Path.GetFullPath(transfer.StagePath);
        string relativePath = Path.GetRelativePath(_stagingRoot, stagePath);
        if (relativePath is "." or ".." ||
            Path.IsPathRooted(relativePath) ||
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException("The staging file must be inside the private staging root.", nameof(transfer));
        }

        string destinationPath = Path.GetFullPath(transfer.DestinationPath);
        string fileName = Path.GetFileName(destinationPath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentException("The destination must name a file.", nameof(transfer));
        }

        var journalEntry = await _journal.ReadAsync(transfer.TransferId, cancellationToken)
            .ConfigureAwait(false);
        if (journalEntry.PendingRename is not null || journalEntry.Transfer != transfer || !journalEntry.SealedOnce ||
            (justified is null
                ? journalEntry.State is not (TransferJournalState.Sealed or TransferJournalState.Retained)
                : journalEntry.State != TransferJournalState.Blocked))
        {
            throw new InvalidOperationException("The transfer must be sealed in the service journal.");
        }

        // Reject symbolic links and junctions in the stage path. A service
        // must never scan one file and publish another through a reparse point.
        for (string? path = stagePath; path is not null &&
             !string.Equals(path, Path.GetDirectoryName(_stagingRoot), StringComparison.OrdinalIgnoreCase);
             path = Path.GetDirectoryName(path))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Staging contains a reparse point.");
            }
        }

        // FileShare.Read lets the inspector open the same bytes, but denies
        // existing and new writable handles until publication completes.
        FileStream sealedFile;
        try
        {
            sealedFile = new FileStream(
                stagePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (IOException)
        {
            // The last cleanup signal can reach the journal before NTFS has
            // finished closing the writer. Leave Sealed for the worker's next
            // attempt; no analysis or publication has started yet.
            return StagedTransferOutcome.Retained;
        }

        await using var lockedFile = sealedFile;
        await _journal.TransitionAsync(transfer.TransferId, journalEntry.State,
            TransferJournalState.Inspecting, null, cancellationToken, transfer).ConfigureAwait(false);
        // File sharing does not revoke an already mapped writable section.
        // Inspect and publish a separate service-only snapshot, so even a
        // delayed paging write cannot change the inspected publication bytes.
        await using var snapshot = await InspectionSnapshot.CreateAsync(
            sealedFile, _stagingRoot, Path.GetExtension(destinationPath), cancellationToken)
            .ConfigureAwait(false);
        FileStream inspectedFile = snapshot.Stream;
        string inspectedDigest = Convert.ToHexString(
            await SHA256.HashDataAsync(inspectedFile, cancellationToken).ConfigureAwait(false));
        inspectedFile.Position = 0;
        if (justified is not null && !string.Equals(inspectedDigest, justified.Digest,
                StringComparison.Ordinal))
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }
        _notifications.Publish(new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Analyzing), transfer.SessionId);

        var info = new FileInfo(stagePath);
        var operation = new FileOperation(
            snapshot.Path,
            fileName,
            Path.GetExtension(destinationPath).ToLowerInvariant(),
            inspectedFile.Length,
            info.LastWriteTimeUtc,
            transfer.ProcessName,
            transfer.ProcessId,
            destinationPath,
            transfer.Destination);

        InspectionResult result;
        try
        {
            result = await _inspection.InspectStagedAsync(operation, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged inspection failed for {TransferId}.", transfer.TransferId);
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, CancellationToken.None).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

        // A justification authorizes precisely the previously inspected
        // digest and policy. Reinspect under the read lock and recheck policy;
        // service restart, changed bytes or changed policy revoke it.
        bool justifiedApproval = justified is not null && result.IsBlocked &&
            result.PolicyVersion == justified.PolicyVersion &&
            await _inspection.IsCurrentStagedJustificationAllowedAsync(
                operation, result, cancellationToken).ConfigureAwait(false);
        if (result.IsBlocked && !justifiedApproval)
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Blocked,
                inspectedDigest, cancellationToken).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Blocked, result.Reason, cancellationToken,
                transfer.TransferId).ConfigureAwait(false);
            bool canJustify = _justifications is not null && transfer.SessionId is not null &&
                await _inspection.IsCurrentStagedJustificationAllowedAsync(
                    operation, result, cancellationToken).ConfigureAwait(false);
            if (canJustify)
            {
                var version = new JustifiedVersion(inspectedDigest, result.PolicyVersion);
                _justifications!.Remember(transfer.TransferId, transfer.SessionId!.Value,
                    async token => await PublishCoreAsync(transfer, version, token).ConfigureAwait(false)
                        == StagedTransferOutcome.Released);
            }
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Blocked,
                result.Findings, canJustify), transfer.SessionId);
            return StagedTransferOutcome.Blocked;
        }

        bool currentApproval = justifiedApproval;
        if (result.InScope && result.Verdict == Verdict.Approved)
        {
            try
            {
                currentApproval = await _inspection.IsCurrentStagedApprovalAsync(
                    operation, result, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // An unreadable policy is not permission to publish.
            }
        }

        if (!currentApproval)
        {
            // Oversize, timeout, unsupported format, parser errors, and a
            // changed policy all keep the staged bytes local.
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained,
                result.Verdict == Verdict.Approved ? "policy_changed" : result.Reason ?? "not_inspected",
                cancellationToken).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

        string directory = Path.GetDirectoryName(destinationPath)!;
        string temporaryDestination = Path.Combine(directory, ".safeupload-" +
            transfer.TransferId.ToString("N") + ".pending");

        // The digest belongs to the same locked version the inspector read.
        sealedFile.Position = 0;
        string digest = Convert.ToHexString(
            await SHA256.HashDataAsync(sealedFile, cancellationToken).ConfigureAwait(false));
        sealedFile.Position = 0;
        if (!string.Equals(digest, inspectedDigest, StringComparison.Ordinal))
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, "stage_changed_during_inspection", cancellationToken).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            digest, cancellationToken).ConfigureAwait(false);
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Approved, TransferJournalState.Publishing,
            null, cancellationToken).ConfigureAwait(false);

        try
        {
            _logger?.LogDebug("Requesting kernel publication permission for {TransferId}.", transfer.TransferId);
            using var permit = _publicationGate.Authorize(transfer, temporaryDestination, digest);
            _logger?.LogDebug("Creating approved publication file for {TransferId}.", transfer.TransferId);
            await using (var output = StagedDestinationFile.Create(temporaryDestination))
            {
                _logger?.LogDebug("Approved publication file opened for {TransferId}.", transfer.TransferId);
                await inspectedFile.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                _logger?.LogDebug("Approved publication bytes copied for {TransferId}.", transfer.TransferId);
                _logger?.LogDebug("Renaming approved publication file for {TransferId}.", transfer.TransferId);
                StagedDestinationFile.Commit(output, temporaryDestination, destinationPath);
            }
            _logger?.LogDebug("Approved publication rename completed for {TransferId}.", transfer.TransferId);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged publication failed for {TransferId}.", transfer.TransferId);
            try { File.Delete(temporaryDestination); } catch (IOException) { }
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Publishing, TransferJournalState.Retained,
                null, CancellationToken.None).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, "publication_failed", CancellationToken.None).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Publishing, TransferJournalState.Released,
            null, cancellationToken).ConfigureAwait(false);
        await _inspection.RecordTransferOutcomeAsync(operation, result,
            Verdict.Approved, justifiedApproval ? "justified_version" : null,
            cancellationToken).ConfigureAwait(false);

        _notifications.Publish(new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Released), transfer.SessionId);
        return StagedTransferOutcome.Released;
    }

    private sealed class InspectionSnapshot : IAsyncDisposable
    {
        public string Path { get; }
        public FileStream Stream { get; }
        private InspectionSnapshot(string path, FileStream stream) => (Path, Stream) = (path, stream);

        public static async Task<InspectionSnapshot> CreateAsync(FileStream source,
            string root, string extension, CancellationToken token)
        {
            string path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N") +
                ".inspection" + extension);
            try
            {
                await using (var output = new FileStream(path, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    source.Position = 0;
                    await source.CopyToAsync(output, token).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                source.Position = 0;
                return new(path, new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan));
            }
            catch
            {
                if (File.Exists(path)) File.Delete(path);
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Stream.DisposeAsync().ConfigureAwait(false);
            File.Delete(Path);
        }
    }
}

public sealed record StagedTransfer(
    Guid TransferId,
    string StagePath,
    string DestinationPath,
    DestinationKind Destination,
    string ProcessName,
    int ProcessId,
    uint? SessionId);

public enum StagedTransferOutcome
{
    Released,
    Blocked,
    Retained
}
