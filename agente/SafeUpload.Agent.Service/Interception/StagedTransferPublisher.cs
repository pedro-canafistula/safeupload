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

    public StagedTransferPublisher(
        InspectionService inspection,
        NotificationHub notifications,
        StagedTransferJournal journal,
        string stagingRoot)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _notifications = notifications ?? throw new ArgumentNullException(nameof(notifications));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _stagingRoot = Path.GetFullPath(stagingRoot);
    }

    public async Task<StagedTransferOutcome> PublishAsync(
        StagedTransfer transfer,
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
        if (string.IsNullOrWhiteSpace(fileName) ||
            !string.Equals(Path.GetExtension(stagePath), Path.GetExtension(destinationPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The staging file and destination must have the same extension.", nameof(transfer));
        }

        var journalEntry = await _journal.ReadAsync(transfer.TransferId, cancellationToken)
            .ConfigureAwait(false);
        if (journalEntry.Transfer != transfer || !journalEntry.SealedOnce ||
            journalEntry.State is not (TransferJournalState.Sealed or TransferJournalState.Retained))
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
            TransferJournalState.Inspecting, null, cancellationToken).ConfigureAwait(false);
        _notifications.Publish(new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Analyzing), transfer.SessionId);

        var info = new FileInfo(stagePath);
        var operation = new FileOperation(
            stagePath,
            fileName,
            Path.GetExtension(destinationPath).ToLowerInvariant(),
            sealedFile.Length,
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
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, CancellationToken.None).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

        if (result.IsBlocked)
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Blocked,
                null, cancellationToken).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Blocked, result.Reason, cancellationToken).ConfigureAwait(false);
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Blocked), transfer.SessionId);
            return StagedTransferOutcome.Blocked;
        }

        bool currentApproval = false;
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
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            digest, cancellationToken).ConfigureAwait(false);
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Approved, TransferJournalState.Publishing,
            null, cancellationToken).ConfigureAwait(false);

        try
        {
            await using (var output = new FileStream(
                temporaryDestination, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await sealedFile.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }

            File.Move(temporaryDestination, destinationPath, overwrite: true);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
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
            Verdict.Approved, null, cancellationToken).ConfigureAwait(false);

        _notifications.Publish(new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Released), transfer.SessionId);
        return StagedTransferOutcome.Released;
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
