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
    private readonly string _stagingRoot;

    public StagedTransferPublisher(
        InspectionService inspection,
        NotificationHub notifications,
        string stagingRoot)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _notifications = notifications ?? throw new ArgumentNullException(nameof(notifications));
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

        _notifications.Publish(new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Analyzing), transfer.SessionId);

        // FileShare.Read lets the inspector open the same bytes, but denies
        // existing and new writable handles until publication completes.
        await using var sealedFile = new FileStream(
            stagePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);

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
            result = await _inspection.InspectAsync(operation, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

        if (result.IsBlocked)
        {
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Blocked), transfer.SessionId);
            return StagedTransferOutcome.Blocked;
        }

        if (!result.InScope || result.Verdict != Verdict.Approved)
        {
            // Oversize, timeout, unsupported format, and parser errors do
            // not constitute inspection. Keep their bytes local.
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

        string directory = Path.GetDirectoryName(destinationPath)!;
        string temporaryDestination = Path.Combine(directory, ".safeupload-" +
            transfer.TransferId.ToString("N") + ".pending");

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
            _notifications.Publish(new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained), transfer.SessionId);
            return StagedTransferOutcome.Retained;
        }

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
