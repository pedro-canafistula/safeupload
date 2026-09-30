using System.Text.Json;
using System.Security.Cryptography;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Durable state for transfers held off the protected destination. Each state
/// change replaces one manifest on the same local volume. A service restart
/// can therefore distinguish an unapproved file from a published one.
/// The journal directory must be writable only by the service account.
/// </summary>
public sealed class StagedTransferJournal
{
    private readonly string _directory;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public StagedTransferJournal(string directory)
    {
        _directory = Path.GetFullPath(directory);
        Directory.CreateDirectory(_directory);
    }

    public async Task<TransferJournalEntry> CreateAsync(
        StagedTransfer transfer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        if (transfer.TransferId == Guid.Empty)
        {
            throw new ArgumentException("A transfer needs a nonempty ID.", nameof(transfer));
        }

        var entry = new TransferJournalEntry(
            transfer, TransferJournalState.Allocated, null, DateTimeOffset.UtcNow);
        string path = ManifestPath(transfer.TransferId);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using (var stream = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            // A complete, flushed manifest becomes visible all at once. A
            // duplicate ID cannot take over an earlier destination.
            File.Move(temporary, path);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
            _gate.Release();
        }

        return entry;
    }

    public async Task<TransferJournalEntry> ReadAsync(
        Guid transferId,
        CancellationToken cancellationToken)
    {
        string path = ManifestPath(transferId);
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var entry = await JsonSerializer.DeserializeAsync<TransferJournalEntry>(
            stream, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (entry is null || entry.Transfer.TransferId != transferId)
        {
            throw new InvalidDataException("The transfer manifest has the wrong ID.");
        }

        return entry;
    }

    public async Task<TransferJournalEntry> TransitionAsync(
        Guid transferId,
        TransferJournalState expected,
        TransferJournalState next,
        string? sha256Hex,
        CancellationToken cancellationToken)
    {
        if (!IsTransitionAllowed(expected, next))
        {
            throw new InvalidOperationException($"Invalid transfer transition: {expected} -> {next}.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await ReadAsync(transferId, cancellationToken).ConfigureAwait(false);
            if (current.State != expected)
            {
                throw new InvalidOperationException(
                    $"Transfer {transferId} is {current.State}; expected {expected}.");
            }

            string? digest = sha256Hex ?? current.Sha256Hex;
            if (next is TransferJournalState.Publishing or TransferJournalState.Released &&
                (digest is null || digest.Length != 64 || !digest.All(Uri.IsHexDigit)))
            {
                throw new InvalidOperationException("Publishing requires the sealed content digest.");
            }

            var updated = current with
            {
                State = next,
                Sha256Hex = digest,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(transferId), updated, cancellationToken)
                .ConfigureAwait(false);
            return updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TransferJournalEntry>> ReadPendingAsync(
        CancellationToken cancellationToken)
    {
        var entries = new List<TransferJournalEntry>();
        foreach (string path in Directory.EnumerateFiles(_directory, "*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out Guid id))
            {
                throw new InvalidDataException($"Unexpected journal file: {path}");
            }

            var entry = await ReadAsync(id, cancellationToken).ConfigureAwait(false);
            if (entry.State != TransferJournalState.Released)
            {
                entries.Add(entry);
            }
        }

        return entries;
    }

    /// <summary>
    /// Resolve a crash after publication started without copying again over
    /// a destination another process may have changed. An exact digest match
    /// proves the approved bytes landed; a mismatch retains the stage for
    /// review. An unreachable destination remains Publishing for a retry.
    /// </summary>
    public async Task ReconcilePublishingAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in await ReadPendingAsync(cancellationToken).ConfigureAwait(false))
        {
            if (entry.State != TransferJournalState.Publishing)
            {
                continue;
            }

            bool matches;
            try
            {
                await using var destination = new FileStream(
                    entry.Transfer.DestinationPath,
                    FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                string digest = Convert.ToHexString(
                    await SHA256.HashDataAsync(destination, cancellationToken).ConfigureAwait(false));
                matches = string.Equals(digest, entry.Sha256Hex,
                    StringComparison.OrdinalIgnoreCase);
            }
            catch (FileNotFoundException)
            {
                matches = false;
            }
            catch (DirectoryNotFoundException)
            {
                // A USB drive or network share may return later.
                continue;
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            await TransitionAsync(entry.Transfer.TransferId,
                TransferJournalState.Publishing,
                matches ? TransferJournalState.Released : TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A process or service crash leaves no trustworthy final-close signal.
    /// Keep incomplete versions local until a fresh seal and inspection.
    /// Publishing is handled separately because its destination may already
    /// contain exactly the approved digest.
    /// </summary>
    public async Task RetainInterruptedAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in await ReadPendingAsync(cancellationToken).ConfigureAwait(false))
        {
            if (entry.State is TransferJournalState.Allocated or
                TransferJournalState.Inspecting or TransferJournalState.Approved)
            {
                await TransitionAsync(entry.Transfer.TransferId,
                    entry.State, TransferJournalState.Retained,
                    null, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ReplaceAsync(
        string manifestPath,
        TransferJournalEntry entry,
        CancellationToken cancellationToken)
    {
        string temporary = manifestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, manifestPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private string ManifestPath(Guid id) =>
        Path.Combine(_directory, id.ToString("N") + ".json");

    private static bool IsTransitionAllowed(
        TransferJournalState from,
        TransferJournalState to) => (from, to) switch
    {
        (TransferJournalState.Allocated, TransferJournalState.Sealed) => true,
        (TransferJournalState.Allocated, TransferJournalState.Retained) => true,
        (TransferJournalState.Sealed, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Approved) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Blocked) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Retained) => true,
        (TransferJournalState.Approved, TransferJournalState.Retained) => true,
        (TransferJournalState.Approved, TransferJournalState.Publishing) => true,
        (TransferJournalState.Publishing, TransferJournalState.Released) => true,
        (TransferJournalState.Publishing, TransferJournalState.Retained) => true,
        (TransferJournalState.Retained, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Sealed) => true,
        _ => false
    };
}

public sealed record TransferJournalEntry(
    StagedTransfer Transfer,
    TransferJournalState State,
    string? Sha256Hex,
    DateTimeOffset UpdatedAtUtc);

public enum TransferJournalState
{
    Allocated,
    Sealed,
    Inspecting,
    Approved,
    Publishing,
    Released,
    Blocked,
    Retained
}
