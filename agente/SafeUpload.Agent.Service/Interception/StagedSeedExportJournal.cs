namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    // Read current durable evidence at every disclosure boundary. A stale scan,
    // callback or Failed diagnostic can never supply a missing permission.
    internal async Task<TransferJournalEntry> EnforceSeedExportAsync(Guid id, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            return StagedSeedExport.Failure(current) is { } reason
                ? await PersistSeedRestrictionCoreAsync(current, reason, token).ConfigureAwait(false) : current;
        }
        finally { _gate.Release(); }
    }

    internal async Task RequireSeedExportAsync(StagedTransfer transfer, CancellationToken token)
    {
        var current = await EnforceSeedExportAsync(transfer.TransferId, token).ConfigureAwait(false);
        if (current.Transfer != transfer) throw new IOException("The hand-back recipient/allocation changed.");
        if (StagedSeedExport.Failure(current, transfer.RequestorSid) is { } reason)
            throw new IOException(reason);
    }

    private async Task<TransferJournalEntry> PersistSeedRestrictionCoreAsync(TransferJournalEntry current,
        string reason, CancellationToken token)
    {
        if (current.State != TransferJournalState.Blocked) return current;
        var updated = StagedSeedExport.PrivateBlocked(current, reason);
        if (updated == current) return current;
        updated = updated with { UpdatedAtUtc = DateTimeOffset.UtcNow };
        await ReplaceAsync(ManifestPath(current.Transfer.TransferId), updated, token).ConfigureAwait(false);
        return updated;
    }
}
