using System.Text.Json;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Models old on-disk state for compatibility tests only. Production never
// emits reserved state 11; ordinary tests use the real measured seal directly.
internal static class LegacyStagedJournalFixture
{
    public static async Task<TransferJournalEntry> SealEmptyAsync(StagedTransferJournal journal,
        string workspace, Guid id, int processId, string stagePath, CancellationToken token,
        StagedVersionIdentity? expectedVersion = null)
    {
        TransferJournalEntry entry = await journal.SealAsync(id, processId, stagePath, token, expectedVersion);
        if (entry.SealedLength != 0) return entry;
        var legacy = entry with
        {
            State = TransferJournalState.LegacyEmptyHeld,
            Sha256Hex = null,
            StateHistory = entry.StateHistory.Select(change => change.State == TransferJournalState.Sealed
                ? change with { State = TransferJournalState.LegacyEmptyHeld } : change).ToArray()
        };
        string manifest = Assert.Single(Directory.GetFiles(workspace, id.ToString("N") + ".json", SearchOption.AllDirectories));
        await File.WriteAllTextAsync(manifest, JsonSerializer.Serialize(legacy), token);
        return await journal.ReadAsync(id, token);
    }
}
