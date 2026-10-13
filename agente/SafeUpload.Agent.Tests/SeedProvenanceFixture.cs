using System.Text.Json;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Synthetic checked authority for component controls only. Production has no
// producer of affirmative evidence; this does not exercise a Windows read check.
internal static class SeedProvenanceFixture
{
    internal static (StagedSeedProvenance Seed, StagedAllocationSecuritySnapshot Security) PublicSeed(
        TransferJournalEntry entry, StagedSeedAuthority read = StagedSeedAuthority.Unproven,
        StagedSeedAuthority recipient = StagedSeedAuthority.Unproven)
    {
        var binding = entry.BoundAllocation ?? SecuritySnapshotFixture.Binding() with
        {
            ReservationId = entry.Transfer.TransferId, Disposition = 1,
            PublicTarget = new StagedStageIdentity(7, 81, 82)
        };
        var security = StagedAllocationSecuritySnapshot.Create(Guid.NewGuid(), binding, 1, 0xf,
            SecuritySnapshotFixture.Descriptor(), SecuritySnapshotFixture.Descriptor());
        var evidence = new StagedSeedExportEvidence(1, Guid.NewGuid(), binding, binding.PublicTarget!, security.Reference(),
            Guid.NewGuid(), "S-1-5-21-111-222-333-2000", entry.Transfer.ProcessId,
            entry.Transfer.RequestorProcessCreationTime ?? 123456, entry.Transfer.RequestorSid!,
            entry.Transfer.SessionId!.Value, read, recipient);
        return (new(1, StagedTransferJournal.VersionIdentity(entry), entry.BoundAllocation,
            StagedSeedOrigin.ExistingPublic, true, null, binding, binding.PublicTarget,
            security.Reference(), evidence, null), security);
    }

    internal static async Task<TransferJournalEntry> AttachAsync(string directory, StagedTransferJournal journal,
        Guid id, StagedSeedAuthority read = StagedSeedAuthority.Unproven,
        StagedSeedAuthority recipient = StagedSeedAuthority.Unproven)
    {
        var entry = await journal.ReadAsync(id, CancellationToken.None);
        var (seed, security) = PublicSeed(entry, read, recipient);
        await File.WriteAllBytesAsync(Path.Combine(directory, security.SnapshotId.ToString("N") + ".security"), security.Encode());
        var updated = entry with { SeedProvenance = seed };
        await WriteAsync(directory, updated);
        return await journal.ReadAsync(id, CancellationToken.None);
    }

    internal static Task WriteAsync(string directory, TransferJournalEntry entry) =>
        File.WriteAllTextAsync(Path.Combine(directory, entry.Transfer.TransferId.ToString("N") + ".json"),
            JsonSerializer.Serialize(entry));
}
