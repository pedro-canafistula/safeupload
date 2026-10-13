#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Real journal persistence with synthetic checked bindings. These controls
// qualify retention and replay, not kernel authorization or physical rename.
public sealed class StagedBoundCompactionTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private readonly Guid _volume = Guid.NewGuid();
    private string JournalPath => Path.Combine(_workspace.Root, "journal");
    private string Locator(string leaf) => Path.Combine(_workspace.Root, "public", leaf);
    private StagedTransferJournal Journal() => new(JournalPath);
    public void Dispose() => _workspace.Dispose();

    private StagedAllocationBindingV23 Binding(string leaf = "Report.txt", bool caseSensitive = false) =>
        new(Guid.NewGuid(), _driver, Guid.Empty, 2, 0, _volume,
            new(7, 11, 12), new(7, 21, 22), caseSensitive, leaf, null);

    private async Task<TransferJournalEntry> Allocate(StagedTransferJournal journal,
        StagedAllocationBindingV23 binding, StagedTransfer? replay = null)
    {
        var transfer = replay ?? new StagedTransfer(binding.ReservationId,
            Path.Combine(_workspace.Root, binding.ReservationId.ToString("N") + ".stage"),
            Locator(binding.CanonicalLeaf), DestinationKind.Cloud, "writer.exe", 1234, 1)
        {
            RequestorSid = "S-1-5-21-100-200-300-1001", RequestorProcessCreationTime = 123456
        };
        if (replay is null) File.WriteAllText(transfer.StagePath, "private version");
        using var turn = await journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        return await journal.CommitBoundAllocationAsync(turn, transfer, binding, CancellationToken.None);
    }

    private static async Task Discard(StagedTransferJournal journal, TransferJournalEntry entry)
    {
        await journal.DiscardAsync(entry.Transfer.TransferId, entry.Transfer.ProcessId,
            entry.Transfer.StagePath, CancellationToken.None);
        File.Delete(entry.Transfer.StagePath);
    }

    [Theory]
    [InlineData("case-sensitive-leaf")]
    [InlineData("parent-high-id")]
    [InlineData("volume-root-high-id")]
    [InlineData("mount-guid")]
    [InlineData("case-rule")]
    public async Task Compaction_keeps_each_bound_identity_maximum_despite_equal_locators(string difference)
    {
        var first = Binding(caseSensitive: true);
        var other = first with { ReservationId = Guid.NewGuid() };
        other = difference switch
        {
            "case-sensitive-leaf" => other with { CanonicalLeaf = "report.txt" },
            "parent-high-id" => other with { Parent = first.Parent with { FileIdHigh = 31 } },
            "volume-root-high-id" => other with { VolumeRoot = first.VolumeRoot with { FileIdHigh = 41 } },
            "mount-guid" => other with { MountManagerVolumeId = Guid.NewGuid() },
            "case-rule" => other with { ParentCaseSensitive = false },
            _ => throw new ArgumentOutOfRangeException(nameof(difference))
        };
        var journal = Journal();
        var firstMaximum = await Allocate(journal, first);
        var otherOld = await Allocate(journal, other);
        var otherMaximum = await Allocate(journal, other with { ReservationId = Guid.NewGuid() });
        Assert.Equal(1, firstMaximum.DestinationGeneration);
        Assert.Equal(2, otherMaximum.DestinationGeneration);
        foreach (var entry in new[] { firstMaximum, otherOld, otherMaximum }) await Discard(journal, entry);

        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        var restarted = Journal();
        await restarted.ReadAsync(first.ReservationId, CancellationToken.None);
        await restarted.ReadAsync(otherMaximum.Transfer.TransferId, CancellationToken.None);
        await Assert.ThrowsAsync<FileNotFoundException>(() => restarted.ReadAsync(other.ReservationId, CancellationToken.None));

        // A lost head must rebuild from this destination's retained manifest,
        // rather than reuse generation one or borrow another identity's claim.
        File.Delete(Path.Combine(JournalPath, "destination-" + first.Destination.StorageKey + ".state"));
        Assert.Equal(2, (await Allocate(restarted, first with { ReservationId = Guid.NewGuid() })).DestinationGeneration);
    }

    [Fact]
    public async Task Compaction_still_merges_case_insensitive_aliases_of_one_bound_destination()
    {
        var first = Binding(); var journal = Journal();
        var old = await Allocate(journal, first);
        var current = await Allocate(journal, first with { ReservationId = Guid.NewGuid(), CanonicalLeaf = "report.txt" });
        Assert.Equal(2, current.DestinationGeneration);
        await Discard(journal, old); await Discard(journal, current);
        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        await Assert.ThrowsAsync<FileNotFoundException>(() => Journal().ReadAsync(old.Transfer.TransferId, CancellationToken.None));
        await Journal().ReadAsync(current.Transfer.TransferId, CancellationToken.None);
    }

    [Fact]
    public async Task Compaction_does_not_substitute_a_bound_claim_for_a_legacy_path_claim()
    {
        var binding = Binding(); var journal = Journal();
        var legacy = new StagedTransfer(Guid.NewGuid(), Path.Combine(_workspace.Root, "legacy.stage"),
            Locator(binding.CanonicalLeaf), DestinationKind.Cloud, "writer.exe", 1234, 1);
        File.WriteAllText(legacy.StagePath, "legacy private version");
        var oldLegacy = await journal.CreateAsync(legacy, CancellationToken.None);
        var boundOld = await Allocate(journal, binding);
        var boundMaximum = await Allocate(journal, binding with { ReservationId = Guid.NewGuid() });
        foreach (var entry in new[] { oldLegacy, boundOld, boundMaximum }) await Discard(journal, entry);

        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        await Journal().ReadAsync(legacy.TransferId, CancellationToken.None);
        await Journal().ReadAsync(boundMaximum.Transfer.TransferId, CancellationToken.None);
        await Assert.ThrowsAsync<FileNotFoundException>(() => Journal().ReadAsync(boundOld.Transfer.TransferId, CancellationToken.None));
    }

    private async Task<TransferJournalEntry> RenamedFixture(StagedTransferJournal journal,
        StagedAllocationBindingV23 source)
    {
        var owner = await Allocate(journal, source);
        var target = source with { CanonicalLeaf = "moved.txt" };
        var renamed = owner with
        {
            Transfer = owner.Transfer with { DestinationPath = Locator(target.CanonicalLeaf) },
            BoundAllocation = target,
            NamespaceTombstones = new StagedNameTombstone(owner.Transfer.DestinationPath,
                owner.DestinationGeneration, null) { AllocationBindingV23 = source }
        };
        // Model the committed rename recovery record without pretending to
        // perform a native rename through these synthetic directory identities.
        await File.WriteAllTextAsync(Path.Combine(JournalPath, owner.Transfer.TransferId.ToString("N") + ".json"),
            JsonSerializer.Serialize(renamed));
        return await Journal().ReadAsync(owner.Transfer.TransferId, CancellationToken.None);
    }

    [Fact]
    public async Task Compaction_keeps_a_bound_tombstone_separate_from_a_case_sensitive_alias()
    {
        var source = Binding(caseSensitive: true); var journal = Journal();
        var owner = await RenamedFixture(journal, source);
        var targetMaximum = await Allocate(journal, owner.BoundAllocation! with { ReservationId = Guid.NewGuid() });
        var alias = source with { ReservationId = Guid.NewGuid(), CanonicalLeaf = "report.txt" };
        var aliasOld = await Allocate(journal, alias);
        var aliasMaximum = await Allocate(journal, alias with { ReservationId = Guid.NewGuid() });
        foreach (var entry in new[] { owner, targetMaximum, aliasOld, aliasMaximum }) await Discard(journal, entry);

        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        var retained = await Journal().ReadAsync(owner.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(source, retained.NamespaceTombstones!.AllocationBindingV23);
        await Assert.ThrowsAsync<FileNotFoundException>(() => Journal().ReadAsync(aliasOld.Transfer.TransferId, CancellationToken.None));
    }

    [Fact]
    public async Task Compaction_retains_the_tombstone_owner_needed_for_exact_allocation_replay()
    {
        var source = Binding(); var journal = Journal();
        var owner = await RenamedFixture(journal, source);
        var targetMaximum = await Allocate(journal, owner.BoundAllocation! with { ReservationId = Guid.NewGuid() });
        var childBinding = source with
        {
            ReservationId = Guid.NewGuid(), ParentTransferId = owner.Transfer.TransferId, ReferenceKind = 2
        };
        var child = await Allocate(journal, childBinding);
        Assert.Null(child.ParentVersionIdentity); Assert.Null(child.DeleteVersionIdentity);
        Assert.Equal(owner.Transfer.TransferId, child.AllocationReferenceId);
        await Discard(journal, owner); await Discard(journal, targetMaximum);

        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        var restarted = Journal();
        await restarted.ReadAsync(owner.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(child, await Allocate(restarted, childBinding, child.Transfer));
    }
}
#endif
