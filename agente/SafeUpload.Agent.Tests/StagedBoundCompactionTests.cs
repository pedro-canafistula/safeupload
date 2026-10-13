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
        StagedAllocationBindingV23 binding, StagedTransfer? replay = null, StagedAllocationSecuritySnapshot? security = null)
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
        return await journal.CommitBoundAllocationAsync(turn, transfer, binding, CancellationToken.None, security);
    }

    private static async Task Discard(StagedTransferJournal journal, TransferJournalEntry entry)
    {
        await journal.DiscardAsync(entry.Transfer.TransferId, entry.Transfer.ProcessId,
            entry.Transfer.StagePath, CancellationToken.None);
        File.Delete(entry.Transfer.StagePath);
    }

    [Fact]
    public async Task Restricted_descendant_retains_private_bytes_ancestry_and_source_security_after_overtaking()
    {
        var journal = Journal();
        var binding = Binding() with { Disposition = 1, PublicTarget = new(7, 91, 92) };
        var security = StagedAllocationSecuritySnapshot.Create(Guid.NewGuid(), binding, 1, 0xf,
            SecuritySnapshotFixture.Descriptor(), SecuritySnapshotFixture.Descriptor());
        var root = await Allocate(journal, binding, security: security);
        var parent = root;
        var lineage = new List<TransferJournalEntry> { root };
        for (int i = 0; i < 2; i++)
        {
            await SeedProvenanceFixture.WriteAsync(JournalPath, parent with
                { State = TransferJournalState.Sealed, StateHistory = [], SealedOnce = true,
                    SealedLength = new FileInfo(parent.Transfer.StagePath).Length });
            binding = binding with { ReservationId = Guid.NewGuid(), ParentTransferId = parent.Transfer.TransferId, ReferenceKind = 1 };
            parent = await Allocate(journal, binding); lineage.Add(parent);
        }
        var blocked = parent with { State = TransferJournalState.Blocked, StateHistory = [], SealedOnce = true,
            SealedLength = new FileInfo(parent.Transfer.StagePath).Length, BlockedPolicyVersion = 1,
            Sha256Hex = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(parent.Transfer.StagePath))) };
        await SeedProvenanceFixture.WriteAsync(JournalPath, blocked);
        blocked = await journal.EnforceSeedExportAsync(blocked.Transfer.TransferId, CancellationToken.None);
        Assert.Equal("seed_export_unproven", blocked.HandbackFailureReason);
        Assert.Equal(root.Transfer.TransferId, blocked.SeedProvenance!.SourceBinding!.ReservationId);
        // Model terminal, cleaned ancestors; the retained descendant still needs
        // their exact lineage and immutable security. This is no native publish claim.
        foreach (var ancestor in lineage.Take(2))
        {
            var terminal = ancestor with { State = TransferJournalState.Released, StateHistory = [],
                SealedOnce = true, SealedLength = new FileInfo(ancestor.Transfer.StagePath).Length,
                Sha256Hex = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(ancestor.Transfer.StagePath))),
                StageDeleted = true };
            File.Delete(ancestor.Transfer.StagePath);
            await SeedProvenanceFixture.WriteAsync(JournalPath, terminal);
        }
        var latest = await Allocate(journal, binding with { ReservationId = Guid.NewGuid(),
            ParentTransferId = Guid.Empty, ReferenceKind = 0, Disposition = 5 });
        await Discard(journal, latest);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        var restarted = Journal();
        foreach (var ancestor in lineage) await restarted.ReadAsync(ancestor.Transfer.TransferId, CancellationToken.None);
        Assert.True(File.Exists(blocked.Transfer.StagePath));
        Assert.True(File.Exists(Path.Combine(JournalPath, security.SnapshotId.ToString("N") + ".security")));
        Assert.False((await restarted.TryBeginStageCleanupAsync(blocked.Transfer.TransferId, CancellationToken.None)).StageCleanupStarted);
        Assert.Equal(security, await restarted.ReadBoundAllocationSecurityAsync(root.Transfer.TransferId, CancellationToken.None));
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
