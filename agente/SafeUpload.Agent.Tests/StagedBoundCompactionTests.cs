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
        if (replay is null) File.WriteAllBytes(transfer.StagePath, []);
        using var turn = await journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        var entry = await journal.CommitBoundAllocationAsync(turn, transfer, binding, CancellationToken.None, security ?? WriterMetadataFixture.Security(binding,
                transfer.ProcessId, transfer.SessionId!.Value, transfer.RequestorProcessCreationTime!.Value, transfer.RequestorSid!));
        // Model retained private bytes for compaction; this is not live exposure.
        if (replay is null) File.WriteAllText(transfer.StagePath, "private version");
        return entry;
    }

    [Fact]
    public async Task Direct_journal_commit_cannot_bypass_required_metadata()
    {
        var binding = Binding(); var journal = Journal();
        string path = Path.Combine(_workspace.Root, "uncommitted.stage"); File.WriteAllText(path, "private bytes");
        var transfer = new StagedTransfer(binding.ReservationId, path, Locator(binding.CanonicalLeaf),
            DestinationKind.Cloud, "writer.exe", 1234, 1)
            { RequestorSid = "S-1-5-21-100-200-300-1001", RequestorProcessCreationTime = 123456 };
        using var turn = await journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.CommitBoundAllocationAsync(
            turn, transfer, binding, CancellationToken.None));
        var metadata = WriterMetadataFixture.Security(binding, transfer.ProcessId, transfer.SessionId!.Value,
            transfer.RequestorProcessCreationTime!.Value, transfer.RequestorSid!);
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<InvalidDataException>(() => journal.CommitBoundAllocationAsync(
            turn, transfer, binding, CancellationToken.None, metadata, seedPending: false))).Message);
        Assert.Equal("seed_completion_unproved", (await Assert.ThrowsAsync<IOException>(() => journal.CommitBoundAllocationAsync(
            turn, transfer, binding, CancellationToken.None, metadata))).Message);
        Assert.Null(await journal.FindBoundAllocationAsync(binding.ReservationId, CancellationToken.None));
        Assert.Equal("private bytes", File.ReadAllText(path));
    }

    [Fact]
    public async Task Captured_source_authority_survives_cross_writer_descendants_and_restart_without_export()
    {
        var binding = Binding() with { Disposition = 1, PublicTarget = new(7, 91, 92) };
        var journal = Journal();
        var source = await Allocate(journal, binding);
        var parent = source;
        // Model already captured descendant manifests; live cross-writer
        // predecessor admission is a separate integration gate.
        for (int generation = 2; generation <= 3; ++generation)
        {
            var childBinding = binding with { ReservationId = Guid.NewGuid(), ReferenceKind = 1,
                ParentTransferId = parent.Transfer.TransferId };
            string path = Path.Combine(_workspace.Root, childBinding.ReservationId.ToString("N") + ".stage");
            File.WriteAllText(path, "private inherited bytes");
            using var held = StagedStageFile.Open(path);
            var transfer = parent.Transfer with { TransferId = childBinding.ReservationId, StagePath = path,
                ProcessId = 2000 + generation, SessionId = (uint)generation,
                RequestorProcessCreationTime = 987654 + generation, RequestorSid = "S-1-5-21-100-200-300-2000" };
            var security = WriterMetadataFixture.Security(childBinding, transfer.ProcessId, transfer.SessionId!.Value,
                transfer.RequestorProcessCreationTime!.Value, transfer.RequestorSid!);
            var child = source with { Transfer = transfer, BoundAllocation = childBinding,
                CreateReservationId = childBinding.ReservationId, AllocationReferenceKind = 1,
                AllocationReferenceId = parent.Transfer.TransferId, ParentVersionIdentity = StagedTransferJournal.VersionIdentity(parent),
                StageIdentity = held.Identity, DestinationGeneration = generation, AllocationSecurity = security.Reference() };
            child = child with { SeedProvenance = StagedSeedProvenance.Inherit(child, parent),
                SeedCompletion = new(StagedTransferJournal.VersionIdentity(child), held.Stream.Length) };
            await File.WriteAllBytesAsync(Path.Combine(JournalPath, security.SnapshotId.ToString("N") + ".security"), security.Encode());
            await SeedProvenanceFixture.WriteAsync(JournalPath, child);
            var recovered = await Journal().ReadAsync(child.Transfer.TransferId, CancellationToken.None);
            Assert.Equal(source.SeedProvenance!.ExportEvidence, recovered.SeedProvenance!.ExportEvidence);
            Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(recovered));
            Assert.True(File.Exists(recovered.Transfer.StagePath));
            parent = recovered;
        }
    }

    [Fact]
    public async Task Legacy_bound_recovery_does_not_admit_refreshed_replay_or_a_new_seed_source()
    {
        var binding = Binding() with { Disposition = 1, PublicTarget = new(7, 91, 92) };
        var transfer = new StagedTransfer(binding.ReservationId,
            Path.Combine(_workspace.Root, "legacy.stage"), Locator(binding.CanonicalLeaf),
            DestinationKind.Cloud, "writer.exe", 1234, 1)
            { RequestorSid = "S-1-5-21-100-200-300-1001", RequestorProcessCreationTime = 123456 };
        File.WriteAllText(transfer.StagePath, "legacy private bytes");
        var journal = Journal();
        var entry = await journal.CreateAsync(transfer, CancellationToken.None);
        var legacy = entry with
        {
            BoundAllocation = binding, AllocationExtensionVersion = 23, AllocationDisposition = 1,
            AllocationReferenceKind = 0, CreateReservationId = binding.ReservationId,
            DriverInstanceId = binding.DriverInstanceId, ParentDirectoryIdentity = binding.Parent
        };
        await SeedProvenanceFixture.WriteAsync(JournalPath, legacy);
        var restarted = Journal();
        Assert.Equal(legacy, await restarted.ReadAsync(transfer.TransferId, CancellationToken.None));
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(legacy));
        var refreshed = WriterMetadataFixture.Security(binding, transfer.ProcessId, transfer.SessionId!.Value,
            transfer.RequestorProcessCreationTime!.Value, transfer.RequestorSid!);
        using (var turn = await restarted.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            await Assert.ThrowsAsync<IOException>(() => restarted.CommitBoundAllocationAsync(
                turn, transfer, binding, CancellationToken.None, refreshed));

        await SeedProvenanceFixture.WriteAsync(JournalPath, legacy with
        {
            State = TransferJournalState.Sealed, StateHistory = [], SealedOnce = true,
            SealedLength = new FileInfo(transfer.StagePath).Length
        });
        var childBinding = binding with { ReservationId = Guid.NewGuid(), ReferenceKind = 1,
            ParentTransferId = transfer.TransferId };
        var child = transfer with { TransferId = childBinding.ReservationId,
            StagePath = Path.Combine(_workspace.Root, "unallocated-child.stage") };
        var refusal = await Assert.ThrowsAsync<InvalidDataException>(() => restarted.ReadBoundAllocationParentAsync(
            child, childBinding, CancellationToken.None));
        Assert.Equal("writer_metadata_incomplete", refusal.Message);
        Assert.Null(await restarted.FindBoundAllocationAsync(child.TransferId, CancellationToken.None));
        Assert.False(File.Exists(child.StagePath));
        Assert.Equal("legacy private bytes", File.ReadAllText(transfer.StagePath));
        var retained = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Null(retained.AllocationSecurity); Assert.Null(retained.SeedProvenance); Assert.Null(retained.SeedCompletion);
    }

    private static async Task Discard(StagedTransferJournal journal, TransferJournalEntry entry)
    {
        await journal.DiscardAsync(entry.Transfer.TransferId, entry.Transfer.ProcessId,
            entry.Transfer.StagePath, CancellationToken.None);
        File.Delete(entry.Transfer.StagePath);
    }

    private async Task<List<TransferJournalEntry>> CapturedPublicLineageAsync()
    {
        var journal = Journal();
        var binding = Binding() with { Disposition = 1, PublicTarget = new(7, 91, 92) };
        var lineage = new List<TransferJournalEntry>();
        for (int i = 0; i < 3; ++i)
        {
            var entry = await Allocate(journal, binding);
            lineage.Add(entry);
            await SeedProvenanceFixture.WriteAsync(JournalPath, entry with
            {
                State = TransferJournalState.Sealed, StateHistory = [], SealedOnce = true,
                SealedLength = new FileInfo(entry.Transfer.StagePath).Length
            });
            binding = binding with { ReservationId = Guid.NewGuid(), ReferenceKind = 1,
                ParentTransferId = entry.Transfer.TransferId };
        }
        return lineage;
    }

    public static IEnumerable<object[]> ProvenanceErasureCases()
    {
        for (int generation = 0; generation < 3; ++generation)
            foreach (string damage in new[] { "none", "provenance", "provenance-and-completion", "binding", "source", "evidence", "restriction" })
                if (damage != "restriction" || generation > 0) yield return [generation, damage];
    }

    [Theory]
    [MemberData(nameof(ProvenanceErasureCases))]
    public async Task Restart_refuses_erased_public_or_inherited_provenance_and_retains_backing(int generation, string damage)
    {
        var lineage = await CapturedPublicLineageAsync();
        var original = await Journal().ReadAsync(lineage[generation].Transfer.TransferId, CancellationToken.None);
        var seed = original.SeedProvenance!;
        var corrupted = original with { SeedProvenance = damage switch
        {
            // Exact review counterexample: keep allocation/security/completion intact.
            "none" => seed with { Origin = StagedSeedOrigin.None, ContainsPriorBytes = false,
                AllocationBinding = null, Predecessor = null, SourceBinding = null, PublicSource = null,
                SourceSecurity = null, ExportEvidence = null, InheritedRestriction = null },
            "provenance" or "provenance-and-completion" => null,
            "binding" => seed with { AllocationBinding = null },
            "source" => seed with { ContainsPriorBytes = false, SourceBinding = null, PublicSource = null,
                SourceSecurity = null, ExportEvidence = null, InheritedRestriction = null },
            "evidence" => seed with { ExportEvidence = null },
            "restriction" => seed with { InheritedRestriction = null },
            _ => throw new ArgumentOutOfRangeException(nameof(damage))
        } };
        if (damage == "provenance-and-completion") corrupted = corrupted with { SeedCompletion = null };
        if (damage is "none" or "provenance" or "provenance-and-completion" or "binding")
            Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(corrupted));
        await SeedProvenanceFixture.WriteAsync(JournalPath, corrupted);
        await AssertCorruptLineageHeldAsync(lineage, generation);
    }

    [Theory]
    [InlineData(1, "id")]
    [InlineData(1, "generation")]
    [InlineData(1, "object")]
    [InlineData(1, "missing-parent")]
    [InlineData(2, "id")]
    [InlineData(2, "generation")]
    [InlineData(2, "object")]
    [InlineData(2, "missing-parent")]
    public async Task Restart_requires_exact_captured_predecessor_and_retains_backing(int generation, string damage)
    {
        var lineage = await CapturedPublicLineageAsync();
        var original = await Journal().ReadAsync(lineage[generation].Transfer.TransferId, CancellationToken.None);
        var parent = original.ParentVersionIdentity!;
        if (damage == "missing-parent")
            File.Delete(Path.Combine(JournalPath, parent.TransferId.ToString("N") + ".json"));
        else
        {
            var forged = damage switch
            {
                "id" => parent with { TransferId = Guid.NewGuid() },
                "generation" => parent with { DestinationGeneration = parent.DestinationGeneration + 1 },
                "object" => parent with { StageIdentity = parent.StageIdentity with { FileIdHigh = 999 } },
                _ => throw new ArgumentOutOfRangeException(nameof(damage))
            };
            // Keep the mutable JSON fields consistent with each other. The
            // captured binding and actual predecessor still have to agree.
            await SeedProvenanceFixture.WriteAsync(JournalPath, original with
            {
                ParentVersionIdentity = forged,
                SeedProvenance = original.SeedProvenance! with { Predecessor = forged }
            });
        }
        await AssertCorruptLineageHeldAsync(lineage, generation);
    }

    private async Task AssertCorruptLineageHeldAsync(List<TransferJournalEntry> lineage, int generation)
    {
        var restarted = Journal();
        foreach (var affected in lineage.Skip(generation))
        {
            Guid id = affected.Transfer.TransferId;
            await Assert.ThrowsAsync<InvalidDataException>(() => restarted.ReadAsync(id, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() => restarted.FindBoundAllocationAsync(id, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() => restarted.EnforceSeedExportAsync(id, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidDataException>(() => restarted.TryBeginStageCleanupAsync(id, CancellationToken.None));
        }
        foreach (var retained in lineage)
        {
            Assert.Equal("private version", File.ReadAllText(retained.Transfer.StagePath));
            var bytes = await File.ReadAllBytesAsync(Path.Combine(JournalPath,
                retained.AllocationSecurity!.SnapshotId.ToString("N") + ".security"));
            Assert.Equal(retained.AllocationSecurity, StagedAllocationSecuritySnapshot.Decode(bytes).Reference());
        }
    }

    [Fact]
    public async Task Bound_scan_revalidates_missing_ancestor_despite_unchanged_cached_child_manifest()
    {
        var lineage = await CapturedPublicLineageAsync();
        var journal = Journal();
        Assert.Equal(3, (await journal.ReadPendingAsync(CancellationToken.None)).Count);
        Assert.Equal(3, journal.ScanCacheEntries);
        File.Delete(Path.Combine(JournalPath, lineage[0].Transfer.TransferId.ToString("N") + ".json"));
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadPendingAsync(CancellationToken.None));
        await AssertCorruptLineageHeldAsync(lineage, 1);
    }

    [Fact]
    public async Task Restricted_descendant_retains_private_bytes_ancestry_and_source_security_after_overtaking()
    {
        var journal = Journal();
        var binding = Binding() with { Disposition = 1, PublicTarget = new(7, 91, 92) };
        var security = WriterMetadataFixture.Security(binding, 1234, 1, 123456, "S-1-5-21-100-200-300-1001");
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
        var originalSecurity = await journal.ReadBoundAllocationSecurityAsync(owner.Transfer.TransferId, CancellationToken.None);
        Assert.NotNull(originalSecurity);
        originalSecurity.RequireBinding(source);
        Assert.Throws<InvalidDataException>(() => originalSecurity.RequireBinding(owner.BoundAllocation!));
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
