using System.Buffers.Binary;
using System.Runtime.InteropServices;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Minifilter;
using Verdict = SafeUpload.Agent.Core.Domain.Verdict;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedLargeFileTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private const long MiB = 1024 * 1024;
    public void Dispose() => _workspace.Dispose();
    private StagedSpaceOptions Options() => new(true, 512 * MiB, 128 * MiB, 32 * MiB);
    private StagedSpaceBudget Budget(long available = 2048 * MiB) => new(_workspace.Root, Options(), () => available);

    [Fact]
    public void User_exhaustion_preserves_another_users_capacity_and_survives_restart()
    {
        var budget = Budget(); Guid first = Guid.NewGuid();
        long capacity = budget.Reserve(first, "S-1-5-21-100");
        Assert.True(capacity > 16 * MiB);
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "S-1-5-21-100"));
        Assert.Equal(capacity, budget.Reserve(Guid.NewGuid(), "S-1-5-21-200"));
        var restarted = Budget();
        Assert.Equal(capacity, restarted.Reserve(first, "S-1-5-21-100"));
        Assert.Throws<StagedSpaceException>(() => restarted.Reserve(Guid.NewGuid(), "S-1-5-21-100"));
        Assert.Throws<IOException>(() => restarted.Reserve(first, "S-1-5-21-300"));
        Assert.Equal(capacity, restarted.Reserve(Guid.NewGuid(), "S-1-5-21-300"));
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(65536 * 4, true)]
    public void Exact_free_space_admission_includes_all_copies_metadata_and_floor(long delta, bool allowed)
    {
        long minimum = Options().FreeSpaceFloorBytes + 2 * StagedSpaceBudget.MetadataBytes + 16 * MiB * 4;
        var budget = Budget(minimum + delta);
        if (allowed) Assert.Equal(16 * MiB + delta / 4, budget.Reserve(Guid.NewGuid(), "one"));
        else Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
    }

    [Fact]
    public async Task Concurrent_same_user_reservations_cannot_double_spend_free_capacity()
    {
        var budget = Budget();
        var capacities = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            try { return budget.Reserve(Guid.NewGuid(), "one"); }
            catch (StagedSpaceException) { return 0; }
        })));
        Assert.Single(capacities, value => value != 0);
        Assert.True(budget.Reserve(Guid.NewGuid(), "two") > 16 * MiB);
    }

    [Fact]
    public void Unknown_private_objects_and_interrupted_accounting_are_never_swept_or_admitted()
    {
        var budget = Budget();
        string unknown = Path.Combine(_workspace.Root, "orphan.inspection.txt");
        File.WriteAllText(unknown, "preserve these bytes");
        Assert.Throws<IOException>(() => budget.VerifyInventory(_workspace.Root));
        Assert.Equal("preserve these bytes", File.ReadAllText(unknown));
        File.WriteAllText(Path.Combine(_workspace.Root, ".space-reservations", Guid.NewGuid().ToString("N") + ".json.new"), "partial");
        Assert.Throws<IOException>(() => Budget());
    }

    [Fact]
    public void Corrupt_receipts_do_not_reset_usage_on_restart()
    {
        Budget().Reserve(Guid.NewGuid(), "one");
        string path = Directory.GetFiles(Path.Combine(_workspace.Root, ".space-reservations"), "*.json").Single();
        File.WriteAllText(path, "{\"Id\":");
        Assert.Throws<System.Text.Json.JsonException>(() => Budget());
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void An_extreme_free_floor_cannot_wrap_into_a_positive_admission()
    {
        var options = Options() with { FreeSpaceFloorBytes = long.MaxValue };
        var budget = new StagedSpaceBudget(_workspace.Root, options, () => 2048 * MiB);
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
    }

    [Fact]
    public void Known_never_created_allocation_retires_content_while_retaining_metadata()
    {
        var budget = Budget(); Guid id = Guid.NewGuid();
        long first = budget.Reserve(id, "one", Path.Combine(_workspace.Root, id.ToString("N") + ".txt"));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), "one"));
        budget.RetireFailedAllocation(id);
        var restarted = Budget();
        long next = restarted.Reserve(Guid.NewGuid(), "one");
        Assert.True(next >= 16 * MiB && next < first); // Content refunded, retained metadata still charged.
    }

    [Fact]
    public void A_failed_seed_can_retry_the_same_stable_intent_after_restart_without_double_charge()
    {
        Guid id = Guid.NewGuid(); string path = Path.Combine(_workspace.Root, id.ToString("N") + ".txt");
        var budget = Budget(); long first = budget.Reserve(id, "one", path);
        budget.RetireFailedAllocation(id);
        var restarted = Budget();
        Assert.Equal(first, restarted.Reserve(id, "one", path));
        Assert.Throws<StagedSpaceException>(() => restarted.Reserve(Guid.NewGuid(), "one"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Terminal_refusal_never_adopts_an_unknown_present_object_as_cleanup_authority(bool reserved)
    {
        Guid id = Guid.NewGuid(); string path = Path.Combine(_workspace.Root, id.ToString("N") + ".txt");
        var budget = Budget();
        if (reserved) budget.Reserve(id, "one", path);
        File.WriteAllText(path, "created before the identity receipt");
        Assert.Throws<IOException>(() => budget.RequireFailedAllocationAbsent(id, path));
        Assert.Equal("created before the identity receipt", File.ReadAllText(path));
        if (reserved)
        {
            var restarted = Budget();
            Assert.Throws<IOException>(() => restarted.RequireFailedAllocationAbsent(id, path));
            Assert.Throws<StagedSpaceException>(() => restarted.Reserve(Guid.NewGuid(), "one"));
            Assert.True(File.Exists(path));
        }
    }

    [Fact]
    public void Terminal_refusal_retires_only_the_recorded_exact_unissued_seed()
    {
        Guid id = Guid.NewGuid(); string path = Path.Combine(_workspace.Root, id.ToString("N") + ".txt");
        var budget = Budget(); budget.Reserve(id, "one", path);
        File.WriteAllText(path, "known failed seed");
        using (var stage = StagedStageFile.Open(path)) budget.RecordStage(id, path, stage.Identity);
        budget.RequireFailedAllocationAbsent(id, path);
        Assert.False(File.Exists(path));
        Assert.True(budget.Reserve(Guid.NewGuid(), "one") >= 16 * MiB);
    }

    [Fact]
    public void Failed_journal_replacement_residue_has_a_bounded_storage_envelope()
    {
        var budget = Budget(); Guid id = Guid.NewGuid(); budget.Reserve(id, "one");
        string journal = Path.Combine(_workspace.Root, "journal"); Directory.CreateDirectory(journal);
        string prefix = Path.Combine(journal, id.ToString("N"));
        for (int i = 0; i < 4; i++) File.WriteAllBytes(prefix + "." + i + ".tmp", new byte[128 * 1024]);
        Assert.Throws<StagedSpaceException>(() => budget.RequireMetadataAdmission(prefix + ".next.tmp"));
        Assert.Equal(4, Directory.GetFiles(journal).Length);
    }

    [Fact]
    public void Negative_allocation_receipts_cannot_exceed_the_global_metadata_envelope()
    {
        var budget = Budget();
        for (int i = 0; i < StagedSpaceBudget.MetadataBytes / 4 / 4096; i++)
            File.WriteAllBytes(Path.Combine(_workspace.Root, Guid.NewGuid().ToString("N") + ".allocation-refused"),
                new byte[Contract.RequestSize]);
        budget.RequireNegativeReceiptSpace(_workspace.Root, creating: false);
        Assert.Throws<StagedSpaceException>(() => budget.RequireNegativeReceiptSpace(_workspace.Root));
        Assert.Equal(StagedSpaceBudget.MetadataBytes / 4 / 4096, Directory.GetFiles(_workspace.Root).Length);
    }

    [Fact]
    public void Unresolved_negative_receipt_temporary_holds_further_admission_without_deleting_evidence()
    {
        var budget = Budget();
        string path = Path.Combine(_workspace.Root,
            Guid.NewGuid().ToString("N") + ".allocation-refused." + Guid.NewGuid().ToString("N") + ".tmp");
        File.WriteAllText(path, "interrupted refusal receipt");
        Assert.Throws<IOException>(() => budget.RequireNegativeReceiptSpace(_workspace.Root));
        Assert.Equal("interrupted refusal receipt", File.ReadAllText(path));
        Assert.Throws<IOException>(() => Budget());
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Oversized_journal_serialization_never_writes_beyond_the_existing_limit()
    {
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() => StagedJournalSerialization.SerializeAsync(output,
            new string('x', StagedJournalFile.MaximumManifestBytes * 2), CancellationToken.None));
        Assert.True(output.Length <= StagedJournalFile.MaximumManifestBytes);
    }

    [Fact]
    public async Task A_failed_write_cannot_approve_even_an_empty_or_clean_prefix()
    {
        var policy = LocalPolicyStore.CreateDefault() with { OverrideAllowed = true };
        var service = new InspectionService(new FixedPolicyStore(policy), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        foreach (string text in new[] { "", "clean prefix" })
        {
            string path = _workspace.WriteText("prefix.txt", text);
            var operation = TestWorkspace.Operation(path);
            var result = await service.InspectStagedFailureAsync(operation, CancellationToken.None);
            Assert.Equal(Verdict.Blocked, result.Verdict);
            Assert.Equal("not_enough_staging_space", result.Reason);
            Assert.Equal(InspectionFailureKind.NotEnoughStagingSpace, result.FailureKind);
            Assert.Empty(result.Findings);
            Assert.False(await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
            Assert.NotNull(result.PolicyContentFingerprint);
            Assert.False(await service.IsCurrentStagedJustificationAllowedAsync(operation, result, CancellationToken.None));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Zip_member_replay_has_bounded_allocations_and_checks_complete_integrity(bool compressed)
    {
        byte[] data = ArchiveFixture.Letters(2 * 1024 * 1024);
        byte[] archive = ArchiveFixture.Zip(new ArchiveFixture.Item("document.txt", data) { Method = compressed ? (ushort)8 : (ushort)0 });
        using var input = new MemoryStream(archive, false);
        var entry = ZipInspectionGuard.Inspect(input, new ArchiveInspectionBudget(8 * MiB), 1, CancellationToken.None).Single();
        long before = GC.GetAllocatedBytesForCurrentThread();
        using var member = ZipInspectionGuard.OpenMember(input, entry, CancellationToken.None);
        byte[] buffer = new byte[8192];
        for (int pass = 0; pass < 3; pass++)
        {
            member.Position = 0;
            long length = 0; int read;
            while ((read = member.Read(buffer)) != 0) length += read;
            Assert.Equal(data.Length, length);
        }
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 512 * 1024);
        archive[(int)entry.DataOffset + (compressed ? 10 : data.Length - 1)] ^= 1;
        member.Position = 0;
        Assert.ThrowsAny<InvalidDataException>(() => { while (member.Read(buffer) != 0) { } });
    }

    [Fact]
    public async Task A_crc_failure_after_a_sensitive_prefix_returns_no_partial_findings()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("CPF 529.982.247-25 clean ending");
        byte[] archive = ArchiveFixture.Zip(new ArchiveFixture.Item("document.txt", data) { Crc = 1 });
        using var input = new MemoryStream(archive, false);
        var result = await StagedParserExecution.InspectAsync(input, ".zip", 64,
            new HashSet<Category> { Category.Cpf }, CancellationToken.None);
        Assert.Equal("parse_error:worker", result.Failure);
        Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData(0, 4, 31, true)]
    [InlineData(-1, 4, 31, false)]
    [InlineData(0, 0, 31, false)]
    [InlineData(0, 8, 31, false)]
    [InlineData(0, 4, 20, false)]
    public void Large_mode_requires_an_exact_matching_driver_support_receipt(int result, uint bytes, uint version, bool valid)
    {
        if (valid) FilterPort.ValidateStageSpaceCapabilities(result, bytes, version);
        else Assert.Throws<IOException>(() => FilterPort.ValidateStageSpaceCapabilities(result, bytes, version));
    }

    [Fact]
    public void Resource_failure_seal_requires_its_exact_additive_envelope_and_zero_padding()
    {
        byte[] bytes = FailureSeal();
        var request = MemoryMarshal.Read<SafeUploadRequest>(bytes);
        Assert.True(request.HasKnownFlags);
        Assert.True(request.UsesStageBinaryPayload);
        Assert.True(request.TryReadStageResourceSeal(out var seal));
        Assert.Equal(7UL, seal.DestinationGeneration);
        Assert.False(request.TryReadStagePayload<SafeUploadStageSealV19>(Operation.StageSeal, out _));
        int image = Offset(nameof(SafeUploadRequest.ImageName));
        foreach (int offset in new[] { 0, 4, 40, 44, 48, Contract.MaxImageNameChars * 2 - 1 })
        {
            byte[] corrupt = (byte[])bytes.Clone(); corrupt[image + offset] ^= 0x80;
            Assert.False(MemoryMarshal.Read<SafeUploadRequest>(corrupt).TryReadStageResourceSeal(out _));
        }
        byte[] invalidOuter = (byte[])bytes.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(invalidOuter.AsSpan(Offset(nameof(SafeUploadRequest.Flags))), 1);
        Assert.False(MemoryMarshal.Read<SafeUploadRequest>(invalidOuter).TryReadStageResourceSeal(out _));
    }

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => Task.FromResult(policy);
    }

    private static int Offset(string name) => Marshal.OffsetOf<SafeUploadRequest>(name).ToInt32();
    private static byte[] FailureSeal()
    {
        var bytes = new byte[Contract.RequestSize];
        void U32(string name, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(Offset(name)), value);
        U32(nameof(SafeUploadRequest.Version), Contract.Version);
        U32(nameof(SafeUploadRequest.StructSize), Contract.RequestSize);
        U32(nameof(SafeUploadRequest.Operation), Operation.StageSeal);
        U32(nameof(SafeUploadRequest.Reserved), 31);
        U32(nameof(SafeUploadRequest.ImageNameLength), 48);
        byte[] path = System.Text.Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume1\staging\stage.txt");
        U32(nameof(SafeUploadRequest.PathLength), (uint)path.Length);
        path.CopyTo(bytes, Offset(nameof(SafeUploadRequest.Path)));
        int image = Offset(nameof(SafeUploadRequest.ImageName));
        var seal = new SafeUploadStageSealV19 { Version = 31, StructSize = 48,
            StageIdentity = new() { VolumeSerialNumber = 1, FileIdLow = 2 }, DestinationGeneration = 7 };
        MemoryMarshal.Write(bytes.AsSpan(image), in seal);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(image + 40), 1);
        return bytes;
    }
}
