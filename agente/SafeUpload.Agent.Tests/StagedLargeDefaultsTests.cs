using System.Buffers.Binary;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using Verdict = SafeUpload.Agent.Core.Domain.Verdict;

namespace SafeUpload.Agent.Tests;

public sealed class StagedLargeDefaultsTests : IDisposable
{
    private const long MiB = 1024 * 1024, GiB = 1024 * MiB;
    private const string Sid = "S-1-5-21-100";
    private readonly TestWorkspace _workspace = new();
    private string Stage => Path.Combine(_workspace.Root, "stage");
    private string Hot => Path.Combine(_workspace.Root, "journal");
    public void Dispose() => _workspace.Dispose();
    private static IConfiguration Config(params (string Key, string Value)[] settings) => new ConfigurationBuilder()
        .AddInMemoryCollection(settings.ToDictionary(x => "Interception:StageSpace:" + x.Key, x => (string?)x.Value)).Build();
    private StagedSpaceBudget Upgrade(StagedSpaceOptions? options = null)
    {
        StagedPrivateStorage.CreateDirectory(Stage);
        return new(Stage, options ?? new(true, 512 * MiB, 128 * MiB, 0), () => 2 * GiB,
            new StagedTransferJournal(Hot, requireProtectedParent: false, deferArchiveLoad: true));
    }

    [Theory]
    [InlineData(0L, 10L, 0L, 0L, 1L)]
    [InlineData(100L, 200L, 10L, 2560L, 10L)]
    [InlineData(640L, 1000L, 32L, 8192L, 50L)]
    public void Product_defaults_derive_from_the_staging_volume_and_enable_accounting(long available, long volume,
        long total, long perUserMiB, long floor)
    {
        string? observed = null;
        var options = StagedSpaceConfiguration.Resolve(Config(), Stage, path =>
        { observed = path; return (available * GiB, volume * GiB); });
        Assert.Equal(Path.GetFullPath(Stage), observed);
        Assert.True(options.Enabled);
        Assert.Equal(total * GiB, options.TotalBytes);
        Assert.Equal(perUserMiB * MiB, options.PerUserBytes);
        Assert.Equal(floor * GiB, options.FreeSpaceFloorBytes);
        Assert.Equal(256 * MiB, StagedSpaceConfiguration.ParserMemoryBytes(Config()));
    }

    [Fact]
    public void Explicit_storage_parser_and_disable_settings_override_each_default()
    {
        var config = Config(("Enabled", "false"), ("TotalBytes", (8 * GiB).ToString()),
            ("PerUserBytes", (3 * GiB).ToString()), ("FreeSpaceFloorBytes", "0"), ("ParserMemoryBytes", (512 * MiB).ToString()));
        var options = StagedSpaceConfiguration.Resolve(config, Stage, _ => (640 * GiB, 1000 * GiB));
        Assert.Equal(new StagedSpaceOptions(false, 8 * GiB, 3 * GiB, 0), options);
        Assert.Equal(512 * MiB, StagedSpaceConfiguration.ParserMemoryBytes(config));
        var derived = StagedSpaceConfiguration.Resolve(Config(("TotalBytes", (4 * GiB).ToString())), Stage, _ => (640 * GiB, 1000 * GiB));
        Assert.Equal(GiB, derived.PerUserBytes);
        Assert.Throws<IOException>(() => StagedSpaceConfiguration.ParserMemoryBytes(Config(("ParserMemoryBytes", "1"))));
    }

    [Fact]
    public void Approved_default_per_user_exhaustion_survives_restart_without_consuming_another_users_share()
    {
        StagedPrivateStorage.CreateDirectory(Stage);
        var options = StagedSpaceConfiguration.Resolve(Config(), Stage, _ => (640 * GiB, 1000 * GiB));
        var budget = new StagedSpaceBudget(Stage, options, () => 640 * GiB);
        long capacity = budget.Reserve(Guid.NewGuid(), Sid);
        Assert.True(capacity > 512 * MiB);
        var failure = Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
        Assert.Contains("Not enough staging space", failure.Message);
        var restarted = new StagedSpaceBudget(Stage, options, () => 640 * GiB);
        Assert.Throws<StagedSpaceException>(() => restarted.Reserve(Guid.NewGuid(), Sid));
        Assert.Equal(capacity, restarted.Reserve(Guid.NewGuid(), "S-1-5-21-200"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Completed_legacy_hot_and_packed_history_remains_compatible_and_unchanged(bool packed)
    {
        var (journal, entry) = await Legacy(completed: true);
        if (packed) Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        var budget = Upgrade();
        budget.VerifyJournalInventory(Hot, new StagedTransferJournal(Hot));
        Assert.Equal(entry, await new StagedTransferJournal(Hot).ReadAsync(entry.Transfer.TransferId, default));
        Assert.Empty(Directory.GetFiles(Path.Combine(Stage, ".space-reservations"), "*.json"));
        Assert.True(budget.Reserve(Guid.NewGuid(), Sid) > 16 * MiB);
        Assert.False(File.Exists(entry.Transfer.StagePath + ".space"));
        Upgrade(); // An interrupted/repeated upgrade neither rewrites nor loses history.
        Assert.Equal(entry, await new StagedTransferJournal(Hot).ReadAsync(entry.Transfer.TransferId, default));
    }

    [Fact]
    public async Task Pending_legacy_stage_is_charged_under_its_original_guard_and_refunded_only_after_exact_cleanup()
    {
        var (_, entry) = await Legacy(completed: false);
        var budget = Upgrade();
        Assert.True(budget.ContentReservationPending(entry.Transfer.TransferId));
        budget.Bind(entry);
        Assert.False(File.Exists(entry.Transfer.StagePath + ".space"));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
        Assert.True(budget.Reserve(Guid.NewGuid(), "S-1-5-21-200") >= 16 * MiB);
        budget = Upgrade();
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
        budget.RetireFailedAllocation(entry.Transfer.TransferId);
        Assert.True(File.Exists(entry.Transfer.StagePath));
        Assert.True(budget.ContentReservationPending(entry.Transfer.TransferId));
        Assert.Throws<IOException>(() => budget.RequireFailedAllocationAbsent(entry.Transfer.TransferId, entry.Transfer.StagePath));
        File.Delete(entry.Transfer.StagePath);
        await Write(entry with { State = TransferJournalState.Released, StageDeleted = true,
            Sha256Hex = new string('A', 64), SealedOnce = true, SealedLength = 7,
            StateHistory = History(TransferJournalState.Released) });
        await budget.ReconcileAsync(new StagedTransferJournal(Hot), default);
        Assert.False(budget.ContentReservationPending(entry.Transfer.TransferId));
        Assert.True(budget.Reserve(Guid.NewGuid(), Sid) >= 16 * MiB);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Over_budget_legacy_recovery_does_not_refuse_startup_or_admit_new_bytes(bool completed)
    {
        var (_, entry) = await Legacy(completed);
        var budget = Upgrade(new(true, 0, 0, 0));
        Assert.Equal(!completed, budget.ContentReservationPending(entry.Transfer.TransferId));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
        Assert.Equal(entry, await new StagedTransferJournal(Hot).ReadAsync(entry.Transfer.TransferId, default));
    }

    [Fact]
    public async Task Partially_imported_legacy_guard_never_accepts_a_later_unaccounted_companion()
    {
        var (_, entry) = await Legacy(completed: false); Upgrade();
        string path = entry.Transfer.StagePath + ".space";
        await File.WriteAllBytesAsync(path, new byte[64]);
        Assert.Throws<IOException>(() => Upgrade());
        Assert.Equal(new byte[64], await File.ReadAllBytesAsync(path));
        Assert.Equal("private", await File.ReadAllTextAsync(entry.Transfer.StagePath));
    }

    [Fact]
    public async Task Missing_legacy_sid_or_identity_is_charged_globally_without_inventing_cleanup_authority()
    {
        var (_, entry) = await Legacy(completed: false);
        entry = entry with { Transfer = entry.Transfer with { RequestorSid = null }, StageIdentity = null };
        await Write(entry);
        var budget = Upgrade();
        Assert.True(budget.ContentReservationPending(entry.Transfer.TransferId));
        Assert.Throws<IOException>(() => budget.Bind(entry));
        budget.RetireFailedAllocation(entry.Transfer.TransferId);
        Assert.True(File.Exists(entry.Transfer.StagePath));
        Assert.True(budget.Reserve(Guid.NewGuid(), Sid) >= 16 * MiB);
        Upgrade();
        Assert.Equal("private", await File.ReadAllTextAsync(entry.Transfer.StagePath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Missing_ledger_cannot_reclassify_a_larger_grant_or_sealed_version_as_legacy(bool sealedEvidence)
    {
        var (_, entry) = await Legacy(completed: false);
        if (sealedEvidence)
            await Write(entry with { State = TransferJournalState.Retained, SealedOnce = true,
                SealedLength = 32 * MiB, Sha256Hex = new string('A', 64),
                StateHistory = History(TransferJournalState.Retained) });
        else
        {
            byte[] grant = new byte[64];
            BinaryPrimitives.WriteUInt64LittleEndian(grant, 0x3150535553464153UL);
            BinaryPrimitives.WriteInt64LittleEndian(grant.AsSpan(8), 64 * MiB);
            BinaryPrimitives.WriteUInt64LittleEndian(grant.AsSpan(16), entry.StageIdentity!.VolumeSerialNumber);
            BinaryPrimitives.WriteUInt64LittleEndian(grant.AsSpan(24), entry.StageIdentity.FileIdLow);
            BinaryPrimitives.WriteUInt64LittleEndian(grant.AsSpan(32), entry.StageIdentity.FileIdHigh);
            entry.Transfer.TransferId.TryWriteBytes(grant.AsSpan(40));
            await File.WriteAllBytesAsync(entry.Transfer.StagePath + ".space", grant);
        }
        Assert.Throws<IOException>(() => Upgrade());
        Assert.Equal("private", await File.ReadAllTextAsync(entry.Transfer.StagePath));
        Assert.Empty(Directory.GetFiles(Path.Combine(Stage, ".space-reservations"), "*.json"));
    }

    [Fact]
    public void Preexisting_negative_receipt_storage_is_accounted_without_an_upgrade_startup_refusal()
    {
        StagedPrivateStorage.CreateDirectory(Stage);
        for (int i = 0; i < 100; i++)
            NegativeReceipt();
        var budget = Upgrade();
        budget.RefreshNegativeReceiptStorage(Stage);
        Assert.True(budget.Reserve(Guid.NewGuid(), Sid) >= 16 * MiB);
        Assert.Equal(100, Directory.GetFiles(Stage).Length);
        Upgrade();
    }

    [Fact]
    public void Structurally_corrupt_legacy_negative_receipt_remains_held_unchanged()
    {
        StagedPrivateStorage.CreateDirectory(Stage);
        string path = Path.Combine(Stage, Guid.NewGuid().ToString("N") + ".allocation-refused");
        File.WriteAllBytes(path, new byte[Contract.RequestSize]);
        var budget = Upgrade();
        Assert.True(budget.Reserve(Guid.NewGuid(), Sid) >= 16 * MiB);
        Assert.Equal(new byte[Contract.RequestSize], File.ReadAllBytes(path));
    }

    [Fact]
    public void Validated_legacy_security_snapshot_is_metadata_compatibility_and_never_transfer_authority()
    {
        StagedPrivateStorage.CreateDirectory(Stage); _ = new StagedTransferJournal(Hot);
        Guid id = Guid.NewGuid(); var binding = SecuritySnapshotFixture.Binding();
        byte[] descriptor = SecuritySnapshotFixture.Descriptor();
        byte[] bytes = StagedAllocationSecuritySnapshot.Create(id, binding, 1, 0x7f, descriptor, descriptor).Encode();
        string path = Path.Combine(Hot, id.ToString("N") + ".security");
        File.WriteAllBytes(path, bytes);
        var budget = Upgrade(); budget.VerifyJournalInventory(Hot);
        Assert.False(budget.ContentReservationPending(id));
        Assert.Throws<StagedSpaceException>(() => budget.RequireMetadataAdmission(Path.Combine(Hot, id.ToString("N") + ".json.tmp")));
        budget.RequireMetadataAdmission(path + "." + Guid.NewGuid().ToString("N") + ".tmp");
        Assert.Equal(bytes, File.ReadAllBytes(path));
        Upgrade();
    }

    [Fact]
    public async Task New_inspection_defaults_cover_large_files_while_explicit_old_policy_values_are_preserved()
    {
        var defaults = LocalPolicyStore.CreateStagedDefault();
        Assert.Equal(4096, defaults.MaxFileSizeMb);
        Assert.Equal(900, defaults.InspectionTimeoutSeconds);
        await File.WriteAllTextAsync(_workspace.PolicyFile,
            """{"version":7,"activeCategories":["Cpf"],"maxFileSizeMb":20,"inspectionTimeoutSeconds":5}""");
        var explicitPolicy = await new LocalPolicyStore(_workspace.PolicyFile).LoadCurrentAsync(default);
        Assert.Equal(20, explicitPolicy.MaxFileSizeMb);
        Assert.Equal(5, explicitPolicy.InspectionTimeoutSeconds);
        await File.WriteAllTextAsync(_workspace.PolicyFile, """{"version":8,"activeCategories":["Cpf"]}""");
        var implicitPolicy = await new LocalPolicyStore(_workspace.PolicyFile).LoadCurrentAsync(default);
        Assert.Equal(4096, implicitPolicy.MaxFileSizeMb);
        Assert.Equal(900, implicitPolicy.InspectionTimeoutSeconds);
        string path = Path.Combine(_workspace.Root, "large.txt");
        await using (var output = File.Create(path))
        {
            byte[] buffer = Enumerable.Repeat((byte)'a', 64 * 1024).ToArray();
            for (int i = 0; i < 1024; i++) await output.WriteAsync(buffer);
        }
        var service = new InspectionService(new FixedPolicy(defaults), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        Assert.Equal(Verdict.Approved, (await service.InspectStagedAsync(TestWorkspace.Operation(path), default)).Verdict);
    }

    private sealed class FixedPolicy(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => Task.FromResult(policy);
    }

    private async Task<(StagedTransferJournal Journal, TransferJournalEntry Entry)> Legacy(bool completed)
    {
        StagedPrivateStorage.CreateDirectory(Stage);
        Guid id = Guid.NewGuid(); string stage = Path.Combine(Stage, id.ToString("N") + ".txt");
        await File.WriteAllTextAsync(stage, "private");
        var journal = new StagedTransferJournal(Hot);
        var transfer = new StagedTransfer(id, stage, Path.Combine(_workspace.Root, "public.txt"),
            DestinationKind.RemovableDrive, "fixture", 42, 1) { RequestorSid = Sid };
        var entry = await journal.CreateAsync(transfer, default);
        if (completed)
        {
            File.Delete(stage);
            entry = entry with { State = TransferJournalState.Released, StageDeleted = true, SealedOnce = true,
                SealedLength = 7, Sha256Hex = new string('A', 64), StateHistory = History(TransferJournalState.Released) };
            await Write(entry);
        }
        return (journal, entry);
    }

    private Task Write(TransferJournalEntry entry) => File.WriteAllTextAsync(
        Path.Combine(Hot, entry.Transfer.TransferId.ToString("N") + ".json"), JsonSerializer.Serialize(entry));

    private void NegativeReceipt()
    {
        Guid id = Guid.NewGuid(); byte[] bytes = new byte[Contract.RequestSize];
        void Put(string name, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(
            Marshal.OffsetOf<SafeUploadRequest>(name).ToInt32()), value);
        Put(nameof(SafeUploadRequest.Version), Contract.Version); Put(nameof(SafeUploadRequest.StructSize), Contract.RequestSize);
        Put(nameof(SafeUploadRequest.RequestId), 123); Put(nameof(SafeUploadRequest.RequestorProcessId), 17);
        Put(nameof(SafeUploadRequest.Operation), Operation.StageAllocate); Put(nameof(SafeUploadRequest.Flags), Contract.StageV20ReplyFlag);
        const string path = @"\Device\HarddiskVolume1\public.txt";
        byte[] encoded = System.Text.Encoding.Unicode.GetBytes(path);
        Put(nameof(SafeUploadRequest.PathLength), (uint)encoded.Length);
        encoded.CopyTo(bytes, Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path)).ToInt32());
        Put(nameof(SafeUploadRequest.Reserved), Contract.StageExtensionVersion);
        Put(nameof(SafeUploadRequest.ImageNameLength), Contract.StageAllocateV20Size);
        var source = new SafeUploadStageAllocateV20 { Intent = new() { Version = Contract.StageExtensionVersion,
            StructSize = Contract.StageAllocateV20Size, AllocationReservationId = id, DriverInstanceId = Guid.NewGuid(), Disposition = 3 },
            RequestorCreationTime = 123456 };
        MemoryMarshal.Write(bytes.AsSpan(Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName)).ToInt32()), in source);
        File.WriteAllBytes(Path.Combine(Stage, id.ToString("N") + ".allocation-refused"), bytes);
    }

    private static TransferJournalStateChange[] History(TransferJournalState terminal)
    {
        TransferJournalState[] states = terminal == TransferJournalState.Released
            ? [TransferJournalState.Allocated, TransferJournalState.Sealed, TransferJournalState.Inspecting,
                TransferJournalState.Approved, TransferJournalState.Publishing, TransferJournalState.Released]
            : [TransferJournalState.Allocated, TransferJournalState.Sealed, TransferJournalState.Retained];
        var start = DateTimeOffset.UtcNow.AddSeconds(-10);
        return states.Select((state, i) => new TransferJournalStateChange(state, start.AddMilliseconds(i))).ToArray();
    }
}
