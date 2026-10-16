using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedLargeIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private string Stage => Path.Combine(_workspace.Root, "stage");
    private string Hot => Path.Combine(_workspace.Root, "journal");
    private string Cold => Path.Combine(Hot, "completed");
    public void Dispose() => _workspace.Dispose();
    private StagedSpaceBudget Budget()
    {
        Directory.CreateDirectory(Stage);
        return new(Stage, new(true, 512L << 20, 128L << 20, 0), () => 2L << 30);
    }

    private TransferJournalEntry Completed()
    {
        Guid id = Guid.NewGuid();
        var transfer = new StagedTransfer(id, Path.Combine(Stage, id.ToString("N") + ".txt"),
            Path.Combine(_workspace.Root, "target.txt"), DestinationKind.RemovableDrive, "fixture", 42, 1);
        var entry = new TransferJournalEntry(transfer, TransferJournalState.Released, new string('A', 64), DateTimeOffset.UtcNow)
        {
            DestinationGeneration = 1, SealedOnce = true, StageIdentity = new(7, 0, 1),
            SealedLength = 1, StageDeleted = true, FileMetadata = new(100, 200, 300, 0x2023)
        };
        File.WriteAllText(Path.Combine(Hot, id.ToString("N") + ".json"), JsonSerializer.Serialize(entry));
        return entry;
    }

    [Fact]
    public async Task Packed_metadata_keeps_its_reservation_and_exact_seal_after_restart()
    {
        var budget = Budget(); var journal = new StagedTransferJournal(Hot);
        var entry = Completed();
        budget.Reserve(entry.Transfer.TransferId, "one", entry.Transfer.StagePath);
        journal.PrivateTemporaryAdmission = budget.RequireMetadataAdmission;
        journal.ArchiveGrowthAdmission = budget.RequireArchiveAdmission;
        journal.ArchiveStorageChanged = budget.RefreshArchiveStorage;
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Assert.Empty(Directory.GetFiles(Hot, "*.json"));
        var restarted = new StagedTransferJournal(Hot);
        budget.VerifyJournalInventory(Hot, restarted);
        Assert.Equal(entry, await restarted.ReadAsync(entry.Transfer.TransferId, default));
        Assert.Equal(entry.FileMetadata, (await restarted.ReadAsync(entry.Transfer.TransferId, default)).FileMetadata);
        Assert.Empty(await restarted.ReadPendingAsync(default));
    }

    [Fact]
    public async Task Enabling_large_mode_cannot_adopt_unreserved_packed_history()
    {
        var budget = Budget(); var journal = new StagedTransferJournal(Hot);
        var entry = Completed();
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Assert.Throws<IOException>(() => budget.VerifyJournalInventory(Hot, new StagedTransferJournal(Hot)));
        Assert.Equal(entry, await journal.ReadAsync(entry.Transfer.TransferId, default));
    }

    [Fact]
    public void Archive_growth_and_compaction_overlap_stay_inside_retained_metadata_debits()
    {
        var budget = Budget(); budget.Reserve(Guid.NewGuid(), "one");
        Directory.CreateDirectory(Cold);
        string segment = Path.Combine(Cold, "00000001.pack");
        long allowance = StagedSpaceBudget.MetadataBytes / 2 + StagedSpaceBudget.MetadataBytes / 4;
        budget.RequireArchiveAdmission(segment, allowance);
        Assert.Throws<StagedSpaceException>(() => budget.RequireArchiveAdmission(segment, allowance + 1));
        using (var file = File.Create(segment)) file.SetLength(allowance - 4096);
        budget.RefreshArchiveStorage(Cold);
        string temporary = segment + ".tmp";
        budget.RequireArchiveAdmission(temporary, 4096);
        Assert.Throws<StagedSpaceException>(() => budget.RequireArchiveAdmission(temporary, 4097));
        budget.Reserve(Guid.NewGuid(), "two");
        budget.RequireArchiveAdmission(temporary, StagedSpaceBudget.MetadataBytes / 2);
        Assert.Equal(allowance - 4096, new FileInfo(segment).Length);
    }

    [Fact]
    public async Task Archive_refusal_keeps_hot_receipt_for_a_later_metadata_only_retry()
    {
        var budget = Budget(); var journal = new StagedTransferJournal(Hot);
        var entry = Completed();
        budget.Reserve(entry.Transfer.TransferId, "one", entry.Transfer.StagePath);
        journal.ArchiveGrowthAdmission = (_, _) => throw new StagedSpaceException("injected metadata exhaustion");
        await Assert.ThrowsAsync<StagedSpaceException>(() => journal.ArchiveCompletedAsync(entry, default));
        Assert.True(File.Exists(Path.Combine(Hot, entry.Transfer.TransferId.ToString("N") + ".json")));
        journal.ArchiveGrowthAdmission = budget.RequireArchiveAdmission;
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Assert.Equal(entry, await new StagedTransferJournal(Hot).ReadAsync(entry.Transfer.TransferId, default));
    }

    [Fact]
    public async Task Exact_metadata_and_sticky_space_failure_both_survive_seal_replay()
    {
        Directory.CreateDirectory(Stage);
        string stage = Path.Combine(Stage, "version.txt"); File.WriteAllText(stage, "clean prefix");
        var journal = new StagedTransferJournal(Hot);
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, Path.Combine(_workspace.Root, "target.txt"),
            DestinationKind.RemovableDrive, "fixture", 42, 1);
        var allocated = await journal.CreateAsync(transfer, default);
        var version = StagedTransferJournal.VersionIdentity(allocated);
        var metadata = new StagedFileMetadata(100, 200, 300, 0x2023);
        var entry = await journal.SealAsync(transfer.TransferId, 42, stage, default, version, metadata, spaceFailed: true);
        Assert.True(entry.StageSpaceFailed); Assert.Equal(metadata, entry.FileMetadata);
        var restarted = new StagedTransferJournal(Hot);
        Assert.Equal(entry, await restarted.SealAsync(transfer.TransferId, 42, stage, default, version, metadata));
        await Assert.ThrowsAsync<InvalidOperationException>(() => restarted.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Approved, new string('A', 64), default));
        Assert.True((await restarted.ReadAsync(transfer.TransferId, default)).StageSpaceFailed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Lost_prepare_refunds_content_only_after_exact_cleanup_hot_or_packed(bool packed)
    {
        const string sid = "S-1-5-21-100";
        var budget = Budget(); var journal = new StagedTransferJournal(Hot);
        Guid id = Guid.NewGuid(), driver = Guid.NewGuid();
        string stage = Path.Combine(Stage, id.ToString("N") + ".txt");
        budget.Reserve(id, sid, stage);
        File.WriteAllText(stage, "private bytes");
        var transfer = new StagedTransfer(id, stage, Path.Combine(_workspace.Root, "target.txt"),
            DestinationKind.RemovableDrive, "fixture", 42, 1) { RequestorSid = sid };
        await journal.ReconcileDriverInstanceV20Async(driver, 0x1bf, default);
        var parent = StagedStageFile.ReadDirectoryIdentity(_workspace.Root);
        var allocated = await journal.CreateAsync(transfer, default, allocationDisposition: 2,
            allocationReferenceKind: 0, driverInstanceId: driver, parentDirectoryIdentity: parent);
        budget.RecordStage(id, stage, allocated.StageIdentity!); budget.Bind(allocated);
        var version = StagedTransferJournal.VersionIdentity(allocated);
        Assert.Equal(8u, await journal.ApplyAttachmentV20Async(new(14, 1, version, driver, parent,
            transfer.DestinationPath, 42), ownerIsLive: false, commitPolicyAllowed: false, default));
        await budget.ReconcileAsync(journal, default);
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), sid));
        var cleanup = Assert.Single(await journal.ReadDiscardPendingAsync(default));
        await journal.CompleteDiscardAsync(cleanup, default);
        var terminal = await journal.ReadAsync(id, default);
        Assert.False(terminal.StageDeleted); Assert.NotNull(terminal.DiscardAcknowledgedAtUtc);
        if (packed) Assert.True(await journal.ArchiveCompletedAsync(terminal, default));
        budget = Budget(); journal = new StagedTransferJournal(Hot);
        budget.VerifyJournalInventory(Hot, journal);
        await budget.ReconcileAsync(journal, default);
        Assert.False(budget.ContentReservationPending(id));
        Assert.True(budget.Reserve(Guid.NewGuid(), sid) >= 16L << 20);
        Assert.Equal(terminal, await journal.ReadAsync(id, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Compaction_pins_unconsumed_content_cleanup_receipts(bool packed)
    {
        var budget = Budget(); var journal = new StagedTransferJournal(Hot);
        var older = Completed() with { UpdatedAtUtc = DateTimeOffset.UtcNow.AddDays(-7) };
        File.WriteAllText(Path.Combine(Hot, older.Transfer.TransferId.ToString("N") + ".json"), JsonSerializer.Serialize(older));
        budget.Reserve(older.Transfer.TransferId, "one", older.Transfer.StagePath);
        journal.ContentReservationPending = budget.ContentReservationPending;
        // A later generation would otherwise make the older receipt obsolete.
        var newer = older with { Transfer = older.Transfer with { TransferId = Guid.NewGuid(), StagePath = Path.Combine(Stage, "absent-new") },
            DestinationGeneration = 2 };
        File.WriteAllText(Path.Combine(Hot, newer.Transfer.TransferId.ToString("N") + ".json"), JsonSerializer.Serialize(newer));
        if (packed) Assert.Equal(2, await journal.ArchiveCompletedBatchAsync([older, newer], default));
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow, default));
        Assert.Equal(older, await journal.ReadAsync(older.Transfer.TransferId, default));
    }

    [Fact]
    public async Task Refunded_history_does_not_participate_in_foreground_reconciliation()
    {
        var budget = Budget(); var journal = new StagedTransferJournal(Hot);
        Guid id = Guid.NewGuid(); string stage = Path.Combine(Stage, id.ToString("N") + ".txt");
        budget.Reserve(id, "one", stage);
        File.WriteAllText(Path.Combine(Hot, id.ToString("N") + ".json"), "invalid historical record");
        await Assert.ThrowsAsync<InvalidDataException>(() => budget.ReconcileAsync(journal, default));
        budget.RetireFailedAllocation(id);
        long reads = journal.ManifestReads;
        await budget.ReconcileAsync(journal, default);
        Assert.Equal(reads, journal.ManifestReads);
    }
}
