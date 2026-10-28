using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedCompletedMetadataTests : IDisposable
{
    private const long MiB = 1024 * 1024;
    private const string Sid = "S-1-5-21-100";
    private readonly TestWorkspace _workspace = new();
    private string Stage => Path.Combine(_workspace.Root, "stage");
    private string Hot => Path.Combine(_workspace.Root, "journal");
    private string Records => Path.Combine(Stage, ".space-reservations");
    private StagedTransferJournal Journal() => new(Hot, requireProtectedParent: false);
    private StagedSpaceBudget Budget(StagedTransferJournal journal) => new(Stage,
        new(true, 512 * MiB, 65 * MiB, 0), () => 2048 * MiB, journal);
    public void Dispose() => _workspace.Dispose();

    private static T Field<T>(StagedSpaceBudget budget, string name) =>
        (T)typeof(StagedSpaceBudget).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(budget)!;
    private static long ReservationBytes(StagedSpaceBudget budget) => Field<long>(budget, "_reservationChargeBytes");
    private static long UserBytes(StagedSpaceBudget budget) =>
        Field<Dictionary<string, long>>(budget, "_reservationChargesBySid").GetValueOrDefault(Sid);
    private static long SharedBytes(StagedSpaceBudget budget) => Field<long>(budget, "_legacyJournalAllowance");

    private async Task<TransferJournalEntry> Allocate(StagedSpaceBudget budget, StagedTransferJournal journal)
    {
        Guid id = Guid.NewGuid(); string path = Path.Combine(Stage, id.ToString("N") + ".txt");
        Assert.Equal(16 * MiB, budget.Reserve(id, Sid, path));
        using (var output = StagedPrivateStorage.CreateFile(path)) { output.WriteByte(42); output.Flush(true); }
        var transfer = new StagedTransfer(id, path, Path.Combine(_workspace.Root, "public.txt"),
            DestinationKind.Cloud, "fixture", 42, 1) { RequestorSid = Sid };
        var entry = await journal.CreateAsync(transfer, default);
        budget.RecordStage(id, path, entry.StageIdentity!); budget.Bind(entry);
        Assert.Equal(65 * MiB, ReservationBytes(budget)); Assert.Equal(65 * MiB, UserBytes(budget));
        return entry;
    }

    // Journal fixtures model the existing durable terminal receipts, independently
    // of inspection/publisher I/O. Content disposal still uses the exact object.
    private async Task<TransferJournalEntry> Complete(TransferJournalEntry allocated, string kind)
    {
        var journal = Journal(); Guid id = allocated.Transfer.TransferId;
        if (kind == "private-discard")
        {
            var request = new StagedDiscardRequest(id, StagedTransferJournal.VersionIdentity(allocated), StagedDiscardKind.PrivateVersion);
            Assert.Equal(StagedDiscardStatus.Pending, await journal.BeginOrConfirmDiscardAsync(request, default));
            Assert.Equal(StagedDiscardStatus.Acknowledged, await journal.CompleteDiscardAsync(request, default));
            return await journal.ReadAsync(id, default);
        }
        var entry = allocated with { State = kind == "discarded" ? TransferJournalState.Discarded :
            kind == "blocked" ? TransferJournalState.Blocked : TransferJournalState.Released,
            SealedOnce = kind != "discarded", SealedLength = kind == "discarded" ? null : 1,
            Sha256Hex = kind == "discarded" ? null : new string('A', 64), StageDeleted = kind != "discarded" };
        if (kind is "blocked" or "released-handback")
            entry = entry with { BlockedPolicyVersion = 1, StageSpaceFailed = true,
                JustificationWindowClosed = true, HandbackState = StagedHandbackState.Verified,
                HandbackPath = Path.Combine(_workspace.Root, "returned.txt"), HandbackLength = 1,
                BlockedDeletionReceipt = new(StagedTransferJournal.VersionIdentity(entry), 0, 1, entry.Sha256Hex!) };
        TransferJournalState[] states = kind == "discarded"
            ? [TransferJournalState.Allocated, TransferJournalState.Unsealed, TransferJournalState.Discarded]
            : kind == "blocked"
                ? [TransferJournalState.Allocated, TransferJournalState.Sealed, TransferJournalState.Inspecting, TransferJournalState.Blocked]
                : [TransferJournalState.Allocated, TransferJournalState.Sealed, TransferJournalState.Inspecting,
                    TransferJournalState.Approved, TransferJournalState.Publishing, TransferJournalState.Released];
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        entry = entry with { StateHistory = states.Select((state, i) => new TransferJournalStateChange(state, start.AddMilliseconds(i))).ToArray() };
        Assert.True(StagedStageFile.TryDeleteExactAndConfirmAbsent(entry.Transfer.StagePath, entry.StageIdentity!, out _));
        await Write(entry);
        return await journal.ReadAsync(id, default);
    }

    private Task Write(TransferJournalEntry entry) => File.WriteAllTextAsync(
        Path.Combine(Hot, entry.Transfer.TransferId.ToString("N") + ".json"), JsonSerializer.Serialize(entry));

    [Theory]
    [InlineData("published", false)]
    [InlineData("blocked", false)]
    [InlineData("released-handback", false)]
    [InlineData("private-discard", false)]
    [InlineData("published", true)]
    [InlineData("blocked", true)]
    [InlineData("released-handback", true)]
    [InlineData("private-discard", true)]
    public async Task Exact_completion_retires_sid_and_global_envelope_live_and_after_restart(string kind, bool restartFirst)
    {
        var journal = Journal(); var budget = Budget(journal);
        var entry = await Complete(await Allocate(budget, journal), kind);
        if (restartFirst) { journal = Journal(); budget = Budget(journal); }
        await budget.ReconcileAsync(journal, default);
        Assert.False(budget.ContentReservationPending(entry.Transfer.TransferId));
        Assert.False(File.Exists(entry.Transfer.StagePath + ".space"));
        Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        Assert.Empty(Directory.GetFiles(Records));
        Assert.True(SharedBytes(budget) >= 16 * MiB);
        long shared = SharedBytes(budget);
        await budget.ReconcileAsync(journal, default); // Duplicate completion cannot refund twice.
        Assert.Equal(shared, SharedBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        Assert.Equal(entry, await journal.ReadAsync(entry.Transfer.TransferId, default));
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        journal = Journal(); budget = Budget(journal);
        Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        Assert.True(SharedBytes(budget) >= 16 * MiB);
        Assert.Equal(entry, await journal.ReadAsync(entry.Transfer.TransferId, default));
        int passes = 0;
        Assert.Equal(16 * MiB, await budget.ReserveAfterPendingRefundsAsync(Guid.NewGuid(), Sid, null, null,
            _ => { ++passes; throw new InvalidOperationException("Completed save must need no grace/refund pass."); },
            StagedSpaceBudget.RefundGrace, default));
        Assert.Equal(0, passes);
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
    }

    [Fact]
    public async Task A_published_save_allows_the_next_same_sid_reservation_without_grace()
    {
        var journal = Journal(); var budget = Budget(journal);
        await Complete(await Allocate(budget, journal), "published");
        await budget.ReconcileAsync(journal, default);
        Assert.Equal(16 * MiB, await budget.ReserveAfterPendingRefundsAsync(Guid.NewGuid(), Sid, null, null,
            _ => throw new InvalidOperationException("No refund pass is needed."), StagedSpaceBudget.RefundGrace, default));
        await budget.ReconcileAsync(journal, default);
        Assert.Equal(65 * MiB, UserBytes(budget)); Assert.Equal(65 * MiB, ReservationBytes(budget));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
    }

    [Fact]
    public async Task Durable_content_only_release_is_retired_after_restart_without_a_second_content_refund()
    {
        var journal = Journal(); var budget = Budget(journal);
        var entry = await Complete(await Allocate(budget, journal), "published");
        File.Delete(entry.Transfer.StagePath + ".space");
        string path = Path.Combine(Records, entry.Transfer.TransferId.ToString("N") + ".json");
        var record = JsonNode.Parse(await File.ReadAllTextAsync(path))!;
        record["ContentReleased"] = true; await File.WriteAllTextAsync(path, record.ToJsonString());
        journal = Journal(); budget = Budget(journal);
        Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        Assert.False(File.Exists(path));
        await budget.ReconcileAsync(journal, default);
        Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        await budget.ReconcileAsync(journal, default);
        Assert.Equal(16 * MiB, budget.Reserve(Guid.NewGuid(), Sid));
    }
    [Fact]
    public async Task A_thousand_completed_saves_keep_sid_debt_zero_and_history_conservatively_charged()
    {
        var journal = Journal(); var budget = Budget(journal);
        var batch = new List<TransferJournalEntry>();
        string[] kinds = ["published", "blocked", "private-discard"];
        for (int i = 0; i < 1024; ++i)
        {
            var entry = await Complete(await Allocate(budget, journal), kinds[i % kinds.Length]);
            Assert.Equal(i + 1, entry.DestinationGeneration);
            await budget.ReconcileAsync(journal, default);
            Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
            batch.Add(entry);
            if (batch.Count == 64)
            {
                Assert.Equal(batch.Count, await journal.ArchiveCompletedBatchAsync(batch, default));
                batch.Clear();
            }
        }
        Assert.Empty(Directory.GetFiles(Records));
        long allocation = Directory.EnumerateFiles(Hot).Concat(Directory.EnumerateFiles(Path.Combine(Hot, "completed")))
            .Sum(path => (new FileInfo(path).Length + 4095) / 4096 * 4096);
        Assert.True(SharedBytes(budget) >= allocation * 2 + 16 * MiB);
        journal = Journal(); budget = Budget(journal);
        Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        Assert.Equal(allocation * 2 + 16 * MiB, SharedBytes(budget));
        Assert.Equal(16 * MiB, budget.Reserve(Guid.NewGuid(), Sid));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
    }

    [Theory]
    [InlineData("no-disposal")]
    [InlineData("no-blocked-receipt")]
    [InlineData("handback-failed")]
    [InlineData("snapshot")]
    [InlineData("replacement-stage")]
    [InlineData("changed-grant")]
    [InlineData("changed-identity")]
    public async Task Unresolved_or_ambiguous_completion_keeps_its_debit(string obstacle)
    {
        var journal = Journal(); var budget = Budget(journal);
        var allocated = await Allocate(budget, journal);
        string? snapshotPath = null; FileStream? lease = null;
        if (obstacle == "snapshot")
        {
            snapshotPath = Path.Combine(Stage, "held.snapshot");
            StagedStageIdentity identity;
            using (var snapshot = StagedPrivateStorage.CreateFile(snapshotPath)) { snapshot.WriteByte(42); snapshot.Flush(true); }
            using (var snapshot = StagedStageFile.Open(snapshotPath)) identity = snapshot.Identity;
            // Durable snapshot fixture; the exclusive reader keeps exact
            // deletion unresolved until its real handle closes.
            string path = Path.Combine(Records, allocated.Transfer.TransferId.ToString("N") + ".json");
            var record = JsonNode.Parse(await File.ReadAllTextAsync(path))!;
            record["Snapshot"] = JsonSerializer.SerializeToNode(new { Path = snapshotPath, Identity = identity });
            await File.WriteAllTextAsync(path, record.ToJsonString());
            budget = Budget(journal);
            lease = new FileStream(snapshotPath, FileMode.Open, FileAccess.Read, FileShare.None);
        }
        var entry = await Complete(allocated, obstacle is "no-blocked-receipt" or "handback-failed" ? "blocked" : "published");
        switch (obstacle)
        {
            case "no-disposal": entry = entry with { StageDeleted = false }; break;
            case "no-blocked-receipt": entry = entry with { BlockedDeletionReceipt = null }; break;
            case "handback-failed": entry = entry with { BlockedDeletionReceipt = null, HandbackState = StagedHandbackState.Failed,
                HandbackPath = null, HandbackLength = null, HandbackFailureReason = "unresolved", StageDeleted = false }; break;
            case "replacement-stage": await File.WriteAllTextAsync(entry.Transfer.StagePath, "replacement"); break;
            case "changed-grant": await File.WriteAllBytesAsync(entry.Transfer.StagePath + ".space", new byte[64]); break;
            case "changed-identity": entry = entry with { StageIdentity = new(9, 0, 99) }; break;
        }
        await Write(entry);
        try
        {
            if (obstacle == "changed-grant") await Assert.ThrowsAsync<IOException>(() => budget.ReconcileAsync(journal, default));
            else await budget.ReconcileAsync(journal, default);
            Assert.True(UserBytes(budget) >= MiB); Assert.Equal(UserBytes(budget), ReservationBytes(budget));
            Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
            Assert.Single(Directory.GetFiles(Records));
            if (obstacle == "snapshot")
            {
                Assert.True(budget.ContentReservationPending(entry.Transfer.TransferId));
                lease!.Dispose(); lease = null;
                await budget.ReconcileAsync(journal, default);
                Assert.False(File.Exists(snapshotPath));
                Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
            }
        }
        finally { lease?.Dispose(); }
    }

    [Fact]
    public async Task Ordinary_discarded_without_an_exact_disposal_receipt_keeps_content_and_metadata_charged()
    {
        var journal = Journal(); var budget = Budget(journal);
        var entry = await Complete(await Allocate(budget, journal), "discarded");
        Assert.False(File.Exists(entry.Transfer.StagePath)); Assert.False(entry.StageDeleted);
        for (int restart = 0; restart < 2; ++restart)
        {
            await budget.ReconcileAsync(journal, default);
            Assert.True(budget.ContentReservationPending(entry.Transfer.TransferId));
            Assert.Equal(65 * MiB, UserBytes(budget)); Assert.Equal(65 * MiB, ReservationBytes(budget));
            Assert.True(File.Exists(entry.Transfer.StagePath + ".space"));
            journal = Journal(); budget = Budget(journal);
        }
    }

    [Fact]
    public async Task Crash_after_durable_ledger_retirement_faults_admission_and_restart_adopts_the_refund_once()
    {
        var journal = Journal(); var budget = Budget(journal);
        var entry = await Complete(await Allocate(budget, journal), "published");
        budget.MetadataRetirementPersistedObserver = id =>
        {
            Assert.Equal(entry.Transfer.TransferId, id);
            Assert.Empty(Directory.GetFiles(Records));
            throw new IOException("Injected interruption after ledger deletion, before totals adoption.");
        };
        await Assert.ThrowsAsync<IOException>(() => budget.ReconcileAsync(journal, default));
        Assert.Equal(65 * MiB, ReservationBytes(budget)); // Old memory cannot admit competing saves.
        Assert.Throws<IOException>(() => budget.Reserve(Guid.NewGuid(), Sid));
        journal = Journal(); budget = Budget(journal);
        Assert.Equal(0, UserBytes(budget)); Assert.Equal(0, ReservationBytes(budget));
        Assert.Equal(entry, await journal.ReadAsync(entry.Transfer.TransferId, default));
        await budget.ReconcileAsync(journal, default);
        Assert.Equal(16 * MiB, budget.Reserve(Guid.NewGuid(), Sid));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
    }

    [Theory]
    [InlineData("grant")]
    [InlineData("identity")]
    [InlineData("missing-journal")]
    [InlineData("unfinished-disposal")]
    public async Task Startup_metadata_only_retirement_still_requires_matching_complete_journal_and_absent_grant(string obstacle)
    {
        var journal = Journal(); var budget = Budget(journal);
        var entry = await Complete(await Allocate(budget, journal), "published");
        if (obstacle != "grant") File.Delete(entry.Transfer.StagePath + ".space");
        string path = Path.Combine(Records, entry.Transfer.TransferId.ToString("N") + ".json");
        var record = JsonNode.Parse(await File.ReadAllTextAsync(path))!;
        record["ContentReleased"] = true;
        await File.WriteAllTextAsync(path, record.ToJsonString());
        if (obstacle == "identity") await Write(entry with { StageIdentity = new(9, 0, 99) });
        if (obstacle == "unfinished-disposal") await Write(entry with { StageDeleted = false });
        if (obstacle == "missing-journal") File.Delete(Path.Combine(Hot, entry.Transfer.TransferId.ToString("N") + ".json"));
        journal = Journal(); budget = Budget(journal);
        Assert.Equal(MiB, UserBytes(budget)); Assert.Equal(MiB, ReservationBytes(budget));
        Assert.True(File.Exists(path));
        Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
    }

}
