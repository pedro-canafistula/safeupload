using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

[CollectionDefinition("Journal scaling", DisableParallelization = true)]
public sealed class JournalScalingCollection;

[Collection("Journal scaling")]
public sealed class StagedTerminalArchiveTests(ITestOutputHelper output) : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private string Hot => Path.Combine(_workspace.Root, "journal");
    private string Cold => Path.Combine(Hot, "completed");
    private StagedTransferJournal Journal() => new(Hot);
    public void Dispose() => _workspace.Dispose();

    // Already-completed disk images, as on service restart. Construction is
    // outside all latency/allocation measurements; real production reads,
    // archive flushes, generation selection and measured seals are exercised.
    private TransferJournalEntry Completed(int number = 1, string? destination = null, long generation = 1)
    {
        Guid id = Guid.NewGuid();
        var transfer = new StagedTransfer(id, Path.Combine(_workspace.Root, "absent-" + id.ToString("N")),
            destination ?? Path.Combine(_workspace.Root, "destination-" + number + ".txt"),
            DestinationKind.RemovableDrive, "fixture", 1234, 1);
        return new(transfer, TransferJournalState.Released, new string('A', 64), DateTimeOffset.UtcNow.AddDays(-7))
        {
            DestinationGeneration = generation, SealedOnce = true,
            StageIdentity = new(7, 0, (ulong)number), SealedLength = 1, StageDeleted = true
        };
    }
    private void Put(TransferJournalEntry entry) => File.WriteAllText(
        Path.Combine(Hot, entry.Transfer.TransferId.ToString("N") + ".json"), JsonSerializer.Serialize(entry));
    private StagedTransfer NewTransfer(string destination)
    {
        Guid id = Guid.NewGuid(); string stage = Path.Combine(_workspace.Root, id.ToString("N") + ".txt");
        File.WriteAllText(stage, "clean");
        return new(id, stage, destination, DestinationKind.RemovableDrive, "fixture", 1234, 1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Ten_thousand_terminal_records_leave_constant_hot_work_and_bounded_allocate_seal_cost(bool sameDestination)
    {
        const int count = 10_000;
        var journal = Journal();
        var timer = Stopwatch.StartNew();
        string destination = Path.Combine(_workspace.Root, "repeated.txt");
        var completed = new List<TransferJournalEntry>(count);
        for (int i = 1; i <= count; i++)
        {
            var entry = Completed(i, sameDestination ? destination : null, sameDestination ? i : 1);
            Put(entry);
            completed.Add(entry);
        }
        Assert.Equal(count, await journal.ArchiveCompletedBatchAsync(completed, default));
        output.WriteLine($"10k migration ms={timer.Elapsed.TotalMilliseconds:F3}; archive bytes={Directory.GetFiles(Cold, "*.pack").Sum(p => new FileInfo(p).Length)}");
        Assert.Empty(Directory.GetFiles(Hot, "*.json"));
        Assert.Equal(count, journal.ArchivedTransfers);
        Assert.InRange(Directory.GetFiles(Cold, "*.pack").Length, 1, 32);
        Assert.All(Directory.GetFiles(Cold, "*.pack"), p => Assert.InRange(new FileInfo(p).Length, 1, StagedTransferJournal.MaximumArchiveSegmentBytes));

        timer.Restart(); var restarted = Journal();
        output.WriteLine($"10k archive startup ms={timer.Elapsed.TotalMilliseconds:F3}");
        // Warm serializer/JIT before measuring; no history is removed.
        await restarted.ReadPendingAsync(default);
        long reads = restarted.ManifestReads;
        long allocated = GC.GetTotalAllocatedBytes(true); timer.Restart();
        for (int i = 0; i < 5; i++)
        {
            Assert.Empty(await restarted.ReadPendingAsync(default));
            Assert.Empty(await restarted.ReadDiscardPendingAsync(default));
        }
        double pendingMs = timer.Elapsed.TotalMilliseconds;
        long pendingBytes = GC.GetTotalAllocatedBytes(true) - allocated;
        Assert.Equal(reads, restarted.ManifestReads);
        Assert.InRange(pendingBytes, 0, 512 * 1024);
        Assert.InRange(pendingMs, 0, 1000);

        var transfer = NewTransfer(sameDestination ? destination : Completed(1).Transfer.DestinationPath);
        allocated = GC.GetTotalAllocatedBytes(true); timer.Restart();
        var created = await restarted.CreateAsync(transfer, default);
        double allocateMs = timer.Elapsed.TotalMilliseconds;
        long allocateBytes = GC.GetTotalAllocatedBytes(true) - allocated;
        Assert.Equal(sameDestination ? count + 1 : 2, created.DestinationGeneration);
        allocated = GC.GetTotalAllocatedBytes(true); timer.Restart();
        var sealedEntry = await restarted.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, default);
        double sealMs = timer.Elapsed.TotalMilliseconds;
        long sealBytes = GC.GetTotalAllocatedBytes(true) - allocated;
        output.WriteLine($"10k sameDestination={sameDestination}: pending(5)={pendingMs:F3}ms/{pendingBytes}B allocate={allocateMs:F3}ms/{allocateBytes}B seal={sealMs:F3}ms/{sealBytes}B");
        // The old warm paths allocated ~10 MB per directory scan. Both bounds
        // fail that implementation even on a fast SSD with warm metadata.
        Assert.InRange(allocateBytes, 0, 1024 * 1024);
        Assert.InRange(sealBytes, 0, 1024 * 1024);
        Assert.InRange(allocateMs, 0, 1000);
        Assert.InRange(sealMs, 0, 1000);
        Assert.Equal(TransferJournalState.Sealed, sealedEntry.State);
        Assert.Single(Directory.GetFiles(Hot, "*.json"));
        Assert.Single(await restarted.ReadPendingAsync(default));
    }

    [Fact]
    public async Task Duplicate_batch_ids_are_refused_before_writing_any_archive_frame()
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        await Assert.ThrowsAsync<ArgumentException>(() => journal.ArchiveCompletedBatchAsync([entry, entry], default));
        Assert.False(Directory.Exists(Cold));
        Assert.Equal(entry, await Journal().ReadAsync(entry.Transfer.TransferId, default));
    }

    private sealed class LastCloseGate : IStagedPublicationGate
    {
        internal bool Held = true;
        internal int Disposals;
        public IDisposable Authorize(StagedTransfer transfer, string temporary, string digest) =>
            throw new Xunit.Sdk.XunitException("Disposal must never authorize another public mutation.");
        public bool DisposeStage(Guid id, uint outcome, uint renames) { Disposals++; return Held; }
    }

    [Fact]
    public async Task Late_driver_last_close_eventually_archives_the_exact_release_without_republishing()
    {
        var journal = Journal();
        string staging = Path.Combine(_workspace.Root, "staging"); Directory.CreateDirectory(staging);
        string stage = Path.Combine(staging, "released.txt"); File.WriteAllText(stage, "clean");
        var entry = Completed();
        using (var original = StagedStageFile.Open(stage))
            entry = entry with { Transfer = entry.Transfer with { StagePath = stage }, StageIdentity = original.Identity,
                StageDeleted = false, SealedLength = 5, Sha256Hex = Convert.ToHexString(SHA256.HashData("clean"u8)) };
        Put(entry);
        var inspection = new SafeUpload.Agent.Core.Application.InspectionService(
            new SafeUpload.Agent.Core.Infrastructure.LocalPolicyStore(_workspace.PolicyFile),
            new SafeUpload.Agent.Core.Infrastructure.LocalQueueAuditSink(_workspace.QueueFile),
            SafeUpload.Agent.Core.Infrastructure.Extraction.ExtractorRegistry.CreateDefault(),
            new SafeUpload.Agent.Core.Application.VerdictCache());
        var gate = new LastCloseGate();
        var publisher = new StagedTransferPublisher(inspection, NotificationTestHub.Create(), journal, staging, gate);
        await publisher.DisposeReleasedStagesAsync(default);
        Assert.Single(Directory.GetFiles(Hot, "*.json")); Assert.True(File.Exists(stage));
        gate.Held = false;
        await publisher.DisposeReleasedStagesAsync(default);
        Assert.Empty(Directory.GetFiles(Hot, "*.json")); Assert.False(File.Exists(stage));
        Assert.True((await Journal().ReadAsync(entry.Transfer.TransferId, default)).StageDeleted);
        int disposals = gate.Disposals;
        await publisher.DisposeReleasedStagesAsync(default);
        Assert.Equal(disposals, gate.Disposals);
    }

    [Fact]
    public async Task Archive_preserves_exact_receipt_and_rejects_changed_completion_and_reused_id()
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.False(await journal.ArchiveCompletedAsync(entry with { DestinationGeneration = 2 }, default));
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Assert.Equal(entry, await Journal().ReadAsync(entry.Transfer.TransferId, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(entry.Transfer, default));
        Assert.Empty(Directory.GetFiles(Hot, "*.json"));
    }

    [Theory]
    [InlineData("stage-present")]
    [InlineData("disposal-pending")]
    [InlineData("rename-pending")]
    [InlineData("handback-failed")]
    [InlineData("window-open")]
    public async Task Unfinished_cleanup_rename_or_handback_stays_hot(string condition)
    {
        var journal = Journal(); var entry = Completed();
        entry = condition switch
        {
            "disposal-pending" => entry with { StageDeleted = false },
            "rename-pending" => entry with { StageDeleted = false, PendingRename = new(51, Path.Combine(_workspace.Root, "rename.txt"), true) },
            "handback-failed" => entry with { State = TransferJournalState.Blocked, StageDeleted = false, BlockedPolicyVersion = 1, JustificationWindowClosed = true, HandbackState = StagedHandbackState.Failed, HandbackFailureReason = "copy_failed" },
            "window-open" => entry with { State = TransferJournalState.Blocked, StageDeleted = false, BlockedPolicyVersion = 1, JustificationExpiresAtUtc = DateTimeOffset.UtcNow.AddDays(1) },
            _ => entry
        };
        if (condition == "stage-present") File.WriteAllText(entry.Transfer.StagePath, "replacement");
        Put(entry);
        Assert.False(await journal.ArchiveCompletedAsync(entry, default));
        Assert.Single(Directory.GetFiles(Hot, "*.json"));
        Assert.Equal(entry, await Journal().ReadAsync(entry.Transfer.TransferId, default));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Terminal_recovery_is_read_free_and_maintenance_still_archives_exact_receipts(
        bool justifiedRelease, bool cleanupOnly)
    {
        var journal = Journal(); var entry = Completed();
        entry = entry with
        {
            State = justifiedRelease ? TransferJournalState.Released : TransferJournalState.Blocked,
            BlockedPolicyVersion = 1, HandbackState = StagedHandbackState.Verified,
            HandbackPath = Path.Combine(_workspace.Root, "returned.txt"), HandbackLength = 1,
            JustificationWindowClosed = true,
            BlockedDeletionReceipt = new(new(entry.Transfer.TransferId, entry.DestinationGeneration, entry.StageIdentity!),
                0, 1, entry.Sha256Hex!)
        };
        Put(entry);
        var terminal = await journal.ReadAsync(entry.Transfer.TransferId, default);
        Assert.True(StagedTransferJournal.BlockedCleanupComplete(terminal));
        var inspection = new SafeUpload.Agent.Core.Application.InspectionService(
            new SafeUpload.Agent.Core.Infrastructure.LocalPolicyStore(_workspace.PolicyFile),
            new SafeUpload.Agent.Core.Infrastructure.LocalQueueAuditSink(_workspace.QueueFile),
            SafeUpload.Agent.Core.Infrastructure.Extraction.ExtractorRegistry.CreateDefault(),
            new SafeUpload.Agent.Core.Application.VerdictCache());
        var gate = new LastCloseGate();
        var publisher = new StagedTransferPublisher(inspection, NotificationTestHub.Create(), journal, _workspace.Root, gate);
        int archiveWrites = 0;
        journal.ArchiveObserver = _ => archiveWrites++;
        long terminalReads = journal.ManifestReads;
        for (int pass = 0; pass < 8; pass++)
        {
            if (cleanupOnly) await publisher.RecoverPendingTransferAsync(terminal, default, cleanupOnly: true);
            else await publisher.RecoverPendingTransferAsync(terminal, default);
        }
        Assert.Equal(terminalReads, journal.ManifestReads);
        Assert.Equal(0, archiveWrites);
        Assert.Equal(0, gate.Disposals);
        Assert.Single(Directory.GetFiles(Hot, "*.json"));

        // Recovery's no-op projection does not remove the maintenance obligation.
        // Maintenance still rereads the exact manifest before durable archival.
        await publisher.ArchiveCompletedTransfersAsync(default);
        Assert.True(journal.ManifestReads > terminalReads);
        Assert.True(archiveWrites > 0);
        Assert.Empty(Directory.GetFiles(Hot, "*.json"));
        var restarted = Journal();
        Assert.Equal(terminal, await restarted.ReadAsync(entry.Transfer.TransferId, default));
        Assert.Equal(entry.DestinationGeneration + 1,
            (await restarted.CreateAsync(NewTransfer(entry.Transfer.DestinationPath), default)).DestinationGeneration);
    }

    [Fact]
    public async Task Blocked_archive_requires_and_preserves_exact_delete_receipt_and_handback()
    {
        var journal = Journal(); var entry = Completed();
        entry = entry with { State = TransferJournalState.Blocked, BlockedPolicyVersion = 1,
            HandbackState = StagedHandbackState.Verified, HandbackPath = Path.Combine(_workspace.Root, "returned.txt"),
            HandbackLength = 1, JustificationWindowClosed = true,
            BlockedDeletionReceipt = new(new(entry.Transfer.TransferId, entry.DestinationGeneration, entry.StageIdentity!), 0, 1, entry.Sha256Hex!) };
        Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Assert.Equal(entry, await Journal().ReadAsync(entry.Transfer.TransferId, default));
        Assert.Empty(await Journal().ReadPendingAsync(default));
    }

    [Fact]
    public async Task Rename_tombstone_barriers_and_maximum_ties_survive_archive_restart_and_compaction()
    {
        var journal = Journal(); string oldName = Path.Combine(_workspace.Root, "old.txt");
        var first = Completed() with { NamespaceTombstones = new(oldName, 19, null) };
        var tie = Completed(2) with { NamespaceTombstones = new(oldName.ToUpperInvariant(), 19, null) };
        Put(first); Put(tie);
        Assert.True(await journal.ArchiveCompletedAsync(first, default));
        Assert.True(await journal.ArchiveCompletedAsync(tie, default));
        Assert.Equal(0, await Journal().CompactAsync(DateTimeOffset.UtcNow, default));
        var created = await Journal().CreateAsync(NewTransfer(oldName), default);
        Assert.Equal(20, created.DestinationGeneration);
        Assert.Equal(first, await Journal().ReadAsync(first.Transfer.TransferId, default));
        Assert.Equal(tie, await Journal().ReadAsync(tie.Transfer.TransferId, default));
    }

    [Theory]
    [InlineData("before-append")]
    [InlineData("before-frontier")]
    [InlineData("before-flush")]
    [InlineData("after-flush")]
    public async Task Interrupted_archive_keeps_a_restartable_exact_receipt(string point)
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        journal.ArchiveObserver = at => { if (at == point) throw new IOException("injected archive interruption"); };
        await Assert.ThrowsAsync<IOException>(() => journal.ArchiveCompletedAsync(entry, default));
        Assert.Single(Directory.GetFiles(Hot, "*.json"));
        var restarted = Journal();
        Assert.Equal(entry, await restarted.ReadAsync(entry.Transfer.TransferId, default));
        Assert.True(await restarted.ArchiveCompletedAsync(entry, default));
        Assert.Empty(Directory.GetFiles(Hot, "*.json"));
        Assert.Equal(entry, await Journal().ReadAsync(entry.Transfer.TransferId, default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Truncated_committed_archive_never_drops_a_barrier_even_with_a_hot_duplicate(bool keepHot)
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        string segment = Assert.Single(Directory.GetFiles(Cold, "*.pack"));
        using (var file = new FileStream(segment, FileMode.Open, FileAccess.Write)) file.SetLength(file.Length - 7);
        if (keepHot) Put(entry);
        Assert.Throws<InvalidDataException>(() => Journal());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4096)]
    public async Task Whole_committed_frame_or_control_loss_is_not_an_empty_archive(int length)
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        string segment = Assert.Single(Directory.GetFiles(Cold, "*.pack"));
        using (var stream = new FileStream(segment, FileMode.Open, FileAccess.Write)) stream.SetLength(length);
        if (length == 0)
        {
            Assert.Throws<EndOfStreamException>(() => Journal());
            await Assert.ThrowsAsync<EndOfStreamException>(() => journal.ReadAsync(entry.Transfer.TransferId, default));
        }
        else
        {
            Assert.Throws<InvalidDataException>(() => Journal());
            await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(entry.Transfer.TransferId, default));
        }
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(NewTransfer(entry.Transfer.DestinationPath), default));
    }

    [Fact]
    public async Task Interrupted_append_before_frontier_preserves_old_receipts_and_leaves_new_work_hot()
    {
        var journal = Journal(); var first = Completed(); Put(first);
        Assert.True(await journal.ArchiveCompletedAsync(first, default));
        var next = Completed(2, first.Transfer.DestinationPath, 2); Put(next);
        journal.ArchiveObserver = at => { if (at == "before-frontier") throw new IOException("injected append interruption"); };
        await Assert.ThrowsAsync<IOException>(() => journal.ArchiveCompletedAsync(next, default));
        var restarted = Journal();
        Assert.Equal(first, await restarted.ReadAsync(first.Transfer.TransferId, default));
        Assert.Equal(next, await restarted.ReadAsync(next.Transfer.TransferId, default));
        Assert.Single(Directory.GetFiles(Hot, "*.json"));
        Assert.True(await restarted.ArchiveCompletedAsync(next, default));
        Assert.Equal(3, (await Journal().CreateAsync(NewTransfer(first.Transfer.DestinationPath), default)).DestinationGeneration);
    }

    [Fact]
    public async Task Uncommitted_append_tail_behind_the_durable_frontier_cannot_add_a_generation()
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        string segment = Assert.Single(Directory.GetFiles(Cold, "*.pack"));
        long committedLength = new FileInfo(segment).Length;
        using (var stream = new FileStream(segment, FileMode.Append, FileAccess.Write)) stream.Write(new byte[41]);
        var restarted = Journal();
        Assert.Equal(committedLength, new FileInfo(segment).Length);
        Assert.Equal(entry, await restarted.ReadAsync(entry.Transfer.TransferId, default));
        Assert.Equal(2, (await restarted.CreateAsync(NewTransfer(entry.Transfer.DestinationPath), default)).DestinationGeneration);
    }

    [Theory]
    [InlineData("digest")]
    [InlineData("length")]
    [InlineData("id")]
    [InlineData("missing")]
    public async Task Archive_damage_holds_all_authority_after_detection_and_refuses_restart(string damage)
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        string segment = Assert.Single(Directory.GetFiles(Cold, "*.pack"));
        if (damage == "missing") File.Delete(segment);
        else
        {
            byte[] frame = File.ReadAllBytes(segment);
            frame[StagedTransferJournal.ArchiveControlBytes + (damage switch { "digest" => 28, "length" => 8, _ => 12 })] ^= 0x40;
            File.WriteAllBytes(segment, frame);
        }
        if (damage == "missing") await Assert.ThrowsAsync<FileNotFoundException>(() => journal.ValidateArchivedSliceAsync(default));
        else await Assert.ThrowsAsync<InvalidDataException>(() => journal.ValidateArchivedSliceAsync(default));
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(NewTransfer(Path.Combine(_workspace.Root, "unrelated.txt")), default));
        Assert.Throws<InvalidDataException>(() => Journal());
    }

    [Fact]
    public async Task Archive_segment_reparse_is_refused_without_changing_its_target()
    {
        if (OperatingSystem.IsWindows()) return; // Windows symlink creation requires separate privilege qualification.
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        string segment = Assert.Single(Directory.GetFiles(Cold, "*.pack"));
        byte[] bytes = File.ReadAllBytes(segment);
        string target = Path.Combine(_workspace.Root, "unrelated.pack");
        File.WriteAllBytes(target, bytes); File.Delete(segment); File.CreateSymbolicLink(segment, target);
        Assert.Throws<IOException>(() => Journal());
        Assert.Equal(bytes, File.ReadAllBytes(target));
    }

    [Fact]
    public async Task Duplicate_hot_archive_disagreement_is_never_silently_selected()
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        Put(entry with { DestinationGeneration = 2 });
        Assert.Throws<InvalidDataException>(() => Journal());
    }

    [Fact]
    public async Task Cancellation_retains_its_separate_generation_and_exact_cleanup_replay()
    {
        var journal = Journal(); var entry = Completed();
        entry = entry with { State = TransferJournalState.Retained, JustificationWindowClosed = true,
            UnboundCancellation = new(Guid.NewGuid(), new(entry.Transfer.TransferId, entry.DestinationGeneration, entry.StageIdentity!), 19) };
        Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        var restarted = Journal();
        await restarted.CompleteUnboundCancellationCleanupAsync(entry, default);
        Assert.Equal(entry, await restarted.ReadAsync(entry.Transfer.TransferId, default));
        Assert.Equal(0, await restarted.CompactAsync(DateTimeOffset.UtcNow, default));
        Assert.Equal(20, (await Journal().CreateAsync(NewTransfer(entry.Transfer.DestinationPath), default)).DestinationGeneration);
    }

    [Fact]
    public async Task Current_epoch_receipts_ignore_age_until_exact_drain_and_keep_the_high_water_afterward()
    {
        var journal = Journal(); Guid epoch = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Active, await journal.ReconcileDriverInstanceV20Async(epoch, 0x1bf, default));
        var first = Completed();
        first = first with { DriverInstanceId = epoch, AllocationReferenceKind = 0 };
        var second = Completed(2, first.Transfer.DestinationPath, 2) with { DriverInstanceId = epoch, AllocationReferenceKind = 0 };
        foreach (var entry in new[] { first, second }) { Put(entry); Assert.True(await journal.ArchiveCompletedAsync(entry, default)); }
        Assert.Equal(0, await Journal().CompactAsync(DateTimeOffset.UtcNow.AddYears(1), default));
        Assert.Equal(first, await Journal().ReadAsync(first.Transfer.TransferId, default));
        Assert.True(await journal.DrainDriverInstanceV20Async(epoch, 71, 72, default));
        Assert.Equal(1, await Journal().CompactAsync(DateTimeOffset.UtcNow, default));
        await Assert.ThrowsAsync<FileNotFoundException>(() => Journal().ReadAsync(first.Transfer.TransferId, default));
        Assert.Equal(second, await Journal().ReadAsync(second.Transfer.TransferId, default));
    }

    [Theory]
    [InlineData("before-compaction-replace")]
    [InlineData("after-compaction-replace")]
    public async Task Compaction_interruption_holds_live_index_and_restart_preserves_all_required_claims(string point)
    {
        var journal = Journal(); var first = Completed(); var last = Completed(2, first.Transfer.DestinationPath, 2);
        foreach (var entry in new[] { first, last }) { Put(entry); Assert.True(await journal.ArchiveCompletedAsync(entry, default)); }
        journal.ArchiveObserver = at => { if (at == point) throw new IOException("injected checkpoint interruption"); };
        await Assert.ThrowsAsync<IOException>(() => journal.CompactAsync(DateTimeOffset.UtcNow, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(NewTransfer(first.Transfer.DestinationPath), default));
        var restarted = Journal();
        Assert.Equal(last, await restarted.ReadAsync(last.Transfer.TransferId, default));
        Assert.Equal(3, (await restarted.CreateAsync(NewTransfer(first.Transfer.DestinationPath), default)).DestinationGeneration);
    }

    [Fact]
    public async Task Coherently_rechecksummed_runtime_rewrite_cannot_change_the_validated_claim_index()
    {
        var journal = Journal(); var entry = Completed(); Put(entry);
        Assert.True(await journal.ArchiveCompletedAsync(entry, default));
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(entry with { DestinationGeneration = 9 });
        string segment = Assert.Single(Directory.GetFiles(Cold, "*.pack"));
        byte[] old = File.ReadAllBytes(segment);
        Assert.Equal(payload.Length, old.Length - StagedTransferJournal.ArchiveControlBytes - StagedTransferJournal.ArchiveHeaderBytes);
        SHA256.HashData(payload).CopyTo(old, StagedTransferJournal.ArchiveControlBytes + 28);
        payload.CopyTo(old, StagedTransferJournal.ArchiveControlBytes + StagedTransferJournal.ArchiveHeaderBytes);
        File.WriteAllBytes(segment, old);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(entry.Transfer.TransferId, default));
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(NewTransfer(entry.Transfer.DestinationPath), default));
    }

    [Fact]
    public async Task Compaction_deletes_old_receipts_but_keeps_generation_and_hot_ancestor_closure()
    {
        var journal = Journal(); var oldest = Completed();
        var parent = Completed(2, oldest.Transfer.DestinationPath, 2);
        var newest = Completed(3, oldest.Transfer.DestinationPath, 3);
        foreach (var e in new[] { oldest, parent, newest }) { Put(e); Assert.True(await journal.ArchiveCompletedAsync(e, default)); }
        var child = Completed(4) with { StageDeleted = false, ParentVersionIdentity = new(parent.Transfer.TransferId, parent.DestinationGeneration, parent.StageIdentity!) };
        Put(child);
        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow, default));
        var restarted = Journal();
        await Assert.ThrowsAsync<FileNotFoundException>(() => restarted.ReadAsync(oldest.Transfer.TransferId, default));
        Assert.Equal(parent, await restarted.ReadAsync(parent.Transfer.TransferId, default));
        Assert.Equal(newest, await restarted.ReadAsync(newest.Transfer.TransferId, default));
        Assert.Equal(child, await restarted.ReadAsync(child.Transfer.TransferId, default));
        Assert.Equal(4, (await restarted.CreateAsync(NewTransfer(oldest.Transfer.DestinationPath), default)).DestinationGeneration);
    }
}
