using System.Security.Principal;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using StageDisposeOutcome = SafeUpload.Agent.Minifilter.StageDisposeOutcome;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedHandbackTests : IDisposable
{
    private const string TestRequestorSid = "S-1-5-21-111-222-333-1000";
    private readonly TestWorkspace _workspace = new();
    private readonly string _stagingRoot;
    private readonly string _journalRoot;
    private readonly StagedTransferJournal _copyJournal;
    private readonly NotificationHub _notifications = NotificationTestHub.Create();

    public StagedHandbackTests()
    {
        // The copier runs with the agent service's (SYSTEM's) privileges: it creates the hand-back directories owned by SYSTEM
        // (SeRestorePrivilege) and walks them with backup-intent opens (SeBackupPrivilege). The builder's SSH session has both
        // enabled; a CI runner's elevated token holds them disabled ("This security ID may not be assigned as the owner of this
        // object", then "Access is denied").
        TestPrivileges.TryEnable("SeRestorePrivilege");
        TestPrivileges.TryEnable("SeBackupPrivilege");
        _stagingRoot = Path.Combine(_workspace.Root, "staging");
        _journalRoot = Path.Combine(_workspace.Root, "journal");
        Directory.CreateDirectory(_stagingRoot);
        _copyJournal = new StagedTransferJournal(Path.Combine(_workspace.Root, "copy-journal"));
    }

    public void Dispose() => _workspace.Dispose();

    private readonly TestPublicationGate _gate = new();

    [Theory]
    [InlineData("resave", false)]
    [InlineData("resave", true)]
    [InlineData("new", false)]
    [InlineData("new", true)]
    [InlineData("replace", false)]
    [InlineData("replace", true)]
    [InlineData("mapped", false)]
    [InlineData("mapped", true)]
    public async Task Completed_harness_patterns_leave_dispatch_and_do_no_entry_io(string pattern, bool block)
    {
        // This control completes service-owned approved-stage disposal. The
        // default gate simulates a driver-held Released stage instead.
        _gate.HoldReleasedStages = false;
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        string source = Path.Combine(_workspace.Root, "protected", pattern == "replace" ? "~tmp-1.txt" : "document.txt");
        string destination = Path.Combine(_workspace.Root, "protected", "document.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (pattern is "resave" or "replace") await File.WriteAllTextAsync(destination, "prior approved bytes");
        string stage = Path.Combine(_stagingRoot, Guid.NewGuid().ToString("N") + ".txt");
        string contents = block ? "CPF: 529.982.247-25" : "clean inspected save";
        await File.WriteAllTextAsync(stage, contents);
        if (pattern == "mapped")
        {
            // Actual mapped stage writes complete before seal, as in the actor.
            using var map = System.IO.MemoryMappedFiles.MemoryMappedFile.CreateFromFile(stage, FileMode.Open);
            using var view = map.CreateViewAccessor();
            view.Write(0, (byte)contents[0]); view.Flush();
        }
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, source, DestinationKind.RemovableDrive,
            "explorer.exe", 4321, 7) { RequestorSid = TestRequestorSid, RequestorProcessCreationTime = 123456 };
        await journal.CreateAsync(transfer, default);
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, stage, default);
        if (pattern == "replace")
        {
            await journal.PrepareRenameAsync(transfer.TransferId, 71, transfer.ProcessId, destination, true, default);
            transfer = (await journal.CompleteRenameAsync(transfer.TransferId, 71, transfer.ProcessId, destination, true, default)).Transfer;
        }
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier);
        Assert.Equal(block ? StagedTransferOutcome.Blocked : StagedTransferOutcome.Released,
            await publisher.PublishAsync(transfer, default));
        if (block)
        {
            var blocked = await journal.ReadAsync(transfer.TransferId, default);
            await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
            await publisher.ProcessBlockedCleanupAsync(blocked, default);
        }
        var terminal = await journal.ReadAsync(transfer.TransferId, default);
        Assert.True(terminal.StageDeleted);
        Assert.False(File.Exists(stage));
        if (block) Assert.True(StagedTransferJournal.MatchesBlockedDeletionReceipt(terminal));
        if (pattern == "replace")
        {
            Assert.True(terminal.LastRenameCommitted);
            Assert.Equal(source, terminal.NamespaceTombstones!.DestinationPath);
        }
        // A service disconnect/restart builds a new scan cache. Warm exactly
        // once, then every repeated real pending projection must be idle.
        foreach (var activeJournal in new[] { journal, new StagedTransferJournal(_journalRoot) })
        {
            var activePublisher = Publisher(activeJournal, policy, new(), copier);
            Assert.DoesNotContain(await activeJournal.ReadPendingAsync(default), e => e.Transfer.TransferId == transfer.TransferId);
            long reads = activeJournal.ManifestReads; int disposals = _gate.Disposals.Count;
            int copies = copier.CopyCount; int authorizations = _gate.AuthorizeCalls;
            for (int pass = 0; pass < 8; pass++)
            {
                foreach (var entry in await activeJournal.ReadPendingAsync(default))
                    await activePublisher.RecoverPendingTransferAsync(entry, default);
                if (block)
                {
                    // Also prove a stale queued completed snapshot does no I/O.
                    await activePublisher.RecoverPendingTransferAsync(terminal, default);
                    await activePublisher.ProcessBlockedCleanupAsync(terminal, default);
                }
            }
            Assert.Equal(reads, activeJournal.ManifestReads);
            Assert.Equal(disposals, _gate.Disposals.Count); Assert.Equal(copies, copier.CopyCount);
            Assert.Equal(authorizations, _gate.AuthorizeCalls);
            var retained = await activeJournal.ReadAsync(transfer.TransferId, default);
            Assert.Equal(terminal.DestinationGeneration, retained.DestinationGeneration);
            Assert.Equal(terminal.NamespaceTombstones, retained.NamespaceTombstones);
            Assert.Equal(terminal.BlockedDeletionReceipt, retained.BlockedDeletionReceipt);
        }
        Assert.Equal(block && (pattern is "resave" or "replace") ? "prior approved bytes" : block ? null : contents,
            File.Exists(destination) ? await File.ReadAllTextAsync(destination) : null);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("transfer")]
    [InlineData("generation")]
    [InlineData("identity")]
    [InlineData("renames")]
    [InlineData("length")]
    [InlineData("digest")]
    public async Task Completed_BLOCK_projection_requires_the_matching_deletion_receipt(string mismatch)
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var publisher = Publisher(journal, policy, new(), new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile")));
        await publisher.PublishAsync(transfer, default);
        var entry = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, entry.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        await publisher.ProcessBlockedCleanupAsync(entry, default);
        entry = await journal.ReadAsync(transfer.TransferId, default);
        var receipt = entry.BlockedDeletionReceipt!;
        var changed = mismatch switch
        {
            "missing" => null,
            "transfer" => receipt with { Version = receipt.Version with { TransferId = Guid.NewGuid() } },
            "generation" => receipt with { Version = receipt.Version with { DestinationGeneration = receipt.Version.DestinationGeneration + 1 } },
            "identity" => receipt with { Version = receipt.Version with { StageIdentity = receipt.Version.StageIdentity! with { FileIdLow = receipt.Version.StageIdentity!.FileIdLow ^ 1 } } },
            "renames" => receipt with { CommittedRenames = receipt.CommittedRenames + 1 },
            "length" => receipt with { Length = receipt.Length + 1 },
            "digest" => receipt with { Sha256Hex = new string('F', 64) },
            _ => throw new InvalidOperationException()
        };
        Assert.False(StagedTransferJournal.PendingDispatchRequired(entry));
        Assert.True(StagedTransferJournal.PendingDispatchRequired(entry with { BlockedDeletionReceipt = changed }));
        Assert.True(StagedTransferJournal.PendingDispatchRequired(entry with { StageDeleted = false }));
        Assert.True(StagedTransferJournal.PendingDispatchRequired(entry with { StageCleanupStarted = true }));
    }

    [Fact]
    public async Task Unfinished_BLOCK_cleanup_uses_bounded_monotonic_backoff_and_last_close_finishes_once()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier);
        long now = 0; publisher.RecoveryTimestamp = () => now;
        await publisher.PublishAsync(transfer, default);
        var entry = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, entry.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        _ = DrainTransfers(subscription).ToArray(); // discard the original publication replay
        using (var driver = new FileStream(transfer.StagePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            foreach (double seconds in new[] { .25, .5, 1, 2, 4, 8, 8 })
            {
                await publisher.RecoverPendingTransferAsync(entry, default, cleanupOnly: true);
                long reads = journal.ManifestReads; int disposals = _gate.Disposals.Count;
                now += (long)(seconds * System.Diagnostics.Stopwatch.Frequency) - 1;
                for (int pass = 0; pass < 8; pass++) await publisher.RecoverPendingTransferAsync(entry, default, cleanupOnly: true);
                Assert.Equal(reads, journal.ManifestReads); Assert.Equal(disposals, _gate.Disposals.Count);
                now++;
            }
        }
        await publisher.RecoverPendingTransferAsync(entry, default, cleanupOnly: true);
        var terminal = await journal.ReadAsync(transfer.TransferId, default);
        Assert.True(terminal.StageDeleted); Assert.Equal(1, copier.CopyCount);
        Assert.Equal(0, _gate.AuthorizeCalls);
        Assert.DoesNotContain(DrainTransfers(subscription), n => n.Phase == TransferPhase.Blocked);
        Assert.DoesNotContain(await journal.ReadPendingAsync(default), e => e.Transfer.TransferId == transfer.TransferId);
    }

    [Fact]
    public async Task Completed_BLOCK_after_requester_exit_remains_idle_across_reconnect_and_name_reuse()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        using var actor = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", "/d /c exit 0")
            { UseShellExecute = false, CreateNoWindow = true })!;
        int owner = actor.Id; long ownerCreation = actor.StartTime.ToFileTimeUtc(); actor.WaitForExit();
        string stage = Path.Combine(_stagingRoot, Guid.NewGuid().ToString("N") + ".txt");
        await File.WriteAllTextAsync(stage, "CPF: 529.982.247-25");
        string destination = Path.Combine(_workspace.Root, "protected", "exited-writer.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, destination, DestinationKind.RemovableDrive,
            "explorer.exe", owner, 7) { RequestorSid = TestRequestorSid, RequestorProcessCreationTime = ownerCreation };
        await journal.CreateAsync(transfer, default); await journal.SealAsync(transfer.TransferId, owner, stage, default);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier);
        Assert.Equal(StagedTransferOutcome.Blocked, await publisher.PublishAsync(transfer, default));
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        await publisher.ProcessBlockedCleanupAsync(blocked, default);
        var terminal = await journal.ReadAsync(transfer.TransferId, default);
        var reconnected = new StagedTransferJournal(_journalRoot);
        Assert.Empty(await reconnected.ReadPendingAsync(default));
        var allocator = new StagedTransferAllocator(_stagingRoot, reconnected);
        Assert.False(File.Exists(destination)); // a blocked new save never created this public name
        var resave = await allocator.AllocateAsync(destination, transfer.Destination, transfer.ProcessName,
            4321, 7, 2 /* FILE_CREATE */, null, default, requestorSid: TestRequestorSid, requestorProcessCreationTime: 654321);
        Assert.False(File.Exists(destination));
        Assert.True((await reconnected.ReadAsync(resave.TransferId, default)).DestinationGeneration > terminal.DestinationGeneration);
        Assert.DoesNotContain(await reconnected.ReadPendingAsync(default), e => e.Transfer.TransferId == transfer.TransferId);
        var restartedPublisher = Publisher(reconnected, policy, new(), copier);
        long reads = reconnected.ManifestReads;
        for (int pass = 0; pass < 8; pass++) await restartedPublisher.RecoverPendingTransferAsync(terminal, default);
        Assert.Equal(reads, reconnected.ManifestReads); Assert.Equal(1, copier.CopyCount);
        Assert.Equal(terminal.BlockedDeletionReceipt, (await reconnected.ReadAsync(transfer.TransferId, default)).BlockedDeletionReceipt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Blocked_same_name_resave_after_retirement_is_ordinary_and_inspected(bool blockAgain)
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var first = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7, processCreationTime: 123456);
        Directory.CreateDirectory(Path.GetDirectoryName(first.DestinationPath)!);
        await File.WriteAllTextAsync(first.DestinationPath, "public pre-save bytes");
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier);
        Assert.Equal(StagedTransferOutcome.Blocked, await publisher.PublishAsync(first, default));
        var allocator = new StagedTransferAllocator(_stagingRoot, journal);
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(first.DestinationPath, first.Destination,
            first.ProcessName, first.ProcessId, first.SessionId, 1, first, default,
            requestorSid: first.RequestorSid, requestorProcessCreationTime: 123456));
        Assert.Equal("public pre-save bytes", await File.ReadAllTextAsync(first.DestinationPath));
        var blocked = await journal.ReadAsync(first.TransferId, default);
        await journal.CloseJustificationWindowAsync(first.TransferId,
            blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        await publisher.ProcessBlockedCleanupAsync(blocked, default);
        Assert.True((await journal.ReadAsync(first.TransferId, default)).StageDeleted);
        var second = await allocator.AllocateAsync(first.DestinationPath, first.Destination, first.ProcessName,
            first.ProcessId, first.SessionId, 1, null, default, requestorSid: first.RequestorSid,
            requestorProcessCreationTime: 123456);
        var allocated = await journal.ReadAsync(second.TransferId, default);
        Assert.Null(allocated.ParentVersionIdentity); Assert.True(allocated.DestinationGeneration > blocked.DestinationGeneration);
        Assert.Equal("public pre-save bytes", await File.ReadAllTextAsync(second.StagePath));
        string contents = blockAgain ? "CPF: 529.982.247-25 second save" : "clean second save";
        await File.WriteAllTextAsync(second.StagePath, contents);
        await journal.SealAsync(second.TransferId, second.ProcessId, second.StagePath, default);
        Assert.Equal(blockAgain ? StagedTransferOutcome.Blocked : StagedTransferOutcome.Released,
            await publisher.PublishAsync(second, default));
        Assert.Equal(blockAgain ? "public pre-save bytes" : contents, await File.ReadAllTextAsync(first.DestinationPath));
        Assert.Equal(blockAgain ? 2 : 1, copier.CopyCount);
    }

    [Fact]
    public async Task Blocked_disposition_shares_driver_read_handle_and_wakes_retirement_before_absence()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier);
        await publisher.PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        using (var driver = new FileStream(transfer.StagePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            await publisher.ProcessBlockedCleanupAsync(blocked, default);
            var pending = await journal.ReadAsync(transfer.TransferId, default);
            Assert.NotNull(pending.BlockedDeletionReceipt); Assert.True(pending.StageCleanupStarted);
            Assert.False(pending.StageDeleted); Assert.True(File.Exists(transfer.StagePath));
            Assert.Equal(new[] { (transfer.TransferId, StageDisposeOutcome.CleanedUp) }, _gate.Disposals);
            await Assert.ThrowsAsync<IOException>(() => journal.CompleteStageCleanupAsync(transfer.TransferId, default));
        }
        var restarted = new StagedTransferJournal(_journalRoot);
        var nextCopier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        await Publisher(restarted, policy, new(), nextCopier).RecoverBlockedAsync(blocked, default);
        Assert.True((await restarted.ReadAsync(transfer.TransferId, default)).StageDeleted);
        Assert.False(File.Exists(transfer.StagePath)); Assert.Equal(0, nextCopier.CopyCount);
        Assert.Equal(0, _gate.AuthorizeCalls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Blocked_cleanup_refuses_every_changed_volume_or_file_identity(int component)
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier); await publisher.PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default); var id = blocked.StageIdentity!;
        var wrong = component switch { 0 => id with { VolumeSerialNumber = id.VolumeSerialNumber ^ 1 },
            1 => id with { FileIdHigh = id.FileIdHigh ^ 1 }, _ => id with { FileIdLow = id.FileIdLow ^ 1 } };
        Assert.Throws<IOException>(() => StagedStageFile.OpenBlockedDeletion(transfer.StagePath, wrong));
        Assert.True(File.Exists(transfer.StagePath)); Assert.Null(blocked.BlockedDeletionReceipt);
    }

    [Fact]
    public async Task Blocked_cleanup_never_deletes_a_replacement_after_verified_handback()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier); await publisher.PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        File.Move(transfer.StagePath, transfer.StagePath + ".original");
        await File.WriteAllTextAsync(transfer.StagePath, "replacement");
        await publisher.ProcessBlockedCleanupAsync(blocked, default);
        var held = await journal.ReadAsync(transfer.TransferId, default);
        Assert.False(held.StageDeleted); Assert.Null(held.BlockedDeletionReceipt); Assert.Empty(_gate.Disposals);
        Assert.Equal("replacement", await File.ReadAllTextAsync(transfer.StagePath)); Assert.Equal(1, copier.CopyCount);
    }

    [Fact]
    public async Task Cleanup_started_without_disposition_receipt_cannot_certify_missing_stage()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier); await publisher.PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        await journal.TryBeginStageCleanupAsync(transfer.TransferId, default); File.Delete(transfer.StagePath);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteStageCleanupAsync(transfer.TransferId, default));
        await publisher.ProcessBlockedCleanupAsync(blocked, default);
        Assert.False((await journal.ReadAsync(transfer.TransferId, default)).StageDeleted);
        Assert.Empty(_gate.Disposals); Assert.Equal(1, copier.CopyCount);
    }

    [Fact]
    public async Task Actual_crash_before_durable_disposition_receipt_keeps_named_recovery_hold()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        await Publisher(journal, policy, new(), copier).PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        await journal.TryBeginStageCleanupAsync(transfer.TransferId, default);
        // Model the process dying after native acceptance, before a receipt
        // reached disk. A new publisher cannot recreate operation evidence.
        using (var deletion = StagedStageFile.OpenBlockedDeletion(transfer.StagePath, blocked.StageIdentity!))
            deletion.MarkBlockedDeletion(transfer.StagePath);
        var restarted = new StagedTransferJournal(_journalRoot);
        var recoveryCopier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        await Publisher(restarted, policy, new(), recoveryCopier).RecoverBlockedAsync(blocked, default);
        var held = await restarted.ReadAsync(transfer.TransferId, default);
        Assert.True(held.StageCleanupStarted); Assert.False(held.StageDeleted); Assert.Null(held.BlockedDeletionReceipt);
        Assert.Equal(0, recoveryCopier.CopyCount); Assert.Empty(_gate.Disposals); Assert.Equal(0, _gate.AuthorizeCalls);
        Assert.Contains(DrainTransfers(subscription), notice => notice.Phase == TransferPhase.Retained &&
            notice.FileName == transfer.DestinationPath && notice.RecoveryAdvice == StagedRecoveryAdvice.CollectDiagnostics);
    }

    [Theory]
    [InlineData("disposition-before")]
    [InlineData("disposition-receipt")]
    [InlineData("completion-before")]
    [InlineData("completion-after")]
    public async Task Blocked_cleanup_crash_retry_finishes_bookkeeping_without_handback_or_publication(string boundary)
    {
        bool injected = false;
        var journal = new StagedTransferJournal(_journalRoot, false, 50_000, (point, entry) =>
        {
            if (injected || entry.BlockedDeletionReceipt is null) return;
            bool fault = boundary.StartsWith("disposition", StringComparison.Ordinal) ? !entry.StageDeleted &&
                point == (boundary == "disposition-before" ? StagedJournalWritePoint.BeforeReplacement : StagedJournalWritePoint.AfterReplacement) :
                entry.StageDeleted && point == (boundary == "completion-before" ? StagedJournalWritePoint.BeforeReplacement :
                    StagedJournalWritePoint.AfterReplacement);
            if (fault) { injected = true; throw new System.ComponentModel.Win32Exception(5); }
        });
        var policy = await PolicyAsync(true); var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new(), copier); await publisher.PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        await journal.CloseJustificationWindowAsync(transfer.TransferId, blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), default);
        await publisher.ProcessBlockedCleanupAsync(blocked, default); Assert.True(injected);
        if (boundary == "disposition-before")
        {
            Assert.Null((await journal.ReadAsync(transfer.TransferId, default)).BlockedDeletionReceipt);
            // Still-live native acceptance finishes only its journal write;
            // reopening the now-pending/gone path cannot supply this authority.
            await publisher.ProcessBlockedCleanupAsync(blocked, default);
        }
        var restarted = new StagedTransferJournal(_journalRoot); var replayCopier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var recovery = Publisher(restarted, policy, new(), replayCopier);
        await recovery.RecoverBlockedAsync(blocked, default); await recovery.ProcessBlockedCleanupAsync(blocked, default);
        Assert.True((await restarted.ReadAsync(transfer.TransferId, default)).StageDeleted);
        Assert.Equal(0, replayCopier.CopyCount); Assert.Equal(1, copier.CopyCount); Assert.Equal(0, _gate.AuthorizeCalls);
        Assert.False(File.Exists(transfer.StagePath));
    }

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [Fact]
    public async Task Recovery_of_legacy_bound_manifest_without_provenance_never_recopies_or_registers()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7, processCreationTime: 123456);
        var entry = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        var binding = SecuritySnapshotFixture.Binding() with { ReservationId = transfer.TransferId,
            CanonicalLeaf = Path.GetFileName(transfer.DestinationPath), Disposition = 1, PublicTarget = new(7, 91, 92) };
        var legacy = entry with { State = TransferJournalState.Blocked, StateHistory = [], BlockedPolicyVersion = 1,
            Sha256Hex = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(transfer.StagePath))),
            BoundAllocation = binding, AllocationExtensionVersion = 23, AllocationDisposition = 1,
            AllocationReferenceKind = 0, CreateReservationId = transfer.TransferId,
            DriverInstanceId = binding.DriverInstanceId, ParentDirectoryIdentity = binding.Parent,
            JustificationExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(1) };
        await SeedProvenanceFixture.WriteAsync(_journalRoot, legacy);
        var restarted = new StagedTransferJournal(_journalRoot); var broker = new StagedJustifications();
        // All recovery readers must preserve the restricted legacy entry and
        // continue enumerating unrelated work, including on a second scan.
        var unrelated = CreateBlockedCandidate(restarted, "unrelated private bytes", 7, processCreationTime: 123456);
        Assert.Equal(legacy, await restarted.ReadAsync(transfer.TransferId, CancellationToken.None));
        Assert.Equal(legacy, await restarted.FindBoundAllocationAsync(transfer.TransferId, CancellationToken.None));
        Assert.Null(await restarted.ReadBoundAllocationSecurityAsync(transfer.TransferId, CancellationToken.None));
        Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(legacy));
        for (int i = 0; i < 2; ++i)
        {
            var pending = await restarted.ReadPendingAsync(CancellationToken.None);
            Assert.Contains(pending, candidate => candidate.Transfer.TransferId == transfer.TransferId);
            Assert.Contains(pending, candidate => candidate.Transfer.TransferId == unrelated.TransferId);
            Assert.Empty(await restarted.ReadDiscardPendingAsync(CancellationToken.None));
        }
        await restarted.RetainInterruptedAsync(CancellationToken.None);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        await Publisher(restarted, policy, broker, copier).RecoverBlockedAsync(legacy, CancellationToken.None);
        var blocked = await restarted.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Blocked, blocked.State); Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
        Assert.Equal("seed_export_unproven", blocked.HandbackFailureReason); Assert.True(blocked.JustificationWindowClosed);
        Assert.Equal(0, copier.CopyCount); Assert.Null(blocked.HandbackPath); Assert.Null(blocked.HandbackLength);
        Assert.False(broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out _));
        Assert.True(File.Exists(transfer.StagePath)); Assert.False(Directory.Exists(Path.Combine(_workspace.Root, "profile")));
        Assert.Null(blocked.SeedProvenance); Assert.Null(blocked.AllocationSecurity); Assert.Null(blocked.SeedCompletion);
        Assert.False((await restarted.TryBeginStageCleanupAsync(transfer.TransferId, CancellationToken.None)).StageCleanupStarted);
        Assert.Equal(0, await restarted.CompactAsync(DateTimeOffset.UtcNow.AddHours(1), CancellationToken.None));
        Assert.Equal("CPF: 529.982.247-25", File.ReadAllText(transfer.StagePath));
        Assert.Equal("unrelated private bytes", File.ReadAllText(unrelated.StagePath));
        Assert.Equal(blocked, await new StagedTransferJournal(_journalRoot).ReadAsync(transfer.TransferId, CancellationToken.None));
    }
#endif

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Legacy_successor_inherits_existing_provenance_only_when_it_copies_prior_bytes(bool truncate)
    {
        var journal = new StagedTransferJournal(_journalRoot);
        var parent = CreateBlockedCandidate(journal, "private prior bytes", 7, processCreationTime: 123456);
        await SeedProvenanceFixture.AttachAsync(_journalRoot, journal, parent.TransferId);
        var allocator = new StagedTransferAllocator(_stagingRoot, journal);
        var child = await allocator.AllocateAsync(parent.DestinationPath, parent.Destination, parent.ProcessName,
            parent.ProcessId, parent.SessionId, truncate ? 5u : 1u, parent, CancellationToken.None,
            requestorSid: parent.RequestorSid, requestorProcessCreationTime: parent.RequestorProcessCreationTime);
        var entry = await new StagedTransferJournal(_journalRoot).ReadAsync(child.TransferId, CancellationToken.None);
        Assert.Null(entry.BoundAllocation);
        if (truncate)
        {
            Assert.Null(entry.SeedProvenance); Assert.Null(StagedSeedExport.Failure(entry));
            Assert.Equal(0, new FileInfo(child.StagePath).Length);
        }
        else
        {
            Assert.Equal(StagedSeedOrigin.PrivatePredecessor, entry.SeedProvenance!.Origin);
            Assert.Equal(parent.TransferId, entry.SeedProvenance.Predecessor!.TransferId);
            Assert.Equal("seed_export_unproven", entry.SeedProvenance.InheritedRestriction);
            Assert.Equal("seed_export_unproven", StagedSeedExport.Failure(entry));
            Assert.Equal("private prior bytes", await File.ReadAllTextAsync(child.StagePath));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Atomic_blocked_failed_persistence_fault_never_starts_export(bool afterReplacement)
    {
        var policy = await PolicyAsync(true); bool injected = false;
        var journal = new StagedTransferJournal(_journalRoot, false, 100, (point, entry) =>
        {
            if (!injected && entry.State == TransferJournalState.Blocked &&
                entry.HandbackState == StagedHandbackState.Failed &&
                point == (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement))
            { injected = true; throw new IOException("Injected private-block persistence interruption"); }
        });
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7, processCreationTime: 123456);
        await SeedProvenanceFixture.AttachAsync(_journalRoot, journal, transfer.TransferId);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var broker = new StagedJustifications(); var publisher = Publisher(journal, policy, broker, copier);
        await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.True(injected); Assert.Equal(0, copier.CopyCount);
        var restarted = new StagedTransferJournal(_journalRoot);
        var interrupted = await restarted.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(afterReplacement ? TransferJournalState.Blocked : TransferJournalState.Inspecting, interrupted.State);
        publisher = Publisher(restarted, policy, broker, copier);
        if (!afterReplacement)
        {
            await restarted.RetainInterruptedAsync(CancellationToken.None);
            Assert.Equal(StagedTransferOutcome.Blocked, await publisher.PublishAsync(transfer, CancellationToken.None));
        }
        else await publisher.RecoverBlockedAsync(interrupted, CancellationToken.None);
        var final = await restarted.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Blocked, final.State); Assert.Equal(StagedHandbackState.Failed, final.HandbackState);
        Assert.Equal("seed_export_unproven", final.HandbackFailureReason);
        Assert.True(final.JustificationWindowClosed); Assert.Null(final.HandbackPath); Assert.Null(final.HandbackLength);
        Assert.Equal(0, copier.CopyCount); Assert.False(broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out _));
        Assert.True(File.Exists(transfer.StagePath)); Assert.False(Directory.Exists(Path.Combine(_workspace.Root, "profile")));
    }

    [Theory]
    [InlineData(StagedSeedAuthority.Allowed, StagedSeedAuthority.Allowed, null)]
    [InlineData(StagedSeedAuthority.Denied, StagedSeedAuthority.Allowed, "seed_export_denied")]
    [InlineData(StagedSeedAuthority.Unproven, StagedSeedAuthority.Allowed, "seed_export_unproven")]
    [InlineData(StagedSeedAuthority.Allowed, StagedSeedAuthority.Unproven, "seed_export_recipient_unproven")]
    public async Task Seed_authority_controls_handback_justification_and_owner_only_notice(
        StagedSeedAuthority read, StagedSeedAuthority recipient, string? failure)
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7, processCreationTime: 123456);
        await SeedProvenanceFixture.AttachAsync(_journalRoot, journal, transfer.TransferId, read, recipient);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var broker = new StagedJustifications(); var publisher = Publisher(journal, policy, broker, copier);
        using var owner = _notifications.Subscribe(7, TestRequestorSid);
        using var stranger = _notifications.Subscribe(7, "S-1-5-21-111-222-333-1001");
        Assert.Equal(StagedTransferOutcome.Blocked, await publisher.PublishAsync(transfer, CancellationToken.None));
        var blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        var notice = Assert.Single(DrainTransfers(owner), n => n.Phase == TransferPhase.Blocked);
        Assert.False(stranger.Reader.TryRead(out _));
        Assert.Equal(failure, blocked.HandbackFailureReason);
        Assert.Equal(failure is null ? 1 : 0, copier.CopyCount);
        Assert.Equal(failure is null, notice.OverrideAllowed);
        Assert.Equal(failure is null, broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out var retry));
        if (failure is null)
        {
            Assert.Equal(StagedHandbackState.Verified, blocked.HandbackState);
            Assert.Null(notice.BlockReason); Assert.NotNull(retry);
            Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
            Assert.True(await retry!(CancellationToken.None));
        }
        else
        {
            Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
            Assert.Equal(StagedBlockReason.SeedExportRestricted, notice.BlockReason);
            Assert.Null(notice.HandbackPath); Assert.False(notice.HandbackVerified);
            Assert.Null(blocked.HandbackPath); Assert.Null(blocked.HandbackLength);
            Assert.True(blocked.JustificationWindowClosed); Assert.Null(retry);
            Assert.True(File.Exists(transfer.StagePath)); Assert.False(File.Exists(transfer.DestinationPath));
            Assert.False(Directory.Exists(Path.Combine(_workspace.Root, "profile")));
            Assert.False((await journal.TryBeginStageCleanupAsync(transfer.TransferId, CancellationToken.None)).StageCleanupStarted);
            await Assert.ThrowsAsync<IOException>(() => journal.CompleteStageCleanupAsync(transfer.TransferId, CancellationToken.None));
        }
    }

    [Theory]
    [InlineData(StagedHandbackState.NotAttempted)]
    [InlineData(StagedHandbackState.Copying)]
    [InlineData(StagedHandbackState.Verified)]
    [InlineData(StagedHandbackState.Failed)]
    public async Task Interrupted_or_historical_blocked_seed_recovers_failed_without_copy_or_justification(
        StagedHandbackState interrupted)
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7, processCreationTime: 123456);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        await SeedProvenanceFixture.AttachAsync(_journalRoot, journal, transfer.TransferId);
        await Publisher(journal, policy, new(), copier).PublishAsync(transfer, CancellationToken.None);
        var blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        var crash = blocked with { HandbackState = interrupted, JustificationWindowClosed = false,
            JustificationExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(1),
            HandbackFailureReason = interrupted == StagedHandbackState.Failed ? "seed_export_unproven" : null,
            HandbackPath = interrupted == StagedHandbackState.Verified ? Path.Combine(_workspace.Root, "never-created.txt") : null,
            HandbackLength = interrupted == StagedHandbackState.Verified ? blocked.SealedLength : null };
        await SeedProvenanceFixture.WriteAsync(_journalRoot, crash);
        var restarted = new StagedTransferJournal(_journalRoot); var broker = new StagedJustifications();
        var publisher = Publisher(restarted, policy, broker, copier);
        await publisher.RecoverBlockedAsync(crash, CancellationToken.None);
        await publisher.RecoverBlockedAsync(crash, CancellationToken.None); // after notification, same stale scan
        var recovered = await restarted.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Blocked, recovered.State);
        Assert.Equal(StagedHandbackState.Failed, recovered.HandbackState);
        Assert.Equal("seed_export_unproven", recovered.HandbackFailureReason);
        Assert.True(recovered.JustificationWindowClosed); Assert.Null(recovered.HandbackPath);
        Assert.Null(recovered.HandbackLength); Assert.Equal(0, copier.CopyCount);
        Assert.False(broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out _));
        Assert.False(Directory.Exists(Path.Combine(_workspace.Root, "profile")));
        await publisher.ProcessBlockedCleanupAsync(crash, CancellationToken.None);
        Assert.True(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task Direct_journal_copier_and_stale_justification_cannot_bypass_seed_restriction()
    {
        var policy = await PolicyAsync(true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7, processCreationTime: 123456);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var broker = new StagedJustifications(); var publisher = Publisher(journal, policy, broker, copier);
        await publisher.PublishAsync(transfer, CancellationToken.None);
        Assert.True(broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out var stale));
        Assert.NotNull(stale);
        // Model loading a previously written provenance-bearing record after the callback was captured.
        await SeedProvenanceFixture.AttachAsync(_journalRoot, journal, transfer.TransferId);
        Assert.False(await stale!(CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginHandbackAttemptAsync(transfer.TransferId, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteHandbackAsync(transfer.TransferId,
            Path.Combine(_workspace.Root, "invented.txt"), 10, null, CancellationToken.None));
        Assert.False(await broker.RememberAsync(journal, transfer.TransferId, 7, TestRequestorSid,
            _ => throw new InvalidOperationException("Must not execute"), DateTimeOffset.UtcNow.AddMinutes(1), CancellationToken.None));
        var realCopier = new StagedHandbackCopier(policy, journal,
            new TestHandbackEnvironment(new SecurityIdentifier(TestRequestorSid), Path.Combine(_workspace.Root, "new-profile")));
        using var source = File.OpenRead(transfer.StagePath);
        var blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => realCopier.CopyVerifiedAsync(transfer, source, source.Length,
            blocked.Sha256Hex!, CancellationToken.None));
        Assert.Throws<IOException>(() => realCopier.OpenVerifiedReadLease(transfer,
            Path.Combine(_workspace.Root, "invented.txt"), source.Length, blocked.Sha256Hex!));
        Assert.Equal("seed_export_unproven", blocked.HandbackFailureReason);
        Assert.Equal(1, copier.CopyCount); Assert.Equal(0, _gate.AuthorizeCalls);
        Assert.False(Directory.Exists(Path.Combine(_workspace.Root, "new-profile")));
    }

    [Theory]
    [InlineData("unchanged")]
    [InlineData("same-version-edit")]
    [InlineData("legacy-missing")]
    public async Task Restart_restores_justification_only_for_the_original_complete_policy(string shape)
    {
        var policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "original public bytes");
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        Assert.Equal(StagedTransferOutcome.Blocked, await Publisher(journal, policy, new StagedJustifications(), copier)
            .PublishAsync(transfer, CancellationToken.None));
        var blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(PolicyContentFingerprint.Compute(await policy.LoadCurrentAsync(CancellationToken.None)), blocked.BlockedPolicyFingerprint);
        if (shape == "same-version-edit")
        {
            var changed = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!;
            changed["maxFileSizeMb"] = (await policy.LoadCurrentAsync(CancellationToken.None)).MaxFileSizeMb + 1;
            await File.WriteAllTextAsync(_workspace.PolicyFile, changed.ToJsonString());
        }
        else if (shape == "legacy-missing")
        {
            string path = Path.Combine(_journalRoot, transfer.TransferId.ToString("N") + ".json");
            var legacy = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
            Assert.True(legacy.Remove("BlockedPolicyFingerprint"));
            await File.WriteAllTextAsync(path, legacy.ToJsonString());
        }
        var restarted = new StagedTransferJournal(_journalRoot); var broker = new StagedJustifications();
        var current = await restarted.ReadAsync(transfer.TransferId, CancellationToken.None);
        await Publisher(restarted, policy, broker, copier).RecoverBlockedAsync(current, CancellationToken.None);
        current = await restarted.ReadAsync(transfer.TransferId, CancellationToken.None);
        if (shape == "unchanged")
        {
            Assert.Equal(blocked.BlockedPolicyFingerprint, current.BlockedPolicyFingerprint);
            Assert.True(broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out var retry));
            Assert.NotNull(retry); Assert.True(await retry!(CancellationToken.None));
            Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(transfer.DestinationPath));
        }
        else
        {
            Assert.False(broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out var retry));
            Assert.Null(retry); Assert.Equal(TransferJournalState.Retained, current.State);
            Assert.True(current.JustificationWindowClosed); Assert.False(current.StageDeleted);
            Assert.Equal("original public bytes", await File.ReadAllTextAsync(transfer.DestinationPath));
            Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(transfer.StagePath));
            Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(current.HandbackPath!));
            Assert.Equal(0, _gate.AuthorizeCalls);
        }
    }

    [Fact]
    public async Task Malformed_durable_policy_binding_is_rejected_without_removing_backing()
    {
        var policy = await PolicyAsync(allowJustification: true); var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        await Publisher(journal, policy, new StagedJustifications(), copier).PublishAsync(transfer, CancellationToken.None);
        string path = Path.Combine(_journalRoot, transfer.TransferId.ToString("N") + ".json");
        var damaged = JsonNode.Parse(await File.ReadAllTextAsync(path))!;
        damaged["BlockedPolicyFingerprint"] = "malformed";
        await File.WriteAllTextAsync(path, damaged.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(transfer.TransferId, CancellationToken.None));
        Assert.True(File.Exists(transfer.StagePath)); Assert.True(File.Exists(path));
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task Journal_failure_resumes_handback_without_terminal_failure_or_duplicate_copy(
        bool completingCopy, bool afterReplacement, bool restart)
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        bool injected = false;
        var journal = new StagedTransferJournal(_journalRoot, false, 100,
            (point, entry) =>
            {
                if (injected || entry.State != TransferJournalState.Blocked ||
                    entry.HandbackState != (completingCopy ? StagedHandbackState.Verified : StagedHandbackState.Copying) ||
                    point != (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement))
                    return;
                injected = true;
                throw new System.ComponentModel.Win32Exception(5);
            });
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "original public content");
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var justifications = new StagedJustifications();
        var publisher = Publisher(journal, policy, justifications, copier);

        var failure = await Assert.ThrowsAsync<StagedJournalPersistenceException>(() =>
            publisher.PublishAsync(transfer, CancellationToken.None));
        Assert.True(injected);
        Assert.Equal(transfer.TransferId, failure.TransferId);
        Assert.Equal(afterReplacement, failure.ReplacementReturned);
        Assert.Contains("nativeError=5", failure.Message);
        Assert.Contains("pointInTimeOnly=true", failure.Message);
        Assert.Contains("temporary=[volume=", failure.Message);
        var interrupted = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.NotEqual(StagedHandbackState.Failed, interrupted.HandbackState);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Empty(_gate.Disposals);
        Assert.Equal("original public content", await File.ReadAllTextAsync(transfer.DestinationPath));

        if (restart)
        {
            journal = new StagedTransferJournal(_journalRoot);
            justifications = new StagedJustifications();
            publisher = Publisher(journal, policy, justifications, copier);
        }
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        if (restart) await publisher.RecoverPendingTransferAsync(interrupted, CancellationToken.None);
        else
        {
            // The service worker queues this obligation from its persistence
            // catch, even when the manifest already says Verified.
            publisher.QueueJournalProgress(interrupted);
            await publisher.RecoverJournalProgressAsync(CancellationToken.None);
            await publisher.RecoverJournalProgressAsync(CancellationToken.None);
        }
        var recovered = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedHandbackState.Verified, recovered.HandbackState);
        Assert.Null(recovered.HandbackFailureReason);
        Assert.Equal(1, copier.CopyCount);
        var notices = new List<TransferNotification>();
        while (subscription.Reader.TryRead(out var notice))
            if (notice is TransferNotification transferNotice) notices.Add(transferNotice);
        var blocked = Assert.Single(notices, n => n.Phase == TransferPhase.Blocked);
        Assert.True(blocked.OverrideAllowed);
        Assert.True(blocked.HandbackVerified);
        Assert.Equal(recovered.HandbackPath, blocked.HandbackPath);
        Assert.True(justifications.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out var retry));
        Assert.NotNull(retry);
        Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(recovered.HandbackPath!));
        Assert.Equal("original public content", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.True(File.Exists(transfer.StagePath)); // Existing justification window still applies.
        Assert.Empty(_gate.Disposals);
    }

    [Fact]
    public async Task Verified_handback_is_idempotent_across_restart_and_cleanup_waits_for_window_close()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath, "protected baseline");
        var firstCopy = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new StagedJustifications(), firstCopy);

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.True(blocked.HandbackState == StagedHandbackState.Verified,
            "Hand-back state " + blocked.HandbackState + ": " + blocked.HandbackFailureReason);
        Assert.Equal(1, firstCopy.CopyCount);
        Assert.False(blocked.JustificationWindowClosed);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal("protected baseline", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(blocked.HandbackPath!));
        Assert.Equal(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(transfer.StagePath))), blocked.Sha256Hex);

        var restartedJournal = new StagedTransferJournal(_journalRoot);
        var afterRestartCopy = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var restartedPublisher = Publisher(restartedJournal, policy,
            new StagedJustifications(), afterRestartCopy);
        await restartedPublisher.RecoverBlockedAsync(
            await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None),
            CancellationToken.None);
        Assert.Equal(0, afterRestartCopy.CopyCount);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Empty(_gate.Disposals); /* the hand-back window is still open: the driver keeps the version */

        blocked = await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await restartedJournal.CloseJustificationWindowAsync(transfer.TransferId,
            blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), CancellationToken.None);
        await restartedPublisher.ProcessBlockedCleanupAsync(
            await restartedJournal.ReadAsync(transfer.TransferId, CancellationToken.None),
            CancellationToken.None);

        TransferJournalEntry cleaned = await restartedJournal.ReadAsync(
            transfer.TransferId, CancellationToken.None);
        Assert.True(cleaned.JustificationWindowClosed);
        Assert.True(cleaned.StageDeleted);
        Assert.False(File.Exists(transfer.StagePath));
        Assert.Equal(0, afterRestartCopy.CopyCount);
        Assert.Equal(new[] { (transfer.TransferId, StageDisposeOutcome.CleanedUp) }, _gate.Disposals);
    }

    [Fact]
    public async Task Copy_failure_is_audited_retains_staging_and_never_reports_a_verified_path()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"), fail: true);
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = Publisher(journal, policy, new StagedJustifications(), copier);

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
        Assert.Null(blocked.HandbackPath);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.Equal(2, (await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(10, CancellationToken.None)).Count);
        var transferNotifications = new List<TransferNotification>();
        while (subscription.Reader.TryRead(out AgentNotification? notification))
            if (notification is TransferNotification transferNotification)
                transferNotifications.Add(transferNotification);
        var blockedNotification = Assert.Single(transferNotifications,
            notification => notification.Phase == TransferPhase.Blocked);
        Assert.Equal(blocked.Sha256Hex, blockedNotification.SnapshotSha256Hex);
        Assert.False(blockedNotification.HandbackVerified);
        Assert.Null(blockedNotification.HandbackPath);
        Assert.DoesNotContain(transferNotifications,
            notification => notification.Phase == TransferPhase.Released);
        await Assert.ThrowsAsync<IOException>(() => journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Blocked, TransferJournalState.Inspecting, null,
            CancellationToken.None, closeJustificationWindow: true));
    }

    [Fact]
    public async Task Reused_session_still_hands_back_to_the_requestor_and_delivers_nothing_to_the_session()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = new StagedTransferPublisher(new InspectionService(policy,
                new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(),
                new VerdictCache()), _notifications, journal, _stagingRoot,
            new TestPublicationGate(), new StagedJustifications(), policyStore: policy,
            handbackCopier: copier, sessionUserSidResolver: _ => "S-1-5-21-999-888-777-1000");

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);

        // The hand-back follows the requestor SID persisted at allocation, never the
        // session's current user; the session's new user receives nothing.
        Assert.Equal(StagedHandbackState.Verified, blocked.HandbackState);
        Assert.Equal(1, copier.CopyCount);
        Assert.NotNull(blocked.HandbackPath);
        Assert.DoesNotContain(DrainTransfers(subscription),
            notification => notification.Phase == TransferPhase.Blocked);
        Assert.Contains(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None),
            audit => audit.Verdict == Verdict.Blocked);
    }

    [Fact]
    public async Task Legacy_manifest_without_requestor_sid_is_never_handed_back_automatically()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7,
            requestorSid: null);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        using var subscription = _notifications.Subscribe(7, TestRequestorSid);
        var publisher = Publisher(journal, policy, new StagedJustifications(), copier);

        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);

        Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
        Assert.Equal("requestor_identity_unavailable", blocked.HandbackFailureReason);
        Assert.Equal(0, copier.CopyCount);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.DoesNotContain(DrainTransfers(subscription),
            notification => notification.Phase == TransferPhase.Blocked);
        Assert.Contains(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None),
            audit => audit.Verdict == Verdict.Blocked);
    }

    [Fact]
    public async Task Recovery_with_a_reused_session_keeps_the_verified_handback_without_recopy()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: false);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var owner = _notifications.Subscribe(7, TestRequestorSid);
        using var ownerLifetime = owner;
        using var newSessionUser = _notifications.Subscribe(7, "S-1-5-21-999-888-777-1000");
        var initialPublisher = Publisher(journal, policy, new StagedJustifications(), copier);
        Assert.Equal(StagedTransferOutcome.Blocked,
            await initialPublisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry verified = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(StagedHandbackState.Verified, verified.HandbackState);
        _ = DrainTransfers(owner).ToArray();
        _ = DrainTransfers(newSessionUser).ToArray();

        var recoveredPublisher = new StagedTransferPublisher(new InspectionService(policy,
                new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(),
                new VerdictCache()), _notifications, journal, _stagingRoot,
            new TestPublicationGate(), new StagedJustifications(), policyStore: policy,
            handbackCopier: copier, sessionUserSidResolver: _ => "S-1-5-21-999-888-777-1000");
        await recoveredPublisher.RecoverBlockedAsync(verified, CancellationToken.None);
        TransferJournalEntry retained = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);

        // Session reuse neither redirects nor invalidates a hand-back bound to the requestor SID.
        Assert.Equal(StagedHandbackState.Verified, retained.HandbackState);
        Assert.Equal(verified.HandbackPath, retained.HandbackPath);
        Assert.Equal(1, copier.CopyCount);
        Assert.DoesNotContain(DrainTransfers(newSessionUser), notification => notification.Phase == TransferPhase.Blocked);
        Assert.DoesNotContain(await new LocalQueueAuditSink(_workspace.QueueFile)
                .ReadRecentAsync(10, CancellationToken.None),
            audit => audit.NotInspectedReason == "requestor_identity_unavailable");
    }

    [Fact]
    public async Task Cleanup_reverification_of_changed_copy_retains_staging_without_recopy_loops()
    {
        IPolicyStore policy = await PolicyAsync(allowJustification: true);
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "CPF: 529.982.247-25", sessionId: 7);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, policy, new StagedJustifications(), copier);
        Assert.Equal(StagedTransferOutcome.Blocked,
            await publisher.PublishAsync(transfer, CancellationToken.None));
        TransferJournalEntry blocked = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await File.WriteAllTextAsync(blocked.HandbackPath!, "changed after verified copy");
        await journal.CloseJustificationWindowAsync(transfer.TransferId,
            blocked.JustificationExpiresAtUtc!.Value.AddTicks(1), CancellationToken.None);

        await publisher.ProcessBlockedCleanupAsync(
            await journal.ReadAsync(transfer.TransferId, CancellationToken.None), CancellationToken.None);
        TransferJournalEntry retained = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        await publisher.ProcessBlockedCleanupAsync(retained, CancellationToken.None);
        await publisher.RecoverBlockedAsync(retained, CancellationToken.None);

        Assert.Equal(StagedHandbackState.Failed, retained.HandbackState);
        Assert.Equal("handback_reverification_failed", retained.HandbackFailureReason);
        Assert.Null(retained.HandbackPath);
        Assert.False(retained.StageDeleted);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(1, copier.CopyCount);
        Assert.Single((await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadRecentAsync(20, CancellationToken.None)), audit =>
            audit.Verdict == Verdict.Retained && audit.NotInspectedReason == "handback_reverification_failed");
    }

    [Fact]
    public async Task Failed_copy_removes_its_uncommitted_temp_by_handle()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "cancel-profile");
        Directory.CreateDirectory(profile);
        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(), _copyJournal,
            new TestHandbackEnvironment(user, profile));
        string sourcePath = _workspace.WriteText("cancel-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        await using var source = new CancelDuringCopyFileStream(sourcePath, cancellation);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, cancellation.Token));

        string blockedDirectory = Path.Combine(profile, "SafeUpload", "_bloqueados");
        Assert.True(Directory.Exists(blockedDirectory));
        Assert.Empty(Directory.EnumerateFiles(blockedDirectory, ".safeupload-*.tmp"));
    }

    [Fact]
    public void File_acl_descriptor_is_explicit_and_contains_only_the_user_and_system()
    {
        var user = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        Assert.Equal($"O:SYD:P(A;;FR;;;{user.Value})(A;;FA;;;SY)",
            StagedHandbackCopier.BuildFileSecurityDescriptorSddl(user));
        Assert.Equal($"O:SYD:P(A;;FR;;;{user.Value})(A;;FA;;;SY)",
            StagedHandbackCopier.BuildDirectorySecurityDescriptorSddl(user));
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("sync")]
    public async Task Protected_or_known_sync_roots_are_refused_before_directory_creation(string scopeKind)
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "refusal-profile");
        Directory.CreateDirectory(profile);
        string safeUpload = Path.Combine(profile, "SafeUpload");
        Directory.CreateDirectory(safeUpload);
        var policy = new LocalPolicyStore(_workspace.PolicyFile);
        await policy.LoadAsync(CancellationToken.None);
        string[] syncRoots = [];
        JsonObject scopeDocument = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        scopeDocument["monitoredScopes"]!["destinationPaths"] = new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, scopeDocument.ToJsonString());
        if (scopeKind == "policy")
        {
            JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
            document["monitoredScopes"]!["destinationPaths"] = new JsonArray(JsonValue.Create(safeUpload));
            await File.WriteAllTextAsync(_workspace.PolicyFile, document.ToJsonString());
        }
        else syncRoots = [safeUpload];

        var copier = new StagedHandbackCopier(policy, _copyJournal,
            new TestHandbackEnvironment(user, profile, syncRoots));
        string sourcePath = _workspace.WriteText("scope-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);

        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(safeUpload, "_bloqueados")));
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("sync")]
    public async Task Unresolvable_registered_scope_fails_closed_before_directory_creation(string scopeKind)
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "unresolved-profile");
        Directory.CreateDirectory(profile);
        string missingRoot = Path.Combine(profile, "missing-registered-root");
        var policy = new LocalPolicyStore(_workspace.PolicyFile);
        await policy.LoadAsync(CancellationToken.None);
        JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        document["monitoredScopes"]!["destinationPaths"] = scopeKind == "policy"
            ? new JsonArray(JsonValue.Create(missingRoot)) : new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, document.ToJsonString());
        string[] syncRoots = scopeKind == "sync" ? [missingRoot] : [];
        var copier = new StagedHandbackCopier(policy, _copyJournal,
            new TestHandbackEnvironment(user, profile, syncRoots));
        string sourcePath = _workspace.WriteText("missing-scope-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);

        await Assert.ThrowsAnyAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(profile, "SafeUpload")));
    }

    [Fact]
    public async Task Extended_length_sync_root_alias_is_matched_by_directory_identity()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "alias-profile");
        string safeUpload = Path.Combine(profile, "SafeUpload");
        Directory.CreateDirectory(safeUpload);
        string alias = "\\\\?\\" + Path.GetFullPath(safeUpload);
        Assert.True(StagedHandbackCopier.DirectoryPathsHaveSameIdentity(safeUpload, alias));
        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(), _copyJournal,
            new TestHandbackEnvironment(user, profile, [alias]));
        string sourcePath = _workspace.WriteText("alias-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);

        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(safeUpload, "_bloqueados")));
    }

    [Fact]
    public async Task Existing_handback_name_is_verified_read_only_and_never_overwritten()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "test-profile");
        Directory.CreateDirectory(profile);
        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(), _copyJournal,
            new TestHandbackEnvironment(user, profile));
        string sourcePath = _workspace.WriteText("sealed.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        string returned;
        await using (var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                         FileShare.Read, 4096, FileOptions.Asynchronous))
        {
            returned = await copier.CopyVerifiedAsync(transfer, source, source.Length,
                digest, CancellationToken.None);
        }
        Assert.Equal("sealed snapshot", await File.ReadAllTextAsync(returned));

        await using (var adoptSource = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
                         FileShare.Read, 4096, FileOptions.Asynchronous))
        {
            string adopted = await copier.CopyVerifiedAsync(transfer, adoptSource,
                adoptSource.Length, digest, CancellationToken.None);
            Assert.Equal(returned, adopted);
        }

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => File.WriteAllTextAsync(returned,
            "user cannot modify the SYSTEM-owned hand-back"));
        Assert.Equal("sealed snapshot", await File.ReadAllTextAsync(returned));
        await File.WriteAllTextAsync(sourcePath, "different source bytes");
        string changedDigest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var retrySource = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);
        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, retrySource, retrySource.Length, changedDigest, CancellationToken.None));
        Assert.Equal("sealed snapshot", await File.ReadAllTextAsync(returned));
    }

    [Fact]
    public async Task Reparse_component_is_refused_when_unprivileged_test_host_can_create_one()
    {
        if (!OperatingSystem.IsWindows()) return;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier user = identity.User ?? throw new InvalidOperationException("Test user SID missing.");
        string profile = Path.Combine(_workspace.Root, "reparse-profile");
        Directory.CreateDirectory(profile);
        string outside = Path.Combine(_workspace.Root, "outside");
        Directory.CreateDirectory(outside);
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(profile, "SafeUpload"), outside);
        }
        catch (Exception error) when (error is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return; // Windows may disable unprivileged symlink creation on the builder.
        }

        var copier = new StagedHandbackCopier(await EmptyScopePolicyAsync(), _copyJournal,
            new TestHandbackEnvironment(user, profile));
        string sourcePath = _workspace.WriteText("reparse-source.txt", "sealed snapshot");
        var transfer = new StagedTransfer(Guid.NewGuid(), sourcePath,
            Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7)
        { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            await File.ReadAllBytesAsync(sourcePath)));
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.Asynchronous);
        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(
            transfer, source, source.Length, digest, CancellationToken.None));
        Assert.Empty(Directory.EnumerateFileSystemEntries(outside));
    }

    [Fact]
    public async Task Handback_never_exports_bytes_using_a_rejected_policy_fallback()
    {
        await new LocalPolicyStore(_workspace.PolicyFile).LoadAsync(CancellationToken.None);
        bool trusted = true;
        var policy = new LocalPolicyStore(_workspace.PolicyFile, _ => trusted);
        await policy.LoadAsync(CancellationToken.None);
        trusted = false;
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var user = identity.User!;
        string profile = Path.Combine(_workspace.Root, "current-policy-profile");
        Directory.CreateDirectory(profile);
        var copier = new StagedHandbackCopier(policy, _copyJournal, new TestHandbackEnvironment(user, profile));
        string path = _workspace.WriteText("current-policy-source.txt", "Private retained bytes.");
        var transfer = new StagedTransfer(Guid.NewGuid(), path, Path.Combine(_workspace.Root, "protected", "report.txt"),
            DestinationKind.RemovableDrive, "explorer.exe", 1234, 7) { RequestorSid = user.Value };
        await _copyJournal.CreateAsync(transfer, CancellationToken.None);
        string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(path)));
        await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        await Assert.ThrowsAsync<PolicyFileAclRejectedException>(() => copier.CopyVerifiedAsync(transfer, source,
            source.Length, digest, CancellationToken.None));
        Assert.Empty(Directory.EnumerateFiles(profile, "*", SearchOption.AllDirectories));
        Assert.Equal("Private retained bytes.", await File.ReadAllTextAsync(path));
    }

    private async Task<IPolicyStore> PolicyAsync(bool allowJustification)
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        JsonObject policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        policy["overrideAllowed"] = allowJustification;
        policy["monitoredScopes"]!["destinationPaths"] = new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        return store;
    }

    private async Task<IPolicyStore> EmptyScopePolicyAsync()
    {
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        await store.LoadAsync(CancellationToken.None);
        JsonObject policy = JsonNode.Parse(await File.ReadAllTextAsync(_workspace.PolicyFile))!.AsObject();
        policy["monitoredScopes"]!["destinationPaths"] = new JsonArray();
        await File.WriteAllTextAsync(_workspace.PolicyFile, policy.ToJsonString());
        return store;
    }

    private StagedTransfer CreateBlockedCandidate(StagedTransferJournal journal,
        string contents, uint? sessionId, string? requestorSid = TestRequestorSid, long? processCreationTime = null)
    {
        string stage = Path.Combine(_stagingRoot, Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(stage, contents);
        string destination = Path.Combine(_workspace.Root, "protected", Path.GetFileName(stage));
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, destination,
            DestinationKind.RemovableDrive, "explorer.exe", 4321, sessionId)
        { RequestorSid = requestorSid, RequestorProcessCreationTime = processCreationTime };
        journal.CreateAsync(transfer, CancellationToken.None).GetAwaiter().GetResult();
        journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None).GetAwaiter().GetResult();
        return transfer;
    }

    private StagedTransferPublisher Publisher(StagedTransferJournal journal, IPolicyStore policy,
        StagedJustifications justifications, IStagedHandbackCopier copier) =>
        new(new InspectionService(policy, new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache()),
            _notifications, journal, _stagingRoot, _gate,
            justifications, policyStore: policy, handbackCopier: copier,
            sessionUserSidResolver: _ => TestRequestorSid);

    private sealed class RecordingHandbackCopier(string profile, bool fail = false) : IStagedHandbackCopier
    {
        public int CopyCount { get; private set; }

        public async Task<string> CopyVerifiedAsync(StagedTransfer transfer, FileStream sealedSnapshot,
            long length, string sha256Hex, CancellationToken token)
        {
            if (fail) throw new IOException("Injected hand-back copy failure.");
            string directory = Path.Combine(profile, "SafeUpload", "_bloqueados");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, transfer.TransferId.ToString("N") +
                Path.GetExtension(transfer.DestinationPath));
            if (File.Exists(path))
            {
                using var verified = OpenVerifiedReadLease(transfer, path, length, sha256Hex);
                return path;
            }
            CopyCount++;
            sealedSnapshot.Position = 0;
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await sealedSnapshot.CopyToAsync(output, token);
                output.Flush(flushToDisk: true);
                if (output.Length != length) throw new IOException("Length mismatch in fake copy.");
            }
            string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                await File.ReadAllBytesAsync(path, token)));
            if (!string.Equals(digest, sha256Hex, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Digest mismatch in fake copy.");
            return path;
        }

        public IDisposable OpenVerifiedReadLease(StagedTransfer transfer, string handbackPath,
            long length, string sha256Hex)
        {
            var stream = new FileStream(handbackPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.SequentialScan);
            try
            {
                string digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream));
                if (stream.Length != length || !string.Equals(digest, sha256Hex,
                        StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The fake hand-back changed after verification.");
                stream.Position = 0;
                return stream;
            }
            catch
            {
                stream.Dispose();
                throw;
            }
        }

        public void CleanupUncommittedTemporary(StagedTransfer transfer) { }
    }

    private sealed class TestHandbackEnvironment(SecurityIdentifier user, string profile,
        string[]? syncRoots = null)
        : IStagedHandbackEnvironment
    {
        public void RequireServiceIdentity() { }
        public SecurityIdentifier ResolveUser(uint? sessionId) => user;
        public string ResolveProfilePath(SecurityIdentifier userSid) => profile;
        public IEnumerable<string> KnownSyncRoots(string profilePath, SecurityIdentifier userSid) =>
            syncRoots ?? Array.Empty<string>();
    }

    private sealed class TestPublicationGate : IStagedPublicationGate, IDisposable
    {
        public readonly List<(Guid TransferId, uint Outcome)> Disposals = [];
        public bool HoldReleasedStages { get; set; } = true;
        public int AuthorizeCalls { get; private set; }
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
        { AuthorizeCalls++; return this; }
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
        {
            Disposals.Add((transferId, outcome));
            return outcome != StageDisposeOutcome.Released || HoldReleasedStages;
        }
        public void Dispose() { }
    }

    private static IEnumerable<TransferNotification> DrainTransfers(NotificationSubscription subscription)
    {
        while (subscription.Reader.TryRead(out AgentNotification? notification))
            if (notification is TransferNotification transfer) yield return transfer;
    }

    private sealed class CancelDuringCopyFileStream(string path, CancellationTokenSource cancellation)
        : FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)
    {
        public override Task CopyToAsync(Stream destination, int bufferSize,
            CancellationToken cancellationToken)
        {
            cancellation.Cancel();
            return base.CopyToAsync(destination, bufferSize, cancellation.Token);
        }
    }
}
