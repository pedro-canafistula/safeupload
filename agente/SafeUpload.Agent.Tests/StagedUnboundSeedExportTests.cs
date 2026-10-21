using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using System.Security.Principal;
using System.Text.Json;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedHandbackTests
{
    private sealed class SeedReadEvaluator(StagedSeedAuthority result, bool fail = false) : IStagedSeedReadAuthorityEvaluator
    {
        public int Calls { get; private set; }
        public StagedSeedAuthority Evaluate(StagedTransfer requestor, SafeFileHandle source)
        {
            Calls++;
            Assert.False(source.IsInvalid); Assert.False(source.IsClosed);
            if (fail) throw new IOException("Injected descriptor/token lookup failure");
            return result;
        }
    }

    private async Task<(StagedTransferJournal Journal, StagedTransfer Transfer, SeedReadEvaluator Evaluator)>
        AllocateUnboundSeed(StagedSeedAuthority authority, uint disposition = 1, bool exists = true, bool fail = false)
    {
        string destination = Path.Combine(_workspace.Root, "protected", "seeded.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        if (exists) await File.WriteAllTextAsync(destination, "previous public content\n");
        var journal = new StagedTransferJournal(_journalRoot);
        var evaluator = new SeedReadEvaluator(authority, fail);
        var allocator = new StagedTransferAllocator(_stagingRoot, journal, seedReadAuthority: evaluator);
        var transfer = await allocator.AllocateAsync(destination, DestinationKind.RemovableDrive, "explorer.exe",
            4321, 7, disposition, null, CancellationToken.None,
            requestorSid: TestRequestorSid, requestorProcessCreationTime: 123456);
        return (journal, transfer, evaluator);
    }

    [Theory]
    [InlineData(StagedSeedAuthority.Allowed, false, null)]
    [InlineData(StagedSeedAuthority.Denied, false, "seed_export_denied")]
    [InlineData(StagedSeedAuthority.Unproven, false, "seed_export_unproven")]
    [InlineData(StagedSeedAuthority.Allowed, true, "seed_export_unproven")]
    public async Task Unbound_seeded_block_uses_persisted_authority_and_recovers_without_disclosure(
        StagedSeedAuthority authority, bool evaluatorThrows, string? reason)
    {
        var (journal, transfer, evaluator) = await AllocateUnboundSeed(authority, fail: evaluatorThrows);
        var allocated = await journal.ReadAsync(transfer.TransferId, default);
        Assert.NotNull(allocated.UnboundSeedExport); Assert.Null(allocated.SeedProvenance); Assert.Null(allocated.BoundAllocation);
        using (var original = StagedStageFile.Open(transfer.DestinationPath))
            Assert.Equal(original.Identity, allocated.UnboundSeedExport.SourceIdentity);
        Assert.Equal(1, evaluator.Calls);
        await File.AppendAllTextAsync(transfer.StagePath, "CPF: 529.982.247-25");
        string blockedBytes = await File.ReadAllTextAsync(transfer.StagePath);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated, TransferJournalState.Sealed, null, default);
        var policy = await PolicyAsync(true); var broker = new StagedJustifications();
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        using var owner = _notifications.Subscribe(7, TestRequestorSid);
        Assert.Equal(StagedTransferOutcome.Blocked, await Publisher(journal, policy, broker, copier).PublishAsync(transfer, default));
        var blocked = await new StagedTransferJournal(_journalRoot).ReadAsync(transfer.TransferId, default);
        var notice = Assert.Single(DrainTransfers(owner), n => n.Phase == TransferPhase.Blocked);
        Assert.Equal(reason, blocked.HandbackFailureReason);
        Assert.Equal(allocated.UnboundSeedExport, blocked.UnboundSeedExport);
        Assert.Equal("previous public content\n", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal(reason is null ? 1 : 0, copier.CopyCount);
        Assert.Equal(reason is null, notice.OverrideAllowed);
        Assert.Equal(reason is null, broker.TryConsume(transfer.TransferId.ToString(), 7, TestRequestorSid, out _));
        if (reason is null)
        {
            Assert.Equal(StagedHandbackState.Verified, blocked.HandbackState);
            Assert.Equal(blockedBytes, await File.ReadAllTextAsync(blocked.HandbackPath!));
            Assert.Null(notice.BlockReason);
        }
        else
        {
            Assert.Equal(StagedHandbackState.Failed, blocked.HandbackState);
            Assert.Equal(StagedBlockReason.SeedExportRestricted, notice.BlockReason);
            Assert.Null(notice.HandbackPath); Assert.False(notice.HandbackVerified);
            Assert.Null(blocked.HandbackPath); Assert.Null(blocked.HandbackLength);
            Assert.True(blocked.JustificationWindowClosed); Assert.Null(blocked.JustificationExpiresAtUtc);
            Assert.True(File.Exists(transfer.StagePath)); Assert.Equal(blockedBytes, await File.ReadAllTextAsync(transfer.StagePath));
            Assert.False(Directory.Exists(Path.Combine(_workspace.Root, "profile")));
            Assert.False((await journal.TryBeginStageCleanupAsync(transfer.TransferId, default)).StageCleanupStarted);
            Assert.False(await journal.ArchiveCompletedAsync(blocked, default));
            var restarted = new StagedTransferJournal(_journalRoot);
            await Publisher(restarted, policy, new StagedJustifications(), copier).RecoverBlockedAsync(blocked, default);
            var recovered = await restarted.ReadAsync(transfer.TransferId, default);
            Assert.Equal(reason, recovered.HandbackFailureReason); Assert.Equal(0, copier.CopyCount);
            Assert.Equal(blocked.UnboundSeedExport, recovered.UnboundSeedExport);
            Assert.Equal(blockedBytes, await File.ReadAllTextAsync(transfer.StagePath));
        }
    }

    [Theory]
    [InlineData(3u, false)] // OPEN_IF absent
    [InlineData(2u, false)] // CREATE absent
    [InlineData(0u, true)] // SUPERSEDE
    [InlineData(4u, true)] // OVERWRITE
    [InlineData(5u, true)] // OVERWRITE_IF
    public async Task Unbound_nonseeded_block_keeps_ordinary_handback_without_evaluating_read(uint disposition, bool exists)
    {
        var (journal, transfer, evaluator) = await AllocateUnboundSeed(StagedSeedAuthority.Denied, disposition, exists);
        Assert.Equal(0, evaluator.Calls);
        var entry = await journal.ReadAsync(transfer.TransferId, default);
        Assert.Null(entry.UnboundSeedExport); Assert.Null(StagedSeedExport.Failure(entry));
        Assert.DoesNotContain("UnboundSeedExport", JsonSerializer.Serialize(entry));
        await File.WriteAllTextAsync(transfer.StagePath, "CPF: 529.982.247-25");
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated, TransferJournalState.Sealed, null, default);
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        await Publisher(journal, await PolicyAsync(true), new StagedJustifications(), copier).PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        Assert.Equal(StagedHandbackState.Verified, blocked.HandbackState); Assert.Equal(1, copier.CopyCount);
        Assert.Equal("CPF: 529.982.247-25", await File.ReadAllTextAsync(blocked.HandbackPath!));
    }

    [Theory]
    [InlineData(StagedSeedAuthority.Denied)]
    [InlineData(StagedSeedAuthority.Unproven)]
    public async Task Unbound_seed_restriction_does_not_change_clean_publication_and_survives_archive(StagedSeedAuthority authority)
    {
        var (journal, transfer, _) = await AllocateUnboundSeed(authority);
        var receipt = (await journal.ReadAsync(transfer.TransferId, default)).UnboundSeedExport;
        await File.AppendAllTextAsync(transfer.StagePath, "clean edit");
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated, TransferJournalState.Sealed, null, default);
        _gate.HoldReleasedStages = false;
        var copier = new RecordingHandbackCopier(Path.Combine(_workspace.Root, "profile"));
        var publisher = Publisher(journal, await PolicyAsync(true), new StagedJustifications(), copier);
        Assert.Equal(StagedTransferOutcome.Released, await publisher.PublishAsync(transfer, default));
        Assert.Equal("previous public content\nclean edit", await File.ReadAllTextAsync(transfer.DestinationPath));
        Assert.Equal(0, copier.CopyCount);
        await publisher.ArchiveCompletedTransfersAsync(default);
        Assert.False(File.Exists(Path.Combine(_journalRoot, transfer.TransferId.ToString("N") + ".json")));
        var terminal = await new StagedTransferJournal(_journalRoot).ReadAsync(transfer.TransferId, default);
        Assert.Equal(TransferJournalState.Released, terminal.State); Assert.True(terminal.StageDeleted);
        Assert.Equal(receipt, terminal.UnboundSeedExport);
    }

    [Theory]
    [InlineData(1u, true)]
    [InlineData(3u, true)]
    [InlineData(5u, false)]
    public async Task Unbound_private_followup_inherits_public_seed_receipt_only_when_preserving(uint disposition, bool preserves)
    {
        var (journal, parent, evaluator) = await AllocateUnboundSeed(StagedSeedAuthority.Denied);
        await journal.TransitionAsync(parent.TransferId, TransferJournalState.Allocated, TransferJournalState.Sealed, null, default);
        var original = (await journal.ReadAsync(parent.TransferId, default)).UnboundSeedExport;
        var allocator = new StagedTransferAllocator(_stagingRoot, journal, seedReadAuthority: evaluator);
        var child = await allocator.AllocateAsync(parent.DestinationPath, parent.Destination, parent.ProcessName,
            parent.ProcessId, parent.SessionId, disposition, parent, default,
            requestorSid: parent.RequestorSid, requestorProcessCreationTime: parent.RequestorProcessCreationTime);
        var entry = await new StagedTransferJournal(_journalRoot).ReadAsync(child.TransferId, default);
        Assert.Equal(1, evaluator.Calls);
        Assert.Equal(preserves ? original : null, entry.UnboundSeedExport);
        Assert.Equal(preserves ? "seed_export_denied" : null, StagedSeedExport.Failure(entry));
        Assert.Equal(preserves ? "previous public content\n" : "", await File.ReadAllTextAsync(child.StagePath));
    }

    [Fact]
    public async Task Unbound_old_journal_without_seed_field_roundtrips_unchanged()
    {
        var journal = new StagedTransferJournal(_journalRoot);
        var transfer = CreateBlockedCandidate(journal, "private bytes", 7);
        var entry = await journal.ReadAsync(transfer.TransferId, default);
        string json = JsonSerializer.Serialize(entry);
        Assert.DoesNotContain("UnboundSeedExport", json);
        Assert.Equal(entry, JsonSerializer.Deserialize<TransferJournalEntry>(json));
        var recovered = await new StagedTransferJournal(_journalRoot).ReadAsync(transfer.TransferId, default);
        Assert.Null(recovered.UnboundSeedExport); Assert.Null(StagedSeedExport.Failure(recovered));
    }

    [Fact]
    public async Task Unbound_seed_denial_guards_real_copier_lease_and_justification_boundaries()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (journal, transfer, _) = await AllocateUnboundSeed(StagedSeedAuthority.Denied);
        await File.AppendAllTextAsync(transfer.StagePath, "CPF: 529.982.247-25");
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated, TransferJournalState.Sealed, null, default);
        var policy = await PolicyAsync(true); var broker = new StagedJustifications();
        await Publisher(journal, policy, broker, new RecordingHandbackCopier(Path.Combine(_workspace.Root, "unused"))).PublishAsync(transfer, default);
        var blocked = await journal.ReadAsync(transfer.TransferId, default);
        string profile = Path.Combine(_workspace.Root, "real-profile");
        var copier = new StagedHandbackCopier(policy, journal, new TestHandbackEnvironment(new SecurityIdentifier(TestRequestorSid), profile));
        using var source = File.OpenRead(transfer.StagePath);
        await Assert.ThrowsAsync<IOException>(() => copier.CopyVerifiedAsync(transfer, source, source.Length, blocked.Sha256Hex!, default));
        Assert.Throws<IOException>(() => copier.OpenVerifiedReadLease(transfer, Path.Combine(profile, "invented.txt"), source.Length, blocked.Sha256Hex!));
        Assert.False(await broker.RememberAsync(journal, transfer.TransferId, 7, TestRequestorSid,
            _ => throw new InvalidOperationException("Must not run"), DateTimeOffset.UtcNow.AddMinutes(1), default));
        Assert.False(Directory.Exists(profile));
    }
}
