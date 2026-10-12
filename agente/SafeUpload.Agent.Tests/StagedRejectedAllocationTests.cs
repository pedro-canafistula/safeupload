using System.ComponentModel;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedRejectedAllocationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    private StagedTransferJournal Journal(Action<StagedJournalWritePoint, TransferJournalEntry>? observer = null) =>
        new(Path.Combine(_workspace.Root, "journal"), false, observer);

    private Task<StagedAllocation> Allocate(StagedTransferJournal journal) =>
        new StagedTransferAllocator(Path.Combine(_workspace.Root, "stage"), journal)
            .AllocateForReplyAsync(Path.Combine(_workspace.Root, "public.txt"), DestinationKind.Cloud,
                "writer.exe", 17, 2, 3, null, CancellationToken.None);

    private static StagedRejectedAllocation Reject(StagedAllocation allocation) =>
        Assert.IsType<StagedRejectedAllocation>(StagedRejectedAllocation.FromReply(
            23, 41, allocation, FilterReplyResult.NoWaiter));

#if SAFEUPLOAD_ADMISSION_EVIDENCE
    [Theory]
    [InlineData(unchecked((int)0x8007010B))]
    [InlineData(unchecked((int)0x800704D5))]
    [InlineData(unchecked((int)0x80070005))]
    public void Other_native_reply_errors_never_become_rejection_authority(int status)
    {
        Assert.Equal(FilterReplyResult.Delivered, FilterPort.DecodeReplyResult(0));
        Assert.Equal(FilterReplyResult.NoWaiter, FilterPort.DecodeReplyResult(unchecked((int)0x801F0020)));
        var error = Assert.Throws<Win32Exception>(() => FilterPort.DecodeReplyResult(status));
        Assert.Equal(status, error.NativeErrorCode);
    }
#endif

    [Fact]
    public async Task Delivered_reply_never_creates_cleanup_authority()
    {
        var journal = Journal();
        StagedAllocation allocation = await Allocate(journal);
        Assert.Null(StagedRejectedAllocation.FromReply(23, 41, allocation, FilterReplyResult.Delivered));
        Assert.Null(StagedRejectedAllocation.FromReply(23, 41, null, FilterReplyResult.NoWaiter));
        Assert.True(File.Exists(allocation.Entry.Transfer.StagePath));
        Assert.Equal(allocation.Entry, await journal.ReadAsync(allocation.Entry.Transfer.TransferId, CancellationToken.None));
    }

    [Fact]
    public async Task Exact_unaccepted_allocation_is_removed_without_touching_public_content_or_reusing_generation()
    {
        if (!OperatingSystem.IsWindows()) return;
        string destination = Path.Combine(_workspace.Root, "public.txt");
        await File.WriteAllTextAsync(destination, "original public bytes");
        var journal = Journal();
        StagedAllocation allocation = await Allocate(journal);
        StagedRejectedAllocation rejected = Reject(allocation);
        Assert.Equal(23UL, rejected.MessageId);
        Assert.Equal(41UL, rejected.RequestId);

        await journal.RetireRejectedAllocationAsync(rejected, CancellationToken.None);

        Assert.False(File.Exists(allocation.Entry.Transfer.StagePath));
        Assert.Equal("original public bytes", await File.ReadAllTextAsync(destination));
        TransferJournalEntry retained = await journal.ReadAsync(allocation.Entry.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Unsealed, retained.State);
        Assert.False(retained.SealedOnce);
        Assert.False(retained.StageDeleted);
        Assert.Equal(allocation.Entry.DestinationGeneration, retained.DestinationGeneration);
        StagedAllocation next = await Allocate(journal);
        Assert.True(next.Entry.DestinationGeneration > retained.DestinationGeneration);
        Assert.Equal("original public bytes", await File.ReadAllTextAsync(destination));
    }

    [Fact]
    public async Task Replaced_stage_is_never_deleted_or_used_as_identity_evidence()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = Journal();
        StagedAllocation allocation = await Allocate(journal);
        string original = allocation.Entry.Transfer.StagePath;
        File.Move(original, original + ".retained");
        await File.WriteAllTextAsync(original, "replacement bytes");
        await Assert.ThrowsAsync<IOException>(() => journal.RetireRejectedAllocationAsync(
            Reject(allocation), CancellationToken.None));
        Assert.Equal("replacement bytes", await File.ReadAllTextAsync(original));
        Assert.True(File.Exists(original + ".retained"));
        Assert.Equal(allocation.Entry, await journal.ReadAsync(allocation.Entry.Transfer.TransferId, CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Journal_state_or_generation_change_blocks_cleanup(bool generationChanged)
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = Journal();
        StagedAllocation allocation = await Allocate(journal);
        StagedRejectedAllocation rejected;
        if (generationChanged)
            rejected = Reject(allocation with { Entry = allocation.Entry with {
                DestinationGeneration = allocation.Entry.DestinationGeneration + 1 } });
        else
        {
            rejected = Reject(allocation);
            await journal.TransitionAsync(allocation.Entry.Transfer.TransferId, TransferJournalState.Allocated,
                TransferJournalState.Sealed, null, CancellationToken.None);
        }
        await Assert.ThrowsAsync<IOException>(() => journal.RetireRejectedAllocationAsync(rejected, CancellationToken.None));
        Assert.True(File.Exists(allocation.Entry.Transfer.StagePath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Journal_failure_keeps_exact_obligation_and_retry_finishes_without_reusing_a_name(bool afterReplacement)
    {
        if (!OperatingSystem.IsWindows()) return;
        bool injected = false;
        var journal = Journal((point, entry) => {
            if (injected || entry.State != TransferJournalState.Unsealed ||
                point != (afterReplacement ? StagedJournalWritePoint.AfterReplacement : StagedJournalWritePoint.BeforeReplacement)) return;
            injected = true;
            throw new Win32Exception(5);
        });
        StagedAllocation allocation = await Allocate(journal);
        StagedRejectedAllocation rejected = Reject(allocation);
        await Assert.ThrowsAsync<StagedJournalPersistenceException>(() =>
            journal.RetireRejectedAllocationAsync(rejected, CancellationToken.None));
        Assert.True(injected);
        Assert.True(File.Exists(allocation.Entry.Transfer.StagePath));
        await journal.RetireRejectedAllocationAsync(rejected, CancellationToken.None);
        Assert.False(File.Exists(allocation.Entry.Transfer.StagePath));
        var final = await journal.ReadAsync(allocation.Entry.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(new[] { TransferJournalState.Allocated, TransferJournalState.Unsealed },
            final.StateHistory.Select(s => s.State));
        Assert.Equal(allocation.Entry.DestinationGeneration, final.DestinationGeneration);
    }

    [Fact]
    public async Task Sharing_failure_retains_file_and_same_receipt_can_retry_after_close()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = Journal();
        StagedAllocation allocation = await Allocate(journal);
        StagedRejectedAllocation rejected = Reject(allocation);
        using (File.Open(allocation.Entry.Transfer.StagePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            await Assert.ThrowsAsync<Win32Exception>(() => journal.RetireRejectedAllocationAsync(rejected, CancellationToken.None));
        Assert.True(File.Exists(allocation.Entry.Transfer.StagePath));
        await journal.RetireRejectedAllocationAsync(rejected, CancellationToken.None);
        Assert.False(File.Exists(allocation.Entry.Transfer.StagePath));
    }

    [Fact]
    public async Task Missing_original_identity_preserves_stage()
    {
        var journal = Journal();
        StagedAllocation allocation = await Allocate(journal);
        await Assert.ThrowsAsync<IOException>(() => journal.RetireRejectedAllocationAsync(
            Reject(allocation with { Identity = null }), CancellationToken.None));
        Assert.True(File.Exists(allocation.Entry.Transfer.StagePath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Restart_without_rejection_receipt_never_removes_an_unsealed_stage(bool dispositionWritten)
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = Journal((point, entry) => {
            if (dispositionWritten && entry.State == TransferJournalState.Unsealed && point == StagedJournalWritePoint.AfterReplacement)
                throw new Win32Exception(5);
        });
        StagedAllocation allocation = await Allocate(journal);
        if (dispositionWritten)
            await Assert.ThrowsAsync<StagedJournalPersistenceException>(() => journal.RetireRejectedAllocationAsync(
                Reject(allocation), CancellationToken.None));
        var restarted = Journal();
        await restarted.RetainInterruptedAsync(CancellationToken.None);
        Assert.True(File.Exists(allocation.Entry.Transfer.StagePath));
        Assert.False((await restarted.ReadAsync(allocation.Entry.Transfer.TransferId, CancellationToken.None)).SealedOnce);
    }
}
