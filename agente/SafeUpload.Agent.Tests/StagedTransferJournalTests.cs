using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferJournalTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    public void Dispose() => _workspace.Dispose();

    private StagedTransferJournal Journal() =>
        new(Path.Combine(_workspace.Root, "journal"));

    private StagedTransfer Transfer() => new(
        Guid.NewGuid(),
        Path.Combine(_workspace.Root, "staging", "document.txt"),
        Path.Combine(_workspace.Root, "destination", "document.txt"),
        DestinationKind.RemovableDrive,
        "explorer.exe", 1234, 1);

    [Fact]
    public async Task Sealed_transfer_survives_service_restart()
    {
        var transfer = Transfer();
        await Journal().CreateAsync(transfer, CancellationToken.None);
        await Journal().TransitionAsync(
            transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);

        var recovered = await Journal().ReadPendingAsync(CancellationToken.None);

        var entry = Assert.Single(recovered);
        Assert.Equal(transfer, entry.Transfer);
        Assert.Equal(TransferJournalState.Sealed, entry.State);
    }

    [Fact]
    public async Task Duplicate_id_cannot_replace_previous_destination()
    {
        var transfer = Transfer();
        await Journal().CreateAsync(transfer, CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() => Journal().CreateAsync(
            transfer with { DestinationPath = "E:\\other.txt" }, CancellationToken.None));
        Assert.Equal(transfer.DestinationPath,
            (await Journal().ReadAsync(transfer.TransferId, CancellationToken.None))
            .Transfer.DestinationPath);
    }

    [Fact]
    public async Task Approval_cannot_skip_inspection_or_publish_without_digest()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Approved, null, CancellationToken.None));

        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Allocated, TransferJournalState.Sealed,
            null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting,
            null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            null, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.Approved,
            TransferJournalState.Publishing, null, CancellationToken.None));
    }

    [Fact]
    public async Task Publishing_state_and_digest_survive_restart()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Allocated, TransferJournalState.Sealed,
            null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting,
            null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            null, CancellationToken.None);

        string digest = new('a', 64);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Approved, TransferJournalState.Publishing,
            digest, CancellationToken.None);

        var recovered = Assert.Single(await Journal().ReadPendingAsync(CancellationToken.None));
        Assert.Equal(TransferJournalState.Publishing, recovered.State);
        Assert.Equal(digest, recovered.Sha256Hex);
    }

    [Theory]
    [InlineData(TransferJournalState.Allocated)]
    [InlineData(TransferJournalState.Inspecting)]
    [InlineData(TransferJournalState.Approved)]
    public async Task Interrupted_unreleased_version_is_retained_on_restart(
        TransferJournalState state)
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        if (state != TransferJournalState.Allocated)
        {
            await journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Allocated, TransferJournalState.Sealed,
                null, CancellationToken.None);
            await journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Sealed, TransferJournalState.Inspecting,
                null, CancellationToken.None);
            if (state == TransferJournalState.Approved)
            {
                await journal.TransitionAsync(transfer.TransferId,
                    TransferJournalState.Inspecting, TransferJournalState.Approved,
                    null, CancellationToken.None);
            }
        }

        await Journal().RetainInterruptedAsync(CancellationToken.None);

        var recovered = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Retained, recovered.State);
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    [Theory]
    [InlineData(true, TransferJournalState.Released)]
    [InlineData(false, TransferJournalState.Retained)]
    public async Task Crash_after_publication_does_not_overwrite_a_changed_destination(
        bool sameContent,
        TransferJournalState expected)
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Allocated, TransferJournalState.Sealed,
            null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting,
            null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            null, CancellationToken.None);

        const string approved = "approved bytes";
        string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(approved)));
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Approved, TransferJournalState.Publishing,
            digest, CancellationToken.None);
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        await File.WriteAllTextAsync(transfer.DestinationPath,
            sameContent ? approved : "changed by another writer");

        await Journal().ReconcilePublishingAsync(CancellationToken.None);

        Assert.Equal(expected,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        Assert.Equal(sameContent ? approved : "changed by another writer",
            await File.ReadAllTextAsync(transfer.DestinationPath));
    }
}
