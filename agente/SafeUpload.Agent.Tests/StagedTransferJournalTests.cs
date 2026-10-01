using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
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
        Assert.True(entry.SealedOnce);
    }

    [Fact]
    public async Task Prepared_rename_survives_restart_without_authorizing_either_destination()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        string renamed = Path.ChangeExtension(transfer.DestinationPath, ".renamed.txt");
        await journal.PrepareRenameAsync(transfer.TransferId, 77, transfer.ProcessId,
            renamed, true, CancellationToken.None);
        var restarted = Journal();
        await restarted.RetainInterruptedAsync(CancellationToken.None);
        var pending = Assert.Single(await restarted.ReadPendingAsync(CancellationToken.None));
        Assert.Equal(transfer, pending.Transfer);
        Assert.Equal(new StagedRename(77, renamed, true), pending.PendingRename);
        await Assert.ThrowsAsync<IOException>(() => restarted.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None));
        var committed = await restarted.CompleteRenameAsync(transfer.TransferId, 77,
            transfer.ProcessId, renamed, true, CancellationToken.None);
        Assert.Null(committed.PendingRename);
        Assert.Equal(renamed, committed.Transfer.DestinationPath);
        Assert.Equal(TransferJournalState.Sealed, committed.State);
        Assert.Equal(committed, await Journal().CompleteRenameAsync(transfer.TransferId, 77,
            transfer.ProcessId, renamed, true, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => restarted.CompleteRenameAsync(transfer.TransferId,
            77, transfer.ProcessId, renamed, false, CancellationToken.None));
    }

    [Fact]
    public async Task Rename_commit_requires_the_prepared_transaction_owner_and_destination()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string renamed = Path.ChangeExtension(transfer.DestinationPath, ".renamed.txt");
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteRenameAsync(transfer.TransferId,
            77, transfer.ProcessId, renamed, true, CancellationToken.None));
        await journal.PrepareRenameAsync(transfer.TransferId, 77, transfer.ProcessId,
            renamed, false, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteRenameAsync(transfer.TransferId,
            78, transfer.ProcessId, renamed, true, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteRenameAsync(transfer.TransferId,
            77, transfer.ProcessId + 1, renamed, true, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteRenameAsync(transfer.TransferId,
            77, transfer.ProcessId, renamed + ".other", true, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.PrepareRenameAsync(transfer.TransferId,
            78, transfer.ProcessId, renamed, false, CancellationToken.None));
        var aborted = await journal.CompleteRenameAsync(transfer.TransferId, 77,
            transfer.ProcessId, renamed, false, CancellationToken.None);
        Assert.Null(aborted.PendingRename);
        Assert.Equal(transfer, aborted.Transfer);
        Assert.False(aborted.SealedOnce);
        Assert.Equal(TransferJournalState.Allocated, aborted.State);
        Assert.Equal(aborted, await Journal().CompleteRenameAsync(transfer.TransferId, 77,
            transfer.ProcessId, renamed, false, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteRenameAsync(transfer.TransferId,
            77, transfer.ProcessId, renamed, true, CancellationToken.None));
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
    public async Task Windows_journal_directory_and_manifest_exclude_ordinary_users()
    {
        if (!OperatingSystem.IsWindows()) return;

        var transfer = Transfer();
        string path = Path.Combine(_workspace.Root, "journal");
        await Journal().CreateAsync(transfer, CancellationToken.None);

        foreach (FileSystemSecurity security in new FileSystemSecurity[]
        {
            new DirectoryInfo(path).GetAccessControl(),
            new FileInfo(Path.Combine(path, transfer.TransferId.ToString("N") + ".json"))
                .GetAccessControl()
        })
        {
            var entries = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>().ToArray();
            Assert.DoesNotContain(entries, rule => rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier sid &&
                (sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) ||
                 sid.IsWellKnown(WellKnownSidType.WorldSid) ||
                 sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid)));
        }
    }

    [Fact]
    public void Journal_rejects_an_untrusted_parent_in_protected_mode()
    {
        if (!OperatingSystem.IsWindows()) return;

        var parent = new DirectoryInfo(_workspace.Root);
        var security = parent.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.DeleteSubdirectoriesAndFiles, AccessControlType.Allow));
        parent.SetAccessControl(security);

        Assert.Throws<UnauthorizedAccessException>(() => new StagedTransferJournal(
            Path.Combine(_workspace.Root, "protected-journal"),
            requireProtectedParent: true));
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
        Assert.Equal(state == TransferJournalState.Allocated
            ? TransferJournalState.Unsealed : TransferJournalState.Retained,
            recovered.State);
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    [Fact]
    public async Task Recovered_unsealed_allocation_cannot_enter_inspection()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await Journal().RetainInterruptedAsync(CancellationToken.None);

        var recovered = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Unsealed, recovered.State);
        Assert.False(recovered.SealedOnce);
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.Unsealed,
            TransferJournalState.Inspecting, null, CancellationToken.None));

        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Unsealed, TransferJournalState.Sealed,
            null, CancellationToken.None);
        var sealedEntry = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.True(sealedEntry.SealedOnce);
        await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting,
            null, CancellationToken.None);
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
