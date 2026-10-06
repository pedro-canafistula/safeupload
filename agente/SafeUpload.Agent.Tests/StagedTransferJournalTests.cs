using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
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

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Redirected_manifest_is_rejected_without_changing_external_acl(
        bool hardLink, bool restart)
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string path = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        string outside = Path.Combine(_workspace.Root, "outside.json");
        File.Copy(path, outside);
        var outsideFile = new FileInfo(outside);
        var security = outsideFile.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        outsideFile.SetAccessControl(security);
        string priorSecurity = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
        byte[] priorBytes = await File.ReadAllBytesAsync(outside);
        File.Delete(path);
        if (hardLink)
        {
            if (!CreateHardLink(path, outside, IntPtr.Zero))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        else File.CreateSymbolicLink(path, outside);
        try
        {
            if (restart) Assert.Throws<IOException>(() => Journal());
            else await Assert.ThrowsAsync<IOException>(() => journal.ReadAsync(transfer.TransferId, CancellationToken.None));
            Assert.Equal(priorBytes, await File.ReadAllBytesAsync(outside));
            Assert.Equal(priorSecurity, outsideFile.GetAccessControl()
                .GetSecurityDescriptorSddlForm(AccessControlSections.All));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Oversized_manifest_is_rejected_before_deserialization_and_retained()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string path = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        await File.AppendAllTextAsync(path, new string(' ', 128 * 1024));
        byte[] prior = await File.ReadAllBytesAsync(path);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(transfer.TransferId, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().RetainInterruptedAsync(CancellationToken.None));
        Assert.Equal(prior, await File.ReadAllBytesAsync(path));
    }

    [Theory]
    [InlineData("null-transfer")]
    [InlineData("unknown-state")]
    [InlineData("negative-generation")]
    [InlineData("relative-destination")]
    [InlineData("invalid-owner")]
    [InlineData("unsealed-publication")]
    [InlineData("zero-rename")]
    [InlineData("invalid-tombstone")]
    public async Task Malformed_manifest_is_rejected_without_recovery_mutation(string corruption)
    {
        var journal = Journal();
        var transfer = Transfer();
        var entry = await journal.CreateAsync(transfer, CancellationToken.None);
        entry = corruption switch
        {
            "null-transfer" => entry with { Transfer = null! },
            "unknown-state" => entry with { State = (TransferJournalState)99 },
            "negative-generation" => entry with { DestinationGeneration = -1 },
            "relative-destination" => entry with { Transfer = transfer with { DestinationPath = "relative.txt" } },
            "invalid-owner" => entry with { Transfer = transfer with { ProcessId = 0 } },
            "unsealed-publication" => entry with { State = TransferJournalState.Publishing, Sha256Hex = new string('A', 64) },
            "zero-rename" => entry with { PendingRename = new StagedRename(0, transfer.DestinationPath, false) },
            "invalid-tombstone" => entry with { NamespaceTombstones = new StagedNameTombstone(transfer.DestinationPath, -1, null) },
            _ => throw new ArgumentException(corruption)
        };
        string path = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        await File.WriteAllTextAsync(path, System.Text.Json.JsonSerializer.Serialize(entry));
        byte[] prior = await File.ReadAllBytesAsync(path);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(transfer.TransferId, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().RetainInterruptedAsync(CancellationToken.None));
        Assert.Equal(prior, await File.ReadAllBytesAsync(path));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Recovery_rejects_unexpected_directory_without_changing_external_acl(bool link)
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string outside = Path.Combine(_workspace.Root, "outside-folder");
        string child = Path.Combine(_workspace.Root, "journal", "unexpected");
        Directory.CreateDirectory(outside);
        string data = Path.Combine(outside, "retained.txt");
        await File.WriteAllTextAsync(data, "retained external bytes");
        var info = new DirectoryInfo(outside);
        string prior = info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        if (link) Directory.CreateSymbolicLink(child, outside);
        else Directory.CreateDirectory(child);
        try
        {
            Assert.Throws<IOException>(() => Journal());
            Assert.Equal(prior, info.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
            Assert.Equal("retained external bytes", await File.ReadAllTextAsync(data));
        }
        finally { Directory.Delete(child); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Unsafe_write_grant_is_rejected_and_never_silently_repaired(bool directory, bool restart)
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        FileSystemSecurity security = directory ? new DirectoryInfo(Path.GetDirectoryName(manifest)!).GetAccessControl() :
            new FileInfo(manifest).GetAccessControl();
        var rule = new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Write, AccessControlType.Allow);
        if (directory)
        {
            var directorySecurity = (DirectorySecurity)security;
            directorySecurity.AddAccessRule(rule);
            new DirectoryInfo(Path.GetDirectoryName(manifest)!).SetAccessControl(directorySecurity);
        }
        else
        {
            var fileSecurity = (FileSecurity)security;
            fileSecurity.AddAccessRule(rule);
            new FileInfo(manifest).SetAccessControl(fileSecurity);
        }
        byte[] prior = await File.ReadAllBytesAsync(manifest);
        // Read back the persisted descriptor: Windows may add the
        // auto-inherited control bit when SetAccessControl returns.
        var persisted = directory ? (FileSystemSecurity)new DirectoryInfo(Path.GetDirectoryName(manifest)!).GetAccessControl() :
            new FileInfo(manifest).GetAccessControl();
        string priorSecurity = persisted.GetSecurityDescriptorSddlForm(AccessControlSections.All);
        if (restart) Assert.Throws<UnauthorizedAccessException>(() => Journal());
        else await Assert.ThrowsAsync<UnauthorizedAccessException>(() => journal.ReadAsync(transfer.TransferId, CancellationToken.None));
        var after = directory ? (FileSystemSecurity)new DirectoryInfo(Path.GetDirectoryName(manifest)!).GetAccessControl() :
            new FileInfo(manifest).GetAccessControl();
        Assert.Equal(priorSecurity, after.GetSecurityDescriptorSddlForm(AccessControlSections.All));
        Assert.Equal(prior, await File.ReadAllBytesAsync(manifest));
    }

    [Fact]
    public async Task Maximum_unicode_namespace_history_round_trips_and_excess_preserves_the_head()
    {
        var journal = Journal();
        // Protocol paths have at most 511 UTF-16 characters; JSON may escape
        // each character to six bytes. Exercise the full 16-name history.
        string folder = Path.Combine(_workspace.Root, new string('\u4E2D', 180), new string('\u4E2D', 180));
        var transfer = Transfer() with { DestinationPath = Path.Combine(folder, "0.txt") };
        await journal.CreateAsync(transfer, CancellationToken.None);
        for (ulong id = 1; id <= 16; id++)
        {
            string destination = Path.Combine(folder, id + ".txt");
            await journal.PrepareRenameAsync(transfer.TransferId, id, transfer.ProcessId, destination, false, CancellationToken.None);
            await journal.CompleteRenameAsync(transfer.TransferId, id, transfer.ProcessId, destination, true, CancellationToken.None);
        }
        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        byte[] prior = await File.ReadAllBytesAsync(manifest);
        Assert.True(prior.Length < StagedJournalFile.MaximumManifestBytes);
        var current = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(Path.Combine(folder, "16.txt"), current.Transfer.DestinationPath);
        await Assert.ThrowsAsync<IOException>(() => journal.PrepareRenameAsync(transfer.TransferId, 17,
            transfer.ProcessId, Path.Combine(folder, "17.txt"), false, CancellationToken.None));
        Assert.Equal(prior, await File.ReadAllBytesAsync(manifest));
    }

    [Fact]
    public async Task Incomplete_json_is_retained_and_never_recovered_as_an_allocation()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string path = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        await File.WriteAllTextAsync(path, "{\"Transfer\":");
        byte[] prior = await File.ReadAllBytesAsync(path);
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(transfer.TransferId, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().RetainInterruptedAsync(CancellationToken.None));
        Assert.Equal(prior, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task Manifest_reader_keeps_prior_state_during_atomic_replacement()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string path = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        using var reader = StagedJournalFile.Open(path);
        Assert.Throws<IOException>(() => new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete));
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        var prior = await System.Text.Json.JsonSerializer.DeserializeAsync<TransferJournalEntry>(reader);
        Assert.Equal(TransferJournalState.Allocated, prior!.State);
        Assert.Equal(TransferJournalState.Sealed, (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Later_allocation_prevents_stale_approval_and_justification_after_restart()
    {
        var journal = Journal();
        var first = Transfer();
        var created = await journal.CreateAsync(first, CancellationToken.None);
        await journal.SealAsync(first.TransferId, first.ProcessId, first.StagePath, CancellationToken.None);
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Blocked, new string('A', 64), CancellationToken.None,
            blockedEvidence: new BlockedTransferEvidence(1, null, WindowClosed: true));
        var second = first with { TransferId = Guid.NewGuid(), StagePath = first.StagePath + ".next" };
        var next = await journal.CreateAsync(second, CancellationToken.None);
        Assert.True(next.DestinationGeneration > created.DestinationGeneration);
        await Assert.ThrowsAsync<IOException>(() => Journal().TransitionAsync(first.TransferId,
            TransferJournalState.Blocked, TransferJournalState.Inspecting, null, CancellationToken.None));
        string moved = second.DestinationPath + ".other";
        await journal.PrepareRenameAsync(second.TransferId, 92, second.ProcessId, moved, false, CancellationToken.None);
        await journal.CompleteRenameAsync(second.TransferId, 92, second.ProcessId, moved, true, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => Journal().TransitionAsync(first.TransferId,
            TransferJournalState.Blocked, TransferJournalState.Inspecting, null, CancellationToken.None));
        var third = await Journal().CreateAsync(second with { TransferId = Guid.NewGuid() }, CancellationToken.None);
        Assert.True(third.DestinationGeneration > next.DestinationGeneration + 1);
    }

    [Fact]
    public async Task Blocked_transition_requires_a_positive_policy_version()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath,
            CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);

        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Blocked,
            new string('A', 64), CancellationToken.None,
            blockedEvidence: new BlockedTransferEvidence(0, null, WindowClosed: true)));

        Assert.Equal(TransferJournalState.Inspecting,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Replacement_reserves_both_names_and_commit_supersedes_target_across_restart()
    {
        var journal = Journal();
        var target = Transfer();
        await journal.CreateAsync(target, CancellationToken.None);
        await journal.SealAsync(target.TransferId, target.ProcessId, target.StagePath, CancellationToken.None);
        var source = target with { TransferId = Guid.NewGuid(), DestinationPath = target.DestinationPath + ".tmp" };
        await journal.CreateAsync(source, CancellationToken.None);
        await journal.PrepareRenameAsync(source.TransferId, 101, source.ProcessId, target.DestinationPath, false, CancellationToken.None);
        foreach (var path in new[] { source.DestinationPath, target.DestinationPath })
            await Assert.ThrowsAsync<IOException>(() => Journal().CreateAsync(
                source with { TransferId = Guid.NewGuid(), DestinationPath = path }, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => Journal().TransitionAsync(target.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None));
        var committed = await Journal().CompleteRenameAsync(source.TransferId, 101, source.ProcessId,
            target.DestinationPath, true, CancellationToken.None);
        Assert.Equal(source.DestinationPath, committed.NamespaceTombstones!.DestinationPath);
        Assert.True(committed.DestinationGeneration > 1);
        await Assert.ThrowsAsync<IOException>(() => Journal().TransitionAsync(target.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None));
        Assert.Equal(committed, await Journal().CompleteRenameAsync(source.TransferId, 101,
            source.ProcessId, target.DestinationPath, true, CancellationToken.None));
    }

    [Fact]
    public async Task Rename_cycles_preserve_all_source_barriers_and_allow_explicit_new_saves()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string other = transfer.DestinationPath + ".other";
        foreach (var (transaction, path) in new[] { (1UL, other), (2UL, transfer.DestinationPath), (3UL, other) })
        {
            await journal.PrepareRenameAsync(transfer.TransferId, transaction, transfer.ProcessId,
                path, false, CancellationToken.None);
            await journal.CompleteRenameAsync(transfer.TransferId, transaction, transfer.ProcessId,
                path, true, CancellationToken.None);
            journal = Journal();
        }
        var moved = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(3, moved.DestinationGeneration);
        var reused = await journal.CreateAsync(transfer with { TransferId = Guid.NewGuid() }, CancellationToken.None);
        Assert.Equal(5, reused.DestinationGeneration);
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
    }

    [Fact]
    public async Task Publication_reserves_destination_until_rename_outcome_is_durable()
    {
        var journal = Journal();
        var first = Transfer();
        await journal.CreateAsync(first, CancellationToken.None);
        await journal.SealAsync(first.TransferId, first.ProcessId, first.StagePath, CancellationToken.None);
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Approved, new string('B', 64), CancellationToken.None);
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Approved,
            TransferJournalState.Publishing, null, CancellationToken.None);
        var next = first with { TransferId = Guid.NewGuid(), StagePath = first.StagePath + ".next" };
        await Assert.ThrowsAsync<IOException>(() => journal.CreateAsync(next, CancellationToken.None));
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Publishing,
            TransferJournalState.Released, null, CancellationToken.None);
        await journal.CreateAsync(next, CancellationToken.None);
    }

    [Fact]
    public async Task Retried_kernel_seal_does_not_reset_inspection_after_reply_loss()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.RetainInterruptedAsync(CancellationToken.None);
        var sealedVersion = await journal.SealAsync(transfer.TransferId, transfer.ProcessId,
            transfer.StagePath, CancellationToken.None);
        Assert.True(sealedVersion.SealedOnce);
        Assert.Equal(TransferJournalState.Sealed, sealedVersion.State);
        var inspecting = await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None);
        Assert.Equal(inspecting, await Journal().SealAsync(transfer.TransferId, transfer.ProcessId,
            transfer.StagePath, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId + 1, transfer.StagePath, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath + ".other", CancellationToken.None));
    }

    [Fact]
    public async Task Pending_namespace_transaction_cannot_be_sealed()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.PrepareRenameAsync(transfer.TransferId, 91, transfer.ProcessId,
            transfer.DestinationPath + ".renamed", false, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None));
        Assert.False((await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).SealedOnce);
    }

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

    [Fact]
    public async Task State_history_round_trips_the_release_timeline_in_utc_order()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Approved, null, CancellationToken.None);
        string digest = new('A', 64);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Approved,
            TransferJournalState.Publishing, digest, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Publishing,
            TransferJournalState.Released, null, CancellationToken.None);

        var restored = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(new[]
        {
            TransferJournalState.Allocated, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            TransferJournalState.Publishing, TransferJournalState.Released
        }, restored.StateHistory.Select(change => change.State));
        Assert.All(restored.StateHistory, change => Assert.Equal(TimeSpan.Zero, change.OccurredAtUtc.Offset));
        Assert.True(restored.StateHistory.Zip(restored.StateHistory.Skip(1),
            (left, right) => right.OccurredAtUtc > left.OccurredAtUtc).All(static monotone => monotone));
    }

    [Fact]
    public async Task Older_manifest_without_state_history_remains_readable_and_migrates_on_next_transition()
    {
        var transfer = Transfer();
        var journal = Journal();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(manifest))!.AsObject();
        document.Remove("StateHistory");
        await File.WriteAllTextAsync(manifest, document.ToJsonString());

        var legacy = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Empty(legacy.StateHistory);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);
        var migrated = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(new[] { TransferJournalState.Allocated, TransferJournalState.Sealed },
            migrated.StateHistory.Select(change => change.State));
    }

    [Theory]
    [InlineData("nonmonotone")]
    [InlineData("wrong-final-state")]
    [InlineData("invalid-seed")]
    [InlineData("too-long")]
    public async Task Invalid_state_history_is_rejected(string corruption)
    {
        var transfer = Transfer();
        var journal = Journal();
        TransferJournalEntry entry = await journal.CreateAsync(transfer, CancellationToken.None);
        entry = corruption switch
        {
            "nonmonotone" => entry with
            {
                StateHistory =
                [
                    new(TransferJournalState.Allocated, entry.UpdatedAtUtc),
                    new(TransferJournalState.Allocated, entry.UpdatedAtUtc)
                ]
            },
            "wrong-final-state" => entry with
            {
                StateHistory = [new(TransferJournalState.Sealed, entry.UpdatedAtUtc)]
            },
            "invalid-seed" => entry with
            {
                State = TransferJournalState.Released,
                Sha256Hex = new string('A', 64),
                SealedOnce = true,
                StateHistory = [new(TransferJournalState.Released, entry.UpdatedAtUtc)]
            },
            "too-long" => entry with
            {
                StateHistory = Enumerable.Range(0, TransferJournalEntry.MaximumStateHistory + 1)
                    .Select(index => new TransferJournalStateChange(TransferJournalState.Allocated,
                        entry.UpdatedAtUtc.AddTicks(index))).ToArray()
            },
            _ => throw new ArgumentException(corruption)
        };
        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        await File.WriteAllTextAsync(manifest, System.Text.Json.JsonSerializer.Serialize(entry));
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.ReadAsync(
            transfer.TransferId, CancellationToken.None));
    }
}
