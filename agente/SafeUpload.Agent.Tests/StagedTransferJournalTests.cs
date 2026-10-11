using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferJournalTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly ITestOutputHelper _output;

    public StagedTransferJournalTests(ITestOutputHelper output) => _output = output;

    public void Dispose() => _workspace.Dispose();

    private StagedTransferJournal Journal() =>
        new(Path.Combine(_workspace.Root, "journal"));

    private StagedTransfer Transfer()
    {
        string stage = Path.Combine(_workspace.Root, "staging", Guid.NewGuid().ToString("N") + ".txt");
        Directory.CreateDirectory(Path.GetDirectoryName(stage)!);
        File.WriteAllText(stage, "positive fixture stage");
        return new StagedTransfer(
            Guid.NewGuid(), stage,
            Path.Combine(_workspace.Root, "destination", "document.txt"),
            DestinationKind.RemovableDrive,
            "explorer.exe", 1234, 1);
    }

    [Fact]
    public async Task Empty_stage_is_measured_sealed_with_the_empty_digest_and_reserved_state_cannot_be_forged()
    {
        var journal = Journal();
        var transfer = Transfer();
        await File.WriteAllBytesAsync(transfer.StagePath, []);
        await journal.CreateAsync(transfer, CancellationToken.None);
        TransferJournalEntry empty = await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Allocated, TransferJournalState.Sealed,
            new string('A', 64), CancellationToken.None, transfer);
        Assert.Equal(TransferJournalState.Sealed, empty.State);
        Assert.Equal(0, empty.SealedLength);
        Assert.True(empty.SealedOnce);
        Assert.NotNull(empty.StageIdentity);
        Assert.Equal(StagedTransferJournal.EmptySha256Hex, empty.Sha256Hex);
        Assert.Equal(11, (int)TransferJournalState.LegacyEmptyHeld);
        Assert.Equal(12, (int)TransferJournalState.DiscardPending);
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.Sealed, TransferJournalState.LegacyEmptyHeld,
            null, CancellationToken.None));
        Assert.Equal(TransferJournalState.Inspecting, (await journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Empty_sealed_rename_keeps_generation_and_measured_length()
    {
        var journal = Journal();
        var transfer = Transfer();
        await File.WriteAllBytesAsync(transfer.StagePath, []);
        var allocated = await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        string renamed = Path.Combine(_workspace.Root, "destination", "renamed.txt");
        await journal.PrepareRenameAsync(transfer.TransferId, 71, transfer.ProcessId,
            renamed, sealedVersion: true, CancellationToken.None);
        var moved = await journal.CompleteRenameAsync(transfer.TransferId, 71, transfer.ProcessId,
            renamed, commit: true, CancellationToken.None);
        Assert.Equal(TransferJournalState.Sealed, moved.State);
        Assert.Equal(0, moved.SealedLength);
        Assert.Equal(allocated.DestinationGeneration + 1, moved.NamespaceTombstones!.Generation);
        Assert.Equal(transfer.TransferId,
            (await journal.ReadPendingAsync(CancellationToken.None)).Single().Transfer.TransferId);
    }

    [Fact]
    public async Task A_stage_that_becomes_empty_does_not_silently_replace_its_measured_seal()
    {
        var journal = Journal();
        var transfer = Transfer();
        var allocated = await journal.CreateAsync(transfer, CancellationToken.None);
        var sealedEntry = await journal.SealAsync(transfer.TransferId, transfer.ProcessId,
            transfer.StagePath, CancellationToken.None);
        Assert.True(sealedEntry.SealedLength is > 0);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        await File.WriteAllBytesAsync(transfer.StagePath, []);
        var retained = await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Retained, null, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None));
        Assert.Equal(sealedEntry.SealedLength, retained.SealedLength);
        Assert.Equal(allocated.DestinationGeneration, retained.DestinationGeneration);
        Assert.Equal(new[] { TransferJournalState.Allocated, TransferJournalState.SealPending,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, TransferJournalState.Retained },
            retained.StateHistory.Select(change => change.State));
    }

    [Fact]
    public async Task Exact_private_discard_can_finish_after_a_newer_ordinary_allocation_without_touching_it()
    {
        var journal = Journal();
        StagedTransfer older = Transfer();
        TransferJournalEntry oldEntry = await journal.CreateAsync(older, CancellationToken.None);
        string newerStage = Path.Combine(Path.GetDirectoryName(older.StagePath)!, "newer.txt");
        await File.WriteAllTextAsync(newerStage, "newer private bytes");
        StagedTransfer newer = older with { TransferId = Guid.NewGuid(), StagePath = newerStage };
        TransferJournalEntry newEntry = await journal.CreateAsync(newer, CancellationToken.None);
        Assert.Equal(oldEntry.DestinationGeneration + 1, newEntry.DestinationGeneration);
        var request = new StagedDiscardRequest(older.TransferId,
            new StagedVersionIdentity(older.TransferId, oldEntry.DestinationGeneration, oldEntry.StageIdentity!),
            StagedDiscardKind.PrivateVersion);
        Assert.Equal(StagedDiscardStatus.Pending, await journal.BeginOrConfirmDiscardAsync(request,
            CancellationToken.None, older.ProcessId));
        Assert.True(File.Exists(older.StagePath)); // journal intent replies before physical cleanup
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(request, CancellationToken.None));
        Assert.False(File.Exists(older.StagePath));
        Assert.Equal("newer private bytes", await File.ReadAllTextAsync(newer.StagePath));
        Assert.Equal(TransferJournalState.Sealed, (await journal.SealAsync(newer.TransferId,
            newer.ProcessId, newer.StagePath, CancellationToken.None)).State);
        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(older.TransferId,
            older.ProcessId, older.StagePath, CancellationToken.None));
        Assert.False(File.Exists(older.DestinationPath));
    }

    [Fact]
    public async Task Seal_refuses_a_version_superseded_by_a_later_destination_generation()
    {
        var journal = Journal();
        var older = Transfer();
        var newer = Transfer();
        await journal.CreateAsync(older, CancellationToken.None);
        await journal.CreateAsync(newer, CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(older.TransferId,
            older.ProcessId, older.StagePath, CancellationToken.None));
        Assert.Equal(TransferJournalState.Allocated,
            (await journal.ReadAsync(older.TransferId, CancellationToken.None)).State);
        Assert.Equal(TransferJournalState.Sealed,
            (await journal.SealAsync(newer.TransferId, newer.ProcessId,
                newer.StagePath, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Startup_retries_a_durable_seal_pending_classification()
    {
        var journal = Journal();
        var transfer = Transfer();
        await File.WriteAllBytesAsync(transfer.StagePath, []);
        TransferJournalEntry allocated = await journal.CreateAsync(transfer, CancellationToken.None);
        DateTimeOffset pendingAt = allocated.UpdatedAtUtc.AddTicks(1);
        var pending = allocated with
        {
            State = TransferJournalState.SealPending,
            SealedOnce = true,
            SealedLength = null,
            UpdatedAtUtc = pendingAt,
            StateHistory =
            [
                new(TransferJournalState.Allocated, allocated.StateHistory[0].OccurredAtUtc),
                new(TransferJournalState.SealPending, pendingAt)
            ]
        };
        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        await File.WriteAllTextAsync(manifest, System.Text.Json.JsonSerializer.Serialize(pending));

        await Journal().RetainInterruptedAsync(CancellationToken.None);

        var recovered = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Sealed, recovered.State);
        Assert.Equal(0, recovered.SealedLength);
        Assert.Equal(new[] { TransferJournalState.Allocated, TransferJournalState.SealPending,
                TransferJournalState.Sealed },
            recovered.StateHistory.Select(change => change.State));
    }

    [Fact]
    public async Task Seal_pending_identity_mismatch_stays_private_across_startup_retry()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string replacement = transfer.StagePath + ".replacement";
        await File.WriteAllTextAsync(replacement, "replacement file identity");
        File.Delete(transfer.StagePath);
        File.Move(replacement, transfer.StagePath);

        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None));
        TransferJournalEntry pending = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.SealPending, pending.State);
        Assert.Null(pending.SealedLength);

        await Journal().RetainInterruptedAsync(CancellationToken.None);

        TransferJournalEntry recovered = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.SealPending, recovered.State);
        Assert.Null(recovered.SealedLength);
        Assert.False(File.Exists(transfer.DestinationPath));
    }

    [Fact]
    public async Task Seal_pending_never_follows_a_stage_symbolic_link()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        string outside = _workspace.WriteText("outside-stage.txt", "must remain private");
        File.Delete(transfer.StagePath);
        try
        {
            File.CreateSymbolicLink(transfer.StagePath, outside);
        }
        catch (Exception error) when (OperatingSystem.IsWindows() &&
            (error is UnauthorizedAccessException or IOException))
        {
            string message = "Required Windows final-reparse check could not create its symbolic link " +
                $"({error.GetType().Name}, HRESULT 0x{error.HResult:X8}); run this test with an identity " +
                "that can create symbolic links before qualifying the Windows no-follow coverage.";
            _output.WriteLine(message);
            throw new InvalidOperationException(message, error);
        }

        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None));
        TransferJournalEntry pending = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.SealPending, pending.State);
        Assert.Null(pending.SealedLength);
        Assert.Equal("must remain private", await File.ReadAllTextAsync(outside));
    }

    [Fact]
    public async Task Seal_pending_rejects_a_stage_with_multiple_hard_links_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            _output.WriteLine("WINDOWS-ONLY CHECK NOT EXECUTED: FILE_STANDARD_INFO link-count validation requires Windows.");
            return;
        }

        var journal = Journal();
        var transfer = Transfer();
        TransferJournalEntry allocated = await journal.CreateAsync(transfer, CancellationToken.None);
        string secondName = transfer.StagePath + ".second-link";
        File.Move(transfer.StagePath, secondName);
        if (!CreateHardLink(transfer.StagePath, secondName, IntPtr.Zero))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                "Could not create the second stage hard link required by this identity test.");

        await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None));
        TransferJournalEntry pending = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.SealPending, pending.State);
        Assert.Equal(allocated.StageIdentity, pending.StageIdentity);
        Assert.Null(pending.SealedLength);
        Assert.Equal("positive fixture stage", await File.ReadAllTextAsync(secondName));
    }

    [Fact]
    public async Task Legacy_sealed_manifest_without_identity_or_length_recovers_private()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        JsonObject document = JsonNode.Parse(await File.ReadAllTextAsync(manifest))!.AsObject();
        document.Remove("StageIdentity");
        document.Remove("SealedLength");
        await File.WriteAllTextAsync(manifest, document.ToJsonString());

        await Journal().RetainInterruptedAsync(CancellationToken.None);

        var recovered = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Retained, recovered.State);
        Assert.Null(recovered.StageIdentity);
        Assert.Null(recovered.SealedLength);
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.Retained, TransferJournalState.Inspecting,
            null, CancellationToken.None));
    }

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
        // Read back from disk: Windows sets the auto-inherited flag (AI) when it stores a DACL under an inheriting parent,
        // so the in-memory descriptor written above is not what "unchanged" is compared with.
        string priorSecurity = outsideFile.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Unknown_inspection_failure_is_refused_in_transition_and_after_manifest_tampering(bool tamper)
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Sealed,
            TransferJournalState.Inspecting, null, CancellationToken.None);
        if (!tamper)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
                transfer.TransferId, TransferJournalState.Inspecting, TransferJournalState.Blocked,
                new string('A', 64), CancellationToken.None,
                blockedEvidence: new BlockedTransferEvidence(1, null, WindowClosed: true,
                    InspectionFailure: (InspectionFailureKind)999)));
            Assert.Equal(TransferJournalState.Inspecting,
                (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
            return;
        }
        await journal.TransitionAsync(transfer.TransferId, TransferJournalState.Inspecting,
            TransferJournalState.Blocked, new string('A', 64), CancellationToken.None,
            blockedEvidence: new BlockedTransferEvidence(1, null, WindowClosed: true,
                InspectionFailure: InspectionFailureKind.Timeout));
        string manifest = Assert.Single(Directory.GetFiles(Path.Combine(_workspace.Root, "journal"), "*.json"));
        var data = JsonNode.Parse(await File.ReadAllTextAsync(manifest))!;
        data["BlockedInspectionFailure"] = 999;
        await File.WriteAllTextAsync(manifest, data.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(() => Journal().ReadAsync(transfer.TransferId, CancellationToken.None));
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
            TransferJournalState.Allocated, TransferJournalState.SealPending,
            TransferJournalState.Sealed,
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
        Assert.Equal(new[] { TransferJournalState.Allocated, TransferJournalState.SealPending,
                TransferJournalState.Sealed },
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

    [Fact]
    public async Task Scans_read_each_manifest_once_until_it_changes()
    {
        var journal = Journal();
        var transfers = Enumerable.Range(0, 24).Select(index => Transfer() with
        {
            DestinationPath = Path.Combine(_workspace.Root, "destination", $"document-{index}.txt")
        }).ToArray();
        foreach (var transfer in transfers) await journal.CreateAsync(transfer, CancellationToken.None);

        var first = await journal.ReadPendingAsync(CancellationToken.None);
        Assert.Equal(transfers.Length, first.Count);
        long afterFirst = journal.ScanManifestReads;
        Assert.Equal(transfers.Length, afterFirst);

        // The publish loop rescans every 250 ms: unchanged manifests must not be read, ACL-checked or parsed again.
        for (int scan = 0; scan < 5; scan++)
            Assert.Equal(transfers.Length, (await journal.ReadPendingAsync(CancellationToken.None)).Count);
        Assert.Equal(afterFirst, journal.ScanManifestReads);

        // SealAsync durably writes SealPending first. Its current-head check
        // must reread that changed manifest, and the final classification
        // write must invalidate it again for the publish-loop scan.
        await journal.SealAsync(transfers[3].TransferId, transfers[3].ProcessId,
            transfers[3].StagePath, CancellationToken.None);
        Assert.Equal(afterFirst + 1, journal.ScanManifestReads);
        var second = await journal.ReadPendingAsync(CancellationToken.None);
        Assert.Equal(afterFirst + 2, journal.ScanManifestReads);
        TransferJournalEntry sealedVersion = second.Single(e => e.Transfer.TransferId == transfers[3].TransferId);
        Assert.Equal(TransferJournalState.Sealed, sealedVersion.State);
        Assert.Contains(sealedVersion.StateHistory, change => change.State == TransferJournalState.SealPending);
        await journal.ReadPendingAsync(CancellationToken.None);
        Assert.Equal(afterFirst + 2, journal.ScanManifestReads);
    }

    [Fact]
    public async Task Scans_notice_a_manifest_changed_behind_the_cache()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        Assert.Single(await journal.ReadPendingAsync(CancellationToken.None));
        long reads = journal.ScanManifestReads;

        string manifest = Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json");
        var entry = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        // Rewritten outside the class with the same state but different bytes and a later timestamp.
        await File.WriteAllTextAsync(manifest, System.Text.Json.JsonSerializer.Serialize(entry) + "\n");
        File.SetLastWriteTimeUtc(manifest, DateTime.UtcNow.AddMinutes(5));

        Assert.Single(await journal.ReadPendingAsync(CancellationToken.None));
        Assert.Equal(reads + 1, journal.ScanManifestReads);
    }

    [Fact]
    public async Task Destination_scans_do_not_reread_unchanged_history()
    {
        var journal = Journal();
        string destination = Path.Combine(_workspace.Root, "destination", "document.txt");
        var ids = new List<Guid>();
        for (int round = 0; round < 12; round++)
        {
            var transfer = new StagedTransfer(Guid.NewGuid(),
                Path.Combine(_workspace.Root, "staging", $"document-{round}.txt"), destination,
                DestinationKind.RemovableDrive, "explorer.exe", 1234, 1);
            Directory.CreateDirectory(Path.GetDirectoryName(transfer.StagePath)!);
            await File.WriteAllTextAsync(transfer.StagePath, "positive fixture stage");
            await journal.CreateAsync(transfer, CancellationToken.None);
            ids.Add(transfer.TransferId);
            await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath,
                CancellationToken.None);
        }
        // Every create scanned the destination's history; each sealed version was read once after its own change, and
        // the creates of later versions reused it. Generations still advance one per version.
        var entries = new List<TransferJournalEntry>();
        foreach (var id in ids) entries.Add(await journal.ReadAsync(id, CancellationToken.None));
        Assert.Equal(Enumerable.Range(1, 12).Select(n => (long)n), entries.Select(e => e.DestinationGeneration));
        Assert.True(journal.ScanManifestReads <= 12L * 3, $"scan reads: {journal.ScanManifestReads}");
    }

    [Theory]
    [InlineData(3, 4)]
    [InlineData(4, 6)]
    public async Task Full_history_scans_above_capacity_evict_individual_entries_without_a_reread_cliff(
        int capacity, int count)
    {
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"),
            requireProtectedParent: false, scanCacheCapacity: capacity);
        var transfers = Enumerable.Range(0, count).Select(_ => Transfer()).ToArray();
        foreach (var transfer in transfers) await journal.CreateAsync(transfer, CancellationToken.None);
        string directory = Path.Combine(_workspace.Root, "journal");
        var originals = Directory.GetFiles(directory, "*.json")
            .ToDictionary(path => path, File.ReadAllBytes);
        await journal.ReadPendingAsync(CancellationToken.None);
        long reads = journal.ScanManifestReads;

        const int scans = 8;
        for (int scan = 0; scan < scans; scan++)
        {
            var entries = await journal.ReadPendingAsync(CancellationToken.None);
            Assert.Equal(transfers.Select(transfer => transfer.TransferId).Order(),
                entries.Select(entry => entry.Transfer.TransferId).Order());
            Assert.All(entries, entry => Assert.Equal(TransferJournalState.Allocated, entry.State));
            Assert.Equal(capacity, journal.ScanCacheEntries);
        }
        // A stable full traversal retains most of the working set even when
        // it cannot all fit. Clear-all and ordinary LRU both reread it all.
        Assert.InRange(journal.ScanManifestReads - reads, 1, (count - capacity + 1L) * scans);
        Assert.True(journal.ScanManifestReads - reads < (long)count * scans);
        Assert.True(journal.ScanCacheEvictions > 0);
        foreach (var (path, bytes) in originals) Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task Eviction_keeps_destination_generations_and_state_invalidation_exact()
    {
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"),
            requireProtectedParent: false, scanCacheCapacity: 3);
        var transfers = Enumerable.Range(0, 12).Select(_ => Transfer()).ToArray();
        for (int i = 0; i < transfers.Length; i++)
        {
            var created = await journal.CreateAsync(transfers[i], CancellationToken.None);
            Assert.Equal(i + 1L, created.DestinationGeneration);
        }
        await journal.ReadPendingAsync(CancellationToken.None);
        foreach (var transfer in transfers.Take(transfers.Length - 1))
        {
            await Assert.ThrowsAsync<IOException>(() => journal.SealAsync(transfer.TransferId,
                transfer.ProcessId, transfer.StagePath, CancellationToken.None));
            Assert.Equal(TransferJournalState.Allocated,
                (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        }
        TransferJournalEntry latest = await journal.SealAsync(
            transfers[^1].TransferId, transfers[^1].ProcessId, transfers[^1].StagePath,
            CancellationToken.None);
        Assert.True(latest.SealedLength is > 0);
        Assert.NotNull(latest.StageIdentity);

        var entries = await journal.ReadPendingAsync(CancellationToken.None);
        Assert.Equal(transfers.Length, entries.Count);
        foreach (var transfer in transfers.Take(transfers.Length - 1))
            Assert.Equal(TransferJournalState.Allocated,
                entries.Single(entry => entry.Transfer.TransferId == transfer.TransferId).State);
        Assert.Equal(TransferJournalState.Sealed,
            entries.Single(entry => entry.Transfer.TransferId == transfers[^1].TransferId).State);
        Assert.Equal(Enumerable.Range(1, 12).Select(i => (long)i),
            entries.Select(entry => entry.DestinationGeneration).Order());
        Assert.Equal(3, journal.ScanCacheEntries);
        Assert.True(journal.ScanCacheEvictions > 0);
    }

    [Fact]
    public async Task A_warm_bounded_scan_cache_never_authorizes_a_manifest_with_an_unsafe_acl()
    {
        if (!OperatingSystem.IsWindows()) return;
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"),
            requireProtectedParent: false, scanCacheCapacity: 3);
        var transfers = Enumerable.Range(0, 4).Select(_ => Transfer()).ToArray();
        foreach (var transfer in transfers) await journal.CreateAsync(transfer, CancellationToken.None);
        await journal.ReadPendingAsync(CancellationToken.None);
        Assert.Equal(3, journal.ScanCacheEntries);
        foreach (var transfer in transfers)
        {
            var file = new FileInfo(Path.Combine(_workspace.Root, "journal", transfer.TransferId.ToString("N") + ".json"));
            byte[] bytes = await File.ReadAllBytesAsync(file.FullName);
            var original = file.GetAccessControl();
            var unsafeSecurity = file.GetAccessControl();
            unsafeSecurity.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.Write, AccessControlType.Allow));
            file.SetAccessControl(unsafeSecurity);
            try
            {
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                    journal.ReadAsync(transfer.TransferId, CancellationToken.None));
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() => journal.SealAsync(
                    transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None));
                Assert.Equal(bytes, await File.ReadAllBytesAsync(file.FullName));
            }
            finally { file.SetAccessControl(original); }
        }
    }

    private static async Task<TransferJournalEntry> ReleaseAsync(StagedTransferJournal journal, StagedTransfer t)
    {
        await WritePositiveStageAsync(t);
        await journal.CreateAsync(t, CancellationToken.None);
        await journal.SealAsync(t.TransferId, t.ProcessId, t.StagePath, CancellationToken.None);
        await journal.TransitionAsync(t.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(t.TransferId, TransferJournalState.Inspecting, TransferJournalState.Approved, new string('B', 64), CancellationToken.None);
        await journal.TransitionAsync(t.TransferId, TransferJournalState.Approved, TransferJournalState.Publishing, null, CancellationToken.None);
        TransferJournalEntry released = await journal.TransitionAsync(t.TransferId,
            TransferJournalState.Publishing, TransferJournalState.Released, null, CancellationToken.None);
        File.Delete(t.StagePath); // Model the completed post-publication stage disposal.
        return released;
    }

    private static async Task BlockAsync(StagedTransferJournal journal, StagedTransfer t, bool windowClosed)
    {
        await WritePositiveStageAsync(t);
        await journal.CreateAsync(t, CancellationToken.None);
        await journal.SealAsync(t.TransferId, t.ProcessId, t.StagePath, CancellationToken.None);
        await journal.TransitionAsync(t.TransferId, TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None);
        await journal.TransitionAsync(t.TransferId, TransferJournalState.Inspecting, TransferJournalState.Blocked, new string('C', 64),
            CancellationToken.None, blockedEvidence: new BlockedTransferEvidence(1,
                windowClosed ? null : DateTimeOffset.UtcNow.AddDays(7), WindowClosed: windowClosed));
    }

    private static async Task WritePositiveStageAsync(StagedTransfer transfer)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.StagePath)!);
        await File.WriteAllTextAsync(transfer.StagePath, "positive fixture stage");
    }

    private string[] Manifests() => Directory.GetFiles(Path.Combine(_workspace.Root, "journal"), "*.json");

    [Fact]
    public async Task Compaction_removes_finished_versions_of_a_destination_together()
    {
        var journal = Journal();
        var first = Transfer();
        var second = first with { TransferId = Guid.NewGuid(), StagePath = first.StagePath + ".next" };
        await ReleaseAsync(journal, first);
        await ReleaseAsync(journal, second);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddMinutes(-5), CancellationToken.None));
        Assert.Equal(2, Manifests().Length);
        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        Assert.Single(Manifests());
        Assert.Single(await Journal().ReadReleasedAsync(CancellationToken.None));
        var third = await journal.CreateAsync(first with { TransferId = Guid.NewGuid() }, CancellationToken.None);
        Assert.Equal(3, third.DestinationGeneration);
    }

    [Fact]
    public async Task Compaction_keeps_the_newest_version_while_an_older_one_can_still_be_justified()
    {
        var journal = Journal();
        var blocked = Transfer();
        var released = blocked with { TransferId = Guid.NewGuid(), StagePath = blocked.StagePath + ".next" };
        await BlockAsync(journal, blocked, windowClosed: false);
        await ReleaseAsync(journal, released);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        Assert.Equal(2, Manifests().Length);
        // The newer released version still supersedes the blocked one: its justification cannot publish over it.
        await Assert.ThrowsAsync<IOException>(() => Journal().TransitionAsync(blocked.TransferId,
            TransferJournalState.Blocked, TransferJournalState.Inspecting, null, CancellationToken.None));
    }

    [Fact]
    public async Task Compaction_keeps_a_released_version_whose_stage_is_still_on_disk()
    {
        var journal = Journal();
        var transfer = Transfer();
        await ReleaseAsync(journal, transfer);
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.StagePath)!);
        await File.WriteAllTextAsync(transfer.StagePath, "approved stage not yet disposed");
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        File.Delete(transfer.StagePath);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        Assert.Single(Manifests()); // The greatest destination generation remains as a high-water claim.
    }

    [Fact]
    public async Task Compaction_removes_a_blocked_version_only_after_verified_hand_back_and_cleanup()
    {
        var journal = Journal();
        var transfer = Transfer();
        await BlockAsync(journal, transfer, windowClosed: true);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        await journal.BeginHandbackAttemptAsync(transfer.TransferId, CancellationToken.None);
        await journal.CompleteHandbackAsync(transfer.TransferId, null, null, "copy failed", CancellationToken.None);
        // A failed hand-back keeps the stage: the user's bytes exist nowhere else.
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));

        var other = Transfer() with { DestinationPath = Path.Combine(_workspace.Root, "destination", "other.txt") };
        await BlockAsync(journal, other, windowClosed: true);
        await journal.BeginHandbackAttemptAsync(other.TransferId, CancellationToken.None);
        await journal.CompleteHandbackAsync(other.TransferId, Path.Combine(_workspace.Root, "handback", "other.txt"), 3, null,
            CancellationToken.None);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        await journal.TryBeginStageCleanupAsync(other.TransferId, CancellationToken.None);
        File.Delete(other.StagePath);
        await File.WriteAllTextAsync(other.StagePath, "replacement remains private");
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteStageCleanupAsync(other.TransferId,
            CancellationToken.None));
        Assert.False((await journal.ReadAsync(other.TransferId, CancellationToken.None)).StageDeleted);
        Assert.Equal("replacement remains private", await File.ReadAllTextAsync(other.StagePath));
        File.Delete(other.StagePath);
        var cleaned = await journal.CompleteStageCleanupAsync(other.TransferId, CancellationToken.None);
        Assert.True(cleaned.StageDeleted);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        Assert.Equal(2, Manifests().Length);
        Assert.Equal(transfer.TransferId, (await Journal().ReadAsync(transfer.TransferId, CancellationToken.None)).Transfer.TransferId);
    }

    [Fact]
    public async Task Discarded_version_keeps_its_generation_and_supersedes_an_older_sealed_one()
    {
        var journal = Journal();
        var sealedFirst = Transfer();
        await journal.CreateAsync(sealedFirst, CancellationToken.None);
        await journal.SealAsync(sealedFirst.TransferId, sealedFirst.ProcessId, sealedFirst.StagePath, CancellationToken.None);
        var deleted = sealedFirst with { TransferId = Guid.NewGuid(), StagePath = sealedFirst.StagePath + ".next" };
        var created = await journal.CreateAsync(deleted, CancellationToken.None);
        var discarded = await journal.DiscardAsync(deleted.TransferId, deleted.ProcessId, deleted.StagePath, CancellationToken.None);
        Assert.Equal(TransferJournalState.Discarded, discarded.State);
        Assert.Equal(created.DestinationGeneration, discarded.DestinationGeneration);
        Assert.Equal(TransferJournalState.Discarded,
            (await Journal().DiscardAsync(deleted.TransferId, deleted.ProcessId, deleted.StagePath, CancellationToken.None)).State);
        // The version sealed before the delete can no longer be inspected, approved or published.
        await Assert.ThrowsAsync<IOException>(() => Journal().TransitionAsync(sealedFirst.TransferId,
            TransferJournalState.Sealed, TransferJournalState.Inspecting, null, CancellationToken.None));
        Assert.DoesNotContain(await Journal().ReadPendingAsync(CancellationToken.None),
            e => e.Transfer.TransferId == deleted.TransferId);
        var later = await journal.CreateAsync(sealedFirst with { TransferId = Guid.NewGuid() }, CancellationToken.None);
        Assert.True(later.DestinationGeneration > discarded.DestinationGeneration);
    }

    [Fact]
    public async Task Discard_requires_the_owner_and_an_unsealed_version()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.DiscardAsync(transfer.TransferId, transfer.ProcessId + 1,
            transfer.StagePath, CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.DiscardAsync(transfer.TransferId, transfer.ProcessId,
            transfer.StagePath + ".other", CancellationToken.None));
        await journal.SealAsync(transfer.TransferId, transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() => journal.DiscardAsync(transfer.TransferId, transfer.ProcessId,
            transfer.StagePath, CancellationToken.None));
        Assert.Equal(TransferJournalState.Sealed, (await Journal().ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task V19_exact_discard_is_pending_private_until_exact_cleanup_ack_and_keeps_high_water()
    {
        var journal = Journal();
        var transfer = Transfer();
        await WritePositiveStageAsync(transfer);
        TransferJournalEntry created = await journal.CreateAsync(transfer, CancellationToken.None);
        var exact = new StagedVersionIdentity(transfer.TransferId, created.DestinationGeneration,
            created.StageIdentity!);
        var request = new StagedDiscardRequest(transfer.TransferId, exact, StagedDiscardKind.PrivateVersion);

        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(request,
            CancellationToken.None, transfer.ProcessId + 1));
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(request, CancellationToken.None));
        TransferJournalEntry pending = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.DiscardPending, pending.State);
        Assert.True(File.Exists(transfer.StagePath)); // The filter-port request never deletes synchronously.
        await Assert.ThrowsAsync<InvalidOperationException>(() => journal.TransitionAsync(
            transfer.TransferId, TransferJournalState.DiscardPending, TransferJournalState.Sealed,
            new string('A', 64), CancellationToken.None));

        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(request, CancellationToken.None));
        Assert.False(File.Exists(transfer.StagePath));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.BeginOrConfirmDiscardAsync(request, CancellationToken.None));
        // The discarded record is the highest generation, so it remains as
        // the durable destination high-water claim and cannot be compacted.
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        TransferJournalEntry highWater = await Journal().ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(exact.DestinationGeneration, highWater.DestinationGeneration);
        Assert.Equal(TransferJournalState.DiscardPending, highWater.State);
        Assert.NotNull(highWater.DiscardAcknowledgedAtUtc);

        var later = Transfer() with { TransferId = Guid.NewGuid(), StagePath = transfer.StagePath + ".later" };
        await WritePositiveStageAsync(later);
        TransferJournalEntry next = await Journal().CreateAsync(later, CancellationToken.None);
        Assert.True(next.DestinationGeneration > exact.DestinationGeneration);
    }

    [Fact]
    public async Task V19_discard_rejects_wrong_reservation_generation_and_stage_identity()
    {
        var journal = Journal();
        var transfer = Transfer();
        await WritePositiveStageAsync(transfer);
        TransferJournalEntry created = await journal.CreateAsync(transfer, CancellationToken.None);
        var version = new StagedVersionIdentity(transfer.TransferId, created.DestinationGeneration,
            created.StageIdentity!);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(Guid.NewGuid(), version, StagedDiscardKind.PrivateVersion),
            CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(transfer.TransferId,
                version with { DestinationGeneration = version.DestinationGeneration + 1 },
                StagedDiscardKind.PrivateVersion), CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            new StagedDiscardRequest(transfer.TransferId,
                version with { StageIdentity = new StagedStageIdentity(0, 17, 29) },
                StagedDiscardKind.PrivateVersion), CancellationToken.None));
        Assert.Equal(TransferJournalState.Allocated,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task V19_discard_refuses_to_delete_a_replacement_stage_object()
    {
        var journal = Journal();
        var transfer = Transfer();
        await WritePositiveStageAsync(transfer);
        TransferJournalEntry created = await journal.CreateAsync(transfer, CancellationToken.None);
        var version = new StagedVersionIdentity(transfer.TransferId, created.DestinationGeneration,
            created.StageIdentity!);
        var request = new StagedDiscardRequest(transfer.TransferId, version, StagedDiscardKind.PrivateVersion);
        await journal.BeginOrConfirmDiscardAsync(request, CancellationToken.None);

        string moved = transfer.StagePath + ".original";
        File.Move(transfer.StagePath, moved);
        await File.WriteAllTextAsync(transfer.StagePath, "replacement bytes");
        StagedStageIdentity replacementIdentity;
        using (StagedStageFile replacement = StagedStageFile.Open(transfer.StagePath))
            replacementIdentity = replacement.Identity;
        Assert.NotEqual(version.StageIdentity, replacementIdentity);
        await Assert.ThrowsAsync<IOException>(() => journal.CompleteDiscardAsync(request, CancellationToken.None));
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(TransferJournalState.DiscardPending,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task V19_unattached_allocation_cleanup_is_exact_epoch_bound_and_ignores_public_collision()
    {
        var journal = Journal();
        var transfer = Transfer() with
        {
            RequestorSid = "S-1-5-21-111-222-333-1000",
            RequestorProcessCreationTime = 638953632000000000
        };
        Guid activeDriver = Guid.NewGuid();
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        TransferJournalEntry created = await journal.CreateAsync(transfer, CancellationToken.None,
            allocationDisposition: 5, allocationReferenceId: null, allocationReferenceKind: 0,
            driverInstanceId: activeDriver,
            parentDirectoryIdentity: StagedStageFile.ReadDirectoryIdentity(
                Path.GetDirectoryName(transfer.DestinationPath)!));
        var exact = new StagedVersionIdentity(transfer.TransferId, created.DestinationGeneration,
            created.StageIdentity!);
        var request = new StagedDiscardRequest(transfer.TransferId, exact,
            StagedDiscardKind.UnattachedAllocation);

        await File.WriteAllTextAsync(transfer.DestinationPath, "public replacement");
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(request,
            CancellationToken.None, transfer.ProcessId, Guid.NewGuid()));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            request with { ReservationId = Guid.NewGuid() }, CancellationToken.None,
            transfer.ProcessId, activeDriver));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            request with { Version = exact with { DestinationGeneration = exact.DestinationGeneration + 1 } },
            CancellationToken.None, transfer.ProcessId, activeDriver));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(
            request with { Version = exact with { StageIdentity = new StagedStageIdentity(0, 17, 29) } },
            CancellationToken.None, transfer.ProcessId, activeDriver));
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(request,
            CancellationToken.None, transfer.ProcessId + 1, activeDriver));

        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(request, CancellationToken.None,
                transfer.ProcessId, activeDriver));
        TransferJournalEntry pending = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.DiscardPending, pending.State);
        Assert.False(pending.SealedOnce);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(request, CancellationToken.None));
        Assert.False(File.Exists(transfer.StagePath));
        Assert.Equal("public replacement", await File.ReadAllTextAsync(transfer.DestinationPath));
        TransferJournalEntry terminal = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(exact.DestinationGeneration, terminal.DestinationGeneration);
        Assert.Equal(StagedDiscardKind.UnattachedAllocation, terminal.DiscardKind);
    }

    [Fact]
    public async Task V19_unattached_allocation_cleanup_cannot_discard_a_sealed_version()
    {
        var journal = Journal();
        var transfer = Transfer() with
        {
            RequestorSid = "S-1-5-21-111-222-333-1000",
            RequestorProcessCreationTime = 638953632000000000
        };
        Guid activeDriver = Guid.NewGuid();
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.DestinationPath)!);
        StagedStageIdentity parentDirectory = StagedStageFile.ReadDirectoryIdentity(
            Path.GetDirectoryName(transfer.DestinationPath)!);
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(activeDriver, 0x3f, CancellationToken.None));
        TransferJournalEntry created = await journal.CreateAsync(transfer, CancellationToken.None,
            allocationDisposition: 5, allocationReferenceId: null, allocationReferenceKind: 0,
            driverInstanceId: activeDriver,
            parentDirectoryIdentity: parentDirectory);
        var exact = new StagedVersionIdentity(transfer.TransferId, created.DestinationGeneration,
            created.StageIdentity!);
        async Task<uint?> Apply(uint operation, ulong requestId) =>
            await journal.ApplyAttachmentV20Async(new StagedAttachmentRequestV20(operation, requestId,
                exact, activeDriver, parentDirectory, transfer.DestinationPath, transfer.ProcessId),
                ownerIsLive: true, commitPolicyAllowed: true, CancellationToken.None);
        Assert.Equal(6u, await Apply(12, 1));
        Assert.Equal(7u, await Apply(13, 2));
        Assert.Equal(16u, await Apply(15, 3));
        Assert.Equal(17u, await Apply(19, 4));
        TransferJournalEntry sealedEntry = await journal.SealAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None, exact);
        var request = new StagedDiscardRequest(transfer.TransferId, exact,
            StagedDiscardKind.UnattachedAllocation);

        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(request,
            CancellationToken.None, transfer.ProcessId, activeDriver));
        Assert.Equal(TransferJournalState.Sealed, sealedEntry.State);
        Assert.Equal(TransferJournalState.Sealed,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        Assert.True(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task V19_driver_unload_empty_cleanup_is_exact_and_terminal()
    {
        var journal = Journal();
        var transfer = Transfer();
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.StagePath)!);
        await File.WriteAllBytesAsync(transfer.StagePath, []);
        TransferJournalEntry created = await journal.CreateAsync(transfer, CancellationToken.None);
        var exact = new StagedVersionIdentity(transfer.TransferId, created.DestinationGeneration,
            created.StageIdentity!);
        TransferJournalEntry empty = await LegacyStagedJournalFixture.SealEmptyAsync(journal, _workspace.Root, transfer.TransferId, transfer.ProcessId,
            transfer.StagePath, CancellationToken.None, exact);
        Assert.Equal(TransferJournalState.LegacyEmptyHeld, empty.State);

        var wrong = new StagedDiscardRequest(Guid.NewGuid(), exact, StagedDiscardKind.DriverUnloadEmpty);
        await Assert.ThrowsAsync<IOException>(() => journal.BeginOrConfirmDiscardAsync(wrong, CancellationToken.None));
        Assert.True(File.Exists(transfer.StagePath));
        var request = new StagedDiscardRequest(transfer.TransferId, exact, StagedDiscardKind.DriverUnloadEmpty);
        Assert.Equal(StagedDiscardStatus.Pending,
            await journal.BeginOrConfirmDiscardAsync(request, CancellationToken.None));
        Assert.Equal(StagedDiscardStatus.Acknowledged,
            await journal.CompleteDiscardAsync(request, CancellationToken.None));
        Assert.False(File.Exists(transfer.StagePath));
        Assert.Equal(TransferJournalState.LegacyEmptyHeld,
            (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Compaction_removes_a_discarded_version_once_nothing_older_is_live()
    {
        var journal = Journal();
        var first = Transfer();
        await ReleaseAsync(journal, first);
        var deleted = first with { TransferId = Guid.NewGuid(), StagePath = first.StagePath + ".next" };
        TransferJournalEntry created = await journal.CreateAsync(deleted, CancellationToken.None);
        await journal.DiscardAsync(deleted.TransferId, deleted.ProcessId, deleted.StagePath, CancellationToken.None);
        Assert.Equal(1, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1), CancellationToken.None));
        Assert.Single(Manifests());
        TransferJournalEntry highWater = await Journal().ReadAsync(deleted.TransferId, CancellationToken.None);
        Assert.Equal(created.DestinationGeneration, highWater.DestinationGeneration);
    }

    [Fact]
    public async Task Discard_cleanup_withholds_completion_until_a_locked_stage_can_be_removed()
    {
        if (!OperatingSystem.IsWindows()) return;

        var journal = Journal();
        var transfer = Transfer();
        Directory.CreateDirectory(Path.GetDirectoryName(transfer.StagePath)!);
        await File.WriteAllTextAsync(transfer.StagePath, "private bytes marked for discard");
        await journal.CreateAsync(transfer, CancellationToken.None);
        TransferJournalEntry discarded = await journal.DiscardAsync(transfer.TransferId, transfer.ProcessId,
            transfer.StagePath, CancellationToken.None);
        Assert.NotNull(discarded.StageIdentity);

        using (var blocker = new FileStream(transfer.StagePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.False(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
                discarded.StageIdentity, out Exception? failure));
            Assert.NotNull(failure);
            Assert.True(File.Exists(transfer.StagePath));
            Assert.Equal(TransferJournalState.Discarded,
                (await journal.ReadAsync(transfer.TransferId, CancellationToken.None)).State);
        }

        Assert.True(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
            discarded.StageIdentity, out Exception? retryFailure));
        Assert.Null(retryFailure);
        Assert.False(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task Legacy_discard_cleanup_retains_a_replacement_at_the_manifest_path()
    {
        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        TransferJournalEntry discarded = await journal.DiscardAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        StagedStageIdentity identity = Assert.IsType<StagedStageIdentity>(discarded.StageIdentity);

        File.Delete(transfer.StagePath);
        await File.WriteAllTextAsync(transfer.StagePath, "replacement must stay private");
        File.SetCreationTimeUtc(transfer.StagePath, DateTime.UtcNow.AddDays(-1));
        using (StagedStageFile replacement = StagedStageFile.Open(transfer.StagePath))
            Assert.NotEqual(identity, replacement.Identity);

        Assert.False(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
            identity, out Exception? failure));
        Assert.Null(failure);
        Assert.Equal("replacement must stay private", await File.ReadAllTextAsync(transfer.StagePath));
        Assert.Contains(await journal.ReadDiscardedWithStageAsync(CancellationToken.None),
            entry => entry.Transfer.TransferId == transfer.TransferId);
        Assert.Equal(0, await journal.CompactAsync(DateTimeOffset.UtcNow.AddSeconds(1),
            CancellationToken.None));

        Assert.False(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
            null, out failure));
        Assert.Equal("replacement must stay private", await File.ReadAllTextAsync(transfer.StagePath));
    }

    [Fact]
    public async Task Legacy_discard_cleanup_refuses_a_hard_linked_stage_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            _output.WriteLine("WINDOWS-ONLY CHECK NOT EXECUTED: FILE_ID_INFO link-count deletion guard requires Windows.");
            return;
        }

        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        TransferJournalEntry discarded = await journal.DiscardAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        string alias = transfer.StagePath + ".alias";
        if (!CreateHardLink(alias, transfer.StagePath, IntPtr.Zero))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                "Could not create the hard link required by the exact deletion test.");
        try
        {
            Assert.False(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
                discarded.StageIdentity, out Exception? failure));
            Assert.Null(failure);
            Assert.True(File.Exists(transfer.StagePath));
            Assert.True(File.Exists(alias));
        }
        finally { File.Delete(alias); }

        Assert.True(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
            discarded.StageIdentity, out Exception? retryFailure));
        Assert.Null(retryFailure);
        Assert.False(File.Exists(transfer.StagePath));
    }

    [Fact]
    public async Task Legacy_discard_cleanup_does_not_follow_a_replacement_symlink_on_windows()
    {
        if (!OperatingSystem.IsWindows())
        {
            _output.WriteLine("WINDOWS-ONLY CHECK NOT EXECUTED: final-component no-follow deletion guard requires Windows.");
            return;
        }

        var journal = Journal();
        var transfer = Transfer();
        await journal.CreateAsync(transfer, CancellationToken.None);
        TransferJournalEntry discarded = await journal.DiscardAsync(transfer.TransferId,
            transfer.ProcessId, transfer.StagePath, CancellationToken.None);
        string original = transfer.StagePath + ".original";
        string outside = Path.Combine(_workspace.Root, "outside-private-data.txt");
        File.Move(transfer.StagePath, original);
        await File.WriteAllTextAsync(outside, "outside target stays unchanged");
        try
        {
            File.CreateSymbolicLink(transfer.StagePath, outside);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
                                      NotSupportedException)
        {
            throw new InvalidOperationException(
                "The required final-component symlink deletion assertion could not be created; this Windows profile is unqualified.",
                error);
        }

        Assert.False(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
            discarded.StageIdentity, out Exception? failure));
        Assert.Null(failure);
        Assert.True(File.Exists(transfer.StagePath));
        Assert.Equal("outside target stays unchanged", await File.ReadAllTextAsync(outside));
        Assert.Equal("positive fixture stage", await File.ReadAllTextAsync(original));
        File.Delete(transfer.StagePath);
        Assert.True(StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(transfer.StagePath,
            discarded.StageIdentity, out Exception? retryFailure));
        Assert.Null(retryFailure);
    }
}
