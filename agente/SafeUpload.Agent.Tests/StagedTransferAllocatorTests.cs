using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Tests;

public sealed class StagedTransferAllocatorTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Allocation_is_journaled_before_the_stage_name_is_returned()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");

        var first = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);
        var second = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);

        Assert.NotEqual(first.TransferId, second.TransferId);
        Assert.NotEqual(first.StagePath, second.StagePath);
        Assert.Equal(".txt", Path.GetExtension(first.StagePath));
        Assert.StartsWith(root + Path.DirectorySeparatorChar, first.StagePath,
            StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(first.StagePath));
        Assert.Equal(0, new FileInfo(first.StagePath).Length);
        Assert.False(File.Exists(destination));
        var entry = await journal.ReadAsync(first.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, entry.State);
        Assert.Equal(first, entry.Transfer);
    }

    [Fact]
    public async Task Backing_file_has_its_own_private_acl_and_restart_removes_extra_grants()
    {
        if (!OperatingSystem.IsWindows()) return;
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        var transfer = await allocator.AllocateAsync(Path.Combine(_workspace.Root, "report.txt"),
            DestinationKind.Cloud, "word.exe", 17, 2, CancellationToken.None);
        var file = new FileInfo(transfer.StagePath);
        var security = file.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        security.AddAccessRule(new FileSystemAccessRule(everyone,
            FileSystemRights.Read, AccessControlType.Allow));
        file.SetAccessControl(security);
        _ = new StagedTransferAllocator(root, journal);
        security = file.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new InvalidOperationException("Test identity has no SID.");
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        Assert.NotEmpty(rules);
        Assert.All(rules, rule => {
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.False(rule.IsInherited);
            var sid = (SecurityIdentifier)rule.IdentityReference;
            Assert.True(sid.Equals(owner) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid));
        });
    }

    [Fact]
    public async Task Allocation_rejects_a_destination_inside_the_stage_root()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var allocator = new StagedTransferAllocator(root,
            new StagedTransferJournal(Path.Combine(_workspace.Root, "journal")));

        await Assert.ThrowsAsync<ArgumentException>(() => allocator.AllocateAsync(
            Path.Combine(root, "escape.txt"), DestinationKind.Cloud,
            "word.exe", 17, null, CancellationToken.None));
    }

    [Fact]
    public async Task Later_open_copies_the_sealed_version_without_changing_it()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");
        var first = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);
        await File.WriteAllTextAsync(first.StagePath, "approved version");
        await journal.TransitionAsync(first.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);

        var second = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, first, CancellationToken.None);
        Assert.NotEqual(first.TransferId, second.TransferId);
        Assert.Equal("approved version", await File.ReadAllTextAsync(second.StagePath));
        await File.AppendAllTextAsync(second.StagePath, " plus changes");
        Assert.Equal("approved version", await File.ReadAllTextAsync(first.StagePath));
        Assert.Equal(TransferJournalState.Allocated,
            (await journal.ReadAsync(second.TransferId, CancellationToken.None)).State);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(511)]
    [InlineData(4095)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(65537)]
    public async Task Noncached_seed_preserves_exact_bytes_and_partial_sector_length(int length)
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "report.txt");
        byte[] content = Enumerable.Range(0, length).Select(i => (byte)(i * 17)).ToArray();
        await File.WriteAllBytesAsync(destination, content);
        var stage = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        Assert.Equal(content, await File.ReadAllBytesAsync(stage.StagePath));
        Assert.Equal(length, new FileInfo(stage.StagePath).Length);
        Assert.Equal(content, await File.ReadAllBytesAsync(destination));
    }

    [Fact]
    public async Task Existing_destination_is_seeded_for_open_and_truncated_for_overwrite()
    {
        string root = Path.Combine(_workspace.Root, "stage");
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "destination", "report.txt");
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        await File.WriteAllTextAsync(destination, "already there");

        var opened = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        Assert.Equal("already there", await File.ReadAllTextAsync(opened.StagePath));
        var overwritten = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 4, null, CancellationToken.None);
        Assert.Equal(0, new FileInfo(overwritten.StagePath).Length);
        Assert.Equal("already there", await File.ReadAllTextAsync(destination));
        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(destination,
            DestinationKind.Cloud, "word.exe", 17, 2, 2, null, CancellationToken.None));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public async Task Oversized_source_is_rejected_without_stage_manifest_or_destination_changes(uint disposition)
    {
        const long maximum = 16 * 1024 * 1024;
        string root = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        var allocator = new StagedTransferAllocator(root, new StagedTransferJournal(journalRoot));
        string destination = Path.Combine(_workspace.Root, "large.txt");
        await using (var source = File.Create(destination)) source.SetLength(maximum + 1);

        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(destination,
            DestinationKind.Cloud, "word.exe", 17, 2, disposition, null, CancellationToken.None));

        Assert.Empty(Directory.EnumerateFiles(root));
        Assert.Empty(Directory.EnumerateFiles(journalRoot));
        Assert.Equal(maximum + 1, new FileInfo(destination).Length);
    }

    [Fact]
    public async Task Exact_maximum_seed_preserves_its_final_byte_and_truncation_needs_no_seed()
    {
        const int maximum = 16 * 1024 * 1024;
        string root = Path.Combine(_workspace.Root, "stage");
        var allocator = new StagedTransferAllocator(root,
            new StagedTransferJournal(Path.Combine(_workspace.Root, "journal")));
        string destination = Path.Combine(_workspace.Root, "boundary.txt");
        await using (var source = File.Create(destination))
        {
            source.SetLength(maximum);
            source.Position = maximum - 1;
            source.WriteByte(0x5a);
        }
        var copied = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 1, null, CancellationToken.None);
        Assert.Equal(maximum, new FileInfo(copied.StagePath).Length);
        await using (var stage = File.OpenRead(copied.StagePath))
        {
            stage.Position = maximum - 1;
            Assert.Equal(0x5a, stage.ReadByte());
        }
        await using (var source = File.OpenWrite(destination)) source.SetLength(maximum + 1L);
        var empty = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, 4, null, CancellationToken.None);
        Assert.Equal(0, new FileInfo(empty.StagePath).Length);
        Assert.Equal(maximum + 1L, new FileInfo(destination).Length);
    }

    [Fact]
    public async Task Oversized_prior_private_version_is_preserved_without_creating_a_followup()
    {
        const long maximum = 16 * 1024 * 1024;
        string root = Path.Combine(_workspace.Root, "stage");
        string journalRoot = Path.Combine(_workspace.Root, "journal");
        var journal = new StagedTransferJournal(journalRoot);
        var allocator = new StagedTransferAllocator(root, journal);
        string destination = Path.Combine(_workspace.Root, "private-large.txt");
        var prior = await allocator.AllocateAsync(destination, DestinationKind.Cloud,
            "word.exe", 17, 2, CancellationToken.None);
        await using (var source = File.OpenWrite(prior.StagePath)) source.SetLength(maximum + 1);
        var sealedEntry = await journal.TransitionAsync(prior.TransferId, TransferJournalState.Allocated,
            TransferJournalState.Sealed, null, CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() => allocator.AllocateAsync(destination,
            DestinationKind.Cloud, "word.exe", 17, 2, 1, prior, CancellationToken.None));

        Assert.Single(Directory.EnumerateFiles(root));
        Assert.Single(Directory.EnumerateFiles(journalRoot));
        Assert.Equal(maximum + 1, new FileInfo(prior.StagePath).Length);
        Assert.Equal(sealedEntry, await journal.ReadAsync(prior.TransferId, CancellationToken.None));
        Assert.False(File.Exists(destination));
    }
}
