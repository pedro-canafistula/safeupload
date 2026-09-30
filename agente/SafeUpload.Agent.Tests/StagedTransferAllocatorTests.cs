using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

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
        Assert.False(File.Exists(first.StagePath));
        Assert.False(File.Exists(destination));
        var entry = await journal.ReadAsync(first.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, entry.State);
        Assert.Equal(first, entry.Transfer);
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
}
