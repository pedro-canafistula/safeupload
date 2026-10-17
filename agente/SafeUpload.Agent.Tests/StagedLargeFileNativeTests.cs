using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Real NTFS allocation/replay controls for the Windows user + SYSTEM matrix.
// These are deliberately not part of the portable Linux diagnostic subset.
[Trait("Category", "NativeWindows")]
public sealed class StagedLargeFileNativeTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private const long MiB = 1024 * 1024;
    private const string Sid = "S-1-5-21-111-222-333-1000";
    private const long Creation = 123456;
    private string Root => Path.Combine(_workspace.Root, "stage");
    private string Destination => Path.Combine(_workspace.Root, "public.txt");
    private StagedSpaceBudget Budget() => new(Root, new(true, 512 * MiB, 128 * MiB, 32 * MiB), () => 2048 * MiB);
    private StagedTransferJournal Journal() => new(Path.Combine(_workspace.Root, "journal"));
    public void Dispose() => _workspace.Dispose();

    private SafeUploadRequest Request(Guid reservation)
    {
        byte[] bytes = new byte[Contract.RequestSize];
        void Put(string name, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(
            Marshal.OffsetOf<SafeUploadRequest>(name).ToInt32()), value);
        Put(nameof(SafeUploadRequest.Version), Contract.Version);
        Put(nameof(SafeUploadRequest.StructSize), Contract.RequestSize);
        Put(nameof(SafeUploadRequest.RequestId), 123);
        Put(nameof(SafeUploadRequest.Operation), Operation.StageAllocate);
        Put(nameof(SafeUploadRequest.RequestorProcessId), 17);
        Put(nameof(SafeUploadRequest.Flags), Contract.StageV20ReplyFlag);
        Put(nameof(SafeUploadRequest.PathLength), checked((uint)Destination.Length * 2));
        Put(nameof(SafeUploadRequest.ImageNameLength), Contract.StageAllocateV20Size);
        Put(nameof(SafeUploadRequest.Reserved), Contract.StageExtensionVersion);
        Encoding.Unicode.GetBytes(Destination).CopyTo(bytes, Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path)).ToInt32());
        var source = new SafeUploadStageAllocateV20
        {
            Intent = new() { Version = Contract.StageExtensionVersion, StructSize = Contract.StageAllocateV20Size,
                AllocationReservationId = reservation, Disposition = 3, DriverInstanceId = _driver },
            RequestorCreationTime = Creation
        };
        MemoryMarshal.Write(bytes.AsSpan(Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName)).ToInt32()), in source);
        return MemoryMarshal.Read<SafeUploadRequest>(bytes);
    }

    private Task<StagedAllocationReply> Allocate(StagedTransferAllocator allocator, Guid reservation) =>
        allocator.AllocateV19CoreAsync(Destination, DestinationKind.Cloud, "writer.exe", 17, 2,
            new(reservation, Guid.Empty, 3, 0, _driver), null, null, Sid, Creation, CancellationToken.None);

    [Fact]
    public async Task Manifest_before_grant_restart_replay_restores_the_exact_large_seed_grant_before_reply()
    {
        var budget = Budget(); var journal = Journal();
        var allocator = new StagedTransferAllocator(Root, journal, spaceBudget: budget);
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default));
        Guid id = Guid.NewGuid(); var request = Request(id);
        using (var output = new FileStream(Destination, FileMode.CreateNew)) output.SetLength(20 * MiB);
        bool interrupted = false;
        journal.AllocationCommitObserver = (point, entry) =>
        {
            if (!interrupted && point == StagedJournalWritePoint.AfterReplacement && entry.State == TransferJournalState.Allocated)
            { interrupted = true; throw new Win32Exception(5); }
        };
        await Assert.ThrowsAnyAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, async () => await Allocate(allocator, id), default));
        Assert.True(interrupted);
        string stage = Path.Combine(Root, id.ToString("N") + ".txt");
        Assert.Equal(20 * MiB, new FileInfo(stage).Length);
        Assert.False(File.Exists(stage + ".space"));
        Assert.False(ReadGrantIssued(id));

        var restarted = new StagedTransferAllocator(Root, Journal(), spaceBudget: Budget());
        var replay = Assert.IsType<StagedAllocationReply>(await restarted.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => throw new InvalidOperationException("Replay must not prepare another allocation."), default));
        Assert.Equal(20 * MiB, replay.InitialLength);
        Assert.True(ReadGrantIssued(id));
        byte[] grant = await File.ReadAllBytesAsync(stage + ".space");
        Assert.Equal(64, grant.Length);
        Assert.True(BinaryPrimitives.ReadInt64LittleEndian(grant.AsSpan(8)) > 20 * MiB);
        Assert.Equal(replay.StageIdentity.VolumeSerialNumber, BinaryPrimitives.ReadUInt64LittleEndian(grant.AsSpan(16)));
        Assert.Equal(replay.StageIdentity.FileIdLow, BinaryPrimitives.ReadUInt64LittleEndian(grant.AsSpan(24)));
        Assert.Equal(replay.StageIdentity.FileIdHigh, BinaryPrimitives.ReadUInt64LittleEndian(grant.AsSpan(32)));
        Assert.Equal(id, new Guid(grant.AsSpan(40, 16)));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused*"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Create_before_identity_restart_keeps_unknown_bytes_held_on_refusal_and_retry(bool retryAllocation)
    {
        Guid id = Guid.NewGuid(); string stage = Path.Combine(Root, id.ToString("N") + ".txt");
        var budget = Budget(); budget.Reserve(id, Sid, stage, Destination);
        await File.WriteAllTextAsync(stage, "unknown object before identity receipt");
        var journal = Journal();
        await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        var restartedBudget = Budget();
        var allocator = new StagedTransferAllocator(Root, journal, spaceBudget: restartedBudget);
        await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(Request(id),
            Destination, DestinationKind.Cloud,
            async () => retryAllocation ? await Allocate(allocator, id) : null, default));
        Assert.Equal("unknown object before identity receipt", await File.ReadAllTextAsync(stage));
        Assert.False(File.Exists(stage + ".space"));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused*"));
        Assert.Throws<StagedSpaceException>(() => restartedBudget.Reserve(Guid.NewGuid(), Sid));
        Assert.False(ReadGrantIssued(id));
    }

    [Fact]
    public async Task Many_failed_creates_and_old_refusals_recover_at_startup_and_background_then_normal_saves_succeed()
    {
        var budget = Budget(); var journal = Journal();
        var allocator = new StagedTransferAllocator(Root, journal, spaceBudget: budget);
        await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        for (int i = 0; i < 96; i++)
        {
            Guid id = Guid.NewGuid(); var request = Request(id);
            Assert.Null(await allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
                () => Task.FromResult<StagedAllocationReply?>(null), default));
            // Upgrade fixture from the regressed build, exceeding the old global threshold.
            await File.WriteAllBytesAsync(Path.Combine(Root, id.ToString("N") + ".allocation-refused"),
                MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref request, 1)).ToArray());
        }
        Guid damaged = Guid.NewGuid(); string partial = Path.Combine(Root,
            damaged.ToString("N") + ".allocation-refused." + Guid.NewGuid().ToString("N") + ".tmp");
        await File.WriteAllTextAsync(partial, "partial legacy refusal: retain exactly");
        var restartedJournal = Journal();
        budget = new StagedSpaceBudget(Root, new(true, 512 * MiB, 128 * MiB, 32 * MiB), () => 2048 * MiB,
            restartedJournal);
        allocator = new StagedTransferAllocator(Root, restartedJournal, spaceBudget: budget);
        var failures = new List<Guid>();
        await allocator.RecoverFailedAllocationsAsync(default, int.MaxValue, (id, _) => failures.Add(id));
        Assert.Equal(new[] { damaged }, failures);
        Assert.Equal(partial, Assert.Single(Directory.GetFiles(Root, "*.allocation-refused*")));
        await allocator.RecoverFailedAllocationsAsync(default, 16); // Background retry is safe/idempotent.
        Assert.Equal("partial legacy refusal: retain exactly", await File.ReadAllTextAsync(partial));
        await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(Request(damaged),
            Destination, DestinationKind.Cloud, () => Task.FromResult<StagedAllocationReply?>(null), default));
        Guid good = Guid.NewGuid();
        var reply = Assert.IsType<StagedAllocationReply>(await allocator.ResolveAllocationRequestV20Async(Request(good),
            Destination, DestinationKind.Cloud, async () => await Allocate(allocator, good), default));
        Assert.True(File.Exists(reply.Transfer.StagePath)); Assert.True(ReadGrantIssued(good));
        Assert.True(budget.Reserve(Guid.NewGuid(), "S-1-5-21-999") >= 16 * MiB);
        Assert.False(File.Exists(Destination));
    }

    private bool ReadGrantIssued(Guid id)
    {
        using var record = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Root, ".space-reservations", id.ToString("N") + ".json")));
        return record.RootElement.GetProperty("GrantIssued").GetBoolean();
    }
}
