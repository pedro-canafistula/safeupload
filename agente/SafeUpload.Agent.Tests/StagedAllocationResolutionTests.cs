using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedAllocationResolutionTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private const long Creation = 123456;
    private const string Sid = "S-1-5-21-111-222-333-1000";
    public void Dispose() => _workspace.Dispose();
    private string Destination => Path.Combine(_workspace.Root, "public.txt");
    private string Root => Path.Combine(_workspace.Root, "stage");
    private StagedTransferJournal Journal(Action<StagedJournalWritePoint, TransferJournalEntry>? observer = null) =>
        new(Path.Combine(_workspace.Root, "journal"), false, 50_000, observer);

    private SafeUploadRequest Request(Guid? reservation = null)
    {
        byte[] bytes = new byte[Contract.RequestSize];
        void Put(int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), value);
        Put(0, Contract.Version); Put(4, Contract.RequestSize); Put(8, 123);
        Put(16, Operation.StageAllocate); Put(20, 17); Put(24, Contract.StageV20ReplyFlag);
        Put(28, checked((uint)Destination.Length * 2)); Put(32, Contract.StageAllocateV20Size);
        Put(36, Contract.StageExtensionVersion);
        Encoding.Unicode.GetBytes(Destination).CopyTo(bytes, 40);
        var source = new SafeUploadStageAllocateV20
        {
            Intent = new() { Version = Contract.StageExtensionVersion, StructSize = Contract.StageAllocateV20Size,
                AllocationReservationId = reservation ?? Guid.NewGuid(), Disposition = 3, DriverInstanceId = _driver },
            RequestorCreationTime = Creation
        };
        MemoryMarshal.Write(bytes.AsSpan(1064), in source);
        return MemoryMarshal.Read<SafeUploadRequest>(bytes);
    }

    private async Task<StagedAllocationReply?> Allocate(StagedTransferAllocator allocator, SafeUploadRequest request)
    {
        Assert.True(request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source));
        var intent = source.Intent;
        return await allocator.AllocateV19CoreAsync(Destination, DestinationKind.Cloud, "writer.exe", 17, 2,
            new(intent.AllocationReservationId, intent.ParentTransferId, intent.Disposition, intent.ReferenceKind,
                intent.DriverInstanceId), null, null, Sid, Creation, CancellationToken.None);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(123457L)]
    public async Task Exited_or_reused_PID_without_manifest_gets_exact_terminal_refusal(long? observedCreation)
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        int allocations = 0;
        var result = await allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            async () =>
            {
                if (!StagedTransferAllocator.AllocationOwnerMatches(Creation, observedCreation)) return null;
                allocations++; return await Allocate(allocator, request);
            }, CancellationToken.None);
        Assert.Null(result); Assert.Equal(0, allocations); Assert.False(File.Exists(Destination));
        var restarted = new StagedTransferAllocator(Root, Journal());
        Assert.Null(await restarted.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            () => throw new InvalidOperationException("A terminal reservation must never be allocated later."), default));
        Assert.Single(Directory.GetFiles(Root, "*.allocation-refused"));
    }

    [Fact]
    public async Task Definitive_refusal_cleans_unjournaled_backing_before_persisting_exact_receipt()
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        Assert.True(request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source));
        string stage = Path.Combine(Root, source.Intent.AllocationReservationId.ToString("N") + ".txt");
        await File.WriteAllTextAsync(stage, "private interrupted bytes");
        Assert.Null(await allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            () => Task.FromResult<StagedAllocationReply?>(null), default));
        Assert.False(File.Exists(stage)); Assert.False(File.Exists(Destination));
        byte[] saved = await File.ReadAllBytesAsync(Assert.Single(Directory.GetFiles(Root, "*.allocation-refused")));
        Assert.Equal(MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref request, 1)).ToArray(), saved);
    }

    [Fact]
    public async Task Unresolved_or_reparse_backing_never_authorizes_terminal_release()
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source);
        string path = Path.Combine(Root, source.Intent.AllocationReservationId.ToString("N") + ".txt");
        // A directory at the backing name is a structural refusal on every host.
        Directory.CreateDirectory(path);
        await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => Task.FromResult<StagedAllocationReply?>(null), default));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused")); Assert.True(Directory.Exists(path));
    }

    [Fact]
    public async Task Existing_manifest_replays_exact_tuple_before_any_live_owner_lookup_or_allocation()
    {
        var journal = Journal(); await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        var allocator = new StagedTransferAllocator(Root, journal); var request = Request();
        var first = Assert.IsType<StagedAllocationReply>(await allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => Allocate(allocator, request), default));
        var restarted = new StagedTransferAllocator(Root, Journal());
        var replay = await restarted.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            () => throw new InvalidOperationException("Requester has exited; never look it up."), default);
        Assert.Equal(first, replay); Assert.True(File.Exists(first.Transfer.StagePath));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Post_commit_failures_keep_backing_and_resolve_by_exact_manifest(bool duringReplacement)
    {
        bool injected = false;
        var journal = Journal();
        journal.AllocationCommitObserver = (point, entry) =>
        {
            if (duringReplacement && !injected && entry.State == TransferJournalState.Allocated &&
                point == StagedJournalWritePoint.AfterReplacement)
            { injected = true; throw new Win32Exception(5); }
        };
        await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        var allocator = new StagedTransferAllocator(Root, journal); var request = Request();
        await Assert.ThrowsAnyAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, async () =>
            {
                await Allocate(allocator, request);
                throw new IOException("Owner lookup or reply failed AFTER commit.");
            }, default));
        Assert.Equal(duringReplacement, injected);
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused"));
        var restarted = new StagedTransferAllocator(Root, Journal());
        var replay = Assert.IsType<StagedAllocationReply>(await restarted.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => throw new InvalidOperationException("No second allocation."), default));
        Assert.True(File.Exists(replay.Transfer.StagePath)); Assert.False(File.Exists(Destination));
    }

    [Fact]
    public async Task Refusal_and_allocation_serialize_and_never_commit_both_for_one_reservation()
    {
        var journal = Journal(); await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        var allocator = new StagedTransferAllocator(Root, journal); var request = Request();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            async () => { entered.SetResult(); await resume.Task; return null; }, default);
        await entered.Task;
        var second = allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            () => Allocate(allocator, request), default);
        Assert.False(second.IsCompleted); resume.SetResult();
        Assert.Null(await first); Assert.Null(await second);
        Assert.Empty(await journal.ReadPendingAsync(default));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(20)]
    [InlineData(40)]
    [InlineData(1128)]
    public async Task Altered_request_cannot_reuse_a_terminal_reservation(int offset)
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        Assert.Null(await allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            () => Task.FromResult<StagedAllocationReply?>(null), default));
        byte[] bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref request, 1)).ToArray();
        bytes[offset] ^= 1; var changed = MemoryMarshal.Read<SafeUploadRequest>(bytes);
        await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(changed, Destination,
            DestinationKind.Cloud, () => throw new InvalidOperationException("No allocator on mismatched receipt."), default));
    }

    [Fact]
    public void Allocation_resolution_layout_and_full_request_echo_use_exact_memory_bytes()
    {
        Contract.Verify(); var request = Request();
        var reply = FilterPort.CreateAllocationResolutionReplyV20(request);
        FilterPort.ValidateAllocationResolutionReplyV20(reply, request);
        byte[] bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref reply, 1)).ToArray();
        Assert.Equal(1216, bytes.Length); Assert.Equal(20u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(20)));
        Assert.Equal(MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref request, 1)).ToArray(), bytes[24..]);
        Assert.Equal(Creation, BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(24 + 1128)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(20)]
    [InlineData(24 + 8)]
    [InlineData(24 + 20)]
    [InlineData(24 + 24)]
    [InlineData(24 + 40)]
    [InlineData(24 + 1072)]
    [InlineData(24 + 1088)]
    [InlineData(24 + 1104)]
    [InlineData(24 + 1108)]
    [InlineData(24 + 1112)]
    [InlineData(24 + 1128)]
    [InlineData(1215)]
    public void Terminal_receipt_refuses_every_altered_envelope_owner_intent_name_or_padding(int offset)
    {
        var request = Request(); var reply = FilterPort.CreateAllocationResolutionReplyV20(request);
        byte[] bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref reply, 1)).ToArray();
        bytes[offset] ^= 1; var altered = MemoryMarshal.Read<SafeUploadStageAllocationResolutionReplyV20>(bytes);
        Assert.Throws<ArgumentException>(() => FilterPort.ValidateAllocationResolutionReplyV20(altered, request));
    }

    [Fact]
    public async Task Allocation_resolution_profile_refuses_the_old_mask_before_epoch_activation()
    {
        var journal = Journal();
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected, await journal.ReconcileDriverInstanceV20Async(_driver, 0xbf, default));
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default));
    }

    [Fact]
    public void Uncertain_post_commit_failure_is_transient_and_semantic_refusal_is_generic_deny()
    {
        Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(new IOException("Post-commit storage failure.")));
        Assert.Null(MinifilterInterceptor.ClassifyAllocationFailure(StagedRequestRefusal.Create("Exact manifest mismatch.")));
        var request = Request();
        var retry = FilterPort.CreateAllocationResolutionReplyV20(request, StageV20Result.RetryableFailure);
        FilterPort.ValidateAllocationResolutionReplyV20(retry, request);
        Assert.NotEqual(StageV20Result.NoAllocationCommitted, retry.Result);
    }

    [Fact]
    public void Requester_exit_during_metadata_read_is_transient_not_a_refusal()
    {
        // A real process that exited after its identity could have been checked: reading its image name now throws.
        var start = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c exit 0") { UseShellExecute = false, CreateNoWindow = true };
        using var child = System.Diagnostics.Process.Start(start)!;
        Assert.True(child.WaitForExit(30_000));
        var error = Assert.Throws<IOException>(() => MinifilterInterceptor.ReadRequesterProcessName(child));
        Assert.IsType<InvalidOperationException>(error.InnerException);
        Assert.False(StagedRequestRefusal.IsPermanent(error));
        Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(error));
        Assert.Null(MinifilterInterceptor.ClassifyAllocationFailure(new InvalidOperationException("Unwrapped race.")));
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        Assert.Equal(self.ProcessName, MinifilterInterceptor.ReadRequesterProcessName(self));
    }
}
