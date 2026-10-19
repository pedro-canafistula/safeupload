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
            () => Task.FromResult<StagedAllocationReply?>(null), default));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused*"));
        Assert.Empty(await Journal().ReadPendingAsync(default));
    }

    [Fact]
    public async Task Definitive_refusal_cleans_unjournaled_backing_without_creating_durable_metadata()
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        Assert.True(request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source));
        string stage = Path.Combine(Root, source.Intent.AllocationReservationId.ToString("N") + ".txt");
        await File.WriteAllTextAsync(stage, "private interrupted bytes");
        Assert.Null(await allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
            () => Task.FromResult<StagedAllocationReply?>(null), default));
        Assert.False(File.Exists(stage)); Assert.False(File.Exists(Destination));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused*"));
        Assert.Empty(await Journal().ReadPendingAsync(default));
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
    public async Task Stateless_refusal_and_late_allocation_serialize_for_exact_kind5_cleanup()
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
        Assert.Null(await first);
        var late = Assert.IsType<StagedAllocationReply>(await second);
        Assert.Single(await journal.ReadPendingAsync(default));
        var discard = new StagedDiscardRequest(late.Transfer.TransferId,
            new(late.Transfer.TransferId, late.DestinationGeneration, late.StageIdentity), StagedDiscardKind.UnattachedAllocation);
        Assert.Equal(StagedDiscardStatus.Pending, await journal.BeginOrConfirmDiscardAsync(discard, default, 17, _driver));
        Assert.Equal(StagedDiscardStatus.Acknowledged, await journal.CompleteDiscardAsync(discard, default));
        Assert.False(File.Exists(late.Transfer.StagePath)); Assert.False(File.Exists(Destination));
        Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused*"));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(20)]
    [InlineData(40)]
    [InlineData(1128)]
    public async Task Altered_request_cannot_reuse_a_terminal_reservation(int offset)
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source);
        await File.WriteAllBytesAsync(Path.Combine(Root, source.Intent.AllocationReservationId.ToString("N") + ".allocation-refused"),
            MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref request, 1)).ToArray());
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

    private StagedSpaceBudget Budget() => new(Root,
        new(true, 512L << 20, 128L << 20, 0), () => 2048L << 20);

    [Fact]
    public async Task Real_budget_exhaustion_proves_no_allocation_without_losing_alert_or_prior_charge()
    {
        StagedPrivateStorage.CreateDirectory(Root);
        var journal = Journal();
        await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        var budget = Budget(); var allocator = new StagedTransferAllocator(Root, journal, spaceBudget: budget);
        var prior = Assert.IsType<StagedAllocationReply>(await Allocate(allocator, Request()));
        byte[] priorBytes = await File.ReadAllBytesAsync(prior.Transfer.StagePath);
        var request = Request();
        foreach (bool restart in new[] { false, true })
        {
            if (restart)
            {
                budget = Budget();
                allocator = new StagedTransferAllocator(Root, Journal(), spaceBudget: budget);
            }
            var error = await Assert.ThrowsAsync<StagedNoAllocationCommittedException>(() =>
                allocator.ResolveAllocationRequestV20Async(request, Destination, DestinationKind.Cloud,
                    () => Allocate(allocator, request), default));
            Assert.IsType<StagedSpaceException>(error.InnerException);
            Assert.True(StagedSpaceFailure.IsSpace(error));
            Assert.Equal(StageV20Result.NoAllocationCommitted, MinifilterInterceptor.ClassifyAllocationFailure(error));
            Assert.Equal(StageV20Result.RetryableFailure,
                MinifilterInterceptor.ClassifyAllocationFailure(new IOException("Wrapped proof is not authority", error)));
            Assert.True(budget.ContentReservationPending(prior.Transfer.TransferId));
            Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
            Assert.Equal(priorBytes, await File.ReadAllBytesAsync(prior.Transfer.StagePath));
            Assert.Single(await Journal().ReadPendingAsync(default));
            Assert.False(File.Exists(Destination));
            Assert.Empty(Directory.GetFiles(Root, "*.allocation-refused*"));
            var reply = FilterPort.CreateAllocationResolutionReplyV20(request,
                MinifilterInterceptor.ClassifyAllocationFailure(error)!.Value);
            FilterPort.ValidateAllocationResolutionReplyV20(reply, request);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Space_failure_after_actual_commit_never_supplies_terminal_release(bool afterReplacement)
    {
        StagedPrivateStorage.CreateDirectory(Root);
        var journal = Journal();
        await journal.ReconcileDriverInstanceV20Async(_driver, (uint)StageV20Capability.Required, default);
        bool injected = false;
        journal.AllocationCommitObserver = (point, entry) =>
        {
            if (afterReplacement && !injected && point == StagedJournalWritePoint.AfterReplacement)
            { injected = true; throw new StagedSpaceException("metadata budget after replacement"); }
        };
        var allocator = new StagedTransferAllocator(Root, journal, spaceBudget: Budget());
        var request = Request();
        var error = await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, async () =>
            {
                await Allocate(allocator, request);
                throw new StagedSpaceException("resource failure after allocation committed");
            }, default));
        Assert.Equal(afterReplacement, injected);
        Assert.True(StagedSpaceFailure.IsSpace(error));
        Assert.IsAssignableFrom<Exception>(error.Data["AllocationAbsenceProofFailure"]);
        Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(error));
        var entry = Assert.Single(await journal.ReadPendingAsync(default));
        byte[] bytes = await File.ReadAllBytesAsync(entry.Transfer.StagePath);
        var restarted = new StagedTransferAllocator(Root, Journal(), spaceBudget: Budget());
        var replay = Assert.IsType<StagedAllocationReply>(await restarted.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => throw new InvalidOperationException("Never seed twice"), default));
        Assert.Equal(entry.Transfer, replay.Transfer);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(replay.Transfer.StagePath));
        Assert.False(File.Exists(Destination));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Space_failure_preserves_unknown_backing_or_orphan_companion_and_alert(bool companion)
    {
        StagedPrivateStorage.CreateDirectory(Root);
        var allocator = new StagedTransferAllocator(Root, Journal(), spaceBudget: Budget());
        var request = Request();
        request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source);
        string path = Path.Combine(Root, source.Intent.AllocationReservationId.ToString("N") + ".txt") +
            (companion ? ".space" : "");
        byte[] residue = [1, 2, 3, 4];
        await File.WriteAllBytesAsync(path, residue);
        var error = await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => throw new StagedSpaceException("space refused"), default));
        Assert.True(StagedSpaceFailure.IsSpace(error));
        Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(error));
        Assert.Equal(residue, await File.ReadAllBytesAsync(path));
        Assert.False(File.Exists(Destination));
    }

    [Fact]
    public async Task Space_exception_without_real_budget_proof_remains_uncertain_and_keeps_residue()
    {
        var allocator = new StagedTransferAllocator(Root, Journal()); var request = Request();
        request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source);
        string path = Path.Combine(Root, source.Intent.AllocationReservationId.ToString("N") + ".txt");
        await File.WriteAllTextAsync(path, "unknown private bytes");
        var error = await Assert.ThrowsAsync<StagedSpaceException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => throw new StagedSpaceException("No budget witness"), default));
        Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(error));
        Assert.Equal("unknown private bytes", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public async Task Failed_ledger_persistence_blocks_absence_proof_even_with_no_backing()
    {
        StagedPrivateStorage.CreateDirectory(Root);
        var budget = Budget(); var allocator = new StagedTransferAllocator(Root, Journal(), spaceBudget: budget);
        var request = Request();
        request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source);
        string temporary = Path.Combine(Root, ".space-reservations", source.Intent.AllocationReservationId.ToString("N") + ".json.new");
        await File.WriteAllTextAsync(temporary, "interrupted metadata");
        Assert.Throws<IOException>(() => budget.Reserve(source.Intent.AllocationReservationId, Sid));
        var error = await Assert.ThrowsAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
            Destination, DestinationKind.Cloud, () => throw new StagedSpaceException("No new capacity"), default));
        Assert.True(StagedSpaceFailure.IsSpace(error));
        Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(error));
        Assert.Equal("interrupted metadata", await File.ReadAllTextAsync(temporary));
        Assert.Throws<IOException>(() => Budget());
    }

    [Theory]
    [InlineData("cleaned")]
    [InlineData("locked")]
    [InlineData("issued")]
    [InlineData("snapshot")]
    [InlineData("replacement")]
    public async Task Space_refusal_needs_exact_unissued_cleanup_without_live_obligations(string custody)
    {
        StagedPrivateStorage.CreateDirectory(Root);
        var budget = Budget(); var allocator = new StagedTransferAllocator(Root, Journal(), spaceBudget: budget);
        var request = Request();
        request.TryReadStagePayload<SafeUploadStageAllocateV20>(Operation.StageAllocate, out var source);
        Guid id = source.Intent.AllocationReservationId;
        string path = Path.Combine(Root, id.ToString("N") + ".txt");
        long capacity = budget.Reserve(id, Sid, path, Destination);
        await File.WriteAllTextAsync(path, "private seed");
        StagedStageIdentity identity;
        using (var stage = StagedStageFile.Open(path)) identity = stage.Identity;
        budget.RecordStage(id, path, identity);
        FileStream? held = null; IDisposable? snapshotLease = null;
        try
        {
            switch (custody)
            {
                case "locked":
                    held = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    break;
                case "issued":
                    var transfer = new StagedTransfer(id, path, Destination, DestinationKind.Cloud, "writer.exe", 17, 2)
                        { RequestorSid = Sid };
                    budget.Bind(new(transfer, TransferJournalState.Allocated, null, DateTimeOffset.UtcNow)
                        { StageIdentity = identity });
                    break;
                case "snapshot":
                    string snapshot = path + ".snapshot";
                    await File.WriteAllTextAsync(snapshot, "inspection snapshot");
                    held = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read);
                    snapshotLease = budget.BeginSnapshot(id, snapshot, held, held.Length);
                    break;
                case "replacement":
                    File.Delete(path);
                    await File.WriteAllTextAsync(path, "replacement private object");
                    using (var replacement = StagedStageFile.Open(path)) Assert.NotEqual(identity, replacement.Identity);
                    break;
            }
            var error = await Assert.ThrowsAnyAsync<IOException>(() => allocator.ResolveAllocationRequestV20Async(request,
                Destination, DestinationKind.Cloud, () => throw new StagedSpaceException("seed preparation exhausted space"), default));
            Assert.True(StagedSpaceFailure.IsSpace(error));
            if (custody == "cleaned")
            {
                Assert.IsType<StagedNoAllocationCommittedException>(error);
                Assert.Equal(StageV20Result.NoAllocationCommitted, MinifilterInterceptor.ClassifyAllocationFailure(error));
                Assert.False(File.Exists(path));
                Assert.False(budget.ContentReservationPending(id));
                Assert.Equal(capacity, budget.Reserve(Guid.NewGuid(), Sid));
            }
            else
            {
                Assert.Equal(StageV20Result.RetryableFailure, MinifilterInterceptor.ClassifyAllocationFailure(error));
                Assert.True(File.Exists(path));
                Assert.True(budget.ContentReservationPending(id));
                Assert.Throws<StagedSpaceException>(() => budget.Reserve(Guid.NewGuid(), Sid));
            }
            Assert.False(File.Exists(Destination));
        }
        finally { snapshotLease?.Dispose(); held?.Dispose(); }
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
