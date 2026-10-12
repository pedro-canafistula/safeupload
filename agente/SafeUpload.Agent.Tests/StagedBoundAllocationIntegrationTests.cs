#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

// Real Windows filesystem integration, without a loaded filter. These prove
// service allocation transactions; protected publication/Verifier remain
// separate VM gates.
public sealed class StagedBoundAllocationIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private string Parent => Path.Combine(_workspace.Root, "public");
    private string Stages => Path.Combine(_workspace.Root, "private");
    private string Journal => Path.Combine(_workspace.Root, "journal");
    public void Dispose() => _workspace.Dispose();

    private StagedAllocationBindingV23 Binding(string leaf, uint disposition, bool present, Guid? reservation = null)
    {
        Directory.CreateDirectory(Parent);
        string root = Path.GetPathRoot(Parent)!;
        var volume = new StringBuilder(128);
        Assert.True(GetVolumeNameForVolumeMountPointW(root, volume, volume.Capacity));
        string text = volume.ToString();
        Guid volumeId = Guid.Parse(text[(text.IndexOf('{') + 1)..text.IndexOf('}')]);
        StagedStageIdentity? target = null;
        if (present) { using var file = StagedStageFile.Open(Path.Combine(Parent, leaf)); target = file.Identity; }
        return new(reservation ?? Guid.NewGuid(), _driver, Guid.Empty, disposition, 0, volumeId,
            StagedStageFile.ReadDirectoryIdentity(root), StagedStageFile.ReadDirectoryIdentity(Parent),
            false, leaf, target);
    }

    private Task<StagedAllocationReply> Allocate(StagedTransferAllocator allocator,
        StagedAllocationBindingV23 binding, string? locator = null)
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var process = Process.GetCurrentProcess();
        return allocator.AllocateV23Async(locator ?? Path.Combine(Parent, binding.CanonicalLeaf), DestinationKind.Cloud,
            process.ProcessName, process.Id, checked((uint)process.SessionId), identity.User!.Value,
            process.StartTime.ToFileTimeUtc(), binding, CancellationToken.None);
    }

    [Theory]
    [InlineData(1u, true)]
    [InlineData(3u, true)]
    [InlineData(0u, false)]
    [InlineData(4u, false)]
    [InlineData(5u, false)]
    public async Task Existing_target_dispositions_seed_only_the_exact_held_source_and_replay_after_reopen(
        uint disposition, bool copied)
    {
        Directory.CreateDirectory(Parent);
        byte[] original = Enumerable.Range(0, 65539).Select(i => (byte)(i % 251)).ToArray();
        File.WriteAllBytes(Path.Combine(Parent, "save.txt"), original);
        var binding = Binding("save.txt", disposition, true);
        var journal = new StagedTransferJournal(Journal);
        var first = await Allocate(new(Stages, journal), binding);
        Assert.Equal(copied ? original : [], File.ReadAllBytes(first.Transfer.StagePath));
        var manifest = await journal.ReadAsync(first.Transfer.TransferId, CancellationToken.None);
        Assert.Equal(binding, manifest.BoundAllocation);
        Assert.Equal(23u, manifest.AllocationExtensionVersion);
        Assert.Equal(first.StageIdentity, manifest.StageIdentity);
        var head = await journal.ReadDestinationHeadAsync(binding.Destination, CancellationToken.None);
        Assert.Equal(first.Transfer.TransferId, head!.CurrentSaveTransferId);
        Assert.Equal(first.DestinationGeneration, head.MaxAllocated);
        var reopened = new StagedTransferJournal(Journal);
        var replay = await Allocate(new(Stages, reopened), binding);
        Assert.Equal(first, replay);
    }

    [Fact]
    public async Task Saved_allocation_replay_requires_the_live_owner_lifetime_and_session()
    {
        var binding = Binding("owned.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        var allocated = await Allocate(new(Stages, journal), binding);
        using var process = Process.GetCurrentProcess();
        var live = SessionResolver.GetRequiredProcessIdentity(process.Id);
        Assert.Equal(live.CreationTimeFileTime, allocated.Transfer.RequestorProcessCreationTime);
        MinifilterInterceptor.RequireBoundWriterIdentity(allocated.Transfer, process.Id);
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { RequestorProcessCreationTime = live.CreationTimeFileTime - 1 }, process.Id));
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { SessionId = live.SessionId + 1 }, process.Id));
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { RequestorSid = "S-1-0-0" }, process.Id));
        Assert.Throws<IOException>(() => MinifilterInterceptor.RequireBoundWriterIdentity(
            allocated.Transfer with { ProcessId = process.Id + 1 }, process.Id));
        var saved = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, saved.State);
        Assert.Equal(allocated.StageIdentity, saved.StageIdentity);
        Assert.True(File.Exists(saved.Transfer.StagePath));
        Assert.False(File.Exists(Path.Combine(Parent, binding.CanonicalLeaf)));
    }

    [Fact]
    public async Task Native_prepare_high_water_includes_retained_bound_manifest_even_after_head_loss()
    {
        Directory.CreateDirectory(Parent);
        File.WriteAllText(Path.Combine(Parent, "save.txt"), "approved source");
        var binding = Binding("save.txt", 1, true);
        var journal = new StagedTransferJournal(Journal);
        var save = await Allocate(new(Stages, journal), binding);
        File.Delete(Path.Combine(Journal, "destination-" + binding.Destination.StorageKey + ".state"));
        var native = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), _driver, 11,
            binding.PublicTarget!, save.Transfer.ProcessId, save.Transfer.RequestorProcessCreationTime!.Value,
            save.Transfer.SessionId!.Value, save.Transfer.RequestorSid!, 42, binding.MountManagerVolumeId);
        using var turn = await journal.EnterDestinationCommitTurnAsync(binding.Destination,
            StagedDestinationTurnPurpose.Allocation, CancellationToken.None);
        var prepared = await journal.BeginNativeDeleteOnCloseCreateAsync(turn, native, Guid.NewGuid(),
            save.Transfer.DestinationPath, retainedManifestHighWater: 0, CancellationToken.None);
        Assert.Equal(save.DestinationGeneration + 1, prepared.Generation);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, prepared.State);
        var head = (await journal.ReadDestinationHeadAsync(binding.Destination, CancellationToken.None))!;
        Assert.Equal(prepared.Generation, head.MaxAllocated);
        Assert.Equal(binding, (await journal.ReadAsync(binding.ReservationId, CancellationToken.None)).BoundAllocation);
    }

    [Fact]
    public async Task Renamed_parent_and_replaced_locator_cannot_select_different_seed_bytes()
    {
        Directory.CreateDirectory(Parent);
        File.WriteAllText(Path.Combine(Parent, "save.txt"), "original approved source");
        var binding = Binding("save.txt", 1, true);
        Directory.Move(Parent, Path.Combine(_workspace.Root, "renamed-original"));
        Directory.CreateDirectory(Parent);
        File.WriteAllText(Path.Combine(Parent, "save.txt"), "replacement locator bytes");
        var journal = new StagedTransferJournal(Journal);
        var result = await Allocate(new(Stages, journal), binding);
        await journal.ValidateAllocationReplyAsync(new(result.Transfer.TransferId, result.DestinationGeneration,
            result.StageIdentity), binding.ReservationId, CancellationToken.None);
        Assert.Equal("original approved source", File.ReadAllText(result.Transfer.StagePath));
        Assert.Equal("replacement locator bytes", File.ReadAllText(Path.Combine(Parent, "save.txt")));
    }

    [Fact]
    public async Task Replaced_public_identity_and_false_absence_never_create_a_manifest()
    {
        Directory.CreateDirectory(Parent);
        string path = Path.Combine(Parent, "save.txt");
        File.WriteAllText(path, "original");
        var existing = Binding("save.txt", 1, true);
        File.Move(path, Path.Combine(Parent, "retained-original.txt"));
        File.WriteAllText(path, "different identity");
        var journal = new StagedTransferJournal(Journal);
        var allocator = new StagedTransferAllocator(Stages, journal);
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, existing));
        Assert.Null(await journal.FindBoundAllocationAsync(existing.ReservationId, CancellationToken.None));
        var absent = Binding("new.txt", 2, false);
        File.WriteAllText(Path.Combine(Parent, "new.txt"), "");
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, absent));
        Assert.Null(await journal.FindBoundAllocationAsync(absent.ReservationId, CancellationToken.None));
        Assert.Empty(Directory.GetFiles(Stages));
    }

    [Fact]
    public async Task Manifest_before_failed_head_claim_replays_the_same_private_identity_and_generation()
    {
        var binding = Binding("empty.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        string blockedHead = Path.Combine(Journal, "destination-" + binding.Destination.StorageKey + ".state");
        Directory.CreateDirectory(blockedHead); // Real native head-commit failure after the manifest flush.
        await Assert.ThrowsAsync<IOException>(() => Allocate(new(Stages, journal), binding));
        var candidate = await journal.ReadAsync(binding.ReservationId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Allocated, candidate.State);
        Assert.True(File.Exists(candidate.Transfer.StagePath));
        Assert.Equal(0, new FileInfo(candidate.Transfer.StagePath).Length);
        await Assert.ThrowsAsync<IOException>(() => journal.ValidateAllocationReplyAsync(
            new(candidate.Transfer.TransferId, candidate.DestinationGeneration, candidate.StageIdentity!),
            binding.ReservationId, CancellationToken.None));
        Directory.Delete(blockedHead);
        var reopened = new StagedTransferJournal(Journal);
        var replay = await Allocate(new(Stages, reopened), binding);
        Assert.Equal(candidate.StageIdentity, replay.StageIdentity);
        Assert.Equal(candidate.DestinationGeneration, replay.DestinationGeneration);
        var head = await reopened.ReadDestinationHeadAsync(binding.Destination, CancellationToken.None);
        Assert.Equal(binding.ReservationId, head!.CurrentSaveTransferId);
        Assert.Equal(candidate.DestinationGeneration, head.MaxAllocated);
    }

    [Fact]
    public async Task Overtaken_manifest_candidate_remains_private_and_never_rolls_back_the_head()
    {
        var first = Binding("empty.txt", 2, false);
        var journal = new StagedTransferJournal(Journal);
        string blockedHead = Path.Combine(Journal, "destination-" + first.Destination.StorageKey + ".state");
        Directory.CreateDirectory(blockedHead);
        var allocator = new StagedTransferAllocator(Stages, journal);
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, first));
        var candidate = await journal.ReadAsync(first.ReservationId, CancellationToken.None);
        Directory.Delete(blockedHead);
        var newer = await Allocate(allocator, first with { ReservationId = Guid.NewGuid() });
        Assert.True(newer.DestinationGeneration > candidate.DestinationGeneration);
        await Assert.ThrowsAsync<IOException>(() => Allocate(allocator, first));
        Assert.True(File.Exists(candidate.Transfer.StagePath));
        var head = await journal.ReadDestinationHeadAsync(first.Destination, CancellationToken.None);
        Assert.Equal(newer.Transfer.TransferId, head!.CurrentSaveTransferId);
        Assert.Equal(newer.DestinationGeneration, head.MaxAllocated);
    }

    [Fact]
    public async Task Concurrent_guid_reuse_cannot_delete_a_different_destination_candidate()
    {
        var first = Binding("first.txt", 2, false);
        var second = first with { CanonicalLeaf = "second.txt" };
        var journal = new StagedTransferJournal(Journal);
        var allocator = new StagedTransferAllocator(Stages, journal);
        async Task<StagedAllocationReply?> Attempt(StagedAllocationBindingV23 binding)
        {
            try { return await Allocate(allocator, binding); }
            catch (IOException) { return null; }
        }
        var replies = await Task.WhenAll(Attempt(first), Attempt(second));
        var winner = Assert.Single(replies, r => r is not null)!;
        using var held = StagedStageFile.Open(winner.Transfer.StagePath);
        Assert.Equal(winner.StageIdentity, held.Identity);
        Assert.Equal(0, held.Stream.Length);
        Assert.Single(Directory.GetFiles(Stages));
        var saved = await journal.ReadAsync(first.ReservationId, CancellationToken.None);
        Assert.Equal(winner.Transfer, saved.Transfer);
    }

    [Fact]
    public async Task Waiting_destination_continuation_leaves_unrelated_work_free_and_drains_before_port_close()
    {
        using var continuations = new StagedRequestContinuations(CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var unrelated = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        continuations.Dispatch(async token =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            finally { stopped.SetResult(); }
        });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        continuations.Dispatch(_ => { unrelated.SetResult(); return Task.CompletedTask; });
        await unrelated.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(stopped.Task.IsCompleted);
        await continuations.DrainAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(stopped.Task.IsCompleted);
        Assert.Throws<InvalidOperationException>(() => continuations.Dispatch(_ => Task.CompletedTask));
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string root, StringBuilder volume, int size);
}
#endif
