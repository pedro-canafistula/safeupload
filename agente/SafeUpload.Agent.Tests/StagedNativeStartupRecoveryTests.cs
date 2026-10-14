#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;
using Microsoft.Extensions.Logging.Abstractions;

namespace SafeUpload.Agent.Tests;

public sealed class StagedNativeStartupRecoveryTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private string JournalPath => Path.Combine(_workspace.Root, "journal");
    private StagedTransferJournal Journal() => new(JournalPath);
    public void Dispose() => _workspace.Dispose();
    private NativeRecordReplay Replay(ulong revision = 17) => new(_driver, 11, revision, 42, []);

    [Fact]
    public async Task Real_durable_intent_matches_replay_without_swapping_file_id_halves_or_volume_identity()
    {
        var journal = Journal(); var volumeId = Guid.NewGuid(); var operation = Guid.NewGuid();
        var destination = new StagedDestinationIdentity(new(7, 11, 12), new(7, 21, 22), false, "document.txt", volumeId);
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), _driver, 10,
            new(7, 91, 92), 1234, 123456, 1, "S-1-5-21-100-200-300-1001", 42, volumeId);
        long generation;
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            generation = (await journal.BeginNativeDeleteOnCloseCreateAsync(turn, binding, operation,
                Path.Combine(_workspace.Root, "document.txt"), 0, CancellationToken.None)).Generation;
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Reconciliation, CancellationToken.None))
            await journal.RecordNativeDeleteOnCloseCreateResultAsync(turn, binding, operation, true, true);
        static SafeUploadStageIdentityV19 Wire(StagedStageIdentity id) => new()
            { VolumeSerialNumber = id.VolumeSerialNumber, FileIdLow = id.FileIdLow, FileIdHigh = id.FileIdHigh };
        var row = new NativeRecordReplayRow(_driver, binding.TransferId, binding.RequestNonce, operation, 10,
            checked((ulong)generation), binding.OwnerProcessCreationTime, Wire(destination.VolumeRoot), Wire(destination.Parent),
            Wire(binding.PublicIdentity), 42, (1u << 24) | 0x1000, 0x10000, 7, 1234, 1, binding.OwnerSid, false,
            destination.CanonicalLeaf, NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown |
            NativeRecordFacts.CreateAccepted | NativeRecordFacts.IdentityChecked, 0, 0, 0, volumeId);
        var startup = new StagedNativeStartupRecovery(journal, () => Replay() with { Records = new[] { row } },
            _ => Task.CompletedTask);
        await startup.Start(CancellationToken.None);
        Assert.True(startup.TryGetResult(_driver, out var result)); Assert.Equal(StagedDriverEpochReconcileV20.Active, result);
        Assert.True(startup.TryGetBoundResult(_driver, out var boundReceipt));
        Assert.True(boundReceipt!.HasUnresolvedPrerequisites);
        var retained = Assert.Single(Assert.Single(await journal.ReadDestinationHeadsAsync(CancellationToken.None)).Deletes);
        Assert.Equal(binding, retained.Binding); Assert.Equal(generation, retained.Generation);
        Assert.Equal(StagedPublicDeleteState.Admitted, retained.State);
    }

    [Fact]
    public async Task Startup_replies_busy_during_private_recovery_and_checks_the_final_live_replay()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int reads = 0;
        var startup = new StagedNativeStartupRecovery(Journal(), () => { reads++; return Replay(); }, async token =>
        { entered.SetResult(); await release.Task.WaitAsync(token); });
        Task run = startup.Start(CancellationToken.None); await entered.Task;
        Assert.False(run.IsCompleted); Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(startup.TryGetBoundResult(_driver, out _));
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
        release.SetResult(); await run;
        Assert.Equal(2, reads);
        Assert.True(startup.TryGetResult(_driver, out var result)); Assert.Equal(StagedDriverEpochReconcileV20.Active, result);
        Assert.False(startup.TryGetResult(Guid.NewGuid(), out _));
        Assert.True(startup.TryGetBoundResult(_driver, out var receipt));
        Assert.Equal(new StagedBoundRecoveryReceipt(_driver, 11, 42, 17, false), receipt);
        startup.Invalidate(); Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(startup.TryGetBoundResult(_driver, out _));
    }

    [Theory]
    [InlineData("revision")]
    [InlineData("connection")]
    [InlineData("driver")]
    [InlineData("boot")]
    public async Task Changed_final_authenticated_replay_cannot_accept_an_epoch(string shape)
    {
        int reads = 0;
        var startup = new StagedNativeStartupRecovery(Journal(), () =>
        {
            if (++reads == 1) return Replay();
            return shape switch
            {
                "revision" => Replay(18),
                "connection" => Replay() with { ConnectionEpoch = 12 },
                "driver" => Replay() with { DriverInstanceId = Guid.NewGuid() },
                _ => Replay() with { OsBootSequence = 43 }
            };
        }, _ => Task.CompletedTask);
        await Assert.ThrowsAsync<IOException>(() => startup.Start(CancellationToken.None));
        Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(startup.TryGetBoundResult(_driver, out _));
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    [Fact]
    public async Task Disconnect_during_private_recovery_never_makes_staging_ready()
    {
        StagedNativeStartupRecovery? startup = null;
        startup = new(Journal(), () => Replay(), _ => { startup!.Invalidate(); return Task.CompletedTask; });
        await Assert.ThrowsAsync<IOException>(() => startup.Start(CancellationToken.None));
        Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(startup.TryGetBoundResult(_driver, out _));
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    [Fact]
    public async Task Startup_cannot_bypass_a_durable_native_hold_before_anchored_recovery_is_connected()
    {
        var journal = Journal();
        var volumeId = Guid.NewGuid();
        var destination = new StagedDestinationIdentity(new(7, 11, 12), new(7, 21, 22), false, "document.txt", volumeId);
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 10,
            new(7, 91, 92), 1234, 123456, 1, "S-1-5-21-100-200-300-1001", 41, volumeId);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            await journal.BeginNativeDeleteOnCloseCreateAsync(turn, binding, Guid.NewGuid(),
                Path.Combine(_workspace.Root, "document.txt"), 0, CancellationToken.None);
        var startup = new StagedNativeStartupRecovery(journal, () => Replay(), _ => Task.CompletedTask);
        var failure = await Assert.ThrowsAsync<IOException>(() => startup.Start(CancellationToken.None));
        Assert.Contains("document.txt", failure.Message);
        Assert.False(startup.TryGetResult(_driver, out _));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single(Assert.Single(await journal.ReadDestinationHeadsAsync(CancellationToken.None)).Deletes).State);
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    [Fact]
    public async Task Startup_native_hold_emits_named_owner_scoped_guidance_without_accepting_epoch_or_releasing_hold()
    {
        var journal = Journal(); var volumeId = Guid.NewGuid(); var operation = Guid.NewGuid();
        var destination = new StagedDestinationIdentity(new(7, 11, 12), new(7, 21, 22), false, "held.txt", volumeId);
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 10,
            new(7, 91, 92), 1234, 123456, 1, "S-1-5-21-100-200-300-1001", 41, volumeId);
        string locator = Path.Combine(_workspace.Root, "held.txt");
        StagedPublicDeleteRecord original;
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            original = await journal.BeginNativeDeleteOnCloseCreateAsync(turn, binding, operation, locator, 0, CancellationToken.None);
        var record = new Emissions();
        var hub = new NotificationHub(record, NullLogger<NotificationHub>.Instance);
        using var owner = hub.Subscribe(1, binding.OwnerSid);
        using var otherUser = hub.Subscribe(1, "S-1-5-21-100-200-300-1002");
        using var otherSession = hub.Subscribe(2, binding.OwnerSid);
        using var unscoped = hub.Subscribe();
        var startup = new StagedNativeStartupRecovery(journal, () => Replay(), _ => Task.CompletedTask,
            (head, delete) => StagedNativeRecoveryNotifications.Publish(hub, NullLogger.Instance,
                head, delete, StagedRecoveryAdvice.CollectDiagnostics, "NativeRecoveryUnresolved"));
        await Assert.ThrowsAsync<IOException>(() => startup.Start(CancellationToken.None));
        Assert.True(owner.Reader.TryRead(out var delivered));
        var notice = Assert.IsType<TransferNotification>(delivered);
        Assert.Equal(locator, notice.FileName); Assert.Equal(binding.TransferId, notice.TransferId);
        Assert.Equal(StagedRecoveryAdvice.CollectDiagnostics, notice.RecoveryAdvice);
        Assert.False(otherUser.Reader.TryRead(out _)); Assert.False(otherSession.Reader.TryRead(out _));
        Assert.False(unscoped.Reader.TryRead(out _));
        Assert.Equal(notice, Assert.Single(record.Notices));
        Assert.Equal(original, Assert.Single(Assert.Single(await Journal().ReadDestinationHeadsAsync(CancellationToken.None)).Deletes));
        Assert.True(startup.HasFailed); Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    [Fact]
    public async Task Failed_startup_hold_reporting_cannot_accept_epoch_or_release_the_durable_barrier()
    {
        var journal = Journal(); var volumeId = Guid.NewGuid();
        var destination = new StagedDestinationIdentity(new(7, 11, 12), new(7, 21, 22), false, "held.txt", volumeId);
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 10,
            new(7, 91, 92), 1234, 123456, 1, "S-1-5-21-100-200-300-1001", 41, volumeId);
        using (var turn = await journal.EnterDestinationCommitTurnAsync(destination,
                   StagedDestinationTurnPurpose.Allocation, CancellationToken.None))
            await journal.BeginNativeDeleteOnCloseCreateAsync(turn, binding, Guid.NewGuid(),
                Path.Combine(_workspace.Root, "held.txt"), 0, CancellationToken.None);
        int calls = 0;
        var startup = new StagedNativeStartupRecovery(journal, () => Replay(), _ => Task.CompletedTask,
            (_, _) => { calls++; throw new IOException("Injected notification failure"); });
        var error = await Assert.ThrowsAsync<IOException>(() => startup.Start(CancellationToken.None));
        Assert.Contains("Injected notification failure", error.Message); Assert.Equal(1, calls);
        Assert.True(startup.HasFailed); Assert.False(startup.TryGetResult(_driver, out _));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single(Assert.Single(await Journal().ReadDestinationHeadsAsync(CancellationToken.None)).Deletes).State);
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    private sealed class Emissions : INotificationRecord
    {
        internal readonly List<AgentNotification> Notices = [];
        public void Append(AgentNotification notification, uint? targetSessionId) => Notices.Add(notification);
    }
}
#endif
