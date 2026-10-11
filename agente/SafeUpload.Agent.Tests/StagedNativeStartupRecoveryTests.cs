#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

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
    public async Task Startup_replies_busy_during_private_recovery_and_checks_the_final_live_replay()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int reads = 0;
        var startup = new StagedNativeStartupRecovery(Journal(), () => { reads++; return Replay(); }, async token =>
        { entered.SetResult(); await release.Task.WaitAsync(token); });
        Task run = startup.Start(CancellationToken.None); await entered.Task;
        Assert.False(run.IsCompleted); Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
        release.SetResult(); await run;
        Assert.Equal(2, reads);
        Assert.True(startup.TryGetResult(_driver, out var result)); Assert.Equal(StagedDriverEpochReconcileV20.Active, result);
        Assert.False(startup.TryGetResult(Guid.NewGuid(), out _));
        startup.Invalidate(); Assert.False(startup.TryGetResult(_driver, out _));
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
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    [Fact]
    public async Task Disconnect_during_private_recovery_never_makes_staging_ready()
    {
        StagedNativeStartupRecovery? startup = null;
        startup = new(Journal(), () => Replay(), _ => { startup!.Invalidate(); return Task.CompletedTask; });
        await Assert.ThrowsAsync<IOException>(() => startup.Start(CancellationToken.None));
        Assert.False(startup.TryGetResult(_driver, out _));
        Assert.False(File.Exists(Path.Combine(JournalPath, "driver-epoch.state")));
    }

    [Fact]
    public async Task Startup_cannot_bypass_a_durable_native_hold_before_anchored_recovery_is_connected()
    {
        var journal = Journal();
        var destination = new StagedDestinationIdentity(new(7, 11, 12), new(7, 21, 22), false, "document.txt");
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 10,
            new(7, 91, 92), 1234, 123456, 1, "S-1-5-21-100-200-300-1001", 41);
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
}
#endif
