using System.Text.Json.Nodes;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class StagedDriverEpochStartupTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _oldDriver = Guid.NewGuid();
    private string DirectoryPath => Path.Combine(_workspace.Root, "journal");
    private string EpochPath => Path.Combine(DirectoryPath, "driver-epoch.state");
    private StagedTransferJournal Journal() => new(DirectoryPath);
    public void Dispose() => _workspace.Dispose();

    private static (StagedNativeRecoverySession Session, StagedNativeRecoverySession.Proof Proof) Evidence(
        Guid driver, uint? boot, bool complete = true, bool reconciled = true)
    {
        var session = new StagedNativeRecoverySession(driver, 11, boot);
        return (session, session.ReconcileReplay(driver, 11, complete, reconciled, []));
    }

    private static Task NoRecovery(CancellationToken _) => Task.CompletedTask;
    private static Task<StagedDriverEpochReconcileV20> Reconcile(StagedTransferJournal journal, Guid driver,
        StagedNativeRecoverySession.Proof proof, Func<CancellationToken, Task>? recover = null,
        CancellationToken token = default) => journal.ReconcileDriverStartupAsync(driver, 0x3f,
            proof, recover ?? NoRecovery, token);

    private async Task Seed(uint boot = 42)
    {
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await Reconcile(Journal(), _oldDriver, Evidence(_oldDriver, boot).Proof));
    }

    [Fact]
    public async Task Restart_acceptance_waits_for_private_recovery_without_holding_the_journal_lock()
    {
        await Seed(); string original = await File.ReadAllTextAsync(EpochPath);
        Guid next = Guid.NewGuid(); var recovered = Journal();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<StagedDriverEpochReconcileV20> pending = Reconcile(recovered, next, Evidence(next, 43).Proof, async token =>
        { entered.SetResult(); await release.Task.WaitAsync(token); });
        await entered.Task;
        Assert.False(pending.IsCompleted);
        Assert.Equal(original, await File.ReadAllTextAsync(EpochPath));
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected,
            await recovered.ReconcileDriverInstanceV20Async(next, 0x3f, CancellationToken.None));
        release.SetResult();
        Assert.Equal(StagedDriverEpochReconcileV20.Active, await pending);
        var epoch = JsonNode.Parse(await File.ReadAllTextAsync(EpochPath))!;
        Assert.Equal(next, epoch["DriverInstanceId"]!.GetValue<Guid>());
        Assert.Equal(43u, epoch["OsBootSequence"]!.GetValue<uint>());
        Assert.Null(epoch["DrainNonce"]); // Restart never fabricates a drain.
    }

    [Theory]
    [InlineData("failure")]
    [InlineData("disconnect")]
    [InlineData("new-replay")]
    [InlineData("cancel")]
    public async Task Failed_or_invalidated_private_recovery_never_replaces_the_epoch(string shape)
    {
        await Seed(); string original = await File.ReadAllTextAsync(EpochPath);
        Guid next = Guid.NewGuid(); var evidence = Evidence(next, 43);
        using var cancel = new CancellationTokenSource();
        async Task Recover(CancellationToken token)
        {
            await Task.Yield();
            if (shape == "failure") throw new IOException("Injected private recovery failure");
            if (shape == "disconnect") evidence.Session.Invalidate();
            if (shape == "new-replay") evidence.Session.ReconcileReplay(next, 11, false, false, []);
            if (shape == "cancel") cancel.Cancel();
        }
        if (shape == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Reconcile(Journal(), next, evidence.Proof, Recover, cancel.Token));
        else await Assert.ThrowsAnyAsync<IOException>(() => Reconcile(Journal(), next, evidence.Proof, Recover));
        Assert.Equal(original, await File.ReadAllTextAsync(EpochPath));
    }

    [Theory]
    [InlineData(42u, 42u)]
    [InlineData(42u, 41u)]
    [InlineData(uint.MaxValue, 0u)]
    public async Task Changed_driver_equal_lower_or_wrapped_boot_does_not_run_recovery(uint oldBoot, uint currentBoot)
    {
        await Seed(oldBoot); string original = await File.ReadAllTextAsync(EpochPath);
        Guid next = Guid.NewGuid(); bool ran = false;
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected, await Reconcile(Journal(), next,
            Evidence(next, currentBoot).Proof, _ => { ran = true; return Task.CompletedTask; }));
        Assert.False(ran); Assert.Equal(original, await File.ReadAllTextAsync(EpochPath));
    }

    [Theory]
    [InlineData("partial")]
    [InlineData("unreconciled")]
    [InlineData("missing-boot")]
    [InlineData("wrong-driver")]
    public async Task Unqualified_current_evidence_cannot_create_an_epoch(string shape)
    {
        var journal = Journal(); Guid driver = Guid.NewGuid();
        var evidence = Evidence(shape == "wrong-driver" ? Guid.NewGuid() : driver,
            shape == "missing-boot" ? null : 42u, complete: shape != "partial", reconciled: shape != "unreconciled");
        bool ran = false;
        await Assert.ThrowsAsync<IOException>(() => Reconcile(journal, driver, evidence.Proof,
            _ => { ran = true; return Task.CompletedTask; }));
        Assert.False(ran); Assert.False(File.Exists(EpochPath));
    }

    [Fact]
    public async Task Legacy_missing_boot_can_only_be_captured_from_the_same_original_driver()
    {
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await Journal().ReconcileDriverInstanceV20Async(_oldDriver, 0x3f, CancellationToken.None));
        string original = await File.ReadAllTextAsync(EpochPath); Guid next = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected,
            await Reconcile(Journal(), next, Evidence(next, 43).Proof));
        Assert.Equal(original, await File.ReadAllTextAsync(EpochPath));
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await Reconcile(Journal(), _oldDriver, Evidence(_oldDriver, 42).Proof));
        var captured = JsonNode.Parse(await File.ReadAllTextAsync(EpochPath))!;
        Assert.Equal(_oldDriver, captured["DriverInstanceId"]!.GetValue<Guid>());
        Assert.Equal(42u, captured["OsBootSequence"]!.GetValue<uint>());
        Assert.Equal(JsonNode.Parse(original)!["AcceptedAtUtc"]!.ToJsonString(), captured["AcceptedAtUtc"]!.ToJsonString());
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await Reconcile(Journal(), next, Evidence(next, 43).Proof));
    }

    [Fact]
    public async Task Same_driver_resume_cannot_change_its_original_boot_baseline()
    {
        await Seed(); string original = await File.ReadAllTextAsync(EpochPath);
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected,
            await Reconcile(Journal(), _oldDriver, Evidence(_oldDriver, 43).Proof));
        Assert.Equal(original, await File.ReadAllTextAsync(EpochPath));
    }

    [Fact]
    public async Task Recovery_does_not_overwrite_a_concurrent_exact_drain_receipt()
    {
        await Seed(); Guid next = Guid.NewGuid(); var journal = Journal();
        Assert.Equal(StagedDriverEpochReconcileV20.Rejected, await Reconcile(journal, next, Evidence(next, 43).Proof,
            async token => Assert.True(await journal.DrainDriverInstanceV20Async(_oldDriver, 7, 8, token))));
        var epoch = JsonNode.Parse(await File.ReadAllTextAsync(EpochPath))!;
        Assert.Equal(_oldDriver, epoch["DriverInstanceId"]!.GetValue<Guid>());
        Assert.Equal(8UL, epoch["DrainNonce"]!.GetValue<ulong>());
        Assert.Equal(StagedDriverEpochReconcileV20.Active,
            await Reconcile(journal, next, Evidence(next, 43).Proof));
    }

    [Fact]
    public async Task Drained_same_epoch_remains_replay_only_and_runs_no_private_recovery()
    {
        await Seed(); var journal = Journal();
        Assert.True(await journal.DrainDriverInstanceV20Async(_oldDriver, 7, 8, CancellationToken.None));
        bool ran = false;
        Assert.Equal(StagedDriverEpochReconcileV20.DrainReplayOnly, await Reconcile(journal, _oldDriver,
            Evidence(_oldDriver, 42).Proof, _ => { ran = true; return Task.CompletedTask; }));
        Assert.False(ran);
    }

    [Fact]
    public async Task Qualified_restart_retains_unsaved_bytes_and_original_attachment_epoch()
    {
        await Seed(); var journal = Journal();
        string dest = Path.Combine(_workspace.Root, "destination"); Directory.CreateDirectory(dest);
        string stage = Path.Combine(_workspace.Root, "stage.txt");
        await File.WriteAllTextAsync(stage, "private unsaved content");
        var transfer = new StagedTransfer(Guid.NewGuid(), stage, Path.Combine(dest, "document.txt"),
            DestinationKind.Cloud, "notepad.exe", 1234, 1)
        {
            RequestorSid = "S-1-5-21-111-222-333-1000",
            RequestorProcessCreationTime = 638953632000000000
        };
        await journal.CreateAsync(transfer, CancellationToken.None, allocationDisposition: 2,
            allocationReferenceKind: 0, driverInstanceId: _oldDriver,
            parentDirectoryIdentity: StagedStageFile.ReadDirectoryIdentity(dest));
        Guid next = Guid.NewGuid();
        Assert.Equal(StagedDriverEpochReconcileV20.Active, await Reconcile(journal, next, Evidence(next, 43).Proof,
            journal.RetainInterruptedAsync));
        var retained = await journal.ReadAsync(transfer.TransferId, CancellationToken.None);
        Assert.Equal(TransferJournalState.Unsealed, retained.State);
        Assert.Equal(_oldDriver, retained.DriverInstanceId);
        Assert.Equal("private unsaved content", await File.ReadAllTextAsync(stage));
        Assert.False(File.Exists(transfer.DestinationPath));
        Assert.False(await journal.DrainDriverInstanceV20Async(_oldDriver, 9, 10, CancellationToken.None));
    }
}
