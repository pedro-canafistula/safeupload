#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class StagedNativeLifecycleDispatcherTests
{
    private sealed class RecoveryCrash : Exception { }

    private StagedNativeStartupRecovery Startup(StagedTransferJournal? journal = null,
        Action<StagedDestinationHead, StagedPublicDeleteRecord, StagedRecoveryAdvice, string>? report = null,
        Func<NativeNameObservationRequest, NativeNameObservation>? observe = null) =>
        new(journal ?? new(Path.Combine(_workspace.Root, "journal")), () => _replay, _ => Task.CompletedTask,
            observeName: observe ?? (expected => { _observations++; return new(expected, _child); }), reportRecovery: report);

    private async Task AcceptedForRecovery(bool closed = true, bool coverageLost = false)
    {
        var prepared = await Send(Request(NativeLifecycleV24.Prepare));
        Advance(Row with { JournalGeneration = prepared.JournalGeneration,
            Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted |
                (closed ? NativeRecordFacts.LastHandleCleanedUp : 0) |
                (coverageLost ? NativeRecordFacts.CleanupCoverageLost : 0),
            CreateStatus = 0, IdentityStatus = unchecked((int)0xc0000001) });
        _observations = 0;
    }

    [Theory]
    [InlineData("result")]
    [InlineData("hold-release")]
    [InlineData("complete")]
    [InlineData("ack-armed")]
    [InlineData("retired")]
    public async Task Startup_restart_at_each_native_durable_boundary_retries_only_bookkeeping(string boundary)
    {
        await AcceptedForRecovery(); _child = null;
        bool injected = false;
        var journal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"))
        {
            DestinationHeadWritten = head =>
            {
                var delete = head.Deletes.SingleOrDefault();
                bool hit = boundary switch
                {
                    "result" => delete is { State: StagedPublicDeleteState.AcceptedUnresolved, NativeCreateAccepted: true },
                    "hold-release" => delete?.State == StagedPublicDeleteState.Admitted,
                    "complete" => delete is { State: StagedPublicDeleteState.Complete, NativeAcknowledgementRevision: null },
                    "ack-armed" => delete?.NativeAcknowledgementRevision is not null,
                    _ => delete is null
                };
                if (hit && !injected) { injected = true; throw new RecoveryCrash(); }
            }
        };
        if (boundary == "retired")
        {
            await Startup().Start(default);
            _replay = _replay with { Revision = _replay.Revision + 1, Records = [] }; // exact kernel ACK removal
        }
        await Assert.ThrowsAsync<RecoveryCrash>(() => Startup(journal).Start(default));
        Assert.True(injected);
        var restarted = Startup(); await restarted.Start(default);
        Assert.True(restarted.TryGetResult(_driver, out var result));
        Assert.Equal(StagedDriverEpochReconcileV20.Active, result);
        var head = await Head(); Assert.Equal(1, head.CommittedDelete); Assert.Equal(1, head.MaxAllocated);
        if (boundary == "retired") Assert.Empty(head.Deletes);
        else Assert.NotNull(Assert.Single(head.Deletes).NativeAcknowledgementRevision);
    }

    [Fact]
    public async Task Startup_live_original_then_last_close_then_directory_change_keeps_distinct_receipts()
    {
        await AcceptedForRecovery(closed: false);
        var notices = new List<StagedRecoveryAdvice>();
        var startup = Startup(report: (_, _, advice, _) => notices.Add(advice));
        await startup.Start(default);
        Assert.True(startup.TryGetResult(_driver, out var result)); Assert.Equal(StagedDriverEpochReconcileV20.Active, result);
        Assert.Equal(0, _observations); Assert.Equal(StagedRecoveryAdvice.CloseApplication, Assert.Single(notices));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single((await Head()).Deletes).State);
        Advance(Row with { Facts = Row.Facts | NativeRecordFacts.LastHandleCleanedUp });
        Assert.Equal(NativeLifecycleV24.Progress, (await Send(Request(NativeLifecycleV24.FactsChanged))).Result);
        Assert.Equal(StagedPublicDeleteState.Admitted, Assert.Single((await Head()).Deletes).State);
        Assert.Null(Assert.Single((await Head()).Deletes).NativeAcknowledgementRevision);
        await Startup().Start(default); // original is still delete-pending: no invented physical ACK
        Assert.Equal(0, (await Head()).CommittedDelete);
        _child = null; Advance(Row); // directory change, same original lifetime facts
        Assert.Equal(NativeLifecycleV24.Terminal, (await Send(Request(NativeLifecycleV24.FactsChanged))).Result);
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [] }; // lost final removal reply
        await Startup().Start(default);
        Assert.Empty((await Head()).Deletes); Assert.Equal(1, (await Head()).CommittedDelete);
    }

    [Theory]
    [InlineData("same-driver")]
    [InlineData("same-boot")]
    [InlineData("rollback")]
    [InlineData("restart")]
    public async Task Forced_instance_requires_exact_cleanup_or_qualified_full_restart(string shape)
    {
        await AcceptedForRecovery(closed: false, coverageLost: true);
        var advice = new List<StagedRecoveryAdvice>();
        await Startup(report: (head, delete, a, _) => { Assert.Contains(delete, head.Deletes); advice.Add(a); }).Start(default);
        Assert.Equal(StagedRecoveryAdvice.RestartWindows, Assert.Single(advice)); Assert.Equal(0, _observations);
        _replay = _replay with { DriverInstanceId = shape == "same-driver" ? _driver : Guid.NewGuid(),
            OsBootSequence = shape == "same-boot" ? 42u : shape == "rollback" ? 41u : 43u, Records = [] };
        _child = null;
        var startup = Startup(); await startup.Start(default);
        if (shape == "restart")
        {
            Assert.True(startup.TryGetResult(_replay.DriverInstanceId, out var result));
            Assert.Equal(StagedDriverEpochReconcileV20.Active, result);
            Assert.Empty((await Head()).Deletes); Assert.Equal(1, _observations); Assert.Equal(1, (await Head()).CommittedDelete);
        }
        else
        {
            Assert.True(startup.HasFailed);
            Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single((await Head()).Deletes).State);
            Assert.Equal(0, _observations);
        }
    }

    [Theory]
    [InlineData("replacement")]
    [InlineData("unreadable")]
    [InlineData("stale")]
    public async Task Startup_observation_failure_or_changed_revision_never_releases_the_name(string shape)
    {
        await AcceptedForRecovery();
        var notices = new List<string>();
        var startup = Startup(report: (_, _, _, reason) => notices.Add(reason), observe: expected =>
        {
            if (shape == "unreadable") throw new IOException("parent unavailable");
            if (shape == "stale") Advance(Row);
            return new(expected, shape == "replacement" ? Id(99) : null);
        });
        if (shape == "stale") await Assert.ThrowsAsync<IOException>(() => startup.Start(default));
        else
        {
            await startup.Start(default);
            Assert.Equal("NativeAnchoredReconciliationUnresolved", Assert.Single(notices));
        }
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single((await Head()).Deletes).State);
        Assert.Equal(0, (await Head()).CommittedDelete);
    }

    [Fact]
    public async Task Retired_native_receipt_cannot_be_recreated_by_old_forwarded_facts()
    {
        await AcceptedForRecovery(); _child = null; await Startup().Start(default);
        var old = _replay;
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [] };
        await Startup().Start(default);
        _replay = old;
        await Assert.ThrowsAsync<IOException>(() => Startup().Start(default));
        Assert.Empty((await Head()).Deletes); Assert.Equal(1, (await Head()).CommittedDelete);
    }

    [Fact]
    public async Task Native_retirement_requires_the_persisted_ack_revision_not_a_caller_supplied_floor()
    {
        await AcceptedForRecovery(); _child = null; await Startup().Start(default);
        var head = await Head(); var delete = Assert.Single(head.Deletes);
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [] };
        var session = new StagedNativeRecoverySession(_driver, _replay.ConnectionEpoch, _replay.OsBootSequence);
        try
        {
            var proof = session.ReconcileReplay(_driver, _replay.ConnectionEpoch, true, true, [], _replay.Revision);
            using var turn = await _journal.EnterDestinationCommitTurnAsync(head.Destination,
                StagedDestinationTurnPurpose.Reconciliation, default);
            await Assert.ThrowsAsync<IOException>(() => _journal.RetireNativeDeleteReceiptAsync(turn, delete.Binding,
                delete.OperationId!.Value, proof, delete.NativeAcknowledgementRevision!.Value - 1, default));
            Assert.Single((await Head()).Deletes);
        }
        finally { session.Invalidate(); }
    }
}
#endif
