#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Tests;

public sealed class StagedNativeLifecycleDispatcherTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid();
    private readonly Guid _volume = Guid.NewGuid();
    private NativeRecordReplay _replay;
    private SafeUploadStageIdentityV19? _child;
    private int _observations;
    private readonly StagedTransferJournal _journal;
    private readonly StagedNativeLifecycleDispatcher _dispatcher;
    private NativeRecordReplayRow Row => Assert.Single(_replay.Records);

    public StagedNativeLifecycleDispatcherTests()
    {
        var row = new NativeRecordReplayRow(_driver, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 11, 0,
            123456, Id(1), Id(2), Id(3), 42, 0x01001000, 0x10000, 7, 1234, 1,
            "S-1-5-21-100-200-300-1001", false, "document.txt", 0, 259, 259, 0, _volume);
        _replay = new(_driver, 11, 17, 42, [row]);
        _child = row.PublicIdentity;
        _journal = new(Path.Combine(_workspace.Root, "journal"));
        _dispatcher = new(_journal, () => _replay,
            expected => { _observations++; return new(expected, _child); },
            _ => Path.Combine(_workspace.Root, "document.txt"), _ => { });
    }

    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Lost_prepare_and_terminal_replies_replay_exactly_and_close_releases_hold_automatically(bool checkedIdentity)
    {
        var prepare = Request(NativeLifecycleV24.Prepare);
        var first = await Send(prepare);
        Assert.Equal(NativeLifecycleV24.Prepared, first.Result);
        Assert.Equal(first.JournalGeneration, (await Send(prepare)).JournalGeneration);
        Assert.Equal(1, (await Head()).MaxAllocated);
        Advance(Row with { JournalGeneration = first.JournalGeneration,
            Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted |
                (checkedIdentity ? NativeRecordFacts.IdentityChecked : 0),
            CreateStatus = 0, IdentityStatus = checkedIdentity ? 0 : unchecked((int)0xc0000001) });
        Assert.Equal(NativeLifecycleV24.Progress, (await Send(Request(NativeLifecycleV24.FactsChanged))).Result);
        Assert.Equal(checkedIdentity ? StagedPublicDeleteState.Admitted : StagedPublicDeleteState.AcceptedUnresolved,
            Assert.Single((await Head()).Deletes).State);
        Assert.Equal(0, _observations); // A live original app handle cannot resolve exceptional acceptance.
        Advance(Row with { Facts = Row.Facts | NativeRecordFacts.LastHandleCleanedUp });
        var closed = await Send(Request(NativeLifecycleV24.FactsChanged));
        Assert.Equal(NativeLifecycleV24.Progress, closed.Result);
        Assert.Equal(StagedPublicDeleteState.Admitted, Assert.Single((await Head()).Deletes).State);
        Assert.Equal(1, _observations); // Original still present: hold ends, cleanup receipt stays.
        _child = null;
        Advance(Row);
        var terminalRequest = Request(NativeLifecycleV24.FactsChanged);
        var terminal = await Send(terminalRequest);
        Assert.Equal(NativeLifecycleV24.Terminal, terminal.Result);
        Assert.Equal(terminal.JournalGeneration, (await Send(terminalRequest)).JournalGeneration);
        var saved = Assert.Single((await Head()).Deletes);
        Assert.Equal(_replay.Revision, saved.NativeAcknowledgementRevision);
        Assert.Equal(StagedPublicDeleteState.Complete, saved.State);
        Assert.Equal(1, (await Head()).CommittedDelete);
        _replay = _replay with { Records = [] }; // An omitted row at the same revision is not an ACK proof.
        await Assert.ThrowsAsync<IOException>(() => Send(terminalRequest));
        Assert.Single((await Head()).Deletes);
        _replay = _replay with { Revision = _replay.Revision + 1 };
        terminalRequest.NativeMapRevision = _replay.Revision;
        Assert.Equal(NativeLifecycleV24.Progress, (await Send(terminalRequest)).Result);
        Assert.Empty((await Head()).Deletes);
        Assert.Equal(1, (await Head()).CommittedDelete);
    }

    [Fact]
    public async Task Unforwarded_negative_receipt_after_lost_prepare_is_terminal_without_name_observation()
    {
        await Send(Request(NativeLifecycleV24.Prepare));
        Advance(Row with { Facts = NativeRecordFacts.CreateOutcomeKnown,
            CreateStatus = unchecked((int)0xc0000120), IdentityStatus = 259 });
        var result = await Send(Request(NativeLifecycleV24.FactsChanged));
        Assert.Equal(NativeLifecycleV24.Terminal, result.Result);
        Assert.Equal(StagedPublicDeleteState.Failed, Assert.Single((await Head()).Deletes).State);
        Assert.Equal(0, _observations);
        Assert.Equal(0, (await Head()).CommittedDelete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Hidden_create_outcome_requires_exact_cancel_close_then_name_reconciliation(bool absent)
    {
        var prepared = await Send(Request(NativeLifecycleV24.Prepare));
        Advance(Row with { JournalGeneration = prepared.JournalGeneration,
            Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CancelledBeforeHandle,
            CreateStatus = unchecked((int)0xc0000120), IdentityStatus = unchecked((int)0xc0000120) });
        Assert.Equal(NativeLifecycleV24.Progress, (await Send(Request(NativeLifecycleV24.FactsChanged))).Result);
        Assert.Equal(0, _observations);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single((await Head()).Deletes).State);
        Advance(Row with { Facts = Row.Facts | NativeRecordFacts.CancelledCloseObserved });
        if (absent) _child = null;
        var result = await Send(Request(NativeLifecycleV24.FactsChanged));
        Assert.Equal(absent ? NativeLifecycleV24.Terminal : NativeLifecycleV24.Progress, result.Result);
        Assert.Equal(1, _observations);
        var saved = Assert.Single((await Head()).Deletes);
        Assert.Equal(absent ? StagedPublicDeleteState.Complete : StagedPublicDeleteState.Admitted, saved.State);
        Assert.Null(saved.NativeCreateAccepted); Assert.Null(saved.NativeOutcome);
        Assert.Equal(absent ? 1 : 0, (await Head()).CommittedDelete);
    }

    [Fact]
    public async Task Reopened_journal_dispatch_reconciles_last_close_from_durable_intent_without_manual_disposition()
    {
        var prepared = await Send(Request(NativeLifecycleV24.Prepare));
        Advance(Row with { JournalGeneration = prepared.JournalGeneration,
            Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted,
            CreateStatus = 0, IdentityStatus = unchecked((int)0xc0000001) });
        await Send(Request(NativeLifecycleV24.FactsChanged));
        Advance(Row with { Facts = Row.Facts | NativeRecordFacts.LastHandleCleanedUp });
        _child = null;
        var restartedJournal = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        var restarted = new StagedNativeLifecycleDispatcher(restartedJournal, () => _replay,
            expected => new(expected, _child), _ => throw new InvalidOperationException("No CREATE is repeated."),
            _ => throw new InvalidOperationException("No old PID lookup substitutes for cleanup."));
        var result = await restarted.ProcessAsync(Request(NativeLifecycleV24.FactsChanged), 1234, _driver, default);
        Assert.Equal(NativeLifecycleV24.Terminal, result.Result);
        Assert.Equal(StagedPublicDeleteState.Complete, Assert.Single((await Head()).Deletes).State);
    }

    [Fact]
    public async Task Changed_native_request_or_outcome_is_rejected_without_releasing_the_hold()
    {
        var prepared = await Send(Request(NativeLifecycleV24.Prepare));
        Advance(Row with { OriginalShareAccess = 0, JournalGeneration = prepared.JournalGeneration,
            Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted,
            CreateStatus = 0 });
        await Assert.ThrowsAsync<IOException>(() => Send(Request(NativeLifecycleV24.FactsChanged)));
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single((await Head()).Deletes).State);
        Advance(Row with { OriginalShareAccess = 7 });
        await Send(Request(NativeLifecycleV24.FactsChanged));
        Advance(Row with { Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown,
            CreateStatus = unchecked((int)0xc0000022) });
        await Assert.ThrowsAsync<IOException>(() => Send(Request(NativeLifecycleV24.FactsChanged)));
        Assert.True(Assert.Single((await Head()).Deletes).NativeCreateAccepted);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Unresolved_close_names_the_held_file_and_uses_only_the_approved_recovery_advice(
        bool coverageLost, bool initiallyChecked)
    {
        var prepared = await Send(Request(NativeLifecycleV24.Prepare));
        Advance(Row with { JournalGeneration = prepared.JournalGeneration,
            Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted |
                (initiallyChecked ? NativeRecordFacts.IdentityChecked : 0),
            CreateStatus = 0, IdentityStatus = initiallyChecked ? 0 : unchecked((int)0xc0000001) });
        await Send(Request(NativeLifecycleV24.FactsChanged)); // Prove the previously admitted path too.
        Advance(Row with { Facts = Row.Facts |
            (coverageLost ? NativeRecordFacts.CleanupCoverageLost : NativeRecordFacts.LastHandleCleanedUp) });
        _child = Id(99); // A replacement with no durable newer publication cannot release the hold.
        var reports = new List<(StagedDestinationHead Head, StagedPublicDeleteRecord Delete, StagedRecoveryAdvice Advice)>();
        var dispatcher = new StagedNativeLifecycleDispatcher(_journal, () => _replay, expected => new(expected, _child),
            _ => throw new InvalidOperationException(), _ => throw new InvalidOperationException(),
            (head, delete, advice, _) => reports.Add((head, delete, advice)));
        if (coverageLost) await dispatcher.ProcessAsync(Request(NativeLifecycleV24.FactsChanged), 1234, _driver, default);
        else await Assert.ThrowsAsync<IOException>(() => dispatcher.ProcessAsync(
            Request(NativeLifecycleV24.FactsChanged), 1234, _driver, default));
        var report = Assert.Single(reports);
        Assert.EndsWith("document.txt", report.Head.Locator);
        Assert.Contains(report.Delete, report.Head.Deletes);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, report.Delete.State);
        Assert.Equal(coverageLost ? StagedRecoveryAdvice.RestartWindows : StagedRecoveryAdvice.CollectDiagnostics, report.Advice);
        Assert.Equal(StagedPublicDeleteState.AcceptedUnresolved, Assert.Single((await Head()).Deletes).State);
    }

    [Theory]
    [InlineData("driver")]
    [InlineData("revision")]
    [InlineData("nonce")]
    [InlineData("pid")]
    [InlineData("epoch")]
    public async Task Stale_or_unbound_prepare_never_creates_a_durable_intent(string change)
    {
        var request = Request(NativeLifecycleV24.Prepare);
        Guid driver = _driver;
        uint pid = 1234;
        switch (change)
        {
            case "driver": driver = Guid.NewGuid(); break;
            case "revision": request.NativeMapRevision--; break;
            case "nonce": request.RequestNonce = Guid.NewGuid(); break;
            case "pid": pid++; break;
            case "epoch": _replay = _replay with { ConnectionEpoch = 12 }; break;
        }
        await Assert.ThrowsAsync<IOException>(() => _dispatcher.ProcessAsync(request, pid, driver, default));
        Assert.Empty(await _journal.ReadDestinationHeadsAsync(default));
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("flags")]
    [InlineData("phase")]
    [InlineData("size")]
    [InlineData("reserved")]
    [InlineData("tail")]
    [InlineData("path")]
    [InlineData("operation")]
    public void Typed_wire_rejects_malformed_carriers_and_cannot_fall_back_to_image_text(string change)
    {
        NativeLifecycleV24.Verify();
        var payload = Request(NativeLifecycleV24.Prepare);
        var request = new SafeUploadRequest { Version = Contract.Version, StructSize = Contract.RequestSize,
            RequestId = 1, Operation = NativeLifecycleV24.Operation, Flags = Contract.StageV19ReplyFlag,
            RequestorProcessId = 1234, Reserved = NativeLifecycleV24.Version,
            ImageNameLength = NativeLifecycleV24.RequestBytes };
        if (change == "phase") payload.Phase = 3;
        if (change == "size") payload.StructSize--;
        if (change == "reserved") payload.Reserved = 1;
        var bytes = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref request, 1));
        MemoryMarshal.Write(bytes[1064..], in payload);
        if (change == "flags") request.Flags |= 1;
        if (change == "tail") bytes[1064 + NativeLifecycleV24.RequestBytes] = 1;
        if (change == "path") bytes[40] = 1;
        if (change == "operation") request.Operation = Operation.StageAllocate;
        Assert.Equal(change == "valid", request.TryReadNativeLifecycleV24(out _));
        Assert.Throws<InvalidOperationException>(() => request.GetImageName());
    }

    private NativeLifecycleRequestV24 Request(uint phase) => new() { Version = NativeLifecycleV24.Version,
        StructSize = NativeLifecycleV24.RequestBytes, Phase = phase, TransferId = Row.TransferId,
        RequestNonce = Row.RequestNonce, OperationId = Row.OperationId, NativeMapRevision = _replay.Revision };
    private Task<NativeLifecycleReplyV24> Send(NativeLifecycleRequestV24 request) =>
        _dispatcher.ProcessAsync(request, 1234, _driver, default);
    private async Task<StagedDestinationHead> Head() => Assert.Single(await _journal.ReadDestinationHeadsAsync(default));
    private void Advance(NativeRecordReplayRow row) => _replay = _replay with { Revision = _replay.Revision + 1, Records = [row] };
    private static SafeUploadStageIdentityV19 Id(ulong low) => new() { VolumeSerialNumber = 7, FileIdLow = low };
}
#endif
