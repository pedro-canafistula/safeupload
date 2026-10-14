#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed partial class PublicOpenBindingTests
{
    [Fact]
    public async Task Ordinary_false_does_not_clear_an_accepted_native_extended_on_close_request()
    {
        await ReadyOpenAsync(); CaptureMutation(9);
        _replay = _replay with { Revision = _replay.Revision + 1,
            Records = [_replay.Records[0] with { InformationClass = 64 }] };
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        Outcome(0, prepared.MutationGeneration);
        await MutationSend(PublicDispositionV25.DispositionFacts);
        ConfirmSlotRemoval(true);
        CaptureMutation(0);
        var clear = await MutationSend(PublicDispositionV25.DispositionPrepare);
        Assert.Equal(0ul, clear.MutationGeneration);
        Outcome(0, 0); await MutationSend(PublicDispositionV25.DispositionFacts);
        var head = (await _journal.ReadDestinationHeadAsync(StagedNativeStartupRecovery.Destination(Open), default))!;
        Assert.Equal(StagedPublicDeleteKind.DispositionOnClose, Assert.Single(head.Deletes).Kind);
        Assert.Equal(StagedPublicDeleteState.Accepted, Assert.Single(head.Deletes).State);
        Assert.Equal(0, head.CommittedDelete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Combined_backend_replay_is_explicit_and_cannot_invent_native_write_or_delete_grants(bool combined)
    {
        byte[] bytes = Page();
        W32(bytes, 64 + 168, 0x10002); // actual writer+DELETE FILE_OPEN
        W32(bytes, 64 + 196, 15); W32(bytes, 64 + 904, 0x10002);
        if (combined) W32(bytes, 64 + 920, (uint)PublicOperationFacts.CombinedBackend);
        if (!combined) Assert.Throws<IOException>(() => PublicOpenReplayWireV25.DecodePage(bytes, 0));
        else
        {
            var row = Assert.Single(PublicOpenReplayWireV25.DecodePage(bytes, 0).Rows);
            Assert.Equal(0x10002u, row.GrantedAccess);
            Assert.True(row.OperationFacts.HasFlag(PublicOperationFacts.CombinedBackend));
            W32(bytes, 64 + 904, 0x10003); // extra READ was never granted
            Assert.Throws<IOException>(() => PublicOpenReplayWireV25.DecodePage(bytes, 0));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Combined_delete_queues_behind_physical_turn_and_only_published_replacement_suppresses(bool published)
    {
        var opened = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [opened with
            { OperationFacts = PublicOperationFacts.CombinedBackend,
                Open = opened.Open with { OriginalDesiredAccess = 0x10002 } }] };
        await ReadyOpenAsync();
        _replay = _replay with { Revision = _replay.Revision + 1,
            Records = [_replay.Records[0] with { GrantedAccess = 0x10002 }] };
        var destination = StagedNativeStartupRecovery.Destination(Open);
        var save = Guid.NewGuid(); long generation;
        using (var allocation = await _journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.Allocation, default))
            generation = await _journal.ReserveSaveGenerationAsync(allocation, save, Path.Combine(_workspace.Root, "document.txt"), 0, default);
        var physical = await _journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit, default);
        Task<PublicDispositionReplyV25> delete;
        try
        {
            CaptureMutation(1);
            delete = MutationSend(PublicDispositionV25.DispositionPrepare);
            Assert.False(delete.IsCompleted);
            if (published)
            {
                var operation = Guid.NewGuid();
                var identity = new StagedStageIdentity(7, 8, 99);
                await _journal.BeginDestinationPublicationAsync(physical, operation, save, generation,
                    new(7, 8, 3), identity, 0, StagedTransferJournal.EmptySha256Hex, default);
                await _journal.RecordDestinationPublicationResultAsync(physical, operation, save, identity, true);
                _child = Id(99);
            }
        }
        finally { physical.Dispose(); }
        var permit = await delete.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(published ? PublicDispositionV25.PreparedNoNameEffect : PublicDispositionV25.Prepared, permit.Result);
        Outcome(0, permit.MutationGeneration);
        await MutationSend(PublicDispositionV25.DispositionFacts);
        var head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Equal(published ? StagedPublicDeleteState.Superseded : StagedPublicDeleteState.Accepted, Assert.Single(head.Deletes).State);
        Assert.True(Assert.Single(head.PublicRelayReceipts!).Original.CombinedBackend);
        Assert.Equal(0, Assert.Single(head.PublicRelayReceipts!).NativeStatus);
    }

    [Theory]
    [InlineData("intent")]
    [InlineData("native")]
    [InlineData("recorded")]
    public async Task Restart_at_ordinary_delete_boundaries_never_reissues_an_accepted_operation(string boundary)
    {
        await ReadyOpenAsync(); CaptureMutation(1);
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        if (boundary != "intent") Outcome(0, prepared.MutationGeneration);
        if (boundary == "recorded") await MutationSend(PublicDispositionV25.DispositionFacts);
        _dispatcher.Dispose(); // service crash loses only the ephemeral turn
        var restarted = new StagedTransferJournal(Path.Combine(_workspace.Root, "journal"));
        using var dispatcher = new StagedPublicOpenDispatcher(restarted, () => _replay,
            expected => new(expected, _child), _ => Path.Combine(_workspace.Root, "document.txt"), _ => { });
        if (boundary == "intent")
        {
            var row = _replay.Records[0];
            _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
                { OperationFacts = PublicOperationFacts.Captured | PublicOperationFacts.Forwarded,
                    MutationGeneration = prepared.MutationGeneration }] };
        }
        var reply = await dispatcher.ProcessAsync(MutationRequest(PublicDispositionV25.DispositionFacts), 1234, _driver, default);
        var head = (await restarted.ReadDestinationHeadAsync(StagedNativeStartupRecovery.Destination(Open), default))!;
        Assert.Equal(boundary == "intent" ? PublicDispositionV25.Progress : PublicDispositionV25.Recorded, reply.Result);
        Assert.Equal(boundary == "intent", head.PendingCommit is not null);
        Assert.Equal(1, head.MaxAllocated);
        Assert.Equal(boundary == "intent" ? StagedPublicDeleteState.Intent : StagedPublicDeleteState.Accepted, Assert.Single(head.Deletes).State);
    }
}
#endif
