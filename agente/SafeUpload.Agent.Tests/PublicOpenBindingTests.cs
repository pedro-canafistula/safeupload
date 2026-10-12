#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class PublicOpenBindingTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private readonly Guid _driver = Guid.NewGuid(), _mount = Guid.NewGuid();
    private readonly StagedTransferJournal _journal;
    private PublicOpenReplay _replay;
    private readonly StagedPublicOpenDispatcher _dispatcher;
    private SafeUploadStageIdentityV19? _child = Id(3);
    private ulong _sequence;
    private NativeRecordReplayRow Open => Assert.Single(_replay.Records).Open;

    public PublicOpenBindingTests()
    {
        _journal = new(Path.Combine(_workspace.Root, "journal"));
        var row = new NativeRecordReplayRow(_driver, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 11, 0,
            123456, Id(1), Id(2), Id(3), 42, 0x01000000, 0x10000, 0, 1234, 1,
            "S-1-5-18", false, "document.txt", 0, 259, 259, 0, _mount);
        _replay = new(_driver, 11, 17, 42,
            [new(row, 0, default, 0, default, default, default, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null)]);
        _dispatcher = new(_journal, () => _replay, expected => new(expected, _child),
            _ => Path.Combine(_workspace.Root, "document.txt"), _ => { });
    }
    public void Dispose() { _dispatcher.Dispose(); _workspace.Dispose(); }
    private static SafeUploadStageIdentityV19 Id(ulong n) => new() { VolumeSerialNumber = 7, FileIdLow = n, FileIdHigh = 8 };
    private PublicDispositionRequestV25 Request(uint phase) => new()
    {
        Version = 25, StructSize = 80, Phase = phase, OpenNonce = Open.RequestNonce,
        OperationId = Open.OperationId, NativeMapRevision = _replay.Revision
    };
    private Task<PublicDispositionReplyV25> Send(uint phase) =>
        _dispatcher.ProcessAsync(Request(phase), 1234, _driver, CancellationToken.None);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Open_binding_allocates_no_delete_and_releases_only_its_short_turn_on_original_outcome(bool accepted)
    {
        var first = await Send(PublicDispositionV25.OpenPrepare);
        Assert.Equal(PublicDispositionV25.Prepared, first.Result);
        Assert.Equal(0ul, first.MutationGeneration); Assert.Equal(0ul, first.PublishedGeneration);
        Assert.Equal(first.Request.OpenNonce, (await Send(PublicDispositionV25.OpenPrepare)).Request.OpenNonce);
        var destination = StagedNativeStartupRecovery.Destination(Open);
        var head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Equal(0, head.MaxAllocated); Assert.Empty(head.Deletes); Assert.Null(head.PendingCommit);
        using var cancellation = new CancellationTokenSource();
        var blocked = _journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.PhysicalCommit, cancellation.Token);
        Assert.False(blocked.IsCompleted);
        var opened = Open with { Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown |
            (accepted ? NativeRecordFacts.CreateAccepted | NativeRecordFacts.IdentityChecked : 0),
            CreateStatus = accepted ? 0 : unchecked((int)0xc0000022), IdentityStatus = accepted ? 0 : 259 };
        _replay = _replay with { Revision = 18, Records = [_replay.Records[0] with
            { Open = opened, GrantedAccess = accepted ? 0x10000u : 0 }] };
        Assert.Equal(PublicDispositionV25.Recorded, (await Send(PublicDispositionV25.OpenFacts)).Result);
        using var resumed = await blocked.WaitAsync(TimeSpan.FromSeconds(10));
        head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Equal(0, head.MaxAllocated); Assert.Empty(head.Deletes); Assert.Equal(0, head.CommittedDelete);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("nonce")]
    [InlineData("revision")]
    [InlineData("driver")]
    public async Task Stale_binding_never_claims_a_destination_or_delete(string change)
    {
        var request = Request(PublicDispositionV25.OpenPrepare); Guid driver = _driver;
        switch (change)
        {
            case "operation": request.OperationId = Guid.NewGuid(); break;
            case "nonce": request.OpenNonce = Guid.NewGuid(); break;
            case "revision": request.NativeMapRevision++; break;
            default: driver = Guid.NewGuid(); break;
        }
        await Assert.ThrowsAsync<IOException>(() => _dispatcher.ProcessAsync(request, 1234, driver, default));
        Assert.Empty(await _journal.ReadDestinationHeadsAsync(default));
    }

    [Fact]
    public async Task Lost_prepare_reply_cannot_accept_changed_published_snapshot_and_release_the_binding_turn()
    {
        await Send(PublicDispositionV25.OpenPrepare);
        var row = _replay.Records[0];
        _replay = _replay with { Revision = 18, Records = [row with
        {
            Open = row.Open with { Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown |
                NativeRecordFacts.CreateAccepted | NativeRecordFacts.IdentityChecked, CreateStatus = 0, IdentityStatus = 0 },
            PublishedGeneration = 9, PublishedIdentity = Id(99), GrantedAccess = 0x10000
        }] };
        await Assert.ThrowsAsync<IOException>(() => Send(PublicDispositionV25.OpenFacts));
        var destination = StagedNativeStartupRecovery.Destination(Open);
        using var canceled = new CancellationTokenSource();
        var pending = _journal.EnterDestinationCommitTurnAsync(destination, StagedDestinationTurnPurpose.PhysicalCommit, canceled.Token);
        Assert.False(pending.IsCompleted); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.Empty((await _journal.ReadDestinationHeadAsync(destination, default))!.Deletes);
    }

    [Fact]
    public void Ordinary_request_fits_opaque_slots_and_cannot_be_decoded_as_image_text()
    {
        PublicDispositionV25.Verify();
        var request = Request(PublicDispositionV25.OpenPrepare);
        SafeUploadRequest outer = new() { Version = Contract.Version, StructSize = Contract.RequestSize,
            RequestId = 17, Operation = 21, Reserved = 25, Flags = Contract.StageV19ReplyFlag,
            RequestorProcessId = 1234, ImageNameLength = 80 };
        var slot = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref outer, 1));
        MemoryMarshal.Write(slot[1064..], in request);
        Assert.True(outer.TryReadPublicDispositionV25(out _)); Assert.True(outer.HasKnownFlags);
        var opaque = outer;
        Assert.Throws<InvalidOperationException>(() => opaque.GetImageName());
        slot[1064 + 80] = 1;
        Assert.False(outer.TryReadPublicDispositionV25(out _));
    }

    [Theory]
    [InlineData("grant")]
    [InlineData("scheduled")]
    [InlineData("generation")]
    [InlineData("unused")]
    [InlineData("version")]
    public void Ordinary_replay_rejects_invented_grants_scheduled_kind_and_nonzero_unused_rows(string change)
    {
        byte[] bytes = Page();
        switch (change)
        {
            case "grant": W32(bytes, 64 + 904, 0x10000); break;
            case "scheduled": W32(bytes, 64 + 164, 0x01001000); break;
            case "generation": W64(bytes, 64 + 72, 1); break;
            case "unused": bytes[64 + 1024] = 1; break;
            default: W32(bytes, 0, 22); break;
        }
        Assert.Throws<IOException>(() => PublicOpenReplayWireV25.DecodePage(bytes, 0));
    }

    [Fact]
    public void Ordinary_replay_preserves_full_binding_without_issuing_a_delete_generation()
    {
        var row = Assert.Single(PublicOpenReplayWireV25.DecodePage(Page(), 0).Rows);
        Assert.Equal(Open.TransferId, row.Open.TransferId); Assert.Equal(Open.RequestNonce, row.Open.RequestNonce);
        Assert.Equal(Open.OperationId, row.Open.OperationId); Assert.Equal(0ul, row.Open.JournalGeneration);
        Assert.Equal(Open.PublicIdentity.FileIdHigh, row.Open.PublicIdentity.FileIdHigh);
        Assert.Equal(0u, row.GrantedAccess); Assert.Equal(0ul, row.OperationSequence);
    }

    private async Task ReadyOpenAsync()
    {
        await Send(PublicDispositionV25.OpenPrepare);
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
        {
            Open = row.Open with { Facts = NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown |
                NativeRecordFacts.CreateAccepted | NativeRecordFacts.IdentityChecked, CreateStatus = 0, IdentityStatus = 0 },
            GrantedAccess = 0x10000
        }] };
        Assert.Equal(PublicDispositionV25.Recorded, (await Send(PublicDispositionV25.OpenFacts)).Result);
    }

    private PublicDispositionRequestV25 MutationRequest(uint phase) => new()
    {
        Version = 25, StructSize = 80, Phase = phase, OpenNonce = Open.RequestNonce,
        MutationNonce = _replay.Records[0].MutationNonce, OperationId = _replay.Records[0].MutationOperationId,
        OperationSequence = _replay.Records[0].OperationSequence, NativeMapRevision = _replay.Revision
    };
    private Task<PublicDispositionReplyV25> MutationSend(uint phase) =>
        _dispatcher.ProcessAsync(MutationRequest(phase), _replay.Records[0].ActorProcessId, _driver, default);
    private void CaptureMutation(uint flags, uint actor = 1234)
    {
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
        {
            OperationSequence = ++_sequence, MutationTransferId = Guid.NewGuid(), MutationNonce = Guid.NewGuid(),
            MutationOperationId = Guid.NewGuid(), InformationClass = 13, DispositionFlags = flags, RequestorMode = 1,
            OperationFacts = PublicOperationFacts.Captured | (row.OperationFacts & PublicOperationFacts.CleanupOutstanding),
            OperationStatus = 259, MutationGeneration = 0, ActorProcessCreationTime = 1234567,
            ActorProcessId = actor, ActorSessionId = 1, ActorSid = "S-1-5-18"
        }] };
    }
    private void Outcome(int status, ulong generation, bool notForwarded = false)
    {
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
        {
            OperationFacts = PublicOperationFacts.Captured | (notForwarded ? PublicOperationFacts.NotForwarded :
                PublicOperationFacts.Forwarded | PublicOperationFacts.ResultKnown) |
                (row.OperationFacts & PublicOperationFacts.CleanupOutstanding),
            OperationStatus = status, MutationGeneration = generation
        }] };
    }
    private void ConfirmSlotRemoval(bool cleanupOutstanding)
    {
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
        {
            OperationSequence = 0, MutationTransferId = default, MutationNonce = default, MutationOperationId = default,
            InformationClass = 0, DispositionFlags = 0, RequestorMode = 0,
            OperationFacts = cleanupOutstanding ? PublicOperationFacts.CleanupOutstanding : 0,
            OperationStatus = 0, MutationGeneration = 0, ActorProcessCreationTime = 0, ActorProcessId = 0,
            ActorSessionId = 0, ActorSid = null
        }] };
    }

    [Fact]
    public async Task Accepted_delete_waits_for_other_reader_then_retires_only_after_exact_cleanup_ack_removal()
    {
        await ReadyOpenAsync(); CaptureMutation(1);
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        Assert.Equal(1ul, prepared.MutationGeneration);
        Assert.Equal(prepared.MutationGeneration, (await MutationSend(PublicDispositionV25.DispositionPrepare)).MutationGeneration);
        var destination = StagedNativeStartupRecovery.Destination(Open);
        Assert.NotNull((await _journal.ReadDestinationHeadAsync(destination, default))!.PendingCommit);
        Outcome(0, prepared.MutationGeneration);
        Assert.Equal(PublicDispositionV25.Recorded, (await MutationSend(PublicDispositionV25.DispositionFacts)).Result);
        var head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Null(head.PendingCommit); Assert.Equal(StagedPublicDeleteState.Accepted, Assert.Single(head.Deletes).State);
        Assert.Equal(_replay.Revision, Assert.Single(head.PublicRelayReceipts!).AcknowledgedRevision);
        ConfirmSlotRemoval(true);
        Assert.Equal(PublicDispositionV25.Progress, (await Send(PublicDispositionV25.OpenFacts)).Result);
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1,
            Records = [row with { Open = row.Open with { Facts = row.Open.Facts | NativeRecordFacts.LastHandleCleanedUp } }] };
        Assert.Equal(PublicDispositionV25.Progress, (await Send(PublicDispositionV25.OpenFacts)).Result); // another reader retains original
        _child = null; _replay = _replay with { Revision = _replay.Revision + 1 };
        Assert.Equal(PublicDispositionV25.Recorded, (await Send(PublicDispositionV25.OpenFacts)).Result);
        Assert.Equal(PublicDispositionV25.Recorded, (await Send(PublicDispositionV25.OpenFacts)).Result); // lost cleanup reply replay
        head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Equal(StagedPublicDeleteState.Complete, Assert.Single(head.Deletes).State);
        Assert.Equal(1, head.CommittedDelete); Assert.Single(head.PublicRelayReceipts!);
        var removal = Request(PublicDispositionV25.OpenFacts);
        _replay = _replay with { Records = [] }; // same revision absence is insufficient
        await Assert.ThrowsAsync<IOException>(() => _dispatcher.ProcessAsync(removal, 1234, _driver, default));
        _replay = _replay with { Revision = _replay.Revision + 1 }; removal.NativeMapRevision = _replay.Revision;
        Assert.Equal(PublicDispositionV25.Recorded, (await _dispatcher.ProcessAsync(removal, 1234, _driver, default)).Result);
        head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Empty(head.Deletes); Assert.Empty(head.PublicRelayReceipts!);
        Assert.Equal(1, head.MaxAllocated); Assert.Equal(1, head.CommittedDelete);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, unchecked((int)0xc0000022))]
    [InlineData(true, unchecked((int)0xc0000120))]
    public async Task Native_noop_failure_and_no_forward_release_only_after_the_exact_result_ack(bool deleting, int status)
    {
        await ReadyOpenAsync(); CaptureMutation(deleting ? 1u : 0u, actor: 4321); // inherited original handle, current actor
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        bool notForwarded = status == unchecked((int)0xc0000120);
        Outcome(status, notForwarded ? 0 : prepared.MutationGeneration, notForwarded);
        Assert.Equal(PublicDispositionV25.Recorded, (await MutationSend(PublicDispositionV25.DispositionFacts)).Result);
        Assert.Equal(PublicDispositionV25.Recorded, (await MutationSend(PublicDispositionV25.DispositionFacts)).Result);
        var destination = StagedNativeStartupRecovery.Destination(Open);
        var head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Equal(status, Assert.Single(head.PublicRelayReceipts!).NativeStatus);
        Assert.Equal(0, head.CommittedDelete);
        ConfirmSlotRemoval(false);
        Assert.Equal(PublicDispositionV25.Recorded, (await Send(PublicDispositionV25.OpenFacts)).Result);
        head = (await _journal.ReadDestinationHeadAsync(destination, default))!;
        Assert.Empty(head.Deletes); Assert.Empty(head.PublicRelayReceipts!);
        Assert.Equal(deleting ? 1 : 0, head.MaxAllocated);
    }

    [Fact]
    public async Task Native_false_cancels_accepted_ordinary_delete_and_all_receipts_retire_without_resetting_high_water()
    {
        await ReadyOpenAsync(); CaptureMutation(1);
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        Outcome(0, prepared.MutationGeneration); await MutationSend(PublicDispositionV25.DispositionFacts);
        ConfirmSlotRemoval(true); CaptureMutation(0);
        prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        Assert.Equal(0ul, prepared.MutationGeneration);
        Outcome(0, 0); await MutationSend(PublicDispositionV25.DispositionFacts);
        ConfirmSlotRemoval(false); await Send(PublicDispositionV25.OpenFacts);
        var head = (await _journal.ReadDestinationHeadAsync(StagedNativeStartupRecovery.Destination(Open), default))!;
        Assert.Empty(head.Deletes); Assert.Empty(head.PublicRelayReceipts!); Assert.Null(head.PendingCommit);
        Assert.Equal(1, head.MaxAllocated); Assert.Equal(0, head.CommittedDelete);
        CaptureMutation(1); Assert.Equal(2ul, (await MutationSend(PublicDispositionV25.DispositionPrepare)).MutationGeneration);
    }

    [Fact]
    public async Task Forwarded_unknown_result_never_clears_its_barrier_or_allocates_a_successor()
    {
        await ReadyOpenAsync(); CaptureMutation(1);
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
            { OperationFacts = PublicOperationFacts.Captured | PublicOperationFacts.Forwarded,
                MutationGeneration = prepared.MutationGeneration }] };
        Assert.Equal(PublicDispositionV25.Progress, (await MutationSend(PublicDispositionV25.DispositionFacts)).Result);
        var head = (await _journal.ReadDestinationHeadAsync(StagedNativeStartupRecovery.Destination(Open), default))!;
        Assert.NotNull(head.PendingCommit); Assert.Null(Assert.Single(head.PublicRelayReceipts!).NativeStatus);
        var changed = MutationRequest(PublicDispositionV25.DispositionPrepare); changed.OperationId = Guid.NewGuid();
        await Assert.ThrowsAsync<IOException>(() => _dispatcher.ProcessAsync(changed, 1234, _driver, default));
        Assert.Equal(1, head.MaxAllocated);
    }

    [Fact]
    public async Task Cleanup_fact_without_its_durable_receipt_never_releases_the_native_hold()
    {
        await ReadyOpenAsync(); ConfirmSlotRemoval(true);
        await Assert.ThrowsAsync<IOException>(() => Send(PublicDispositionV25.OpenFacts));
    }

    [Fact]
    public async Task Replayed_capture_after_a_durable_result_never_returns_a_second_forward_permit()
    {
        await ReadyOpenAsync(); CaptureMutation(1);
        var prepared = await MutationSend(PublicDispositionV25.DispositionPrepare);
        Outcome(0, prepared.MutationGeneration); await MutationSend(PublicDispositionV25.DispositionFacts);
        var row = _replay.Records[0];
        _replay = _replay with { Revision = _replay.Revision + 1, Records = [row with
            { OperationFacts = PublicOperationFacts.Captured, OperationStatus = 259, MutationGeneration = 0 }] };
        await Assert.ThrowsAsync<IOException>(() => MutationSend(PublicDispositionV25.DispositionPrepare));
        var head = (await _journal.ReadDestinationHeadAsync(StagedNativeStartupRecovery.Destination(Open), default))!;
        Assert.Null(head.PendingCommit); Assert.Equal(0, Assert.Single(head.PublicRelayReceipts!).NativeStatus);
        Assert.Equal(StagedPublicDeleteState.Accepted, Assert.Single(head.Deletes).State);
        Assert.Equal(1, head.MaxAllocated);
    }

    private byte[] Page()
    {
        byte[] bytes = new byte[PublicDispositionV25.ReplayPageBytes];
        W32(bytes, 0, 25); W32(bytes, 4, (uint)bytes.Length); _driver.TryWriteBytes(bytes.AsSpan(8, 16));
        W64(bytes, 24, 11); W64(bytes, 32, 17); W32(bytes, 40, 42); W32(bytes, 48, 1); W32(bytes, 52, 1);
        Span<byte> b = bytes.AsSpan(64, 1024);
        _driver.TryWriteBytes(b[..16]); Open.TransferId.TryWriteBytes(b.Slice(16, 16));
        Open.RequestNonce.TryWriteBytes(b.Slice(32, 16)); Open.OperationId.TryWriteBytes(b.Slice(48, 16));
        W64(b, 64, 11); W64(b, 80, 123456);
        for (int i = 0; i < 3; i++) { W64(b, 88 + i * 24, 7); W64(b, 96 + i * 24, (ulong)i + 1); W64(b, 104 + i * 24, 8); }
        W32(b, 160, 42); W32(b, 164, 0x01000000); W32(b, 168, 0x10000); W32(b, 176, 1234);
        W32(b, 180, 1); W32(b, 184, 12); W32(b, 192, (uint)Encoding.Unicode.GetByteCount("document.txt"));
        b[216] = 1; b[217] = 1; b[223] = 5; W32(b, 224, 18);
        Encoding.Unicode.GetBytes("document.txt").CopyTo(b[284..]); _mount.TryWriteBytes(b.Slice(800, 16));
        return bytes;
    }
    private static void W32(Span<byte> bytes, int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[at..], value);
    private static void W64(Span<byte> bytes, int at, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes[at..], value);
}
#endif
