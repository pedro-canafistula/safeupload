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
    private NativeRecordReplayRow Open => Assert.Single(_replay.Records).Open;

    public PublicOpenBindingTests()
    {
        _journal = new(Path.Combine(_workspace.Root, "journal"));
        var row = new NativeRecordReplayRow(_driver, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 11, 0,
            123456, Id(1), Id(2), Id(3), 42, 0x01000000, 0x10000, 0, 1234, 1,
            "S-1-5-18", false, "document.txt", 0, 259, 259, 0, _mount);
        _replay = new(_driver, 11, 17, 42,
            [new(row, 0, default, 0, default, default, default, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null)]);
        _dispatcher = new(_journal, () => _replay, expected => new(expected, Open.PublicIdentity),
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
    public unsafe void Ordinary_request_fits_opaque_slots_and_cannot_be_decoded_as_image_text()
    {
        PublicDispositionV25.Verify();
        var request = Request(PublicDispositionV25.OpenPrepare);
        SafeUploadRequest outer = new() { Version = Contract.Version, StructSize = Contract.RequestSize,
            RequestId = 17, Operation = 21, Reserved = 25, Flags = Contract.StageV19ReplyFlag,
            RequestorProcessId = 1234, ImageNameLength = 80 };
        Buffer.MemoryCopy(&request, outer.ImageName, 128, 80);
        Assert.True(outer.TryReadPublicDispositionV25(out _)); Assert.True(outer.HasKnownFlags);
        var opaque = outer;
        Assert.Throws<InvalidOperationException>(() => opaque.GetImageName());
        outer.ImageName[40] = 'x';
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
