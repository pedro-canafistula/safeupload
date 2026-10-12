#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class BoundPublicationTransportTests
{
    private static readonly Guid Driver = G(111), Mount = G(222);
    private const ulong Epoch = 11, Revision = 17;
    private static Guid G(int n) => new(n, 0, 0, new byte[8]);
    private static SafeUploadStageIdentityV19 Id(ulong n) => new() { VolumeSerialNumber = 7, FileIdLow = n, FileIdHigh = 8 };
    private static BoundPublicationRequestV26 Create(int n = 0) => BoundPublicationV26.WithPayload(new()
    {
        Phase = BoundPublicationPhase.Create, TransferId = G(1000 + n), DriverInstanceId = Driver,
        CreateNonce = G(3000 + n), PermitNonce = G(3000 + n), OperationId = G(5000 + n),
        DestinationGeneration = 1, ExpectedMaxAllocated = 1, MountManagerVolumeId = Mount,
        VolumeRootIdentity = Id(1), ParentIdentity = Id(2), StageIdentity = Id(3), MeasuredLength = 37
    }, "document.txt", ".safeupload-" + n + ".pending", SHA256.HashData(new byte[37]));

    [Fact]
    public void Feature_layout_preserves_core_and_both_native_identity_halves()
    {
        BoundPublicationV26.Verify();
        var request = Create(); var decoded = MemoryMarshal.Read<BoundPublicationRequestV26>(BoundPublicationV26.Encode(request));
        Assert.Equal(18u, decoded.Control.Version); Assert.Equal(33u, decoded.Control.Command);
        Assert.Equal(Id(3).FileIdHigh, decoded.StageIdentity.FileIdHigh);
        Assert.Equal("document.txt", decoded.GetDestinationLeaf());
        Assert.Equal(request.GetDigest(), decoded.GetDigest());
    }

    [Theory]
    [InlineData("different-volume")]
    [InlineData("missing-public-id")]
    [InlineData("renewed-create-nonce")]
    [InlineData("wildcard")]
    [InlineData("stream")]
    [InlineData("rename-without-temp")]
    public void Invalid_authority_never_reaches_native_sender(string defect)
    {
        var r = Create();
        switch (defect)
        {
            case "different-volume": r.ParentIdentity.VolumeSerialNumber++; break;
            case "missing-public-id": r.Flags = 1; break;
            case "renewed-create-nonce": r.PermitNonce = G(7000); break;
            case "wildcard": Assert.Throws<ArgumentException>(() => BoundPublicationV26.WithPayload(r, "*.txt", "temp", r.GetDigest())); return;
            case "stream": Assert.Throws<ArgumentException>(() => BoundPublicationV26.WithPayload(r, "document:stream", "temp", r.GetDigest())); return;
            case "rename-without-temp": r.Phase = BoundPublicationPhase.Rename; r.PermitNonce = G(7000); break;
        }
        var sender = new Sender(_ => []);
        using var port = Port(sender);
        Assert.Throws<ArgumentException>(() => port.SendBoundPublication(r)); Assert.Equal(0, sender.Calls);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("nonce")]
    [InlineData("phase")]
    [InlineData("epoch")]
    [InlineData("reserved")]
    [InlineData("ack-as-grant")]
    [InlineData("short")]
    [InlineData("positive-hresult")]
    public void Changed_or_incomplete_reply_cannot_authorize_forwarding(string defect)
    {
        var request = Create(); var reply = Reply(request, BoundPublicationResult.Prepared);
        switch (defect)
        {
            case "operation": reply.OperationId = G(999); break;
            case "nonce": reply.PermitNonce = G(999); break;
            case "phase": reply.Phase = BoundPublicationPhase.Rename; break;
            case "epoch": reply.ConnectionEpoch = 0; break;
            case "reserved": reply.ReservedEnd = 1; break;
            case "ack-as-grant": reply.Result = BoundPublicationResult.Acknowledged; break;
        }
        var sender = new Sender(_ => Bytes(reply)) { ReturnedAdjustment = defect == "short" ? -1 : 0, HResult = defect == "positive-hresult" ? 1 : 0 };
        using var port = Port(sender);
        if (defect == "positive-hresult") Assert.Throws<System.ComponentModel.Win32Exception>(() => port.SendBoundPublication(request));
        else Assert.Throws<IOException>(() => port.SendBoundPublication(request));
    }

    [Fact]
    public void Result_only_receipt_is_returned_without_reclassifying_it_as_prepared()
    {
        var request = Create(); var sender = new Sender(_ => Bytes(Reply(request, BoundPublicationResult.Consumed)));
        using var port = Port(sender);
        Assert.Equal(BoundPublicationResult.Consumed, port.SendBoundPublication(request).Result);
    }

    [Theory]
    [InlineData("short-nonfinal")]
    [InlineData("unused-row")]
    [InlineData("revision")]
    [InlineData("missing-final")]
    [InlineData("duplicate-nonce")]
    public void Partial_or_changed_map_is_unknown_not_an_absence_receipt(string defect)
    {
        var sender = new Sender(input =>
        {
            uint cursor = U32(input.Span, 56); byte[] page;
            if (defect == "duplicate-nonce")
            {
                page = Page(cursor, cursor == 0 ? 8 : 1, cursor != 0);
                if (cursor != 0) Page(0, 1, true).AsSpan(64, BoundPublicationV26.RowBytes).CopyTo(page.AsSpan(64));
            }
            else page = Page(cursor, cursor == 0 ? 1 : 0, true);
            switch (defect)
            {
                case "short-nonfinal": W32(page, 52, 0); break;
                case "unused-row": page[64 + BoundPublicationV26.RowBytes] = 1; break;
                case "revision": if (cursor != 0) W64(page, 32, Revision + 1); break;
                case "missing-final": if (cursor != 0) W32(page, 52, 0); break;
            }
            return page;
        });
        using var port = Port(sender); Assert.Throws<IOException>(() => port.ReadBoundPublicationFacts());
    }

    [Fact]
    public void Complete_snapshot_is_pinned_through_its_final_empty_check()
    {
        var sender = new Sender(input =>
        {
            uint cursor = U32(input.Span, 56);
            Assert.Equal(64, input.Length); Assert.Equal(4u, U32(input.Span, 20));
            if (cursor != 0)
            {
                Assert.Equal(Driver, new Guid(input.Span.Slice(24, 16)));
                Assert.Equal(Epoch, U64(input.Span, 40)); Assert.Equal(Revision, U64(input.Span, 48));
            }
            return Page(cursor, cursor == 0 ? 8 : cursor == 8 ? 1 : 0, cursor != 0);
        });
        using var port = Port(sender); var replay = port.ReadBoundPublicationFacts();
        Assert.Equal(9, replay.Records.Count); Assert.Equal(3, sender.Calls);
        Assert.All(replay.Records, r => Assert.False(r.HasTerminalLocalProof));
    }

    [Theory]
    [InlineData("missing-fence")]
    [InlineData("inflight-write")]
    [InlineData("wrong-target")]
    [InlineData("wrong-source")]
    [InlineData("cleanup-after-rename")]
    [InlineData("pending-native-result")]
    public void Accepted_rename_requires_exact_object_target_fence_and_final_result(string defect)
    {
        var r = Renamed();
        switch (defect)
        {
            case "missing-fence": r.Flags &= ~BoundPublicationFacts.DataFenced; break;
            case "inflight-write": r.InFlightWrites = 1; break;
            case "wrong-target": r.ObservedPublicIdentity = Id(9); r.Flags &= ~BoundPublicationFacts.TargetAbsent; break;
            case "wrong-source": r.Rename.StageIdentity = Id(9); break;
            case "cleanup-after-rename": r.Flags |= BoundPublicationFacts.CleanupArmed; r.CleanupNonce = G(12000); r.CleanupOperationId = G(13000); break;
            case "pending-native-result": r.RenameStatus = 259; break;
        }
        var sender = new Sender(_ => PageWith(r)); using var port = Port(sender);
        Assert.Throws<IOException>(() => port.ReadBoundPublicationFacts());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Known_failed_create_can_retire_but_malformed_information_cannot(bool malformed)
    {
        var r = Row(0); r.Flags = BoundPublicationFacts.CreateConsumed | BoundPublicationFacts.CreateForwarded | BoundPublicationFacts.CreateResultKnown;
        r.CreateStatus = unchecked((int)0xc0000035); r.CreateInformation = malformed ? 2ul : 4ul;
        var sender = new Sender(input => U32(input.Span, 56) == 0 ? PageWith(r) : Page(1, 0, true));
        using var port = Port(sender); var replay = port.ReadBoundPublicationFacts(); var row = Assert.Single(replay.Records);
        Assert.Equal(!malformed, row.HasTerminalLocalProof);
        if (malformed) Assert.Throws<ArgumentException>(() => BoundPublicationV26.AckRequest(replay, row));
        else Assert.Equal(5u, U32(BoundPublicationV26.AckRequest(replay, row), 20));
    }

    [Fact]
    public void Coverage_loss_cannot_be_acknowledged_as_last_cleanup()
    {
        var r = Renamed(); r.Flags |= BoundPublicationFacts.CoverageLost;
        var sender = new Sender(input => U32(input.Span, 56) == 0 ? PageWith(r) : Page(1, 0, true));
        using var port = Port(sender); var replay = port.ReadBoundPublicationFacts();
        Assert.Throws<ArgumentException>(() => BoundPublicationV26.AckRequest(replay, Assert.Single(replay.Records)));
    }

    [Fact]
    public void Failed_identity_query_is_retained_without_inventing_a_temporary_or_cleanup_proof()
    {
        var r = Row(0); r.Flags = BoundPublicationFacts.CreateConsumed | BoundPublicationFacts.CreateForwarded |
            BoundPublicationFacts.CreateResultKnown | BoundPublicationFacts.CreateAccepted;
        r.CreateInformation = 2; r.IdentityStatus = unchecked((int)0xc0000022);
        var sender = new Sender(input => U32(input.Span, 56) == 0 ? PageWith(r) : Page(1, 0, true));
        using var port = Port(sender); var replay = port.ReadBoundPublicationFacts(); var row = Assert.Single(replay.Records);
        Assert.Equal(r.IdentityStatus, row.Facts.IdentityStatus); Assert.False(row.HasTerminalLocalProof);
        Assert.Throws<ArgumentException>(() => BoundPublicationV26.AckRequest(replay, row));
    }

    [Fact]
    public void Full_bounded_map_is_not_truncated_at_its_final_cursor()
    {
        var sender = new Sender(input =>
        {
            uint cursor = U32(input.Span, 56);
            return Page(cursor, cursor == 1024 ? 0 : 8, cursor >= 1016);
        });
        using var port = Port(sender); Assert.Equal(1024, port.ReadBoundPublicationFacts().Records.Count);
        Assert.Equal(129, sender.Calls);
        Assert.Throws<ArgumentException>(() => BoundPublicationV26.FactsRequest(1025, Driver, Epoch, Revision));
    }

    [Fact]
    public void Cleanup_ack_is_never_a_forwarding_grant()
    {
        var row = Renamed(); row.Flags |= BoundPublicationFacts.LastCleanup;
        var sender = new Sender(input =>
        {
            if (U32(input.Span, 20) != 5) return U32(input.Span, 56) == 0 ? PageWith(row) : Page(1, 0, true);
            Assert.Equal(row.Create.CreateNonce, new Guid(input.Span.Slice(40, 16)));
            Assert.Equal(Revision, U64(input.Span, 56));
            var reply = Reply(row.Create, BoundPublicationResult.Prepared); reply.Phase = BoundPublicationPhase.CleanupAck;
            return Bytes(reply);
        });
        using var port = Port(sender); var replay = port.ReadBoundPublicationFacts();
        Assert.Throws<IOException>(() => port.AcknowledgeBoundPublication(replay, Assert.Single(replay.Records)));
    }

    private static BoundPublicationFactsRowV26 Row(int n) => new()
    {
        Create = Create(n), OriginalProcessId = 1234, OriginalSessionId = 1, OriginalProcessCreationTime = 123456,
        OriginalConnectionEpoch = Epoch, OsBootSequence = 42
    };
    private static BoundPublicationFactsRowV26 Renamed()
    {
        var r = Row(0); var rename = r.Create;
        rename.Phase = BoundPublicationPhase.Rename; rename.PermitNonce = G(7000); rename.OperationId = G(9000); rename.TemporaryIdentity = Id(4);
        r.Rename = rename; r.TemporaryIdentity = Id(4); r.CreateInformation = 2; r.ObservedEof = 37;
        r.Flags = BoundPublicationFacts.CreateConsumed | BoundPublicationFacts.CreateForwarded | BoundPublicationFacts.CreateResultKnown |
            BoundPublicationFacts.CreateAccepted | BoundPublicationFacts.TemporaryIdentityKnown | BoundPublicationFacts.DataFenced |
            BoundPublicationFacts.DataDrained | BoundPublicationFacts.FlushResultKnown | BoundPublicationFacts.FlushSucceeded |
            BoundPublicationFacts.RenameArmed | BoundPublicationFacts.RenameConsumed | BoundPublicationFacts.RenameForwarded |
            BoundPublicationFacts.RenameResultKnown | BoundPublicationFacts.RenameAccepted | BoundPublicationFacts.TargetObservationKnown | BoundPublicationFacts.TargetAbsent;
        return r;
    }
    private static byte[] PageWith(BoundPublicationFactsRowV26 row)
    { byte[] page = Page(0, 1, true); Bytes(row).CopyTo(page, 64); return page; }
    private static byte[] Page(uint cursor, int count, bool complete)
    {
        byte[] b = new byte[BoundPublicationV26.PageBytes]; W32(b, 0, 26); W32(b, 4, BoundPublicationV26.PageBytes);
        Driver.TryWriteBytes(b.AsSpan(8)); W64(b, 24, Epoch); W64(b, 32, Revision); W32(b, 40, 42);
        W32(b, 44, cursor); W32(b, 48, (uint)count); W32(b, 52, complete ? 1u : 0u);
        for (int i = 0; i < count; i++) Bytes(Row(checked((int)cursor + i))).CopyTo(b, 64 + i * BoundPublicationV26.RowBytes);
        return b;
    }
    private static BoundPublicationReplyV26 Reply(BoundPublicationRequestV26 r, BoundPublicationResult result) => new()
    {
        ExtensionVersion = 26, StructSize = 128, Phase = r.Phase, TransferId = r.TransferId, DriverInstanceId = r.DriverInstanceId,
        PermitNonce = r.PermitNonce, CreateNonce = r.CreateNonce, OperationId = r.OperationId, DestinationGeneration = r.DestinationGeneration,
        ConnectionEpoch = Epoch, AuthorityRevision = 23, Result = result
    };
    private static byte[] Bytes<T>(T value) where T : struct
    { byte[] b = new byte[Marshal.SizeOf<T>()]; MemoryMarshal.Write(b, in value); return b; }
    private static uint U32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
    private static ulong U64(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b[o..]);
    private static void W32(byte[] b, int o, uint n) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o), n);
    private static void W64(byte[] b, int o, ulong n) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(o), n);
    private static FilterPort Port(Sender sender) => FilterPort.CreateForNativeReplayTesting(new SafeFileHandle(new IntPtr(123), ownsHandle: false), sender);
    private sealed class Sender(Func<ReadOnlyMemory<byte>, byte[]> response) : INativeRecordReplayNativeSender
    {
        public int Calls, HResult, ReturnedAdjustment;
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint returned)
        {
            Assert.False(handle.IsClosed); Calls++; byte[] b = response(input); b.AsSpan().CopyTo(output.Span);
            returned = checked((uint)(b.Length + ReturnedAdjustment)); return HResult;
        }
    }
}
#endif
