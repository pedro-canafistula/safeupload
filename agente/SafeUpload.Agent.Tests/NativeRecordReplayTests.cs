#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.ComponentModel;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class NativeRecordReplayTests
{
    private static readonly Guid Driver = Guid.Parse("11000000-0000-0000-0000-000000000001");
    private static readonly Guid MountVolume = Guid.Parse("22000000-0000-0000-0000-000000000002");
    private const ulong Epoch = 9, Revision = 23;
    private const uint Boot = 40;

    [Fact]
    public void Complete_replay_binds_every_page_and_final_empty_check_to_one_connection_and_revision()
    {
        var sender = new Sender(input =>
        {
            uint index = U32(input.Span, 20);
            Assert.Equal(Contract.Version, U32(input.Span, 0));
            Assert.Equal(64u, U32(input.Span, 4));
            Assert.Equal(30u, U32(input.Span, 8));
            Assert.Equal(22u, U32(input.Span, 16));
            Assert.Equal(0u, U32(input.Span, 12));
            Assert.Equal(0ul, U64(input.Span, 56));
            if (index == 0)
            {
                Assert.Equal(Guid.Empty, new Guid(input.Span.Slice(24, 16)));
                Assert.Equal(0ul, U64(input.Span, 40)); Assert.Equal(0ul, U64(input.Span, 48));
                return Page(0, 16, false);
            }
            Assert.Equal(Driver, new Guid(input.Span.Slice(24, 16)));
            Assert.Equal(Epoch, U64(input.Span, 40)); Assert.Equal(Revision, U64(input.Span, 48));
            return index switch { 16 => Page(16, 1, true), 17 => Page(17, 0, true), _ => throw new Exception("Unexpected replay cursor.") };
        });
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        var result = port.ReadNativeRecordReplay();
        Assert.Equal(3, sender.Calls);
        Assert.Equal(17, result.Records.Count);
        Assert.Equal(Driver, result.DriverInstanceId); Assert.Equal(Epoch, result.ConnectionEpoch);
        Assert.Equal(Revision, result.Revision); Assert.Equal(Boot, result.OsBootSequence);
        Assert.Equal(0xAABBCCDDEEFF1122ul, result.Records[0].PublicIdentity.FileIdHigh);
        Assert.Equal("S-1-5-18", result.Records[0].CallerSid);
        Assert.Equal("file0.txt", result.Records[0].CanonicalLeaf);
        Assert.Equal(MountVolume, result.Records[0].MountManagerVolumeId);
        Assert.Throws<NotSupportedException>(() => ((IList<NativeRecordReplayRow>)result.Records).Clear());
    }

    [Fact]
    public void Empty_replay_requires_an_authenticated_final_revision_check_too()
    {
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), new Sender(input => Page(U32(input.Span, 20), 0, true)));
        var replay = port.ReadNativeRecordReplay();
        Assert.Empty(replay.Records);
        Assert.Equal(Driver, replay.DriverInstanceId);
    }

    [Fact]
    public void Scheduled_create_replay_cannot_reclassify_an_ordinary_open_as_native_delete_on_close()
    {
        byte[] page = Page(0, 1, true);
        W32(page, 64 + 164, 0x01000000);
        Assert.Throws<IOException>(() => NativeRecordReplayWire.DecodePage(page, 0));
    }

    [Theory]
    [InlineData("version")]
    [InlineData("legacy-volume-identity-version")]
    [InlineData("size")]
    [InlineData("driver")]
    [InlineData("epoch")]
    [InlineData("revision")]
    [InlineData("cursor")]
    [InlineData("count")]
    [InlineData("complete")]
    [InlineData("reserved")]
    [InlineData("nonterminal-short")]
    [InlineData("unused-row")]
    public void Invalid_page_never_becomes_a_complete_absence_snapshot(string defect)
    {
        byte[] bytes = Page(0, 1, true);
        switch (defect)
        {
            case "version": W32(bytes, 0, 20); break;
            case "legacy-volume-identity-version": W32(bytes, 0, 21); break;
            case "size": W32(bytes, 4, 64); break;
            case "driver": bytes.AsSpan(8, 16).Clear(); break;
            case "epoch": W64(bytes, 24, 0); break;
            case "revision": W64(bytes, 32, 0); break;
            case "cursor": W32(bytes, 44, 16); break;
            case "count": W32(bytes, 48, 17); break;
            case "complete": W32(bytes, 52, 2); break;
            case "reserved": W64(bytes, 56, 1); break;
            case "nonterminal-short": W32(bytes, 52, 0); break;
            case "unused-row": bytes[NativeRecordReplayWire.HeaderBytes + NativeRecordReplayWire.RowBytes] = 1; break;
        }
        Assert.Throws<IOException>(() => NativeRecordReplayWire.DecodePage(bytes, 0));
    }

    [Theory]
    [InlineData("driver")]
    [InlineData("transfer")]
    [InlineData("nonce")]
    [InlineData("operation")]
    [InlineData("future-epoch")]
    [InlineData("wrong-boot")]
    [InlineData("zero-high-and-low-id")]
    [InlineData("other-volume")]
    [InlineData("writing-access")]
    [InlineData("maximum-allowed")]
    [InlineData("create-disposition")]
    [InlineData("file-id-open")]
    [InlineData("invalid-sid-length")]
    [InlineData("sid-tail")]
    [InlineData("leaf-tail")]
    [InlineData("invalid-utf16")]
    [InlineData("path-in-leaf")]
    [InlineData("unknown-facts")]
    [InlineData("accepted-without-outcome")]
    [InlineData("grant-without-accepted")]
    [InlineData("forwarded-without-generation")]
    [InlineData("row-reserved")]
    [InlineData("row-reserved-end")]
    [InlineData("missing-mount-volume")]
    public void Invalid_original_object_binding_never_supplies_lifetime_evidence(string defect)
    {
        byte[] page = Page(0, 1, true);
        var row = page.AsSpan(NativeRecordReplayWire.HeaderBytes, NativeRecordReplayWire.RowBytes);
        switch (defect)
        {
            case "driver": row[..16].Clear(); break;
            case "transfer": row.Slice(16, 16).Clear(); break;
            case "nonce": row.Slice(32, 16).Clear(); break;
            case "operation": row.Slice(48, 16).Clear(); break;
            case "future-epoch": W64(row, 64, Epoch + 1); break;
            case "wrong-boot": W32(row, 160, Boot + 1); break;
            case "zero-high-and-low-id": row.Slice(144, 16).Clear(); break;
            case "other-volume": W64(row, 112, 222); break;
            case "writing-access": W32(row, 168, 0x10002); break;
            case "maximum-allowed": W32(row, 168, 0x2010000); break;
            case "create-disposition": W32(row, 164, 2u << 24); break;
            case "file-id-open": W32(row, 164, (1u << 24) | 0x2000); break;
            case "invalid-sid-length": W32(row, 184, 68); break;
            case "sid-tail": row[228] = 1; break;
            case "leaf-tail": row[310] = 1; break;
            case "invalid-utf16": row[284] = 0; row[285] = 0xD8; break;
            case "path-in-leaf": row[284] = (byte)'/'; break;
            case "unknown-facts": W32(row, 196, 256); break;
            case "accepted-without-outcome": W32(row, 196, 5); break;
            case "grant-without-accepted": W32(row, 196, 9); break;
            case "forwarded-without-generation": W64(row, 72, 0); break;
            case "row-reserved": W32(row, 212, 1); break;
            case "row-reserved-end": W32(row, 796, 1); break;
            case "missing-mount-volume": row.Slice(800, 16).Clear(); break;
        }
        Assert.Throws<IOException>(() => NativeRecordReplayWire.DecodePage(page, 0));
    }

    [Theory]
    [InlineData("driver")]
    [InlineData("epoch")]
    [InlineData("revision")]
    [InlineData("boot")]
    [InlineData("truncated")]
    [InlineData("overreported")]
    [InlineData("native-failure")]
    public void Final_check_failure_rejects_all_earlier_valid_pages(string defect)
    {
        var sender = new Sender(input =>
        {
            byte[] page = Page(U32(input.Span, 20), 0, true);
            if (U64(input.Span, 48) == 0) return page;
            switch (defect)
            {
                case "driver": Guid.NewGuid().TryWriteBytes(page.AsSpan(8, 16)); break;
                case "epoch": W64(page, 24, Epoch + 1); break;
                case "revision": W64(page, 32, Revision + 1); break;
                case "boot": W32(page, 40, Boot + 1); break;
            }
            return page;
        }) { FailFinal = defect == "native-failure", FinalReturnedAdjustment = defect == "truncated" ? -1 : defect == "overreported" ? 1 : 0 };
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        if (defect == "native-failure") Assert.Throws<Win32Exception>(() => port.ReadNativeRecordReplay());
        else Assert.Throws<IOException>(() => port.ReadNativeRecordReplay());
        Assert.Equal(2, sender.Calls);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(48)]
    public void Duplicate_transfer_nonce_or_operation_rejects_a_multipage_replay(int field)
    {
        var sender = new Sender(input =>
        {
            uint index = U32(input.Span, 20);
            byte[] page = index == 0 ? Page(0, 16, false) : Page(16, 1, true);
            if (index != 0) Page(0, 1, true).AsSpan(64 + field, 16).CopyTo(page.AsSpan(64 + field, 16));
            return page;
        });
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        Assert.Throws<IOException>(() => port.ReadNativeRecordReplay());
    }

    [Theory]
    [InlineData(NativeRecordFacts.Forwarded | NativeRecordFacts.CancelledBeforeHandle)]
    [InlineData(NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted | NativeRecordFacts.CancelledCloseObserved)]
    [InlineData(NativeRecordFacts.Forwarded | NativeRecordFacts.CreateOutcomeKnown | NativeRecordFacts.CreateAccepted | NativeRecordFacts.LastHandleCleanedUp | NativeRecordFacts.CleanupCoverageLost)]
    public void Cancellation_cleanup_and_coverage_facts_are_preserved_without_inventing_a_negative_create(NativeRecordFacts facts)
    {
        byte[] page = Page(0, 1, true);
        W32(page, 64 + 196, (uint)facts);
        var row = Assert.Single(NativeRecordReplayWire.DecodePage(page, 0).Rows);
        Assert.Equal(facts, row.Facts);
        if (facts.HasFlag(NativeRecordFacts.CancelledBeforeHandle)) Assert.False(row.Facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown));
    }

    [Fact]
    public void Full_bounded_map_finishes_without_truncating_or_looping_at_the_last_cursor()
    {
        var sender = new Sender(input =>
        {
            uint index = U32(input.Span, 20);
            return Page(index, index == 1024 ? 0 : 16, index >= 1008);
        });
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        Assert.Equal(1024, port.ReadNativeRecordReplay().Records.Count);
        Assert.Equal(65, sender.Calls);
        Assert.Throws<ArgumentException>(() => NativeRecordReplayWire.CreateRequest(1025, Driver, Epoch, Revision));
    }

    [Fact]
    public void Disposed_port_cannot_supply_a_replay_from_a_stale_handle()
    {
        var sender = new Sender(input => Page(U32(input.Span, 20), 0, true));
        var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        port.Dispose();
        Assert.Throws<ObjectDisposedException>(() => port.ReadNativeRecordReplay());
        Assert.Equal(0, sender.Calls);
    }

    private static byte[] Page(uint index, int count, bool complete)
    {
        byte[] b = new byte[NativeRecordReplayWire.PageBytes];
        W32(b, 0, 22); W32(b, 4, (uint)b.Length); Driver.TryWriteBytes(b.AsSpan(8, 16));
        W64(b, 24, Epoch); W64(b, 32, Revision); W32(b, 40, Boot);
        W32(b, 44, index); W32(b, 48, (uint)count); W32(b, 52, complete ? 1u : 0u);
        for (int i = 0; i < count; i++) Row(b.AsSpan(64 + i * 816, 816), index + (uint)i);
        return b;
    }

    private static void Row(Span<byte> b, uint index)
    {
        Driver.TryWriteBytes(b[..16]);
        for (int i = 1; i <= 3; i++) new Guid((int)index + 1, 0, (short)i, new byte[8]).TryWriteBytes(b.Slice(i * 16, 16));
        W64(b, 64, Epoch - 1); W64(b, 72, index + 1); W64(b, 80, 12345678);
        for (int i = 0; i < 3; i++) { W64(b, 88 + i * 24, 20); W64(b, 96 + i * 24, (ulong)i + 1); W64(b, 104 + i * 24, 0xAABBCCDDEEFF1122); }
        W32(b, 160, Boot); W32(b, 164, (1u << 24) | 0x1000); W32(b, 168, 0x10000); W32(b, 172, 7);
        W32(b, 176, 100); W32(b, 180, 1); W32(b, 184, 12); W32(b, 196, 1);
        b[216] = 1; b[217] = 1; b[223] = 5; b[224] = 18; // S-1-5-18
        byte[] leaf = Encoding.Unicode.GetBytes($"file{index}.txt");
        W32(b, 192, (uint)leaf.Length); leaf.AsSpan().CopyTo(b[284..]);
        MountVolume.TryWriteBytes(b.Slice(800, 16));
    }

    private static SafeFileHandle Handle() => new(new IntPtr(123), false);
    private static uint U32(ReadOnlySpan<byte> b, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(b[offset..]);
    private static ulong U64(ReadOnlySpan<byte> b, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(b[offset..]);
    private static void W32(Span<byte> b, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(b[offset..], value);
    private static void W64(Span<byte> b, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(b[offset..], value);

    private sealed class Sender(Func<ReadOnlyMemory<byte>, byte[]> response) : INativeRecordReplayNativeSender
    {
        internal int Calls;
        internal bool FailFinal;
        internal int FinalReturnedAdjustment;
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint returned)
        {
            Assert.False(handle.IsClosed);
            Calls++;
            bool final = U64(input.Span, 48) != 0;
            byte[] bytes = response(input);
            bytes.AsSpan().CopyTo(output.Span);
            returned = (uint)(bytes.Length + (final ? FinalReturnedAdjustment : 0));
            return final && FailFinal ? unchecked((int)0x80070005) : 0;
        }
    }
}
#endif
