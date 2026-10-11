#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Tests;

public sealed class NativeNameObservationTests
{
    private static NativeNameObservationRequest Binding() => new(Guid.NewGuid(), 4, 9, 30, Guid.NewGuid(),
        new() { VolumeSerialNumber = 42, FileIdLow = 5, FileIdHigh = 0xABCDEF },
        new() { VolumeSerialNumber = 42, FileIdLow = 6 }, true, "private.txt");

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Authenticated_send_preserves_exact_binding_and_full_child_identity(bool present)
    {
        var binding = Binding();
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), new Sender(input =>
        {
            Assert.Equal(640, input.Length); Assert.Equal(31u, U32(input.Span, 8));
            Assert.Equal(22u, U32(input.Span, 16)); Assert.Equal(0u, U32(input.Span, 12));
            return Reply(input.Span, present);
        }));
        var result = port.ObserveNativeName(binding);
        Assert.Equal(binding, result.Binding);
        Assert.Equal(present, result.ChildIdentity.HasValue);
        if (present)
        {
            Assert.Equal(0x1122334455667788ul, result.ChildIdentity!.Value.FileIdLow);
            Assert.Equal(0xFFEEDDCCBBAA0099ul, result.ChildIdentity.Value.FileIdHigh);
            Assert.Equal(42ul, result.ChildIdentity.Value.VolumeSerialNumber);
        }
    }

    [Theory]
    [InlineData(0)] // version
    [InlineData(4)] // size
    [InlineData(8)] // driver
    [InlineData(24)] // connection
    [InlineData(32)] // revision
    [InlineData(40)] // boot
    [InlineData(44)] // incomplete scans
    [InlineData(48)] // volume GUID, including a serial/ID clone
    [InlineData(64)] // root serial
    [InlineData(72)] // root low ID
    [InlineData(80)] // root high ID
    [InlineData(88)] // parent serial
    [InlineData(96)] // parent low ID
    [InlineData(104)] // parent high ID
    [InlineData(112)] // case mode
    [InlineData(116)] // leaf length
    [InlineData(120)] // leaf
    [InlineData(630)] // unused leaf tail
    [InlineData(636)] // reserved
    [InlineData(640)] // child volume
    public void Mismatched_or_incomplete_reply_never_supplies_name_observation(int offset)
    {
        var binding = Binding();
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), new Sender(input =>
        {
            var bytes = Reply(input.Span, true); bytes[offset] ^= 0x80; return bytes;
        }));
        Assert.Throws<IOException>(() => port.ObserveNativeName(binding));
    }

    [Theory]
    [InlineData("absent-with-id")]
    [InlineData("absent-with-serial")]
    [InlineData("present-without-id")]
    [InlineData("unknown-present")]
    public void Invalid_presence_facts_are_refused(string defect)
    {
        var binding = Binding();
        var bytes = Reply(NativeNameObservationWire.CreateRequest(binding), true);
        switch (defect)
        {
            case "absent-with-id": W32(bytes, 632, 0); break;
            case "absent-with-serial": W32(bytes, 632, 0); bytes.AsSpan(648, 16).Clear(); break;
            case "present-without-id": bytes.AsSpan(648, 16).Clear(); break;
            case "unknown-present": W32(bytes, 632, 2); break;
        }
        Assert.Throws<IOException>(() => NativeNameObservationWire.DecodeReply(bytes, binding));
    }

    [Theory]
    [InlineData("missing-volume")]
    [InlineData("missing-driver")]
    [InlineData("missing-epoch")]
    [InlineData("missing-revision")]
    [InlineData("missing-root")]
    [InlineData("missing-parent")]
    [InlineData("other-volume")]
    [InlineData("path")]
    [InlineData("stream")]
    [InlineData("wildcard")]
    [InlineData("dot")]
    [InlineData("nul")]
    [InlineData("invalid-utf16")]
    [InlineData("oversized-leaf")]
    public void Invalid_requests_never_reach_the_port(string defect)
    {
        var binding = Binding();
        binding = defect switch
        {
            "missing-volume" => binding with { MountManagerVolumeId = Guid.Empty },
            "missing-driver" => binding with { DriverInstanceId = Guid.Empty },
            "missing-epoch" => binding with { ConnectionEpoch = 0 },
            "missing-revision" => binding with { Revision = 0 },
            "missing-root" => binding with { VolumeRootIdentity = default },
            "missing-parent" => binding with { ParentIdentity = default },
            "other-volume" => binding with { ParentIdentity = new() { VolumeSerialNumber = 43, FileIdLow = 6 } },
            "path" => binding with { CanonicalLeaf = "child/name" },
            "stream" => binding with { CanonicalLeaf = "name:stream" },
            "wildcard" => binding with { CanonicalLeaf = "*.txt" },
            "dot" => binding with { CanonicalLeaf = ".." },
            "nul" => binding with { CanonicalLeaf = "name\0.txt" },
            "invalid-utf16" => binding with { CanonicalLeaf = "\uD800" },
            "oversized-leaf" => binding with { CanonicalLeaf = new string('a', 256) },
            _ => throw new Exception("Unknown defect")
        };
        var sender = new Sender(_ => throw new Exception("Invalid request reached native transport"));
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        Assert.ThrowsAny<ArgumentException>(() => port.ObserveNativeName(binding));
        Assert.Equal(0, sender.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Native_failure_or_short_reply_cannot_become_absence(bool shortReply)
    {
        var sender = new Sender(input => Reply(input.Span, false))
            { Error = shortReply ? 0 : unchecked((int)0x80070005), Short = shortReply };
        using var port = FilterPort.CreateForNativeReplayTesting(Handle(), sender);
        if (shortReply) Assert.Throws<IOException>(() => port.ObserveNativeName(Binding()));
        else Assert.Throws<Win32Exception>(() => port.ObserveNativeName(Binding()));
    }

    private static byte[] Reply(ReadOnlySpan<byte> input, bool present)
    {
        byte[] bytes = new byte[664];
        W32(bytes, 0, 22); W32(bytes, 4, 664);
        input.Slice(24, 16).CopyTo(bytes.AsSpan(8));
        input.Slice(40, 16).CopyTo(bytes.AsSpan(24));
        input.Slice(20, 4).CopyTo(bytes.AsSpan(40)); W32(bytes, 44, 2);
        input.Slice(56, 16).CopyTo(bytes.AsSpan(48));
        input.Slice(72, 48).CopyTo(bytes.AsSpan(64));
        input.Slice(120, 520).CopyTo(bytes.AsSpan(112));
        W32(bytes, 632, present ? 1u : 0u);
        if (present)
        {
            input.Slice(96, 8).CopyTo(bytes.AsSpan(640));
            W64(bytes, 648, 0x1122334455667788); W64(bytes, 656, 0xFFEEDDCCBBAA0099);
        }
        return bytes;
    }
    private static SafeFileHandle Handle() => new(new IntPtr(77), ownsHandle: false);
    private static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    private static void W32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[offset..], value);
    private static void W64(Span<byte> bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes[offset..], value);

    private sealed class Sender(Func<ReadOnlyMemory<byte>, byte[]> reply) : INativeRecordReplayNativeSender
    {
        public int Calls { get; private set; }
        public int Error { get; init; }
        public bool Short { get; init; }
        public int Send(SafeFileHandle handle, ReadOnlyMemory<byte> input, Memory<byte> output, out uint returned)
        {
            Calls++;
            reply(input).CopyTo(output); returned = checked((uint)output.Length - (Short ? 1u : 0u)); return Error;
        }
    }
}
#endif
