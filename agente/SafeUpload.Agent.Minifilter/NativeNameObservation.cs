#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.ComponentModel;
using System.Text;

namespace SafeUpload.Agent.Minifilter;

public sealed record NativeNameObservationRequest(Guid DriverInstanceId, ulong ConnectionEpoch,
    ulong Revision, uint OsBootSequence, Guid MountManagerVolumeId,
    SafeUploadStageIdentityV19 VolumeRootIdentity, SafeUploadStageIdentityV19 ParentIdentity,
    bool ParentCaseSensitive, string CanonicalLeaf);

// A momentary name mapping, not a physical cleanup ACK or a mutation grant.
// Durable reconciliation additionally requires independent handle-lifetime
// proof and the destination's reconciliation turn.
public sealed record NativeNameObservation(NativeNameObservationRequest Binding,
    SafeUploadStageIdentityV19? ChildIdentity);

internal static class NativeNameObservationWire
{
    internal const uint Command = 31;
    internal const int RequestBytes = 640, ReplyBytes = 664;
    private static readonly Encoding StrictUtf16 = new UnicodeEncoding(false, false, true);

    internal static byte[] CreateRequest(NativeNameObservationRequest binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        if (binding.DriverInstanceId == Guid.Empty || binding.ConnectionEpoch == 0 || binding.Revision == 0 ||
            binding.MountManagerVolumeId == Guid.Empty || !binding.VolumeRootIdentity.HasNonzeroFileId ||
            !binding.ParentIdentity.HasNonzeroFileId ||
            binding.VolumeRootIdentity.VolumeSerialNumber != binding.ParentIdentity.VolumeSerialNumber)
            throw new ArgumentException("Name observation requires exact volume, directory and replay provenance.");
        if (string.IsNullOrEmpty(binding.CanonicalLeaf) || binding.CanonicalLeaf is "." or ".." ||
            binding.CanonicalLeaf.Any(c => c == 0 || c is '\\' or '/' or ':' or '*' or '?'))
            throw new ArgumentException("Name observation requires one canonical leaf.");
        byte[] leaf;
        try { leaf = StrictUtf16.GetBytes(binding.CanonicalLeaf); }
        catch (EncoderFallbackException ex) { throw new ArgumentException("Invalid canonical leaf encoding.", ex); }
        if (leaf.Length >= 512) throw new ArgumentException("The canonical leaf exceeds the native bound.");
        byte[] bytes = new byte[RequestBytes];
        W32(bytes, 0, Contract.Version); W32(bytes, 4, RequestBytes); W32(bytes, 8, Command);
        W32(bytes, 16, NativeRecordReplayWire.ExtensionVersion); W32(bytes, 20, binding.OsBootSequence);
        binding.DriverInstanceId.TryWriteBytes(bytes.AsSpan(24, 16));
        W64(bytes, 40, binding.ConnectionEpoch); W64(bytes, 48, binding.Revision);
        binding.MountManagerVolumeId.TryWriteBytes(bytes.AsSpan(56, 16));
        WriteIdentity(bytes, 72, binding.VolumeRootIdentity); WriteIdentity(bytes, 96, binding.ParentIdentity);
        W32(bytes, 120, binding.ParentCaseSensitive ? 1u : 0u); W32(bytes, 124, checked((uint)leaf.Length));
        leaf.CopyTo(bytes, 128);
        return bytes;
    }

    internal static NativeNameObservation DecodeReply(ReadOnlySpan<byte> bytes, NativeNameObservationRequest expected)
    {
        byte[] request = CreateRequest(expected);
        if (bytes.Length != ReplyBytes || U32(bytes, 0) != NativeRecordReplayWire.ExtensionVersion ||
            U32(bytes, 4) != ReplyBytes || !bytes.Slice(8, 16).SequenceEqual(request.AsSpan(24, 16)) ||
            U64(bytes, 24) != expected.ConnectionEpoch || U64(bytes, 32) != expected.Revision ||
            U32(bytes, 40) != expected.OsBootSequence || U32(bytes, 44) != 2 ||
            !bytes.Slice(48, 16).SequenceEqual(request.AsSpan(56, 16)) ||
            !bytes.Slice(64, 48).SequenceEqual(request.AsSpan(72, 48)) ||
            !bytes.Slice(112, 520).SequenceEqual(request.AsSpan(120, 520)) ||
            U32(bytes, 632) > 1 || U32(bytes, 636) != 0)
            throw new IOException("Incomplete, stale or mismatched native name observation.");
        var child = ReadIdentity(bytes, 640);
        if (U32(bytes, 632) == 0)
        {
            if (child.VolumeSerialNumber != 0 || child.HasNonzeroFileId)
                throw new IOException("An absent native name carries a child identity.");
            return new(expected, null);
        }
        if (!child.HasNonzeroFileId || child.VolumeSerialNumber != expected.ParentIdentity.VolumeSerialNumber)
            throw new IOException("Native name observation contains an unknown or foreign child identity.");
        return new(expected, child);
    }

    private static void WriteIdentity(Span<byte> bytes, int offset, SafeUploadStageIdentityV19 identity)
    {
        W64(bytes, offset, identity.VolumeSerialNumber); W64(bytes, offset + 8, identity.FileIdLow);
        W64(bytes, offset + 16, identity.FileIdHigh);
    }
    private static SafeUploadStageIdentityV19 ReadIdentity(ReadOnlySpan<byte> bytes, int offset) => new()
    { VolumeSerialNumber = U64(bytes, offset), FileIdLow = U64(bytes, offset + 8), FileIdHigh = U64(bytes, offset + 16) };
    private static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    private static ulong U64(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]);
    private static void W32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[offset..], value);
    private static void W64(Span<byte> bytes, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes[offset..], value);
}

public sealed partial class FilterPort
{
    public NativeNameObservation ObserveNativeName(NativeNameObservationRequest binding)
    {
        byte[] input = NativeNameObservationWire.CreateRequest(binding);
        byte[] output = new byte[NativeNameObservationWire.ReplyBytes];
        using SendLease lease = EnterSend();
        int hr;
        uint returned;
        if (_nativeRecordReplaySender is { } sender) hr = sender.Send(lease.Handle, input, output, out returned);
        else
        {
            unsafe
            {
                fixed (byte* i = input)
                fixed (byte* o = output)
                    hr = FilterSendMessage(lease.Handle, (IntPtr)i, (uint)input.Length, (IntPtr)o, (uint)output.Length, out returned);
            }
        }
        if (hr != 0) throw new Win32Exception(hr, $"Native name observation failed: 0x{hr:X8}");
        if (returned != output.Length) throw new IOException("Short native name observation receipt.");
        return NativeNameObservationWire.DecodeReply(output, binding);
    }
}
#endif
