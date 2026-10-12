#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

public static class NativeLifecycleV24
{
    public const uint Operation = 20, Version = 24, Prepare = 1, FactsChanged = 2;
    public const uint Prepared = 1, Progress = 2, Terminal = 3;
    public const int RequestBytes = 72, ReplyBytes = 88;

    public static unsafe void Verify()
    {
        if (sizeof(NativeLifecycleRequestV24) != RequestBytes || sizeof(NativeLifecycleReplyV24) != ReplyBytes ||
            Marshal.OffsetOf<NativeLifecycleRequestV24>(nameof(NativeLifecycleRequestV24.NativeMapRevision)).ToInt32() != 64 ||
            Marshal.OffsetOf<NativeLifecycleReplyV24>(nameof(NativeLifecycleReplyV24.JournalGeneration)).ToInt32() != 72)
            throw new InvalidOperationException("Native lifecycle ABI mismatch.");
    }

    public static bool Valid(NativeLifecycleRequestV24 value) =>
        value.Version == Version && value.StructSize == RequestBytes && value.Reserved == 0 &&
        value.Phase is Prepare or FactsChanged && value.TransferId != Guid.Empty &&
        value.RequestNonce != Guid.Empty && value.OperationId != Guid.Empty && value.NativeMapRevision != 0;

    public static bool Valid(NativeLifecycleReplyV24 value) => Valid(value.Request) &&
        value.JournalGeneration is > 0 and <= long.MaxValue && value.Reserved == 0 &&
        (value.Request.Phase == Prepare ? value.Result == Prepared : value.Result is Progress or Terminal);
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct NativeLifecycleRequestV24
{
    public uint Version, StructSize, Phase, Reserved;
    public Guid TransferId, RequestNonce, OperationId;
    public ulong NativeMapRevision;
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct NativeLifecycleReplyV24
{
    public NativeLifecycleRequestV24 Request;
    public ulong JournalGeneration;
    public uint Result, Reserved;
}

public unsafe partial struct SafeUploadRequest
{
    public bool TryReadNativeLifecycleV24(out NativeLifecycleRequestV24 payload)
    {
        payload = default;
        if (Version != Contract.Version || StructSize != Contract.RequestSize || RequestId == 0 ||
            Operation != NativeLifecycleV24.Operation || Reserved != NativeLifecycleV24.Version ||
            Flags != Contract.StageV19ReplyFlag || RequestorProcessId == 0 || RequestorProcessId > int.MaxValue ||
            ImageNameLength != NativeLifecycleV24.RequestBytes || PathLength != 0) return false;
        fixed (char* image = ImageName)
        fixed (char* path = Path)
        {
            var bytes = new ReadOnlySpan<byte>((byte*)image, Contract.MaxImageChars * sizeof(char));
            if (!IsZero(bytes[NativeLifecycleV24.RequestBytes..]) ||
                !IsZero(new ReadOnlySpan<byte>((byte*)path, Contract.MaxPathChars * sizeof(char)))) return false;
            var candidate = MemoryMarshal.Read<NativeLifecycleRequestV24>(bytes);
            if (!NativeLifecycleV24.Valid(candidate)) return false;
            payload = candidate;
            return true;
        }
    }
}

public sealed partial class FilterPort
{
    public unsafe bool ReplyNativeLifecycleV24(ulong messageId, ulong requestId, NativeLifecycleReplyV24 reply)
    {
        if (requestId == 0 || !NativeLifecycleV24.Valid(reply))
            throw new ArgumentException("Invalid native lifecycle receipt.", nameof(reply));
        return ReplyStageStatusPayloadV20(messageId, requestId, NativeLifecycleV24.ReplyBytes,
            &reply, sizeof(NativeLifecycleReplyV24));
    }
}
#endif
