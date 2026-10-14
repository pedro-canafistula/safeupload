#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

public static class PrivateCancellationV28
{
    public const uint Operation = 22, Version = 28, Canceled = 1, RequiresPublicDelete = 2;
    public const int RequestBytes = 104, ReplyBytes = 120;
    public static unsafe void Verify()
    {
        if (sizeof(PrivateCancellationRequestV28) != RequestBytes || sizeof(PrivateCancellationReplyV28) != ReplyBytes ||
            Marshal.OffsetOf<PrivateCancellationRequestV28>(nameof(PrivateCancellationRequestV28.Generation)).ToInt32() != 80)
            throw new InvalidOperationException("Private cancellation ABI mismatch.");
    }
    public static bool Valid(PrivateCancellationRequestV28 r) => r.Version == Version && r.StructSize == RequestBytes &&
        r.Reserved == 0 && r.OperationId != Guid.Empty && r.TransferId != Guid.Empty && r.DriverInstanceId != Guid.Empty &&
        r.StageIdentity.HasNonzeroFileId && r.Generation is > 0 and <= long.MaxValue &&
        r.OwnerCreationTime > 0 && r.OwnerProcessId is > 0 and <= int.MaxValue;
    public static bool Valid(PrivateCancellationReplyV28 r) => Valid(r.Request) && r.Reserved == 0 &&
        (r.Result == Canceled ? r.CancellationGeneration > r.Request.Generation && r.CancellationGeneration <= long.MaxValue :
            r.Result == RequiresPublicDelete && r.CancellationGeneration == 0);
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct PrivateCancellationRequestV28
{
    public uint Version, StructSize;
    public Guid OperationId, TransferId, DriverInstanceId;
    public SafeUploadStageIdentityV19 StageIdentity;
    public ulong Generation;
    public long OwnerCreationTime;
    public uint OwnerProcessId, Reserved;
}
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct PrivateCancellationReplyV28
{
    public PrivateCancellationRequestV28 Request;
    public ulong CancellationGeneration;
    public uint Result, Reserved;
}

public unsafe partial struct SafeUploadRequest
{
    public bool TryReadPrivateCancellationV28(out PrivateCancellationRequestV28 payload)
    {
        payload = default;
        if (Version != Contract.Version || StructSize != Contract.RequestSize || RequestId == 0 ||
            Operation != PrivateCancellationV28.Operation || Reserved != PrivateCancellationV28.Version ||
            Flags != Contract.StageV19ReplyFlag || ImageNameLength != PrivateCancellationV28.RequestBytes || PathLength != 0)
            return false;
        fixed (char* image = ImageName)
        fixed (char* path = Path)
        {
            var bytes = new ReadOnlySpan<byte>((byte*)image, Contract.MaxImageChars * sizeof(char));
            if (!IsZero(bytes[PrivateCancellationV28.RequestBytes..]) ||
                !IsZero(new ReadOnlySpan<byte>((byte*)path, Contract.MaxPathChars * sizeof(char)))) return false;
            var candidate = MemoryMarshal.Read<PrivateCancellationRequestV28>(bytes);
            if (!PrivateCancellationV28.Valid(candidate) || candidate.OwnerProcessId != RequestorProcessId) return false;
            payload = candidate;
            return true;
        }
    }
}
public sealed partial class FilterPort
{
    public unsafe bool ReplyPrivateCancellationV28(ulong messageId, ulong requestId, PrivateCancellationReplyV28 reply)
    {
        if (requestId == 0 || !PrivateCancellationV28.Valid(reply)) throw new ArgumentException("Invalid private cancellation receipt.");
        return ReplyStageStatusPayloadV20(messageId, requestId, PrivateCancellationV28.ReplyBytes, &reply, sizeof(PrivateCancellationReplyV28));
    }
}
#endif
