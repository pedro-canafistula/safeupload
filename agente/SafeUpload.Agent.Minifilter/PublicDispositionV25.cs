#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

// Ordinary FILE_OPEN is not a scheduled delete. Its zero-generation binding
// and SetInformation transactions use a separate, checked feature-only ABI.
public static class PublicDispositionV25
{
    public const uint Operation = 21, Version = 25, ReplayControl = 32;
    public const uint OpenPrepare = 1, OpenFacts = 2, DispositionPrepare = 3, DispositionFacts = 4;
    public const uint Prepared = 1, Progress = 2, Recorded = 3;
    public const int RequestBytes = 80, ReplyBytes = 128, ReplayRowBytes = 1024, ReplayPageBytes = 16448;

    public static unsafe void Verify()
    {
        if (sizeof(PublicDispositionRequestV25) != RequestBytes || sizeof(PublicDispositionReplyV25) != ReplyBytes ||
            Marshal.OffsetOf<PublicDispositionRequestV25>(nameof(PublicDispositionRequestV25.NativeMapRevision)).ToInt32() != 64 ||
            Marshal.OffsetOf<PublicDispositionReplyV25>(nameof(PublicDispositionReplyV25.MutationGeneration)).ToInt32() != 112)
            throw new InvalidOperationException("Ordinary public disposition ABI mismatch.");
    }

    public static bool Valid(PublicDispositionRequestV25 value)
    {
        if (value.Version != Version || value.StructSize != RequestBytes || value.Reserved != 0 ||
            value.NativeMapRevision == 0 || value.OpenNonce == Guid.Empty || value.OperationId == Guid.Empty) return false;
        return value.Phase is OpenPrepare or OpenFacts
            ? value.OperationSequence == 0 && value.MutationNonce == Guid.Empty
            : value.Phase is DispositionPrepare or DispositionFacts && value.OperationSequence != 0 &&
                value.MutationNonce != Guid.Empty && value.MutationNonce != value.OpenNonce;
    }

    public static bool Valid(PublicDispositionReplyV25 value) => Valid(value.Request) && value.Reserved == 0 &&
        value.PublishedGeneration <= long.MaxValue && value.MutationGeneration <= long.MaxValue &&
        (value.PublishedGeneration == 0 ? !value.PublishedIdentity.HasNonzeroFileId &&
            value.PublishedIdentity.VolumeSerialNumber == 0 : value.PublishedIdentity.HasNonzeroFileId) &&
        (value.Request.Phase is OpenPrepare or OpenFacts ? value.MutationGeneration == 0 : true) &&
        (value.Request.Phase is OpenPrepare or DispositionPrepare ? value.Result == Prepared :
            value.Result is Progress or Recorded);
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct PublicDispositionRequestV25
{
    public uint Version, StructSize, Phase, Reserved;
    public Guid OpenNonce, MutationNonce, OperationId;
    public ulong NativeMapRevision, OperationSequence;
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct PublicDispositionReplyV25
{
    public PublicDispositionRequestV25 Request;
    public ulong PublishedGeneration;
    public SafeUploadStageIdentityV19 PublishedIdentity;
    public ulong MutationGeneration;
    public uint Result, Reserved;
}

public unsafe partial struct SafeUploadRequest
{
    public bool TryReadPublicDispositionV25(out PublicDispositionRequestV25 payload)
    {
        payload = default;
        if (Version != Contract.Version || StructSize != Contract.RequestSize || RequestId == 0 ||
            Operation != PublicDispositionV25.Operation || Reserved != PublicDispositionV25.Version ||
            Flags != Contract.StageV19ReplyFlag || RequestorProcessId == 0 || RequestorProcessId > int.MaxValue ||
            ImageNameLength != PublicDispositionV25.RequestBytes || PathLength != 0) return false;
        fixed (char* image = ImageName)
        fixed (char* path = Path)
        {
            var bytes = new ReadOnlySpan<byte>((byte*)image, Contract.MaxImageChars * sizeof(char));
            if (!IsZero(bytes[PublicDispositionV25.RequestBytes..]) ||
                !IsZero(new ReadOnlySpan<byte>((byte*)path, Contract.MaxPathChars * sizeof(char)))) return false;
            var candidate = MemoryMarshal.Read<PublicDispositionRequestV25>(bytes);
            if (!PublicDispositionV25.Valid(candidate)) return false;
            payload = candidate;
            return true;
        }
    }
}

public sealed partial class FilterPort
{
    public unsafe bool ReplyPublicDispositionV25(ulong messageId, ulong requestId, PublicDispositionReplyV25 reply)
    {
        if (requestId == 0 || !PublicDispositionV25.Valid(reply))
            throw new ArgumentException("Invalid ordinary disposition receipt.", nameof(reply));
        return ReplyStageStatusPayloadV20(messageId, requestId, PublicDispositionV25.ReplyBytes,
            &reply, sizeof(PublicDispositionReplyV25));
    }
}
#endif
