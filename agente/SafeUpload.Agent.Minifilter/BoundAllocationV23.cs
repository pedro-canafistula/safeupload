#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Runtime.InteropServices;
using System.Text;

namespace SafeUpload.Agent.Minifilter;

// Transport only. No producer, capability advertisement, allocation authority
// or publication fallback is enabled by this contract.
public static class BoundAllocationV23Contract
{
    public const int PayloadBytes = 124;
    public const uint Capability = 0x40;

    public static unsafe void Verify()
    {
        if (sizeof(SafeUploadStageAllocateV23) != PayloadBytes)
            throw new InvalidOperationException("Bound allocation payload size mismatch.");
        Offset(nameof(SafeUploadStageAllocateV23.AllocationReservationId), 8);
        Offset(nameof(SafeUploadStageAllocateV23.ParentTransferId), 24);
        Offset(nameof(SafeUploadStageAllocateV23.Disposition), 40);
        Offset(nameof(SafeUploadStageAllocateV23.ReferenceKind), 44);
        Offset(nameof(SafeUploadStageAllocateV23.PublicTargetIdLow), 48);
        Offset(nameof(SafeUploadStageAllocateV23.PublicTargetIdHigh), 56);
        Offset(nameof(SafeUploadStageAllocateV23.MountManagerVolumeId), 64);
        Offset(nameof(SafeUploadStageAllocateV23.VolumeRootIdLow), 80);
        Offset(nameof(SafeUploadStageAllocateV23.VolumeRootIdHigh), 88);
        Offset(nameof(SafeUploadStageAllocateV23.ParentIdentity), 96);
        Offset(nameof(SafeUploadStageAllocateV23.ParentCaseSensitive), 120);
        Offset(nameof(SafeUploadStageAllocateV23.CanonicalLeafBytes), 122);
    }

    private static void Offset(string field, int expected)
    {
        if (Marshal.OffsetOf<SafeUploadStageAllocateV23>(field).ToInt32() != expected)
            throw new InvalidOperationException("Bound allocation offset mismatch: " + field);
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct SafeUploadStageAllocateV23
{
    public uint Version;
    public uint StructSize;
    public Guid AllocationReservationId;
    public Guid ParentTransferId;
    public uint Disposition;
    public uint ReferenceKind;
    public ulong PublicTargetIdLow;
    public ulong PublicTargetIdHigh;
    public Guid MountManagerVolumeId;
    public ulong VolumeRootIdLow;
    public ulong VolumeRootIdHigh;
    public SafeUploadStageIdentityV19 ParentIdentity;
    public ushort ParentCaseSensitive;
    public ushort CanonicalLeafBytes;

    public readonly bool PublicTargetPresent => (PublicTargetIdLow | PublicTargetIdHigh) != 0;
}

public unsafe partial struct SafeUploadRequest
{
    private static readonly Encoding BoundStrictUtf16 = new UnicodeEncoding(false, false, true);

    // This checks untrusted bytes, not their filesystem authority. The live
    // dispatcher must additionally verify the negotiated pair, anchored
    // binding, exact seed and durable allocation/head transaction.
    public bool TryReadBoundAllocationV23(out SafeUploadStageAllocateV23 payload, out string canonicalLeaf)
    {
        payload = default;
        canonicalLeaf = "";
        if (Version != Contract.Version || StructSize != Contract.RequestSize || RequestId == 0 ||
            RequestorProcessId == 0 || RequestorProcessId > int.MaxValue ||
            Operation != global::SafeUpload.Agent.Minifilter.Operation.StageAllocate ||
            Reserved != Contract.StageBoundAllocationVersion || !HasKnownFlags ||
            ImageNameLength != BoundAllocationV23Contract.PayloadBytes ||
            PathLength == 0 || PathLength > (Contract.MaxPathChars - 1) * sizeof(char) ||
            (PathLength % sizeof(char)) != 0)
            return false;

        SafeUploadStageAllocateV23 candidate;
        fixed (char* image = ImageName)
        {
            var slot = new ReadOnlySpan<byte>((byte*)image, Contract.MaxImageNameChars * sizeof(char));
            if (!IsZero(slot[BoundAllocationV23Contract.PayloadBytes..])) return false;
            candidate = MemoryMarshal.Read<SafeUploadStageAllocateV23>(slot);
        }
        if (candidate.Version != Contract.StageBoundAllocationVersion ||
            candidate.StructSize != BoundAllocationV23Contract.PayloadBytes ||
            candidate.AllocationReservationId == Guid.Empty || candidate.MountManagerVolumeId == Guid.Empty ||
            candidate.Disposition > 5 || candidate.ReferenceKind > StageV19AllocationReferenceKind.Tombstone ||
            (candidate.ReferenceKind == StageV19AllocationReferenceKind.None) != (candidate.ParentTransferId == Guid.Empty) ||
            (candidate.VolumeRootIdLow | candidate.VolumeRootIdHigh) == 0 || !candidate.ParentIdentity.HasNonzeroFileId ||
            candidate.ParentCaseSensitive > 1 || candidate.CanonicalLeafBytes == 0 ||
            candidate.CanonicalLeafBytes >= 512 || (candidate.CanonicalLeafBytes % sizeof(char)) != 0)
            return false;

        // Absence is independent of copying. FOLLOWUP existence is checked
        // against the exact private predecessor by the allocator, not inferred
        // from this public-target field.
        if (candidate.ReferenceKind == StageV19AllocationReferenceKind.None &&
            (((candidate.Disposition is 1 or 4) && !candidate.PublicTargetPresent) ||
             (candidate.Disposition == 2 && candidate.PublicTargetPresent)))
            return false;
        if (candidate.ReferenceKind == StageV19AllocationReferenceKind.Tombstone &&
            (candidate.Disposition != 2 || candidate.PublicTargetPresent))
            return false;

        string pathText;
        fixed (char* path = Path)
        {
            var slot = new ReadOnlySpan<byte>((byte*)path, Contract.MaxPathChars * sizeof(char));
            if (!IsZero(slot[checked((int)PathLength)..])) return false;
            try { pathText = BoundStrictUtf16.GetString(slot[..checked((int)PathLength)]); }
            catch (DecoderFallbackException) { return false; }
        }
        if (pathText.IndexOf('\0') >= 0 || pathText.Contains('/')) return false;
        int boundary = pathText.LastIndexOf('\\');
        if (boundary < 1) return false;
        string leaf = pathText[(boundary + 1)..];
        if (leaf.Length * sizeof(char) != candidate.CanonicalLeafBytes ||
            leaf is "." or ".." || leaf.EndsWith('.') || leaf.EndsWith(' ') ||
            leaf.Any(c => c < 32 || "<>:\"/\\|?*".Contains(c)))
            return false;

        payload = candidate;
        canonicalLeaf = leaf; // Exact UTF-16; never independently case-fold.
        return true;
    }
}
#endif
