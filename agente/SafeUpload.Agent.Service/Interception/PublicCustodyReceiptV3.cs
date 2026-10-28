#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Text;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record PublicCustodyDestinationV3(StagedStageIdentity VolumeRootIdentity,
    StagedStageIdentity ParentIdentity, Guid MountManagerVolumeId, bool CaseSensitive, string Leaf);
internal sealed record PublicCustodyReceiptV3(Guid ReceiptId, Guid InstallationId, Guid DriverInstanceId,
    Guid TransferId, long AllocationGeneration, long DestinationGeneration, StagedStageIdentity StageIdentity,
    uint Slot, ResourceSlotRoleV2 Role, long Incarnation, Guid ClaimId, long ClaimRevision, long AcceptedBudgetRevision,
    StagedStageIdentity DeliveredObjectIdentity, PublicCustodyDestinationV3 DeliveredDestination, uint TransferKind,
    Guid JournalProofRecordId, long JournalProofRecordRevision, uint ProofKind, string RequestorSid,
    Guid PromotionOperationId, StagedStageIdentity? ExpectedPublicPredecessorIdentity, Guid OwnerEpoch,
    Guid AuthorizationWitnessId, PublicCustodyDestinationV3 OriginalDestination, Guid PrivateRundownWitnessId);

// This leaf proves representation/correlation only, never native success/drain.
internal static class PublicCustodyReceiptCodecV3
{
    internal const int Size = 2048;
    private static readonly UnicodeEncoding Utf16 = new(false, false, true);

    internal static byte[] Serialize(PublicCustodyReceiptV3 value, bool sourceCompletion)
    {
        Validate(value, sourceCompletion);
        var bytes = new byte[Size];
        "SAFCST03"u8.CopyTo(bytes); U32(bytes, 8, 3); U32(bytes, 12, Size);
        Id(bytes, 16, value.ReceiptId); Id(bytes, 32, value.InstallationId);
        Id(bytes, 48, value.DriverInstanceId); Id(bytes, 64, value.TransferId);
        I64(bytes, 80, value.AllocationGeneration); I64(bytes, 88, value.DestinationGeneration);
        Identity(bytes, 96, value.StageIdentity); U32(bytes, 120, value.Slot); U32(bytes, 124, (uint)value.Role);
        I64(bytes, 128, value.Incarnation); Id(bytes, 136, value.ClaimId); I64(bytes, 152, value.ClaimRevision);
        I64(bytes, 160, value.AcceptedBudgetRevision); Identity(bytes, 168, value.DeliveredObjectIdentity);
        Identity(bytes, 192, value.DeliveredDestination.VolumeRootIdentity); Identity(bytes, 216, value.DeliveredDestination.ParentIdentity);
        Id(bytes, 240, value.DeliveredDestination.MountManagerVolumeId);
        U32(bytes, 256, value.DeliveredDestination.CaseSensitive ? 1u : 0u); U32(bytes, 260, value.TransferKind);
        Id(bytes, 264, value.JournalProofRecordId); I64(bytes, 280, value.JournalProofRecordRevision); U32(bytes, 288, value.ProofKind);
        U32(bytes, 292, (uint)Utf16.GetBytes(value.DeliveredDestination.Leaf, bytes.AsSpan(384, 512)));
        U32(bytes, 296, (uint)Utf16.GetBytes(value.RequestorSid, bytes.AsSpan(896, 368)));
        Id(bytes, 304, value.PromotionOperationId);
        if (value.ExpectedPublicPredecessorIdentity is { } predecessor) { Identity(bytes, 320, predecessor); U32(bytes, 344, 1); }
        Id(bytes, 352, value.OwnerEpoch); Id(bytes, 368, value.AuthorizationWitnessId);
        Identity(bytes, 1264, value.OriginalDestination.VolumeRootIdentity); Identity(bytes, 1288, value.OriginalDestination.ParentIdentity);
        Id(bytes, 1312, value.OriginalDestination.MountManagerVolumeId); U32(bytes, 1328, value.OriginalDestination.CaseSensitive ? 1u : 0u);
        U32(bytes, 1332, (uint)Utf16.GetBytes(value.OriginalDestination.Leaf, bytes.AsSpan(1336, 512)));
        Id(bytes, 1848, value.PrivateRundownWitnessId);
        return bytes;
    }

    internal static PublicCustodyReceiptV3 Deserialize(ReadOnlySpan<byte> bytes, bool sourceCompletion)
    {
        Require(bytes.Length == Size, "Custody receipt length differs.");
        Require(bytes[..8].SequenceEqual("SAFCST03"u8) && U32(bytes, 8) == 3 && U32(bytes, 12) == Size &&
            U32(bytes, 300) == 0 && U32(bytes, 348) == 0 && Zero(bytes[1864..]) &&
            U32(bytes, 256) <= 1 && U32(bytes, 1328) <= 1 && U32(bytes, 344) <= 1, "Custody receipt header/reserved fields differ.");
        uint flags = U32(bytes, 344);
        if (flags == 0) Require(Zero(bytes.Slice(320, 24)), "Absent predecessor has bytes.");
        var value = new PublicCustodyReceiptV3(Id(bytes, 16), Id(bytes, 32), Id(bytes, 48), Id(bytes, 64),
            I64(bytes, 80), I64(bytes, 88), Identity(bytes, 96), U32(bytes, 120), (ResourceSlotRoleV2)U32(bytes, 124),
            I64(bytes, 128), Id(bytes, 136), I64(bytes, 152), I64(bytes, 160), Identity(bytes, 168),
            new(Identity(bytes, 192), Identity(bytes, 216), Id(bytes, 240), U32(bytes, 256) == 1, Carrier(bytes, 384, 512, U32(bytes, 292), 510)),
            U32(bytes, 260), Id(bytes, 264), I64(bytes, 280), U32(bytes, 288), Carrier(bytes, 896, 368, U32(bytes, 296), 368),
            Id(bytes, 304), flags == 0 ? null : Identity(bytes, 320), Id(bytes, 352), Id(bytes, 368),
            new(Identity(bytes, 1264), Identity(bytes, 1288), Id(bytes, 1312), U32(bytes, 1328) == 1, Carrier(bytes, 1336, 512, U32(bytes, 1332), 510)),
            Id(bytes, 1848));
        Validate(value, sourceCompletion); return value;
    }

    internal static void Validate(PublicCustodyReceiptV3 value, bool sourceCompletion)
    {
        foreach (Guid id in new[] { value.ReceiptId, value.InstallationId, value.DriverInstanceId, value.TransferId,
            value.ClaimId, value.JournalProofRecordId, value.PromotionOperationId, value.OwnerEpoch,
            value.AuthorizationWitnessId, value.PrivateRundownWitnessId }) ResourceJsonV3.Id(id);
        Require(value.AllocationGeneration > 0 && value.DestinationGeneration > 0 && value.Slot < 4 && value.Incarnation > 0 &&
            value.ClaimRevision > 0 && value.JournalProofRecordRevision > 0 &&
            (sourceCompletion ? value.AcceptedBudgetRevision == 0 : value.AcceptedBudgetRevision > 0), "Custody receipt counters differ.");
        Require(value.Role is ResourceSlotRoleV2.PublicationTemporary or ResourceSlotRoleV2.Handback &&
            (value.Role == ResourceSlotRoleV2.PublicationTemporary ? value.TransferKind == 1 && value.ProofKind is 1 or 2 :
                value.TransferKind == 2 && value.ProofKind == 3 && value.ExpectedPublicPredecessorIdentity is null),
            "Custody receipt role/kind differs.");
        ResourceJsonV3.Identity(value.StageIdentity); ResourceJsonV3.Identity(value.DeliveredObjectIdentity);
        Destination(value.DeliveredDestination); Destination(value.OriginalDestination);
        Require(value.StageIdentity.VolumeSerialNumber == value.OriginalDestination.VolumeRootIdentity.VolumeSerialNumber &&
            value.DeliveredObjectIdentity.VolumeSerialNumber == value.DeliveredDestination.VolumeRootIdentity.VolumeSerialNumber,
            "Custody receipt volume differs.");
        if (value.ExpectedPublicPredecessorIdentity is { } predecessor)
        {
            ResourceJsonV3.Identity(predecessor);
            Require(predecessor.VolumeSerialNumber == value.DeliveredObjectIdentity.VolumeSerialNumber, "Predecessor volume differs.");
        }
        if (value.TransferKind == 1) Require(value.DeliveredDestination == value.OriginalDestination,
            "Publication destination differs from original.");
        PublicationApprovalCodecV1.ValidateSid(value.RequestorSid);
    }

    private static void Destination(PublicCustodyDestinationV3 value)
    {
        ResourceJsonV3.Identity(value.VolumeRootIdentity); ResourceJsonV3.Identity(value.ParentIdentity);
        ResourceJsonV3.Id(value.MountManagerVolumeId); ResourceJsonV3.Text(value.Leaf, 1, 255);
        Require(value.VolumeRootIdentity.VolumeSerialNumber == value.ParentIdentity.VolumeSerialNumber &&
            ResourceControlWireV32.LeafValid(value.Leaf) && value.Leaf[^1] is not (' ' or '.') &&
            !value.Leaf.Any(c => c < 32 || c is '"' or '<' or '>' or '|' or '?' or '*'), "Custody destination leaf/volume differs.");
    }
    private static string Carrier(ReadOnlySpan<byte> bytes, int offset, int capacity, uint length, int maximum)
    {
        Require(length >= 2 && length <= maximum && (length & 1) == 0 && Zero(bytes.Slice(offset + (int)length, capacity - (int)length)),
            "Custody receipt carrier length/padding differs.");
        try { return Utf16.GetString(bytes.Slice(offset, (int)length)); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Custody receipt UTF-16 differs.", error); }
    }
    private static bool Zero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    private static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition, string message) => ResourceJsonV3.Require(condition, message);
    private static uint U32(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[offset..]);
    private static void U32(Span<byte> bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[offset..], value);
    private static long I64(ReadOnlySpan<byte> bytes, int offset) => BinaryPrimitives.ReadInt64LittleEndian(bytes[offset..]);
    private static void I64(Span<byte> bytes, int offset, long value) => BinaryPrimitives.WriteInt64LittleEndian(bytes[offset..], value);
    private static Guid Id(ReadOnlySpan<byte> bytes, int offset) => new(bytes.Slice(offset, 16));
    private static void Id(Span<byte> bytes, int offset, Guid value) => value.TryWriteBytes(bytes.Slice(offset, 16));
    private static StagedStageIdentity Identity(ReadOnlySpan<byte> bytes, int offset) => new(
        BinaryPrimitives.ReadUInt64LittleEndian(bytes[offset..]), BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset + 16)..]),
        BinaryPrimitives.ReadUInt64LittleEndian(bytes[(offset + 8)..]));
    private static void Identity(Span<byte> bytes, int offset, StagedStageIdentity value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[offset..], value.VolumeSerialNumber);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[(offset + 8)..], value.FileIdLow);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[(offset + 16)..], value.FileIdHigh);
    }
}
#endif
