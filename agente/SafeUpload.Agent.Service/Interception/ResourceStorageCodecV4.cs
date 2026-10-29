#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Security.Cryptography;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record ResourceCompanionV4(Guid DriverInstanceId, Guid TransferId, long AllocationGeneration, long InitialDestinationGeneration,
    StagedStageIdentity StageIdentity, long Alignment, long InitialCapacity, long AuthorizedCapacity, long GrantRevision,
    ulong GrowthSequence, Guid OperationId, StagedStageIdentity Identity);
internal sealed record ResourceMarkerV4(Guid InstallationId, StagedStageIdentity StageRoot, StagedStageIdentity Reservations, StagedStageIdentity JournalHot);
internal sealed record ResourceInventoryV4(Guid InstallationId, StagedStageIdentity CompletedDirectoryIdentity, uint RangeEnd,
    ulong Revision, Guid LastHandoffTransactionId, uint FirstSelectedSegment, Guid CompactionTransactionId, ulong PreviousRevision);
internal sealed record ResourceFrontierV4(Guid InstallationId, StagedStageIdentity SegmentIdentity, int Alignment, int SlotIndex,
    ulong Sequence, long End, Guid LastAppendTransactionId);
internal sealed record ResourceFrameV4(Guid RecordId, byte[] Payload);

internal static class ResourceStorageCodecV4
{
    internal const int SegmentMaximumBytes = 4194304;
    internal static byte[] Serialize(ResourceCompanionV4 value)
    {
        ResourceJsonV3.Id(value.DriverInstanceId); ResourceJsonV3.Id(value.TransferId); ResourceJsonV3.Id(value.OperationId);
        ResourceJsonV3.Identity(value.StageIdentity); ResourceJsonV3.Identity(value.Identity);
        EvidenceBinaryV1.Need(value.Identity != value.StageIdentity && value.AllocationGeneration > 0 && value.InitialDestinationGeneration > 0 &&
            value.Alignment >= 65536 && (value.Alignment & (value.Alignment - 1)) == 0 && value.InitialCapacity >= 16777216 &&
            value.InitialCapacity % value.Alignment == 0 && value.AuthorizedCapacity >= value.InitialCapacity &&
            value.AuthorizedCapacity % value.Alignment == 0 && value.GrantRevision > 0, "Invalid companion contract.");
        var bytes = new byte[192]; "SAFGRW02"u8.CopyTo(bytes); EvidenceBinaryV1.U32(bytes, 8, 2); EvidenceBinaryV1.U32(bytes, 12, 192);
        EvidenceBinaryV1.Id(bytes, 16, value.DriverInstanceId); EvidenceBinaryV1.Id(bytes, 32, value.TransferId);
        EvidenceBinaryV1.I64(bytes, 48, value.AllocationGeneration); EvidenceBinaryV1.I64(bytes, 56, value.InitialDestinationGeneration);
        EvidenceBinaryV1.Identity(bytes, 64, value.StageIdentity); EvidenceBinaryV1.I64(bytes, 88, value.Alignment);
        EvidenceBinaryV1.I64(bytes, 96, value.InitialCapacity); EvidenceBinaryV1.I64(bytes, 104, value.AuthorizedCapacity);
        EvidenceBinaryV1.I64(bytes, 112, value.GrantRevision); EvidenceBinaryV1.U64(bytes, 120, value.GrowthSequence);
        EvidenceBinaryV1.Id(bytes, 128, value.OperationId); EvidenceBinaryV1.Identity(bytes, 144, value.Identity); return bytes;
    }
    internal static ResourceCompanionV4 ReadCompanion(ReadOnlySpan<byte> bytes)
    {
        Header(bytes, 192, "SAFGRW02"u8, 2); EvidenceBinaryV1.Zero(bytes[168..]);
        var value = new ResourceCompanionV4(EvidenceBinaryV1.Id(bytes, 16), EvidenceBinaryV1.Id(bytes, 32), EvidenceBinaryV1.I64(bytes, 48),
            EvidenceBinaryV1.I64(bytes, 56), EvidenceBinaryV1.Identity(bytes, 64), EvidenceBinaryV1.I64(bytes, 88), EvidenceBinaryV1.I64(bytes, 96),
            EvidenceBinaryV1.I64(bytes, 104), EvidenceBinaryV1.I64(bytes, 112), EvidenceBinaryV1.U64(bytes, 120), EvidenceBinaryV1.Id(bytes, 128), EvidenceBinaryV1.Identity(bytes, 144));
        _ = Serialize(value); return value;
    }
    internal static byte[] Serialize(ResourceMarkerV4 value)
    {
        ResourceJsonV3.Id(value.InstallationId); ResourceJsonV3.Identity(value.StageRoot); ResourceJsonV3.Identity(value.Reservations); ResourceJsonV3.Identity(value.JournalHot);
        var bytes = new byte[128]; "SAFMT004"u8.CopyTo(bytes); EvidenceBinaryV1.U32(bytes, 8, 4); EvidenceBinaryV1.U32(bytes, 12, 128);
        EvidenceBinaryV1.Id(bytes, 16, value.InstallationId); EvidenceBinaryV1.Identity(bytes, 32, value.StageRoot);
        EvidenceBinaryV1.Identity(bytes, 56, value.Reservations); EvidenceBinaryV1.Identity(bytes, 80, value.JournalHot); EvidenceBinaryV1.U64(bytes, 104, 0x1ff); return bytes;
    }
    internal static ResourceMarkerV4 ReadMarker(ReadOnlySpan<byte> bytes)
    {
        Header(bytes, 128, "SAFMT004"u8, 4); EvidenceBinaryV1.Need(EvidenceBinaryV1.U64(bytes, 104) == 0x1ff, "Unsupported marker capabilities.");
        EvidenceBinaryV1.Zero(bytes[112..]); var value = new ResourceMarkerV4(EvidenceBinaryV1.Id(bytes, 16), EvidenceBinaryV1.Identity(bytes, 32),
            EvidenceBinaryV1.Identity(bytes, 56), EvidenceBinaryV1.Identity(bytes, 80)); _ = Serialize(value); return value;
    }
    internal static byte[] Serialize(ResourceInventoryV4 value)
    {
        ResourceJsonV3.Id(value.InstallationId); ResourceJsonV3.Identity(value.CompletedDirectoryIdentity);
        EvidenceBinaryV1.Need(value.Revision > 0 && value.PreviousRevision == value.Revision - 1 &&
            (value.RangeEnd == 0 ? value.FirstSelectedSegment == 0 : value.FirstSelectedSegment > 0 && value.FirstSelectedSegment <= value.RangeEnd) &&
            (value.Revision == 1 || value.LastHandoffTransactionId != Guid.Empty), "Inventory range/revision differs.");
        var bytes = new byte[128]; "SAFHIS03"u8.CopyTo(bytes); EvidenceBinaryV1.U32(bytes, 8, 3); EvidenceBinaryV1.U32(bytes, 12, 128);
        EvidenceBinaryV1.Id(bytes, 16, value.InstallationId); EvidenceBinaryV1.Identity(bytes, 32, value.CompletedDirectoryIdentity);
        EvidenceBinaryV1.U32(bytes, 56, value.RangeEnd); EvidenceBinaryV1.U64(bytes, 64, value.Revision);
        EvidenceBinaryV1.Id(bytes, 72, value.LastHandoffTransactionId); EvidenceBinaryV1.U32(bytes, 88, value.FirstSelectedSegment);
        EvidenceBinaryV1.Id(bytes, 96, value.CompactionTransactionId); EvidenceBinaryV1.U64(bytes, 112, value.PreviousRevision); return bytes;
    }
    internal static ResourceInventoryV4 ReadInventory(ReadOnlySpan<byte> bytes)
    {
        Header(bytes, 128, "SAFHIS03"u8, 3); EvidenceBinaryV1.Zero(bytes.Slice(60, 4)); EvidenceBinaryV1.Zero(bytes.Slice(92, 4)); EvidenceBinaryV1.Zero(bytes[120..]);
        var value = new ResourceInventoryV4(EvidenceBinaryV1.Id(bytes, 16), EvidenceBinaryV1.Identity(bytes, 32), EvidenceBinaryV1.U32(bytes, 56),
            EvidenceBinaryV1.U64(bytes, 64), EvidenceBinaryV1.Id(bytes, 72), EvidenceBinaryV1.U32(bytes, 88), EvidenceBinaryV1.Id(bytes, 96), EvidenceBinaryV1.U64(bytes, 112));
        _ = Serialize(value); return value;
    }
    internal static byte[] Serialize(ResourceFrontierV4 value)
    {
        EvidenceBinaryV1.Alignment(value.Alignment); ResourceJsonV3.Id(value.InstallationId); ResourceJsonV3.Identity(value.SegmentIdentity);
        EvidenceBinaryV1.Need(value.Sequence > 0 && value.SlotIndex == (int)((value.Sequence - 1) % 2) &&
            value.End >= 2 * value.Alignment && value.End <= SegmentMaximumBytes && value.End % value.Alignment == 0 &&
            (value.Sequence == 1 ? value.End == 2 * value.Alignment && value.LastAppendTransactionId == Guid.Empty : value.LastAppendTransactionId != Guid.Empty),
            "Frontier sequence/parity/end differs.");
        var bytes = new byte[value.Alignment]; "SAFEND03"u8.CopyTo(bytes); EvidenceBinaryV1.U32(bytes, 8, 3); EvidenceBinaryV1.U32(bytes, 12, 128);
        EvidenceBinaryV1.Id(bytes, 16, value.InstallationId); EvidenceBinaryV1.Identity(bytes, 32, value.SegmentIdentity);
        EvidenceBinaryV1.U32(bytes, 56, value.Alignment); EvidenceBinaryV1.U32(bytes, 60, value.SlotIndex);
        EvidenceBinaryV1.U64(bytes, 64, value.Sequence); EvidenceBinaryV1.I64(bytes, 72, value.End); EvidenceBinaryV1.Id(bytes, 80, value.LastAppendTransactionId);
        SHA256.HashData(bytes.AsSpan(0, 96)).CopyTo(bytes, 96); return bytes;
    }
    internal static ResourceFrontierV4 ReadFrontier(ReadOnlySpan<byte> bytes, int alignment, int slot)
    {
        EvidenceBinaryV1.Alignment(alignment); EvidenceBinaryV1.Need(bytes.Length == alignment, "Frontier length differs.");
        EvidenceBinaryV1.Need(bytes[..8].SequenceEqual("SAFEND03"u8) && EvidenceBinaryV1.U32(bytes, 8) == 3 && EvidenceBinaryV1.U32(bytes, 12) == 128 &&
            EvidenceBinaryV1.U32(bytes, 56) == alignment && EvidenceBinaryV1.U32(bytes, 60) == slot, "Frontier header/physical slot differs.");
        EvidenceBinaryV1.Hash(bytes[..96], bytes.Slice(96, 32)); EvidenceBinaryV1.Zero(bytes[128..]);
        var value = new ResourceFrontierV4(EvidenceBinaryV1.Id(bytes, 16), EvidenceBinaryV1.Identity(bytes, 32), alignment, slot,
            EvidenceBinaryV1.U64(bytes, 64), EvidenceBinaryV1.I64(bytes, 72), EvidenceBinaryV1.Id(bytes, 80)); _ = Serialize(value); return value;
    }
    internal static byte[] Serialize(ResourceFrameV4 value, int alignment)
    {
        EvidenceBinaryV1.Alignment(alignment); ResourceJsonV3.Id(value.RecordId);
        EvidenceBinaryV1.Need(value.Payload.Length is > 0 and <= 131072, "Archive payload exceeds its bound.");
        var bytes = new byte[checked((60 + value.Payload.Length + alignment - 1) / alignment * alignment)];
        EvidenceBinaryV1.U32(bytes, 0, 0x414a5553); EvidenceBinaryV1.U32(bytes, 4, 3); EvidenceBinaryV1.U32(bytes, 8, value.Payload.Length);
        EvidenceBinaryV1.Id(bytes, 12, value.RecordId); SHA256.HashData(value.Payload).CopyTo(bytes, 28); value.Payload.CopyTo(bytes, 60); return bytes;
    }
    internal static ResourceFrameV4 ReadFrame(ReadOnlySpan<byte> bytes, int alignment)
    {
        EvidenceBinaryV1.Alignment(alignment); EvidenceBinaryV1.Need(bytes.Length >= alignment && bytes.Length % alignment == 0 && bytes.Length >= 60,
            "Frame stride is invalid.");
        uint size = EvidenceBinaryV1.U32(bytes, 8);
        EvidenceBinaryV1.Need(EvidenceBinaryV1.U32(bytes, 0) == 0x414a5553 && EvidenceBinaryV1.U32(bytes, 4) == 3 && size is > 0 and <= 131072 &&
            bytes.Length == (60 + size + alignment - 1) / alignment * alignment, "Frame header/length differs.");
        var payload = bytes.Slice(60, (int)size); EvidenceBinaryV1.Hash(payload, bytes.Slice(28, 32)); EvidenceBinaryV1.Zero(bytes[(60 + (int)size)..]);
        var value = new ResourceFrameV4(EvidenceBinaryV1.Id(bytes, 12), payload.ToArray()); ResourceJsonV3.Id(value.RecordId); return value;
    }
    private static void Header(ReadOnlySpan<byte> bytes, int size, ReadOnlySpan<byte> magic, uint version) => EvidenceBinaryV1.Need(bytes.Length == size &&
        bytes[..8].SequenceEqual(magic) && EvidenceBinaryV1.U32(bytes, 8) == version && EvidenceBinaryV1.U32(bytes, 12) == size, "Fixed storage header differs.");
}
#endif
