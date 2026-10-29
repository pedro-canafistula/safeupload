#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SafeUpload.Agent.Service.Interception;

internal enum EvidenceKindV1 : uint { Authorization = 1, EntryCore = 2 }
internal sealed record EvidenceOwnerV1(Guid InstallationId, Guid TransferId, Guid OperationId, Guid RecordId,
    long Generation, EvidenceKindV1 Kind, long AllocationGeneration, long DestinationGeneration, Guid AuthorizationWitnessId);
internal sealed record EvidenceReferenceV1(EvidenceOwnerV1 Owner, StagedStageIdentity Identity, long Length, string Sha256);

internal static class EvidenceReferenceCodecV1
{
    internal const int Size = 192;
    internal static byte[] Serialize(EvidenceReferenceV1 value)
    {
        Validate(value); var bytes = new byte[Size];
        "SAFEVR01"u8.CopyTo(bytes); EvidenceBinaryV1.U32(bytes, 8, 1); EvidenceBinaryV1.U32(bytes, 12, Size);
        EvidenceBinaryV1.Owner(bytes, value.Owner); EvidenceBinaryV1.Identity(bytes, 88, value.Identity);
        EvidenceBinaryV1.I64(bytes, 112, value.Length); Convert.FromHexString(value.Sha256).CopyTo(bytes, 120);
        EvidenceBinaryV1.U32(bytes, 152, (uint)value.Owner.Kind);
        return bytes;
    }
    internal static EvidenceReferenceV1 Deserialize(ReadOnlySpan<byte> bytes)
    {
        EvidenceBinaryV1.Need(bytes.Length == Size, "Evidence reference length differs.");
        EvidenceBinaryV1.Need(bytes[..8].SequenceEqual("SAFEVR01"u8) && EvidenceBinaryV1.U32(bytes, 8) == 1 &&
            EvidenceBinaryV1.U32(bytes, 12) == Size && EvidenceBinaryV1.U32(bytes, 156) == 0, "Evidence reference header differs.");
        var value = new EvidenceReferenceV1(EvidenceBinaryV1.Owner(bytes, 152), EvidenceBinaryV1.Identity(bytes, 88),
            EvidenceBinaryV1.I64(bytes, 112), Convert.ToHexString(bytes.Slice(120, 32)));
        Validate(value); return value;
    }
    internal static void Validate(EvidenceReferenceV1 value)
    {
        ValidateOwner(value.Owner); ResourceJsonV3.Identity(value.Identity); ResourceJsonV3.Hex(value.Sha256);
        EvidenceBinaryV1.Need(value.Length is >= 135168 and <= EvidencePackCodecV1.MaximumFileBytes && value.Length % 4096 == 0,
            "Evidence reference length is outside the container bound.");
    }
    internal static void ValidateOwner(EvidenceOwnerV1 value)
    {
        ResourceJsonV3.Id(value.InstallationId); ResourceJsonV3.Id(value.TransferId); ResourceJsonV3.Id(value.OperationId);
        ResourceJsonV3.Id(value.RecordId); ResourceJsonV3.Id(value.AuthorizationWitnessId);
        EvidenceBinaryV1.Need(Enum.IsDefined(value.Kind) && value.Generation > 0 && value.AllocationGeneration > 0 &&
            value.DestinationGeneration > 0, "Evidence owner kind/generation differs.");
    }
    internal static string Leaf(EvidenceReferenceV1 value) => value.Owner.RecordId.ToString("N") + ".evidence";
}

internal static class EvidenceBinaryV1
{
    internal static void Need([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition, string message)
    { if (!condition) throw new InvalidDataException(message); }
    internal static int Alignment(int value)
    { Need(value is >= 4096 and <= 65536 && (value & (value - 1)) == 0, "Invalid evidence alignment."); return value; }
    internal static uint U32(ReadOnlySpan<byte> bytes, int at) => BinaryPrimitives.ReadUInt32LittleEndian(bytes[at..]);
    internal static void U32(Span<byte> bytes, int at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes[at..], value);
    internal static void U32(Span<byte> bytes, int at, int value) => U32(bytes, at, checked((uint)value));
    internal static long I64(ReadOnlySpan<byte> bytes, int at) => BinaryPrimitives.ReadInt64LittleEndian(bytes[at..]);
    internal static void I64(Span<byte> bytes, int at, long value) => BinaryPrimitives.WriteInt64LittleEndian(bytes[at..], value);
    internal static ulong U64(ReadOnlySpan<byte> bytes, int at) => BinaryPrimitives.ReadUInt64LittleEndian(bytes[at..]);
    internal static void U64(Span<byte> bytes, int at, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(bytes[at..], value);
    internal static Guid Id(ReadOnlySpan<byte> bytes, int at) => new(bytes.Slice(at, 16));
    internal static void Id(Span<byte> bytes, int at, Guid value) => value.TryWriteBytes(bytes.Slice(at, 16));
    internal static StagedStageIdentity Identity(ReadOnlySpan<byte> bytes, int at) => new(U64(bytes, at), U64(bytes, at + 16), U64(bytes, at + 8));
    internal static void Identity(Span<byte> bytes, int at, StagedStageIdentity value)
    { U64(bytes, at, value.VolumeSerialNumber); U64(bytes, at + 8, value.FileIdLow); U64(bytes, at + 16, value.FileIdHigh); }
    internal static EvidenceOwnerV1 Owner(ReadOnlySpan<byte> bytes, int kindAt) => new(Id(bytes, 16), Id(bytes, 32), Id(bytes, 48), Id(bytes, 64),
        I64(bytes, 80), (EvidenceKindV1)U32(bytes, kindAt), I64(bytes, 160), I64(bytes, 168), Id(bytes, 176));
    internal static void Owner(Span<byte> bytes, EvidenceOwnerV1 value)
    {
        Id(bytes, 16, value.InstallationId); Id(bytes, 32, value.TransferId); Id(bytes, 48, value.OperationId); Id(bytes, 64, value.RecordId);
        I64(bytes, 80, value.Generation); I64(bytes, 160, value.AllocationGeneration); I64(bytes, 168, value.DestinationGeneration);
        Id(bytes, 176, value.AuthorizationWitnessId);
    }
    internal static void Zero(ReadOnlySpan<byte> bytes) => Need(bytes.IndexOfAnyExcept((byte)0) < 0, "Nonzero reserved/padding bytes.");
    internal static void Hash(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> expected) => Need(
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), expected), "Evidence hash differs.");
}
#endif
