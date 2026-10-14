using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SafeUpload.Agent.Minifilter;

// Immutable captured evidence. No constructor or page read grants authority.
// The binary codec is also used by normal-build conservative journal recovery;
// only the FilterPort transport is feature compiled.
public sealed record WriterMetadataSnapshot(Guid DriverInstanceId, Guid ReservationId, ulong RequestId,
    ulong ConnectionEpoch, ulong AuthorityRevision, Guid SnapshotId, uint Flags, string EnvelopeHex)
{
    public byte[] Blob() => Convert.FromHexString(EnvelopeHex)[WriterMetadataV27.HeaderBytes..];
}

public static class WriterMetadataV27
{
    public const int Version = 27, Control = 34, HeaderBytes = 136, PagePayloadBytes = 4096;
    public const int PageBytes = HeaderBytes + PagePayloadBytes, FactsBytes = 1024;
    public const int MaximumDescriptorBytes = 131228, MaximumBlobBytes = FactsBytes + 2 * MaximumDescriptorBytes;
    public const int MaximumEnvelopeBytes = HeaderBytes + MaximumBlobBytes;
    public const uint CompleteFlags = 31, Discover = 1, Read = 2, Confirm = 3;

    public static WriterMetadataSnapshot Fetch(Func<byte[], byte[]> send, Guid driver, Guid reservation,
        ulong requestId, CancellationToken cancellationToken = default)
    {
        if (driver == Guid.Empty || reservation == Guid.Empty || requestId == 0)
            throw new InvalidDataException("writer_metadata_binding_mismatch");
        cancellationToken.ThrowIfCancellationRequested();
        byte[] initial = send(Request(driver, reservation, requestId, Discover, 0));
        ValidatePage(initial, driver, reservation, requestId, Discover, 0, null);
        byte[] header = initial[..HeaderBytes];
        int total = checked((int)U32(header, 92));
        byte[] envelope = new byte[HeaderBytes + total];
        header.CopyTo(envelope, 0);
        for (int offset = 0; offset < total; offset += PagePayloadBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byte[] page = send(Request(driver, reservation, requestId, Read, (uint)offset, header));
            ValidatePage(page, driver, reservation, requestId, Read, (uint)offset, header);
            page.AsSpan(HeaderBytes, checked((int)U32(page, 96))).CopyTo(envelope.AsSpan(HeaderBytes + offset));
        }
        cancellationToken.ThrowIfCancellationRequested();
        byte[] final = send(Request(driver, reservation, requestId, Confirm, (uint)total, header));
        ValidatePage(final, driver, reservation, requestId, Confirm, (uint)total, header);
        cancellationToken.ThrowIfCancellationRequested();
        return DecodeEnvelope(envelope);
    }

    private static byte[] Request(Guid driver, Guid reservation, ulong request, uint phase, uint offset,
        byte[]? pinned = null)
    {
        byte[] result = new byte[HeaderBytes];
        Put32(result, 0, 18); Put32(result, 4, HeaderBytes); Put32(result, 8, Control);
        Put32(result, 16, Version); Put32(result, 20, phase);
        driver.TryWriteBytes(result.AsSpan(24)); reservation.TryWriteBytes(result.AsSpan(40));
        Put64(result, 56, request); Put32(result, 96, offset);
        if (pinned is not null)
        {
            pinned.AsSpan(56, 32).CopyTo(result.AsSpan(64)); // epoch, revision, snapshot
            pinned.AsSpan(104, 32).CopyTo(result.AsSpan(104));
        }
        return result;
    }

    private static void ValidatePage(byte[] page, Guid driver, Guid reservation, ulong request, uint phase,
        uint offset, byte[]? pinned)
    {
        if (page.Length != PageBytes) throw new InvalidDataException("writer_metadata_incomplete");
        uint total = U32(page, 92), count = U32(page, 96);
        if (U32(page, 0) != Version || U32(page, 4) != PageBytes || U32(page, 8) != phase ||
            U32(page, 12) != 1 || new Guid(page.AsSpan(16, 16)) != driver ||
            new Guid(page.AsSpan(32, 16)) != reservation || U64(page, 48) != request ||
            U64(page, 56) == 0 || U64(page, 64) == 0 || new Guid(page.AsSpan(72, 16)) == Guid.Empty ||
            U32(page, 88) != offset || total < FactsBytes || total > MaximumBlobBytes ||
            U32(page, 100) != CompleteFlags || Zero(page.AsSpan(104, 32)) ||
            count != (phase == Read && offset < total ? Math.Min((uint)PagePayloadBytes, total - offset) : 0) ||
            (phase == Read && (offset >= total || offset % PagePayloadBytes != 0)) ||
            (phase == Confirm && offset != total) || !Zero(page.AsSpan(HeaderBytes + checked((int)count))))
            throw new InvalidDataException("writer_metadata_incomplete_or_mismatched");
        if (pinned is not null && (!page.AsSpan(16, 72).SequenceEqual(pinned.AsSpan(16, 72)) ||
            !page.AsSpan(92, 4).SequenceEqual(pinned.AsSpan(92, 4)) ||
            !page.AsSpan(100, 36).SequenceEqual(pinned.AsSpan(100, 36))))
            throw new InvalidDataException("writer_metadata_stale");
    }

    public static WriterMetadataSnapshot DecodeEnvelope(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < HeaderBytes + FactsBytes || envelope.Length > MaximumEnvelopeBytes)
            throw new InvalidDataException("writer_metadata_storage_bounds");
        byte[] headerPage = new byte[PageBytes]; envelope[..HeaderBytes].CopyTo(headerPage);
        Guid driver = new(envelope.Slice(16, 16)), reservation = new(envelope.Slice(32, 16));
        ulong request = U64(envelope, 48);
        if (driver == Guid.Empty || reservation == Guid.Empty || request == 0)
            throw new InvalidDataException("writer_metadata_binding_mismatch");
        ValidatePage(headerPage, driver, reservation, request, Discover, 0, null);
        ReadOnlySpan<byte> blob = envelope[HeaderBytes..];
        if (blob.Length != U32(envelope, 92) || !SHA256.HashData(blob).AsSpan().SequenceEqual(envelope.Slice(104, 32)))
            throw new InvalidDataException("writer_metadata_digest_mismatch");
        uint construction = U32(blob, 904), stored = U32(blob, 908);
        if (U32(blob, 0) != 1 || U32(blob, 4) != FactsBytes || U32(blob, 8) != 23 || U32(blob, 12) != 124 ||
            new Guid(blob.Slice(16, 16)) != reservation || U32(blob, 644) is 0 or > int.MaxValue ||
            BinaryPrimitives.ReadInt64LittleEndian(blob[652..]) <= 0 || U32(blob, 860) is < 2 or > 128 ||
            Zero(blob.Slice(864, 32)) || U32(blob, 896) == 0 || U32(blob, 900) != 0x10000 ||
            construction < 20 || construction > MaximumDescriptorBytes || stored < 20 || stored > MaximumDescriptorBytes ||
            (ulong)FactsBytes + construction + stored != (ulong)blob.Length ||
            U32(blob, 912) > 2 || U32(blob, 916) != 0 || U32(blob, 920) != 0 ||
            U32(blob, 924) != 0xC00000BB || U32(blob, 928) != 0xC00000BB ||
            new Guid(blob.Slice(932, 16)) == Guid.Empty || !Zero(blob[948..FactsBytes]))
            throw new InvalidDataException("writer_metadata_security_or_provenance_unproved");
        RequireSid(blob.Slice(664, 68), U32(blob, 660)); RequireSid(blob.Slice(736, 68), U32(blob, 732));
        uint disposition = U32(blob, 48), reference = U32(blob, 52);
        bool present = !Zero(blob.Slice(56, 16));
        uint origin = disposition is 1 or 3 ? reference == 1 ? 2u : present ? 1u : 0u : 0u;
        int leafBytes = BinaryPrimitives.ReadUInt16LittleEndian(blob[130..]);
        if (disposition > 5 || reference > 2 || (reference == 0) != (new Guid(blob.Slice(32, 16)) == Guid.Empty) ||
            U32(blob, 912) != origin || (U32(blob, 828) >> 24) != disposition ||
            leafBytes is <= 0 or > 510 || (leafBytes & 1) != 0 || !Zero(blob.Slice(132 + leafBytes, 512 - leafBytes)))
            throw new InvalidDataException("writer_metadata_create_binding_mismatch");
        return new(driver, reservation, request, U64(envelope, 56), U64(envelope, 64),
            new(envelope.Slice(72, 16)), U32(envelope, 100), Convert.ToHexString(envelope));
    }

    private static void RequireSid(ReadOnlySpan<byte> sid, uint bytes)
    {
        if (bytes is < 8 or > 68 || sid[0] != 1 || sid[1] > 15 || bytes != 8 + 4 * sid[1] ||
            !Zero(sid[checked((int)bytes)..])) throw new InvalidDataException("writer_metadata_subject_incomplete");
    }
    private static bool Zero(ReadOnlySpan<byte> bytes) => bytes.IndexOfAnyExcept((byte)0) < 0;
    private static uint U32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
    private static ulong U64(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b[o..]);
    private static void Put32(Span<byte> b, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b[o..], v);
    private static void Put64(Span<byte> b, int o, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b[o..], v);
}
