using System.Buffers.Binary;

namespace SafeUpload.Agent.Minifilter;

/// <summary>
/// Prepared decoder for Protocol.h at driver e0df8d1c (T8 increment 0).
/// No transport, service registration or capability/enforcement decision. Existing
/// diagnostics have different layouts in M2 and still require pair qualification.
/// </summary>
public static class StageStreamDiagnosticsContract
{
    public const uint Command = 29;
    // Pin this layout independently: a future change to Contract.Version must
    // not silently approve this decoder for a different protocol.
    public const uint ProtocolVersion = 18;
    public const int Capacity = 16;
    public const int NameCodeUnits = 48;
    public const int RecordBytes = 160;
    public const int HeaderBytes = 16;
    public const int SnapshotBytes = HeaderBytes + Capacity * RecordBytes;

    public static StageStreamDiagnosticSnapshot Decode(ReadOnlySpan<byte> response)
    {
        if (response.Length != SnapshotBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(response) != SnapshotBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(response[4..]) != ProtocolVersion)
            throw new InvalidDataException("Stage-stream diagnostic response has an unsupported size or protocol.");

        uint count = BinaryPrimitives.ReadUInt32LittleEndian(response[8..]);
        uint total = BinaryPrimitives.ReadUInt32LittleEndian(response[12..]);
        if (count > Capacity || count > total)
            throw new InvalidDataException("Stage-stream diagnostic response has invalid counts.");

        // Allocation depends on validated Count, never the potentially large Total.
        var records = new StageStreamDiagnosticRecord[(int)count];
        Span<char> name = stackalloc char[NameCodeUnits];
        for (int index = 0; index < records.Length; index++)
        {
            var entry = response.Slice(HeaderBytes + index * RecordBytes, RecordBytes);
            uint chars = BinaryPrimitives.ReadUInt32LittleEndian(entry[56..]);
            if (chars > NameCodeUnits)
                throw new InvalidDataException("Stage-stream diagnostic response has an invalid name length.");
            // WCHAR count is authoritative, not a NUL terminator. Preserve UTF-16
            // code units (including a truncated surrogate) without replacement.
            for (int i = 0; i < (int)chars; i++)
                name[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(entry[(64 + i * 2)..]);
            records[index] = new StageStreamDiagnosticRecord(new Guid(entry[..16]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[16..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[20..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[24..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[28..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[32..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[36..]),
                BinaryPrimitives.ReadUInt32LittleEndian(entry[40..]),
                BinaryPrimitives.ReadUInt64LittleEndian(entry[48..]), name[..(int)chars].ToString());
        }
        return new StageStreamDiagnosticSnapshot(Array.AsReadOnly(records), total);
    }
}

/// <summary>Raw flags/section bits are preserved, including unknown bits; none grant permission.</summary>
public sealed record StageStreamDiagnosticRecord(Guid TransferId, uint Flags, uint FileObjects,
    uint ShareOpenCount, uint RpcReferences, uint OwnerProcessId, uint Wait, uint SectionBits,
    ulong DestinationGeneration, string Name);

/// <summary>Read-only bounded view, not a transactional or complete state when Total exceeds Count.</summary>
public sealed record StageStreamDiagnosticSnapshot(IReadOnlyList<StageStreamDiagnosticRecord> Records, uint Total)
{
    public bool Truncated => Total > (uint)Records.Count;
}
