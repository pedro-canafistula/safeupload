using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SafeUpload.Agent.Service.Interception;

// An immutable storage record, not a permission or a descriptor constructor.
// The checked driver producer must establish native assignment and completeness.
// Construction and expected stored form are separate: never infer one by masking
// flags from the other, or by reparsing through SDDL.
public sealed record StagedAllocationSecuritySnapshot(
    Guid SnapshotId, Guid DriverInstanceId, Guid ReservationId,
    uint AssignmentRevision, uint SecurityInformation,
    string BindingSha256Hex, string ConstructionHex, string ExpectedStoredHex)
{
    internal const int HeaderBytes = 112;
    internal const int MaximumBytes = HeaderBytes + 2 * StagedSecurityDescriptor.MaximumBytes;

    internal void RequireBinding(StagedAllocationBindingV23 binding)
    {
        if (DriverInstanceId != binding.DriverInstanceId || ReservationId != binding.ReservationId ||
            BindingSha256Hex != BindingDigest(binding))
            throw new InvalidDataException("The security snapshot belongs to another driver or reservation.");
        Validate();
    }

    internal void Validate()
    {
        if (SnapshotId == Guid.Empty || DriverInstanceId == Guid.Empty || ReservationId == Guid.Empty ||
            AssignmentRevision == 0 || SecurityInformation == 0 || BindingSha256Hex is null ||
            BindingSha256Hex.Length != 64 ||
            BindingSha256Hex.Any(c => !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))))
            throw new InvalidDataException("The security snapshot has incomplete identity or provenance.");
        _ = ReadCanonical(ConstructionHex);
        _ = ReadCanonical(ExpectedStoredHex);
    }

    internal static StagedAllocationSecuritySnapshot Create(Guid snapshot, StagedAllocationBindingV23 binding,
        uint assignmentRevision, uint securityInformation, ReadOnlySpan<byte> construction,
        ReadOnlySpan<byte> expectedStored) => new(snapshot, binding.DriverInstanceId, binding.ReservationId,
            assignmentRevision, securityInformation, BindingDigest(binding),
            Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(construction)),
            Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(expectedStored)));

    internal byte[] Encode()
    {
        Validate();
        byte[] construction = ReadCanonical(ConstructionHex), stored = ReadCanonical(ExpectedStoredHex);
        byte[] bytes = new byte[checked(HeaderBytes + construction.Length + stored.Length)];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, 1); // storage format, not a wire revision
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), HeaderBytes);
        SnapshotId.TryWriteBytes(bytes.AsSpan(8, 16));
        DriverInstanceId.TryWriteBytes(bytes.AsSpan(24, 16));
        ReservationId.TryWriteBytes(bytes.AsSpan(40, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(56), AssignmentRevision);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), SecurityInformation);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(64), checked((uint)construction.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(68), checked((uint)stored.Length));
        // 72..79 are reserved zero. There is no variable or untrusted filename.
        Convert.FromHexString(BindingSha256Hex).CopyTo(bytes, 80);
        construction.CopyTo(bytes, HeaderBytes);
        stored.CopyTo(bytes, HeaderBytes + construction.Length);
        return bytes;
    }

    internal static StagedAllocationSecuritySnapshot Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < HeaderBytes || bytes.Length > MaximumBytes ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes) != 1 ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..]) != HeaderBytes ||
            BinaryPrimitives.ReadUInt64LittleEndian(bytes[72..]) != 0)
            throw new InvalidDataException("Invalid security snapshot framing.");
        uint construction = BinaryPrimitives.ReadUInt32LittleEndian(bytes[64..]);
        uint stored = BinaryPrimitives.ReadUInt32LittleEndian(bytes[68..]);
        if (construction < 20 || stored < 20 || construction > StagedSecurityDescriptor.MaximumBytes ||
            stored > StagedSecurityDescriptor.MaximumBytes ||
            (ulong)HeaderBytes + construction + stored != (ulong)bytes.Length)
            throw new InvalidDataException("Invalid security snapshot lengths or trailing data.");
        var snapshot = new StagedAllocationSecuritySnapshot(new(bytes.Slice(8, 16)),
            new(bytes.Slice(24, 16)), new(bytes.Slice(40, 16)),
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[56..]),
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[60..]),
            Convert.ToHexString(bytes.Slice(80, 32)),
            Convert.ToHexString(bytes.Slice(HeaderBytes, (int)construction)),
            Convert.ToHexString(bytes.Slice(HeaderBytes + (int)construction, (int)stored)));
        snapshot.Validate();
        return snapshot;
    }

    internal StagedAllocationSecurityReference Reference()
    {
        byte[] bytes = Encode();
        return new(SnapshotId, bytes.Length, Convert.ToHexString(SHA256.HashData(bytes)));
    }

    private static byte[] ReadCanonical(string hex)
    {
        if (hex is null || hex.Length < 40 || hex.Length > 2 * StagedSecurityDescriptor.MaximumBytes ||
            (hex.Length & 1) != 0)
            throw new InvalidDataException("Invalid security descriptor storage length.");
        byte[] bytes;
        try { bytes = Convert.FromHexString(hex); }
        catch (FormatException error) { throw new InvalidDataException("Invalid security descriptor encoding.", error); }
        if (Convert.ToHexString(StagedSecurityDescriptor.Canonicalize(bytes)) != hex)
            throw new InvalidDataException("Security descriptor storage is not canonical.");
        return bytes;
    }

    // Storage-format commitment to every binding field, with exact UTF-16 leaf
    // bytes. No locator, case folding or JSON serializer participates in authority.
    private static string BindingDigest(StagedAllocationBindingV23 binding)
    {
        binding.Validate();
        byte[] leaf;
        try { leaf = new UnicodeEncoding(false, false, true).GetBytes(binding.CanonicalLeaf); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("Invalid allocation leaf encoding.", error); }
        byte[] bytes = new byte[152 + leaf.Length];
        binding.ReservationId.TryWriteBytes(bytes.AsSpan(0, 16));
        binding.DriverInstanceId.TryWriteBytes(bytes.AsSpan(16, 16));
        binding.ParentTransferId.TryWriteBytes(bytes.AsSpan(32, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(48), binding.Disposition);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(52), binding.ReferenceKind);
        binding.MountManagerVolumeId.TryWriteBytes(bytes.AsSpan(56, 16));
        WriteIdentity(bytes.AsSpan(72, 24), binding.VolumeRoot);
        WriteIdentity(bytes.AsSpan(96, 24), binding.Parent);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(120), binding.ParentCaseSensitive ? (ushort)1 : (ushort)0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(122), checked((ushort)leaf.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(124), binding.PublicTarget is null ? 0u : 1u);
        if (binding.PublicTarget is { } target) WriteIdentity(bytes.AsSpan(128, 24), target);
        leaf.CopyTo(bytes, 152);
        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static void WriteIdentity(Span<byte> bytes, StagedStageIdentity identity)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, identity.VolumeSerialNumber);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], identity.FileIdLow);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes[16..], identity.FileIdHigh);
    }
}

public sealed record StagedAllocationSecurityReference(Guid SnapshotId, int Bytes, string Sha256Hex)
{
    internal void Validate()
    {
        if (SnapshotId == Guid.Empty || Bytes < StagedAllocationSecuritySnapshot.HeaderBytes + 40 ||
            Bytes > StagedAllocationSecuritySnapshot.MaximumBytes || Sha256Hex is null ||
            Sha256Hex.Length != 64 || Sha256Hex.Any(c => !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))))
            throw new InvalidDataException("Invalid allocation security snapshot reference.");
    }
}

internal static class StagedSecurityDescriptor
{
    // Two maximal ACLs and two maximal SIDs, with DWORD component alignment.
    // Outer offsets/padding are representation only. Preserve every control/RM
    // bit and every ACL byte (including its ordered opaque ACEs and unused tail).
    internal const int MaximumBytes = 20 + 2 * 68 + 2 * 65536;

    internal static byte[] Canonicalize(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 20 || bytes[0] != 1 ||
            (BinaryPrimitives.ReadUInt16LittleEndian(bytes[2..]) & 0x8000) == 0)
            throw new InvalidDataException("Security descriptor must be revision-one self-relative binary.");
        var components = new (int Offset, int Length, bool Sid)[4];
        int total = 20;
        for (int index = 0; index < components.Length; index++)
        {
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes[(4 + 4 * index)..]);
            if (offset == 0) continue; // Keep absent, NULL and empty ACLs distinct through control + bytes.
            bool sid = index < 2;
            if (offset < 20 || (offset & 3) != 0 || offset > (uint)(bytes.Length - 8))
                throw new InvalidDataException("Security descriptor component is outside its buffer.");
            int start = (int)offset;
            int length;
            if (sid)
            {
                if (bytes[start] != 1 || bytes[start + 1] > 15)
                    throw new InvalidDataException("Invalid security descriptor SID header.");
                length = 8 + 4 * bytes[start + 1];
            }
            else
            {
                length = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(start + 2)..]);
                if (length < 8 || length > bytes.Length - start)
                    throw new InvalidDataException("Invalid security descriptor ACL length.");
                int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(start + 4)..]);
                int next = 8;
                for (int ace = 0; ace < count; ace++)
                {
                    if ((next & 3) != 0 || next > length - 4)
                        throw new InvalidDataException("Invalid ordered ACE boundary.");
                    int size = BinaryPrimitives.ReadUInt16LittleEndian(bytes[(start + next + 2)..]);
                    if (size < 4 || size > length - next)
                        throw new InvalidDataException("Invalid opaque ACE length.");
                    next += size;
                }
            }
            if (length > bytes.Length - start)
                throw new InvalidDataException("Truncated security descriptor component.");
            foreach (var prior in components.AsSpan(0, index))
                if (prior.Length != 0 && start < prior.Offset + prior.Length && prior.Offset < start + length &&
                    (start != prior.Offset || length != prior.Length || sid != prior.Sid))
                    throw new InvalidDataException("Security descriptor components overlap.");
            components[index] = (start, length, sid);
            total = checked(total + ((length + 3) & ~3));
        }
        if (total > MaximumBytes) throw new InvalidDataException("Security descriptor exceeds its component bound.");
        byte[] result = new byte[total];
        bytes[..4].CopyTo(result); // Revision, RM byte and full control flags survive verbatim.
        int position = 20;
        for (int index = 0; index < components.Length; index++)
        {
            var component = components[index];
            if (component.Length == 0) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4 + 4 * index), (uint)position);
            bytes.Slice(component.Offset, component.Length).CopyTo(result.AsSpan(position));
            position += (component.Length + 3) & ~3;
        }
        return result;
    }
}
