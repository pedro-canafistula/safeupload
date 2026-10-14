using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SafeUpload.Agent.Minifilter;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

// Synthetic qualified construction for component controls ONLY. The kernel
// intentionally cannot emit these complete flags in increment 3.
internal static class WriterMetadataFixture
{
    internal static StagedAllocationSecuritySnapshot Current(StagedAllocationBindingV23 binding,
        byte[]? construction = null, byte[]? stored = null)
    {
        using var process = Process.GetCurrentProcess(); using var user = WindowsIdentity.GetCurrent();
        return Security(binding, process.Id, (uint)process.SessionId, process.StartTime.ToFileTimeUtc(), user.User!.Value,
            construction, stored);
    }

    internal static StagedAllocationSecuritySnapshot Security(StagedAllocationBindingV23 binding,
        int process = 42, uint session = 7, long creation = 123456, string sid = "S-1-5-21-111-222-333-1000",
        byte[]? construction = null, byte[]? stored = null) =>
        StagedAllocationSecuritySnapshot.FromWriterMetadata(WriterMetadataV27.DecodeEnvelope(
            Envelope(binding, process, session, creation, sid, construction, stored)));

    internal static byte[] Envelope(StagedAllocationBindingV23 binding, int process = 42, uint session = 7,
        long creation = 123456, string sid = "S-1-5-21-111-222-333-1000", byte[]? construction = null, byte[]? stored = null)
    {
        construction ??= SecuritySnapshotFixture.Descriptor(); stored ??= construction;
        byte[] b = new byte[1024 + construction.Length + stored.Length];
        Put32(b, 0, 1); Put32(b, 4, 1024); Put32(b, 8, 23); Put32(b, 12, 124);
        binding.ReservationId.TryWriteBytes(b.AsSpan(16)); binding.ParentTransferId.TryWriteBytes(b.AsSpan(32));
        Put32(b, 48, binding.Disposition); Put32(b, 52, binding.ReferenceKind);
        if (binding.PublicTarget is { } target) { Put64(b, 56, target.FileIdLow); Put64(b, 64, target.FileIdHigh); }
        binding.MountManagerVolumeId.TryWriteBytes(b.AsSpan(72));
        Put64(b, 88, binding.VolumeRoot.FileIdLow); Put64(b, 96, binding.VolumeRoot.FileIdHigh);
        Put64(b, 104, binding.Parent.VolumeSerialNumber); Put64(b, 112, binding.Parent.FileIdLow); Put64(b, 120, binding.Parent.FileIdHigh);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(128), binding.ParentCaseSensitive ? (ushort)1 : (ushort)0);
        byte[] leaf = Encoding.Unicode.GetBytes(binding.CanonicalLeaf);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(130), (ushort)leaf.Length); leaf.CopyTo(b, 132);
        Put32(b, 644, (uint)process); Put32(b, 648, session); Put64(b, 652, (ulong)creation);
        var identity = new SecurityIdentifier(sid); Put32(b, 660, (uint)identity.BinaryLength); identity.GetBinaryForm(b, 664);
        var subject = new SecurityIdentifier("S-1-5-21-111-222-333-2000");
        Put32(b, 732, (uint)subject.BinaryLength); subject.GetBinaryForm(b, 736);
        Put32(b, 804, 2); Put32(b, 808, 2); Put32(b, 820, 2); Put32(b, 824, 2);
        Put32(b, 828, binding.Disposition << 24); Put32(b, 844, 1); Put32(b, 848, 1);
        Put32(b, 860, 2); SHA256.HashData("complete synthetic ancestor tuple"u8).CopyTo(b, 864);
        Put32(b, 896, 1); Put32(b, 900, 0x10000); Put32(b, 904, (uint)construction.Length); Put32(b, 908, (uint)stored.Length);
        Put32(b, 912, binding.Disposition is 1 or 3 ? binding.ReferenceKind == 1 ? 2u : binding.PublicTarget is null ? 0u : 1u : 0u);
        Put32(b, 924, 0xC00000BB); Put32(b, 928, 0xC00000BB);
        binding.ReservationId.TryWriteBytes(b.AsSpan(932));
        construction.CopyTo(b, 1024); stored.CopyTo(b, 1024 + construction.Length);
        byte[] result = new byte[136 + b.Length];
        Put32(result, 0, 27); Put32(result, 4, 4232); Put32(result, 8, 1); Put32(result, 12, 1);
        binding.DriverInstanceId.TryWriteBytes(result.AsSpan(16)); binding.ReservationId.TryWriteBytes(result.AsSpan(32));
        Put64(result, 48, 17); Put64(result, 56, 19); Put64(result, 64, 23);
        binding.ReservationId.TryWriteBytes(result.AsSpan(72)); // deterministic exact fixture replay
        Put32(result, 92, (uint)b.Length); Put32(result, 100, 31); SHA256.HashData(b).CopyTo(result, 104); b.CopyTo(result, 136);
        return result;
    }

    internal static byte[] Page(byte[] envelope, byte[] request)
    {
        uint phase = U32(request, 20), offset = U32(request, 96);
        byte[] result = new byte[4232]; envelope.AsSpan(0, 136).CopyTo(result);
        Put32(result, 8, phase); Put32(result, 88, offset);
        if (phase == 2)
        {
            int count = Math.Min(4096, envelope.Length - 136 - (int)offset);
            Put32(result, 96, (uint)count); envelope.AsSpan(136 + (int)offset, count).CopyTo(result.AsSpan(136));
        }
        return result;
    }
    internal static uint U32(byte[] b, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(offset));
    internal static void Put32(byte[] b, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset), value);
    internal static void Put64(byte[] b, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(offset), value);
}
