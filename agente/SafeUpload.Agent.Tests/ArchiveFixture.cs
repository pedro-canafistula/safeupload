using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace SafeUpload.Agent.Tests;

// Independent ZIP records/CRC, not the product guard or a ZIP SDK writer.
internal static class ArchiveFixture
{
    internal sealed record Item(string Name, byte[] Data)
    {
        internal ushort Method { get; init; }
        internal ushort Flags { get; init; } = 0x800;
        internal byte[]? Encoded { get; init; }
        internal uint? Length { get; init; }
        internal uint? Crc { get; init; }
        internal byte[] Extra { get; init; } = [];
        internal byte[] Comment { get; init; } = [];
        internal uint Attributes { get; init; } = 0x81a40000;
        internal bool Descriptor { get; init; }
        internal bool DescriptorSignature { get; init; } = true;
    }
    internal static Item Text(string name, string text) => new(name, Encoding.UTF8.GetBytes(text));
    internal static byte[] Zip(params Item[] items)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        var central = new List<(Item Item, byte[] Name, byte[] Encoded, uint Offset, uint Crc, uint Length, ushort Flags, ushort Version)>();
        foreach (var item in items)
        {
            byte[] name = Encoding.UTF8.GetBytes(item.Name);
            byte[] encoded = item.Encoded ?? (item.Method == 8 ? Deflate(item.Data) : item.Data);
            uint crc = item.Crc ?? Crc32(item.Data), length = item.Length ?? (uint)item.Data.Length;
            uint offset = (uint)stream.Position;
            ushort flags = (ushort)(item.Flags | (item.Descriptor ? 8 : 0));
            ushort version = (ushort)(item.Method == 8 || item.Descriptor ? 20 : 10);
            writer.Write(0x04034b50u); writer.Write(version); writer.Write(flags); writer.Write(item.Method);
            writer.Write((ushort)0); writer.Write((ushort)0);
            writer.Write(item.Descriptor ? 0u : crc); writer.Write(item.Descriptor ? 0u : (uint)encoded.Length); writer.Write(item.Descriptor ? 0u : length);
            writer.Write((ushort)name.Length); writer.Write((ushort)item.Extra.Length); writer.Write(name); writer.Write(item.Extra); writer.Write(encoded);
            if (item.Descriptor)
            {
                if (item.DescriptorSignature) writer.Write(0x08074b50u);
                writer.Write(crc); writer.Write((uint)encoded.Length); writer.Write(length);
            }
            central.Add((item, name, encoded, offset, crc, length, flags, version));
        }
        uint start = (uint)stream.Position;
        foreach (var entry in central)
        {
            writer.Write(0x02014b50u); writer.Write((ushort)0x0314); writer.Write(entry.Version); writer.Write(entry.Flags); writer.Write(entry.Item.Method);
            writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(entry.Crc); writer.Write((uint)entry.Encoded.Length); writer.Write(entry.Length);
            writer.Write((ushort)entry.Name.Length); writer.Write((ushort)entry.Item.Extra.Length); writer.Write((ushort)entry.Item.Comment.Length);
            writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(entry.Item.Attributes); writer.Write(entry.Offset);
            writer.Write(entry.Name); writer.Write(entry.Item.Extra); writer.Write(entry.Item.Comment);
        }
        uint size = (uint)stream.Position - start;
        writer.Write(0x06054b50u); writer.Write((ushort)0); writer.Write((ushort)0); writer.Write((ushort)items.Length); writer.Write((ushort)items.Length);
        writer.Write(size); writer.Write(start); writer.Write((ushort)0);
        return stream.ToArray();
    }
    internal static byte[] Deflate(byte[] data)
    {
        if (data.Length == 0) return [3, 0]; // A final fixed block with only end-of-block, RFC 1951.
        using var stream = new MemoryStream();
        using (var deflate = new DeflateStream(stream, CompressionLevel.SmallestSize, leaveOpen: true)) deflate.Write(data);
        return stream.ToArray();
    }
    internal static uint Crc32(byte[] data)
    {
        uint crc = uint.MaxValue;
        foreach (byte value in data)
        {
            crc ^= value;
            for (int i = 0; i < 8; i++) crc = (crc & 1) == 0 ? crc >> 1 : crc >> 1 ^ 0xedb88320;
        }
        return ~crc;
    }
    internal static int Central(byte[] data) => (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(data.Length - 6, 4));
    internal static void U16(byte[] bytes, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset, 2), value);
    internal static void U32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), value);
    internal static byte[] Letters(int count)
    {
        var bytes = new byte[count]; uint state = 2463534242;
        for (int i = 0; i < count; i++) { state ^= state << 13; state ^= state >> 17; state ^= state << 5; bytes[i] = (byte)('a' + state % 26); }
        return bytes;
    }
}
