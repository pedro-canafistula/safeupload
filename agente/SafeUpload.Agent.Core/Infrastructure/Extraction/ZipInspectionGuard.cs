using System.Buffers.Binary;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

// A strict ZIP admission recognizer, before BCL metadata/decoder allocation.
// PKWARE APPNOTE 6.3.10 record layouts; no filesystem extraction or name routing.
internal static class ZipInspectionGuard
{
    internal sealed record Entry(string Name, byte[] RawName, ushort Flags, ushort Method, ushort Version,
        ushort Time, ushort Date, uint Crc, uint CompressedLength, uint Length, uint LocalOffset, bool Directory)
    {
        internal long DataOffset;
    }
    private static readonly uint[] CrcTable = MakeCrcTable();

    internal static IReadOnlyList<Entry> Inspect(Stream source, ArchiveInspectionBudget budget, int depth, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!source.CanRead || !source.CanSeek) throw new InvalidDataException("A ZIP requires a held seekable source.");
        budget.CheckSize(source.Length);
        if (source.Length < 22) throw new InvalidDataException("The ZIP has no end record.");
        long end = source.Length - 22;
        byte[] eocd = ReadAt(source, end, 22, token);
        if (U32(eocd, 0) != 0x06054b50)
        {
            // A possible archive comment is refused, never treated as a clean
            // suffix. Other missing/truncated end records are parse failures.
            int length = (int)Math.Min(source.Length, 65_557);
            byte[] tail = ReadAt(source, source.Length - length, length, token);
            for (int i = length - 22; i >= 0; i--)
                if (U32(tail, i) == 0x06054b50 && i + 22 + U16(tail, i + 20) == length)
                    throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            throw new InvalidDataException("The ZIP end record is invalid.");
        }
        if (U16(eocd, 20) != 0 || U16(eocd, 4) != 0 || U16(eocd, 6) != 0 || U16(eocd, 8) != U16(eocd, 10))
            throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
        int count = U16(eocd, 10);
        long centralSize = U32(eocd, 12), central = U32(eocd, 16);
        if (count == ushort.MaxValue || centralSize == uint.MaxValue || central == uint.MaxValue)
            throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure); // ZIP64/multi-disk are not admitted.
        budget.Enter(depth, count);
        if (central + centralSize != end) throw new InvalidDataException("The ZIP central extent is invalid.");
        var entries = new List<Entry>(count);
        var names = new HashSet<string>(StringComparer.Ordinal);
        long cursor = central, expanded = 0;
        for (int i = 0; i < count; i++)
        {
            token.ThrowIfCancellationRequested();
            RequireExtent(cursor, 46, end);
            byte[] header = ReadAt(source, cursor, 46, token);
            if (U32(header, 0) != 0x02014b50) throw new InvalidDataException("The ZIP central header is invalid.");
            ushort version = U16(header, 6), flags = U16(header, 8), method = U16(header, 10);
            if ((flags & (1 | 0x40 | 0x2000)) != 0) throw new ArchiveRefusalException(ArchiveRefusal.Encrypted);
            if (version is not (10 or 20) || method is not (0 or 8) || (flags & ~(0x800 | 8 | 6)) != 0 ||
                method == 0 && (flags & 6) != 0 || (flags & 8) != 0 && version != 20)
                throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            uint compressed = U32(header, 20), length = U32(header, 24), offset = U32(header, 42);
            if (compressed == uint.MaxValue || length == uint.MaxValue || offset == uint.MaxValue || U16(header, 34) != 0)
                throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            int nameSize = U16(header, 28), extraSize = U16(header, 30), commentSize = U16(header, 32);
            if (nameSize == 0 || commentSize != 0) throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            RequireExtent(cursor + 46, nameSize + extraSize + commentSize, end);
            byte[] nameBytes = ReadAt(source, cursor + 46, nameSize, token);
            if ((flags & 0x800) == 0 && nameBytes.Any(value => value >= 128))
                throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            string name = new UTF8Encoding(false, true).GetString(nameBytes);
            if (!names.Add(name)) throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            bool directory = name.EndsWith("/", StringComparison.Ordinal);
            uint attributes = U32(header, 38), kind = attributes >> 16 & 0xf000;
            if (kind is not (0 or 0x8000 or 0x4000) || (attributes & 0x400) != 0 ||
                kind == 0x4000 && !directory || (attributes & 0x10) != 0 && !directory || directory && length != 0)
                throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            ValidateExtra(ReadAt(source, cursor + 46 + nameSize, extraSize, token), central: true);
            if (method == 0 && compressed != length) throw new InvalidDataException("Stored ZIP lengths disagree.");
            if (length > (long)compressed * ArchiveInspectionBudget.MaximumRatio)
                throw new SafeUpload.Agent.Core.Domain.InspectionLimitException();
            expanded += length; budget.CheckExpansion(expanded);
            entries.Add(new(name, nameBytes, flags, method, version, U16(header, 12), U16(header, 14),
                U32(header, 16), compressed, length, offset, directory));
            cursor += 46L + nameSize + extraSize + commentSize;
        }
        if (cursor != end) throw new InvalidDataException("The ZIP central inventory is incomplete.");

        cursor = 0;
        foreach (var entry in entries.OrderBy(entry => entry.LocalOffset))
        {
            token.ThrowIfCancellationRequested();
            if (entry.LocalOffset != cursor) throw new InvalidDataException("The ZIP has hidden or overlapping records.");
            RequireExtent(cursor, 30, central);
            byte[] header = ReadAt(source, cursor, 30, token);
            if (U32(header, 0) != 0x04034b50 || U16(header, 4) != entry.Version || U16(header, 6) != entry.Flags ||
                U16(header, 8) != entry.Method || U16(header, 10) != entry.Time || U16(header, 12) != entry.Date)
                throw new InvalidDataException("The ZIP local header disagrees.");
            bool descriptor = (entry.Flags & 8) != 0;
            bool Match(uint local, uint expected) => local == expected || descriptor && local == 0;
            if (!Match(U32(header, 14), entry.Crc) || !Match(U32(header, 18), entry.CompressedLength) || !Match(U32(header, 22), entry.Length))
                throw new InvalidDataException("The ZIP local lengths or checksum disagree.");
            int nameSize = U16(header, 26), extraSize = U16(header, 28);
            RequireExtent(cursor + 30, nameSize + extraSize, central);
            if (!ReadAt(source, cursor + 30, nameSize, token).AsSpan().SequenceEqual(entry.RawName))
                throw new InvalidDataException("The ZIP local name disagrees.");
            ValidateExtra(ReadAt(source, cursor + 30 + nameSize, extraSize, token), central: false);
            entry.DataOffset = cursor + 30 + nameSize + extraSize;
            RequireExtent(entry.DataOffset, entry.CompressedLength, central);
            cursor = entry.DataOffset + entry.CompressedLength;
            if (descriptor)
            {
                RequireExtent(cursor, 12, central);
                bool signature = U32(ReadAt(source, cursor, 4, token), 0) == 0x08074b50;
                int size = signature ? 16 : 12, shift = signature ? 4 : 0;
                RequireExtent(cursor, size, central);
                byte[] data = ReadAt(source, cursor, size, token);
                if (U32(data, shift) != entry.Crc || U32(data, shift + 4) != entry.CompressedLength || U32(data, shift + 8) != entry.Length)
                    throw new InvalidDataException("The ZIP descriptor disagrees.");
                cursor += size;
            }
        }
        if (cursor != central) throw new InvalidDataException("The ZIP local inventory is incomplete.");
        return entries;
    }

    internal static byte[] ReadMember(Stream source, Entry entry, ArchiveInspectionBudget budget, CancellationToken token)
    {
        budget.CheckExpansion(entry.Length);
        if (entry.Length > Array.MaxLength) throw new ArchiveSizeException();
        byte[] bytes = new byte[(int)entry.Length];
        try
        {
            using var encoded = new EncodedStream(source, entry.DataOffset, entry.CompressedLength, entry.Method == 8, token);
            using Stream decoded = entry.Method == 8 ? new DeflateStream(encoded, CompressionMode.Decompress, leaveOpen: true) : encoded;
            int position = 0;
            while (position < bytes.Length)
            {
                token.ThrowIfCancellationRequested();
                int count = decoded.Read(bytes.AsSpan(position, Math.Min(8192, bytes.Length - position)));
                if (count == 0) throw new InvalidDataException("A ZIP member ended early.");
                budget.Charge(count); position += count;
            }
            // A nonempty read must observe the final DEFLATE marker. A physical
            // EOF throws in EncodedStream; truncated streams cannot return 0.
            Span<byte> extra = stackalloc byte[1];
            if (decoded.Read(extra) != 0) { budget.Charge(1); throw new InvalidDataException("A ZIP member exceeds its declared length."); }
            if (encoded.Position != entry.CompressedLength || Crc32(bytes, token) != entry.Crc)
                throw new InvalidDataException("ZIP consumption or checksum is incomplete.");
            return bytes;
        }
        catch { CryptographicOperations.ZeroMemory(bytes); throw; }
    }

    private static void ValidateExtra(byte[] bytes, bool central)
    {
        var seen = new HashSet<ushort>();
        int offset = 0;
        while (offset < bytes.Length)
        {
            if (bytes.Length - offset < 4) throw new InvalidDataException("The ZIP extra field is truncated.");
            ushort id = U16(bytes, offset), size = U16(bytes, offset + 2);
            offset += 4;
            if (size > bytes.Length - offset) throw new InvalidDataException("The ZIP extra extent is invalid.");
            if (!seen.Add(id)) throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            if (id == 0x5455 && size >= 1) // Extended timestamps, fixed-width numbers only.
            {
                byte flags = bytes[offset];
                int expected = 1 + 4 * (central ? (flags & 1) : BitOperations.PopCount((uint)flags));
                if ((flags & ~7) != 0 || size != expected) throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            }
            else if (id == 0x000a && size == 32) // NTFS time triplet.
            {
                if (U32(bytes, offset) != 0 || U16(bytes, offset + 4) != 1 || U16(bytes, offset + 6) != 24)
                    throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            }
            else throw new ArchiveRefusalException(ArchiveRefusal.UnsupportedStructure);
            offset += size;
        }
    }

    private static void RequireExtent(long start, long size, long end)
    {
        if (start < 0 || size < 0 || start > end || size > end - start) throw new InvalidDataException("A ZIP extent is invalid.");
    }
    private static byte[] ReadAt(Stream source, long position, int count, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); source.Position = position;
        var bytes = new byte[count]; source.ReadExactly(bytes); return bytes;
    }
    private static ushort U16(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset, 2));
    private static uint U32(byte[] bytes, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
    private static uint Crc32(byte[] bytes, CancellationToken token)
    {
        uint crc = uint.MaxValue;
        for (int i = 0; i < bytes.Length; i++)
        {
            if ((i & 8191) == 0) token.ThrowIfCancellationRequested();
            crc = CrcTable[(crc ^ bytes[i]) & 255] ^ crc >> 8;
        }
        return ~crc;
    }
    private static uint[] MakeCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < table.Length; i++)
        {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? crc >> 1 ^ 0xedb88320 : crc >> 1;
            table[i] = crc;
        }
        return table;
    }

    private sealed class EncodedStream(Stream source, long start, long length, bool strictDeflate, CancellationToken token) : Stream
    {
        private long _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            token.ThrowIfCancellationRequested();
            if (buffer.IsEmpty) return 0;
            if (_position == length)
            {
                if (strictDeflate) throw new InvalidDataException("The ZIP deflate marker is missing.");
                return 0;
            }
            int count = (int)Math.Min(strictDeflate ? 1 : buffer.Length, length - _position);
            source.Position = start + _position;
            int read = source.Read(buffer[..count]);
            if (read == 0) throw new EndOfStreamException();
            _position += read; return read;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
