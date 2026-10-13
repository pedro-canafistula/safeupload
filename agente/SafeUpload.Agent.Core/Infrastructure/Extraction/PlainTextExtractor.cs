using System.Text;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>
/// Extrator de arquivos de texto puro: <c>.txt</c> e <c>.csv</c>.
///
/// O CSV é lido literalmente, sem interpretar delimitadores. Para a varredura
/// isso é o que se quer: vírgula e ponto-e-vírgula não são separadores válidos
/// dentro de um número, então células vizinhas não se colam por acidente.
/// </summary>
public sealed class PlainTextExtractor : IStreamingTextExtractor
{
    /// <inheritdoc />
    public IReadOnlySet<string> SupportedExtensions { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt", ".csv" };

    /// <inheritdoc />
    public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
    {
        using var reader = await OpenReaderAsync(content, cancellationToken).ConfigureAwait(false);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<TextReader> OpenReaderAsync(Stream content, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);

        // StreamReader's automatic BOM switch uses permissive decoders for
        // UTF-16/32, even when its initial UTF-8 encoding is strict. Select
        // every supported BOM ourselves so malformed input is a parse error,
        // never an approval based on silently replaced content.
        var header = new byte[4];
        int length = 0;
        while (length < header.Length)
        {
            int read = await content.ReadAsync(header.AsMemory(length), cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            length += read;
        }
        var encoding = DetectEncoding(header.AsSpan(0, length), out int bomLength);
        var prefixed = new PrefixReadStream(content, header.AsMemory(bomLength, length - bomLength));
        return new StreamReader(
            prefixed,
            encoding,
            detectEncodingFromByteOrderMarks: false,
            leaveOpen: false); // Disposes the prefix wrapper, never the caller's stream.
    }

    private static Encoding DetectEncoding(ReadOnlySpan<byte> header, out int bomLength)
    {
        // UTF-32 LE starts with the UTF-16 LE marker; test the longer BOM first.
        if (header.StartsWith<byte>([0xFF, 0xFE, 0x00, 0x00]))
        {
            bomLength = 4;
            return new UTF32Encoding(bigEndian: false, byteOrderMark: false, throwOnInvalidCharacters: true);
        }
        if (header.StartsWith<byte>([0x00, 0x00, 0xFE, 0xFF]))
        {
            bomLength = 4;
            return new UTF32Encoding(bigEndian: true, byteOrderMark: false, throwOnInvalidCharacters: true);
        }
        if (header.StartsWith<byte>([0xEF, 0xBB, 0xBF]))
        {
            bomLength = 3;
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
        }
        if (header.StartsWith<byte>([0xFF, 0xFE]))
        {
            bomLength = 2;
            return new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true);
        }
        if (header.StartsWith<byte>([0xFE, 0xFF]))
        {
            bomLength = 2;
            return new UnicodeEncoding(bigEndian: true, byteOrderMark: false, throwOnInvalidBytes: true);
        }
        bomLength = 0;
        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    }

    // Preserve bytes following a BOM (and the whole header without one).
    // No seek is needed, and disposing the reader never closes its caller's stream.
    private sealed class PrefixReadStream(Stream content, ReadOnlyMemory<byte> prefix) : Stream
    {
        private ReadOnlyMemory<byte> _prefix = prefix;
        public override bool CanRead => content.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (_prefix.IsEmpty) return content.Read(buffer);
            int count = Math.Min(buffer.Length, _prefix.Length);
            _prefix.Span[..count].CopyTo(buffer);
            _prefix = _prefix[count..];
            return count;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            token.ThrowIfCancellationRequested();
            return _prefix.IsEmpty ? content.ReadAsync(buffer, token) : ValueTask.FromResult(Read(buffer.Span));
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
