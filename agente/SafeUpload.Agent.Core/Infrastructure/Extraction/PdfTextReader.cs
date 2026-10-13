using UglyToad.PdfPig;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>Streams page letters and auxiliary payloads without a document-wide text copy.</summary>
internal sealed class PdfTextReader : TextReader
{
    private readonly PdfDocument _document;
    private readonly ChunkedTextReader _reader;

    public PdfTextReader(Stream content)
    {
        _document = PdfDocument.Open(new BorrowedStream(content), new ParsingOptions
        { UseLenientParsing = false, SkipMissingFonts = false, UseActualText = false, MaxStackDepth = 256 });
        _reader = new ChunkedTextReader(ReadChunks);
    }
    private IEnumerable<ReadOnlyMemory<char>> ReadChunks(Func<CancellationToken> token)
    {
        var auxiliary = new PdfAuxiliaryText(_document);
        for (int number = 1; number <= _document.NumberOfPages; number++)
        {
            token().ThrowIfCancellationRequested();
            // PdfPig still owns page/document allocations; bounded extraction
            // buffers do not establish a worst-case parser memory bound.
            var page = _document.GetPage(number);
            if (page.NumberOfImages != 0) throw new UnsupportedContentException();
            foreach (var letter in page.Letters)
            { token().ThrowIfCancellationRequested(); yield return letter.Value.AsMemory(); }
            yield return Environment.NewLine.AsMemory();
            foreach (var text in auxiliary.ReadPage(page, token)) yield return text;
        }
        foreach (var text in auxiliary.ReadDocument(token)) yield return text;
    }
    public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default) => _reader.ReadAsync(buffer, token);
    public override int Read(Span<char> buffer) => _reader.Read(buffer);
    public override int Read(char[] buffer, int index, int count) => _reader.Read(buffer, index, count);
    public override int Read() => _reader.Read();
    public override int Peek() => _reader.Peek();
    protected override void Dispose(bool disposing)
    {
        if (disposing) { try { _reader.Dispose(); } finally { _document.Dispose(); } }
        base.Dispose(disposing);
    }

    private sealed class BorrowedStream(Stream inner) : Stream
    {
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => inner.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => inner.ReadAsync(buffer, token);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
