using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>Consumes page letters in content order without Page.Text or a document-wide string.</summary>
internal sealed class PdfTextReader : TextReader
{
    private readonly PdfDocument _document;
    private Page? _page;
    private int _pageNumber = 1, _letter, _letterOffset, _newlineOffset, _lookahead = -2;
    private bool _disposed;

    public PdfTextReader(Stream content) => _document = PdfDocument.Open(new BorrowedStream(content));

    public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default) =>
        ValueTask.FromResult(Fill(buffer.Span, token));
    public override int Read(Span<char> buffer) => Fill(buffer, CancellationToken.None);
    public override int Read(char[] buffer, int index, int count)
    { ArgumentNullException.ThrowIfNull(buffer); return Fill(buffer.AsSpan(index, count), CancellationToken.None); }
    public override int Read()
    { Span<char> one = stackalloc char[1]; return Fill(one, CancellationToken.None) == 0 ? -1 : one[0]; }
    public override int Peek()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_lookahead == -2)
        { Span<char> one = stackalloc char[1]; _lookahead = FillCore(one, CancellationToken.None) == 0 ? -1 : one[0]; }
        return _lookahead;
    }
    private int Fill(Span<char> buffer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); token.ThrowIfCancellationRequested();
        if (buffer.IsEmpty || _lookahead == -1) return 0;
        if (_lookahead < 0) return FillCore(buffer, token);
        buffer[0] = (char)_lookahead; _lookahead = -2;
        return 1 + FillCore(buffer[1..], token);
    }
    private int FillCore(Span<char> buffer, CancellationToken token)
    {
        int written = 0;
        while (written < buffer.Length)
        {
            token.ThrowIfCancellationRequested();
            if (_page is null)
            {
                if (_pageNumber > _document.NumberOfPages) break;
                // The parser still owns page/document metadata allocations.
                // This reader removes extracted-text copies; it does not
                // claim a worst-case parser memory bound.
                _page = _document.GetPage(_pageNumber++);
                if (_page.NumberOfImages != 0) throw new UnsupportedContentException();
                _letter = _letterOffset = _newlineOffset = 0;
            }
            if (_letter < _page.Letters.Count)
            {
                string value = _page.Letters[_letter].Value;
                int count = Math.Min(value.Length - _letterOffset, buffer.Length - written);
                value.AsSpan(_letterOffset, count).CopyTo(buffer[written..]);
                written += count; _letterOffset += count;
                if (_letterOffset == value.Length) { _letter++; _letterOffset = 0; }
            }
            else
            {
                string newline = Environment.NewLine;
                int count = Math.Min(newline.Length - _newlineOffset, buffer.Length - written);
                newline.AsSpan(_newlineOffset, count).CopyTo(buffer[written..]);
                written += count; _newlineOffset += count;
                if (_newlineOffset == newline.Length) _page = null;
            }
        }
        return written;
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed) { _disposed = true; _page = null; _document.Dispose(); }
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
