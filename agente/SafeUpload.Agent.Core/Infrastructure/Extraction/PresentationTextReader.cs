using DocumentFormat.OpenXml.Packaging;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

// All presentation text is DrawingML or auxiliary XML. The shared reader reads
// every admitted part to EOF, preserves rich paragraph runs and separates scalar
// values/attributes, without constructing part DOMs or complete XML values.
internal sealed class PresentationTextReader : TextReader
{
    private readonly PresentationDocument _document;
    private readonly TextReader _text;
    private bool _disposed;

    public PresentationTextReader(Stream content, CancellationToken token)
    {
        OpenXmlInspectionGuard.PreflightPartCount(content, token);
        _document = PresentationDocument.Open(new BorrowedStream(content), isEditable: false);
        try
        {
            var parts = OpenXmlInspectionGuard.Inspect(_document, content, token);
            _ = _document.PresentationPart ?? throw new InvalidDataException("The presentation has no main part.");
            _text = OpenXmlAuxiliaryText.Create(parts, content);
        }
        catch { _document.Dispose(); throw; }
    }

    public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        => _text.ReadAsync(buffer, token);
    public override int Read(Span<char> buffer) => _text.Read(buffer);
    public override int Read(char[] buffer, int index, int count) => _text.Read(buffer, index, count);
    public override int Read() => _text.Read();
    public override int Peek() => _text.Peek();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            try { _text.Dispose(); }
            finally { _document.Dispose(); }
        }
        base.Dispose(disposing);
    }

    // Package disposal never owns the caller's held snapshot.
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
