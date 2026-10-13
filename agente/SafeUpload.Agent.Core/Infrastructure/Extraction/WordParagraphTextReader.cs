using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>Pulls paragraph text without loading part DOMs or complete text nodes.</summary>
internal sealed class WordParagraphTextReader : TextReader
{
    private const string TransitionalNamespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private const string StrictNamespace = "http://purl.oclc.org/ooxml/wordprocessingml/main";
    private const int MaximumParts = 16_384;
    private const int MaximumDepth = 256;
    private readonly record struct Part(OpenXmlPart Value, string Root, bool BodyRequired = false);
    private sealed class Paragraph(int depth) { public int Depth { get; } = depth; public bool HasText; }
    private readonly WordprocessingDocument _document;
    private readonly List<Part> _parts = [];
    private readonly List<Paragraph> _paragraphs = [];
    private readonly char[] _characters = new char[8192];
    private XmlReader? _xml;
    private readonly TextReader _auxiliary;
    private int _partIndex, _characterOffset, _characterCount, _bodyDepth = -1;
    private int _lookahead = -2;
    private bool _rootSeen, _bodySeen, _value, _newline, _disposed;

    public WordParagraphTextReader(Stream content, CancellationToken token)
    {
        _document = WordprocessingDocument.Open(new BorrowedStream(content), isEditable: false);
        try
        {
            var parts = OpenXmlInspectionGuard.Inspect(_document, content, token);
            _auxiliary = OpenXmlAuxiliaryText.Create(parts, content);
            _ = _document.MainDocumentPart ?? throw new InvalidDataException("The Word package has no main document part.");
            foreach (var part in parts)
            {
                if (part is MainDocumentPart or HeaderPart or FooterPart or FootnotesPart or EndnotesPart or WordprocessingCommentsPart)
                    Add(part, OpenXmlInspectionGuard.Root(part).Root, part is MainDocumentPart);
            }
        }
        catch { _document.Dispose(); throw; }

        void Add(OpenXmlPart part, string root, bool bodyRequired = false)
        {
            token.ThrowIfCancellationRequested();
            if (_parts.Count == MaximumParts) throw new InspectionLimitException();
            _parts.Add(new(part, root, bodyRequired));
        }
    }

    public override ValueTask<int> ReadAsync(Memory<char> buffer, CancellationToken token = default)
        => ValueTask.FromResult(Fill(buffer.Span, token));

    public override int Read(Span<char> buffer) => Fill(buffer, CancellationToken.None);
    public override int Read()
    {
        Span<char> character = stackalloc char[1];
        return Fill(character, CancellationToken.None) == 0 ? -1 : character[0];
    }
    public override int Peek()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_lookahead == -2)
        {
            Span<char> character = stackalloc char[1];
            _lookahead = FillCore(character, CancellationToken.None) == 0 ? -1 : character[0];
        }
        return _lookahead;
    }
    public override int Read(char[] buffer, int index, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        return Fill(buffer.AsSpan(index, count), CancellationToken.None);
    }

    private int Fill(Span<char> buffer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        if (buffer.Length == 0 || _lookahead == -1) return 0;
        if (_lookahead >= 0)
        {
            buffer[0] = (char)_lookahead; _lookahead = -2;
            return 1 + FillCore(buffer[1..], token);
        }
        return FillCore(buffer, token);
    }

    private int FillCore(Span<char> buffer, CancellationToken token)
    {
        int written = 0;
        while (written < buffer.Length)
        {
            token.ThrowIfCancellationRequested();
            if (_characterOffset < _characterCount)
            {
                int count = Math.Min(_characterCount - _characterOffset, buffer.Length - written);
                _characters.AsSpan(_characterOffset, count).CopyTo(buffer[written..]);
                _characterOffset += count; written += count; continue;
            }
            if (_newline) { buffer[written++] = '\n'; _newline = false; continue; }
            if (!Advance(token)) break;
        }
        return written;
    }

    private bool Advance(CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            if (_xml is null)
            {
                if (_partIndex == _parts.Count)
                {
                    _characterOffset = 0;
                    _characterCount = _auxiliary.ReadAsync(_characters.AsMemory(), token).GetAwaiter().GetResult();
                    return _characterCount != 0;
                }
                var stream = _parts[_partIndex].Value.GetStream(FileMode.Open, FileAccess.Read);
                try
                {
                    _xml = XmlReader.Create(stream, new XmlReaderSettings { CloseInput = true,
                        DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreWhitespace = true });
                }
                catch { stream.Dispose(); throw; }
                _rootSeen = _bodySeen = false; _bodyDepth = -1;
            }
            if (_value)
            {
                _characterOffset = 0;
                _characterCount = _xml.ReadValueChunk(_characters, 0, _characters.Length);
                if (_characterCount != 0) { _paragraphs[^1].HasText = true; return true; }
                _value = false;
            }
            if (!_xml.Read())
            {
                if (!_rootSeen || _parts[_partIndex].BodyRequired && !_bodySeen)
                    throw new InvalidDataException("The Word part has no required root or body.");
                _xml.Dispose(); _xml = null; _partIndex++; _paragraphs.Clear(); continue;
            }
            if (_xml.Depth > MaximumDepth) throw new InspectionLimitException();
            bool word = _xml.NamespaceURI is TransitionalNamespace or StrictNamespace;
            if (_xml.NodeType == XmlNodeType.Element)
            {
                if (!_rootSeen)
                {
                    if (_xml.Depth != 0 || !word || _xml.LocalName != _parts[_partIndex].Root)
                        throw new InvalidDataException("The Word part has an invalid root.");
                    _rootSeen = true;
                }
                if (_parts[_partIndex].BodyRequired && word && _xml.LocalName == "body" && _xml.Depth == 1)
                { _bodySeen = true; if (!_xml.IsEmptyElement) _bodyDepth = _xml.Depth; }
                if ((word || OpenXmlAuxiliaryText.NamespaceMatches(_xml.NamespaceURI, OpenXmlInspectionGuard.Drawing)) && _xml.LocalName == "p" && (!_parts[_partIndex].BodyRequired || _bodyDepth >= 0))
                {
                    // Text boxes may contain nested paragraphs. Emit each
                    // paragraph once, separating it from surrounding text.
                    if (_paragraphs.Count != 0 && _paragraphs[^1].HasText)
                    { _newline = true; _paragraphs[^1].HasText = false; }
                    if (!_xml.IsEmptyElement) _paragraphs.Add(new(_xml.Depth));
                    if (_newline) return true;
                }
            }
            else if (_xml.NodeType == XmlNodeType.EndElement)
            {
                if (_paragraphs.Count != 0 && _xml.Depth == _paragraphs[^1].Depth)
                {
                    _newline = _paragraphs[^1].HasText;
                    _paragraphs.RemoveAt(_paragraphs.Count - 1);
                    if (_paragraphs.Count != 0) _paragraphs[^1].HasText = false;
                    if (_newline) return true;
                }
                if (word && _xml.LocalName == "body" && _xml.Depth == _bodyDepth) _bodyDepth = -1;
            }
            else if (_paragraphs.Count != 0 && _xml.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
                _value = true;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            try { _xml?.Dispose(); _auxiliary.Dispose(); }
            finally { _document.Dispose(); }
        }
        base.Dispose(disposing);
    }

    // The package owns this facade, never the held caller snapshot.
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
