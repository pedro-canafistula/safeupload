using System.Globalization;
using System.Text;
using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

/// <summary>Streams stored spreadsheet text once; cell references are validated, not materialized.</summary>
internal sealed class SpreadsheetTextReader : TextReader
{
    private const string TransitionalNamespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private const string StrictNamespace = "http://purl.oclc.org/ooxml/spreadsheetml/main";
    private enum Kind { Workbook, SharedStrings, Worksheet, Comments }
    private readonly record struct Part(OpenXmlPart Value, string Root, Kind Kind);
    private readonly SpreadsheetDocument _document;
    private readonly List<Part> _parts = [];
    private readonly char[] _characters = new char[8192];
    private readonly StringBuilder _reference = new(32);
    private XmlReader? _xml;
    private readonly TextReader _auxiliary;
    private int _partIndex, _offset, _count, _lookahead = -2, _textDepth = -1, _cellDepth = -1;
    private int _sharedCount;
    private string _cellType = "";
    private bool _rootSeen, _value, _newline, _captureReference, _disposed;
    private bool _formula, _cached, _inline, _referenceSeen;

    public SpreadsheetTextReader(Stream content, CancellationToken token)
    {
        OpenXmlInspectionGuard.PreflightPartCount(content, token);
        _document = SpreadsheetDocument.Open(new BorrowedStream(content), isEditable: false);
        try
        {
            var parts = OpenXmlInspectionGuard.Inspect(_document, content, token);
            _auxiliary = OpenXmlAuxiliaryText.Create(parts, content);
            var workbook = _document.WorkbookPart ?? throw new InvalidDataException("The spreadsheet has no workbook part.");
            if (parts.OfType<WorkbookPart>().Count() != 1) throw new UnsupportedContentException();
            Add(workbook, "workbook", Kind.Workbook);
            foreach (var table in parts.OfType<SharedStringTablePart>()) Add(table, "sst", Kind.SharedStrings);
            foreach (var sheet in parts.OfType<WorksheetPart>()) Add(sheet, "worksheet", Kind.Worksheet);
            foreach (var comments in parts.OfType<WorksheetCommentsPart>()) Add(comments, "comments", Kind.Comments);
        }
        catch { _document.Dispose(); throw; }

        void Add(OpenXmlPart part, string root, Kind kind)
        {
            token.ThrowIfCancellationRequested();
            if (_parts.Count == 16_384) throw new InspectionLimitException();
            _parts.Add(new(part, root, kind));
        }
    }

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
            if (_offset < _count)
            {
                int copy = Math.Min(_count - _offset, buffer.Length - written);
                _characters.AsSpan(_offset, copy).CopyTo(buffer[written..]);
                written += copy; _offset += copy; continue;
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
                    _offset = 0; _count = _auxiliary.ReadAsync(_characters.AsMemory(), token).GetAwaiter().GetResult();
                    return _count != 0;
                }
                var stream = _parts[_partIndex].Value.GetStream(FileMode.Open, FileAccess.Read);
                try { _xml = XmlReader.Create(stream, new XmlReaderSettings { CloseInput = true,
                    DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, IgnoreWhitespace = true }); }
                catch { stream.Dispose(); throw; }
                _rootSeen = false;
            }
            if (_value)
            {
                _offset = 0; _count = _xml.ReadValueChunk(_characters, 0, _characters.Length);
                if (_count != 0)
                {
                    if (!_captureReference) return true;
                    if (_reference.Length + _count > 32) throw new InvalidDataException("The shared-string reference is invalid.");
                    _reference.Append(_characters, 0, _count); _count = 0; continue;
                }
                _value = false;
            }
            if (!_xml.Read())
            {
                if (!_rootSeen) throw new InvalidDataException("The spreadsheet part has no root.");
                _xml.Dispose(); _xml = null; _partIndex++; continue;
            }
            if (_xml.Depth > 256) throw new InspectionLimitException();
            bool sheet = _xml.NamespaceURI is TransitionalNamespace or StrictNamespace;
            if (_xml.NodeType == XmlNodeType.Element)
            {
                if (!_rootSeen)
                {
                    if (_xml.Depth != 0 || !sheet || _xml.LocalName != _parts[_partIndex].Root)
                        throw new InvalidDataException("The spreadsheet part has an invalid root.");
                    _rootSeen = true;
                }
                if (!sheet) continue;
                Kind kind = _parts[_partIndex].Kind;
                string name = _xml.LocalName;
                if (kind == Kind.Worksheet && name == "c")
                {
                    if (_cellDepth >= 0) throw new InvalidDataException("Spreadsheet cells cannot be nested.");
                    _cellDepth = _xml.Depth; _cellType = _xml.GetAttribute("t") ?? "";
                    if (_cellType is not ("" or "b" or "d" or "e" or "n" or "s" or "str" or "inlineStr"))
                        throw new InvalidDataException("The cell type is invalid.");
                    _formula = _cached = _inline = _referenceSeen = false;
                    if (_xml.IsEmptyElement) FinishCell();
                }
                bool text = kind == Kind.SharedStrings && name == "si" && _xml.Depth == 1 ||
                    kind == Kind.Workbook && name == "definedName" ||
                    kind == Kind.Comments && name is ("author" or "text") ||
                    kind == Kind.Worksheet && _cellDepth >= 0 && _xml.Depth == _cellDepth + 1 && name is ("f" or "v" or "is");
                if (!text) continue;
                if (_textDepth >= 0) throw new InvalidDataException("The spreadsheet text containers are nested.");
                if (kind == Kind.SharedStrings) _sharedCount = checked(_sharedCount + 1);
                _captureReference = kind == Kind.Worksheet && name == "v" && _cellType == "s";
                if (kind == Kind.Worksheet)
                {
                    if (name == "f") _formula = true;
                    if (name == "v") _cached = true;
                    if (name == "is") _inline = true;
                }
                if (_captureReference) _reference.Clear();
                _textDepth = _xml.Depth;
                if (_xml.IsEmptyElement)
                {
                    FinishText();
                    if (_newline) return true;
                }
            }
            else if (_xml.NodeType == XmlNodeType.EndElement)
            {
                if (_xml.Depth == _textDepth)
                { FinishText(); if (_newline) return true; }
                if (_xml.Depth == _cellDepth) FinishCell();
            }
            else if (_textDepth >= 0 && _xml.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
                _value = true;
        }
    }

    private void FinishText()
    {
        if (_captureReference)
        {
            if (!int.TryParse(_reference.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int index) ||
                index < 0 || index >= _sharedCount)
                throw new InvalidDataException("The cell has an invalid shared-string reference.");
            _referenceSeen = true;
        }
        else _newline = true;
        _captureReference = false; _textDepth = -1;
    }
    private void FinishCell()
    {
        if (_formula && !_cached) throw new UnsupportedContentException();
        if (_cellType == "s" && !_referenceSeen || _cellType == "inlineStr" && !_inline)
            throw new InvalidDataException("The cell has no required value.");
        _cellDepth = -1;
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        { _disposed = true; try { _xml?.Dispose(); _auxiliary.Dispose(); } finally { _document.Dispose(); } }
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
