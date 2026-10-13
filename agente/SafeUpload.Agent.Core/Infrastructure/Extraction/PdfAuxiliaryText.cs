using System.Globalization;
using System.Xml;
using SafeUpload.Agent.Core.Domain;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;
using UglyToad.PdfPig.Tokens;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

// Read stored strings directly, without the convenience APIs that can omit
// malformed entries. All new graph walks are depth/count limited and cancellable.
internal sealed class PdfAuxiliaryText(PdfDocument document)
{
    internal const int MaximumAnnotations = 4096;
    internal const int MaximumFields = 4096;
    internal const int MaximumBookmarks = 4096;
    private const int MaximumObjects = 65_536;
    private const int MaximumDepth = 64;
    private enum Kind { Other, Field, Bookmark }
    private int _annotations, _fields, _bookmarks, _objects;
    private readonly HashSet<DictionaryToken> _active = new(ReferenceEqualityComparer.Instance);

    internal IEnumerable<ReadOnlyMemory<char>> ReadPage(Page page, Func<CancellationToken> token)
    {
        RefusePayloads(page.Dictionary, token);
        if (Get(page.Dictionary, "Annots") is { } annotations)
        {
            if (Resolve(annotations, token) is not ArrayToken array) throw new InvalidDataException("The PDF annotations are not an array.");
            foreach (var item in array.Data)
            {
                token().ThrowIfCancellationRequested();
                if (++_annotations > MaximumAnnotations) throw new InspectionLimitException();
                if (Resolve(item, token) is not DictionaryToken annotation) throw new InvalidDataException("The PDF annotation is not a dictionary.");
                foreach (var text in ReadObject(annotation, Kind.Other, 0, token)) yield return text;
                if (Get(annotation, "Subtype") is { } subtype && IsName(Resolve(subtype, token), "Widget"))
                    foreach (var text in ReadFieldParents(annotation, token)) yield return text;
            }
        }
        // Keep glyph inspection and inspect alternate descriptions separately.
        // Replacement spans are refused below until their rendering order is covered.
        foreach (var element in page.GetMarkedContents())
            foreach (var text in ReadMarked(element, 0, token)) yield return text;
        foreach (string key in new[] { "AA", "Metadata" })
        {
            if (Get(page.Dictionary, key) is not { } value) continue;
            // Page-level metadata streams need their own decoder/coverage route.
            if (key == "Metadata") throw new UnsupportedContentException();
            foreach (var text in ReadObject(value, Kind.Other, 0, token)) yield return text;
        }
    }

    private IEnumerable<ReadOnlyMemory<char>> ReadFieldParents(DictionaryToken widget, Func<CancellationToken> token)
    {
        var seen = new HashSet<DictionaryToken>(ReferenceEqualityComparer.Instance);
        int depth = 0;
        while (Get(widget, "Parent") is { } parent)
        {
            Check(++depth, token);
            if (++_fields > MaximumFields) throw new InspectionLimitException();
            if (Resolve(parent, token) is not DictionaryToken field || !seen.Add(field))
                throw new InvalidDataException("The PDF field parent chain is invalid.");
            RefusePayloads(field, token);
            foreach (var pair in field.Data)
            {
                if (pair.Key is "Parent" or "Kids" or "P") continue;
                var value = Resolve(pair.Value, token);
                if (pair.Key is "V" or "DV" && value is NameToken name)
                { yield return name.Data.AsMemory(); yield return "\n".AsMemory(); }
                else if (pair.Key is "V" or "DV" && value is NumericToken number)
                { yield return number.Data.ToString("R", CultureInfo.InvariantCulture).AsMemory(); yield return "\n".AsMemory(); }
                else foreach (var text in ReadObject(value, Kind.Other, depth, token)) yield return text;
            }
            widget = field;
        }
    }

    private IEnumerable<ReadOnlyMemory<char>> ReadMarked(MarkedContentElement element, int depth, Func<CancellationToken> token)
    {
        Check(depth, token);
        // Replacement spans can concatenate across content operators; until that
        // second rendering order is implemented, refuse them rather than split it.
        if (Get(element.Properties, "ActualText") is not null) throw new UnsupportedContentException();
        foreach (var text in ReadObject(element.Properties, Kind.Other, depth, token)) yield return text;
        foreach (var child in element.Children)
            foreach (var text in ReadMarked(child, depth + 1, token)) yield return text;
    }

    internal IEnumerable<ReadOnlyMemory<char>> ReadDocument(Func<CancellationToken> token)
    {
        var catalog = document.Structure.Catalog.CatalogDictionary;
        RefusePayloads(catalog, token);
        if (document.Structure.Trailer.PreviousCrossReferenceOffset is not null)
            throw new UnsupportedContentException();
        foreach (var pair in catalog.Data)
        {
            token().ThrowIfCancellationRequested();
            // Page streams/resources are interpreted by PdfPig; metadata is XML.
            if (pair.Key is "Type" or "Pages" or "Metadata") continue;
            var value = Resolve(pair.Value, token);
            if (pair.Key is "AcroForm" or "Outlines" or "Names" && value is not DictionaryToken)
                throw new InvalidDataException("The PDF auxiliary root is not a dictionary.");
            foreach (var text in ReadObject(value, Kind.Other, 0, token)) yield return text;
        }
        if (document.Information.DocumentInformationDictionary is { } information)
            foreach (var text in ReadObject(information, Kind.Other, 0, token)) yield return text;
        if (Get(catalog, "Metadata") is not null)
        {
            if (!document.TryGetXmpMetadata(out var metadata)) throw new InvalidDataException("The PDF metadata could not be read.");
            // PdfPig decodes streams into memory. Bound our subsequent XML work;
            // this is not a claim about the decoder's peak allocation.
            var bytes = metadata.GetXmlMemory();
            if (bytes.Length > 8 * 1024 * 1024) throw new InspectionLimitException();
            using var stream = new MetadataStream(bytes);
            using var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null, IgnoreWhitespace = true });
            var buffer = new char[8192]; bool root = false, textSeen = false;
            while (xml.Read())
            {
                token().ThrowIfCancellationRequested();
                if (xml.Depth > 256) throw new InspectionLimitException();
                if (xml.NodeType == XmlNodeType.Element)
                {
                    root = true;
                    if (textSeen) { textSeen = false; yield return "\n".AsMemory(); }
                    if (xml.MoveToFirstAttribute())
                    {
                        do
                        {
                            if (xml.NamespaceURI == "http://www.w3.org/2000/xmlns/") continue;
                            int count;
                            while ((count = xml.ReadValueChunk(buffer, 0, buffer.Length)) != 0)
                            { token().ThrowIfCancellationRequested(); yield return buffer.AsMemory(0, count); }
                            yield return "\n".AsMemory();
                        } while (xml.MoveToNextAttribute());
                        xml.MoveToElement();
                    }
                }
                else if (xml.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
                {
                    int count;
                    while ((count = xml.ReadValueChunk(buffer, 0, buffer.Length)) != 0)
                    { token().ThrowIfCancellationRequested(); textSeen = true; yield return buffer.AsMemory(0, count); }
                }
                else if (xml.NodeType == XmlNodeType.EndElement && textSeen)
                { textSeen = false; yield return "\n".AsMemory(); }
            }
            if (!root) throw new InvalidDataException("The PDF metadata has no root.");
        }
    }

    private IEnumerable<ReadOnlyMemory<char>> ReadObject(IToken value, Kind kind, int depth, Func<CancellationToken> token)
    {
        Check(depth, token);
        value = Resolve(value, token);
        if (value is StringToken literal)
        { yield return literal.Data.AsMemory(); yield return "\n".AsMemory(); }
        else if (value is HexToken hex)
        { yield return hex.Data.AsMemory(); yield return "\n".AsMemory(); }
        else if (value is ArrayToken array)
        {
            foreach (var item in array.Data)
                foreach (var text in ReadObject(item, kind, depth + 1, token)) yield return text;
        }
        else if (value is StreamToken) throw new UnsupportedContentException();
        else if (value is DictionaryToken dictionary)
        {
            RefusePayloads(dictionary, token);
            if (IsName(Get(dictionary, "Type"), "Page") || IsName(Get(dictionary, "Type"), "Pages")) yield break;
            if (kind == Kind.Field && ++_fields > MaximumFields || kind == Kind.Bookmark && ++_bookmarks > MaximumBookmarks)
                throw new InspectionLimitException();
            if (!_active.Add(dictionary)) throw new InvalidDataException("The PDF auxiliary graph contains a cycle.");
            try
            {
                if (Get(dictionary, "S") is { } action && !IsName(Resolve(action, token), "URI") && !IsName(Resolve(action, token), "GoTo"))
                    throw new UnsupportedContentException();
                foreach (var pair in dictionary.Data)
                {
                    token().ThrowIfCancellationRequested();
                    // Backlinks do not own text; children and forward siblings do.
                    if (pair.Key is "Parent" or "P" or "Pg" or "Prev" or "Last") continue;
                    var item = Resolve(pair.Value, token);
                    // Button/choice values may be PDF names rather than strings.
                    if (pair.Key is "V" or "DV" && item is NameToken name)
                    { yield return name.Data.AsMemory(); yield return "\n".AsMemory(); }
                    else if (pair.Key is "V" or "DV" && item is NumericToken number)
                    { yield return number.Data.ToString("R", CultureInfo.InvariantCulture).AsMemory(); yield return "\n".AsMemory(); }
                    else
                    {
                        Kind childKind = pair.Key == "Fields" || kind == Kind.Field && pair.Key == "Kids" ? Kind.Field :
                            pair.Key == "First" || kind == Kind.Bookmark && pair.Key == "Next" ? Kind.Bookmark : Kind.Other;
                        foreach (var text in ReadObject(item, childKind, depth + 1, token)) yield return text;
                    }
                }
            }
            finally { _active.Remove(dictionary); }
        }
    }

    private static IToken? Get(DictionaryToken dictionary, string key) =>
        dictionary.TryGet(NameToken.Create(key), out IToken value) ? value : null;
    private static bool IsName(IToken? value, string name) => value is NameToken token && token.Data == name;
    private void RefusePayloads(DictionaryToken dictionary, Func<CancellationToken> token)
    {
        // AP/RC can contain independent appearance/rich text, which the page
        // letter reader does not consume. Never approve only a clean /Contents.
        foreach (string key in new[] { "EmbeddedFiles", "EF", "AF", "XFA", "AP", "RC", "RichMediaContent", "JS", "ActualText" })
            if (Get(dictionary, key) is not null) throw new UnsupportedContentException();
        IToken? subtype = Get(dictionary, "Subtype"), type = Get(dictionary, "Type");
        if (subtype is not null) subtype = Resolve(subtype, token);
        if (type is not null) type = Resolve(type, token);
        if (IsName(subtype, "FileAttachment") || IsName(type, "EmbeddedFile") || IsName(type, "Filespec") ||
            IsName(subtype, "Image") || IsName(subtype, "RichMedia") || IsName(subtype, "Movie") ||
            IsName(subtype, "Sound") || IsName(subtype, "3D") || IsName(subtype, "Screen")) throw new UnsupportedContentException();
    }
    private IToken Resolve(IToken value, Func<CancellationToken> token)
    {
        int depth = 0;
        while (value is IndirectReferenceToken reference)
        {
            token().ThrowIfCancellationRequested();
            if (++depth > MaximumDepth) throw new InspectionLimitException();
            value = document.Structure.GetObject(reference.Data).Data;
        }
        return value;
    }
    private void Check(int depth, Func<CancellationToken> token)
    {
        token().ThrowIfCancellationRequested();
        if (depth > MaximumDepth || ++_objects > MaximumObjects) throw new InspectionLimitException();
    }

    private sealed class MetadataStream(ReadOnlyMemory<byte> bytes) : Stream
    {
        private int _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => bytes.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            int count = Math.Min(buffer.Length, bytes.Length - _position);
            bytes.Span.Slice(_position, count).CopyTo(buffer); _position += count; return count;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
