using System.Globalization;
using System.IO.Compression;
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
    internal const int MaximumAppearanceTokens = 65_536;
    internal const int MaximumAppearanceBytes = 8 * 1024 * 1024;
    private int _appearanceTokens, _appearanceBytes;
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
                if (pair.Key == "AP")
                {
                    foreach (var text in ReadAppearances(pair.Value, depth + 1, token)) yield return text;
                    continue;
                }
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

    private IEnumerable<ReadOnlyMemory<char>> ReadObject(IToken value, Kind kind, int depth, Func<CancellationToken> token, bool appearance = false)
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
                foreach (var text in ReadObject(item, kind, depth + 1, token, appearance)) yield return text;
        }
        else if (value is StreamToken) throw new UnsupportedContentException();
        else if (value is DictionaryToken dictionary)
        {
            RefusePayloads(dictionary, token);
            if (!appearance && (IsName(Get(dictionary, "Type"), "Page") || IsName(Get(dictionary, "Type"), "Pages"))) yield break;
            if (kind == Kind.Field && ++_fields > MaximumFields || kind == Kind.Bookmark && ++_bookmarks > MaximumBookmarks)
                throw new InspectionLimitException();
            if (!_active.Add(dictionary)) throw new InvalidDataException("The PDF auxiliary graph contains a cycle.");
            try
            {
                if (!appearance && Get(dictionary, "S") is { } action && !IsName(Resolve(action, token), "URI") && !IsName(Resolve(action, token), "GoTo"))
                    throw new UnsupportedContentException();
                foreach (var pair in dictionary.Data)
                {
                    token().ThrowIfCancellationRequested();
                    // Backlinks do not own text; children and forward siblings do.
                    if (!appearance && pair.Key is "Parent" or "P" or "Pg" or "Prev" or "Last") continue;
                    if (pair.Key == "AP")
                    {
                        if (appearance) throw new UnsupportedContentException();
                        foreach (var text in ReadAppearances(pair.Value, depth + 1, token)) yield return text;
                        continue;
                    }
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
                        foreach (var text in ReadObject(item, childKind, depth + 1, token, appearance)) yield return text;
                    }
                }
            }
            finally { _active.Remove(dictionary); }
        }
    }

    private IEnumerable<ReadOnlyMemory<char>> ReadAppearances(IToken value, int depth, Func<CancellationToken> token)
    {
        Check(depth, token);
        if (Resolve(value, token) is not DictionaryToken appearances) throw new UnsupportedContentException();
        foreach (var pair in appearances.Data)
        {
            if (pair.Key is not ("N" or "R" or "D")) throw new UnsupportedContentException();
            var item = Resolve(pair.Value, token);
            if (item is StreamToken stream)
            {
                foreach (var text in ReadAppearanceStream(stream, depth + 1, token)) yield return text;
            }
            else if (item is DictionaryToken states)
            {
                foreach (var state in states.Data)
                {
                    Check(depth + 1, token);
                    yield return state.Key.AsMemory(); yield return "\n".AsMemory();
                    if (Resolve(state.Value, token) is not StreamToken stateStream) throw new UnsupportedContentException();
                    foreach (var text in ReadAppearanceStream(stateStream, depth + 2, token)) yield return text;
                }
            }
            else throw new UnsupportedContentException();
        }
    }

    private IEnumerable<ReadOnlyMemory<char>> ReadAppearanceStream(StreamToken stream, int depth, Func<CancellationToken> token)
    {
        Check(depth, token);
        var dictionary = stream.StreamDictionary;
        if (Get(dictionary, "Subtype") is not { } subtype || !IsName(Resolve(subtype, token), "Form") ||
            Get(dictionary, "Type") is { } type && !IsName(Resolve(type, token), "XObject")) throw new UnsupportedContentException();
        RequireNumbers(Get(dictionary, "BBox"), 4);
        if (Get(dictionary, "Matrix") is { } matrix) RequireNumbers(matrix, 6);
        if (Get(dictionary, "FormType") is { } form && (Resolve(form, token) is not NumericToken version || version.Data != 1))
            throw new UnsupportedContentException();
        foreach (string key in new[] { "F", "FFilter", "FDecodeParms", "Ref" })
            if (Get(dictionary, key) is not null) throw new UnsupportedContentException();
        // No inherited resource scope: even a device color can be remapped by
        // DefaultRGB/Gray/CMYK. Inspect all explicit resources, including unused
        // entries, and refuse nested streams (patterns, soft masks, images).
        if (Get(dictionary, "Resources") is not { } resourceToken || Resolve(resourceToken, token) is not DictionaryToken resources)
            throw new UnsupportedContentException();
        foreach (var text in ReadObject(dictionary, Kind.Other, depth + 1, token, appearance: true)) yield return text;
        var bytes = DecodeAppearance(stream, token);
        if (bytes.Length > MaximumAppearanceBytes - _appearanceBytes) throw new InspectionLimitException();
        _appearanceBytes += bytes.Length;
        var lexer = new PdfAppearanceLexer(bytes, () =>
        {
            if (++_appearanceTokens > MaximumAppearanceTokens) throw new InspectionLimitException();
        }, (category, name) =>
        {
            if (Get(resources, category) is not { } group || Resolve(group, token) is not DictionaryToken entries || Get(entries, name) is not { } entry)
                throw new UnsupportedContentException();
            var resolved = Resolve(entry, token);
            if (category == "ColorSpace" ? resolved is not (NameToken or ArrayToken) : resolved is not DictionaryToken)
                throw new UnsupportedContentException();
        }, token);
        lexer.Validate();
        foreach (var text in lexer.ReadText()) yield return text;

        void RequireNumbers(IToken? value, int count)
        {
            if (value is null || Resolve(value, token) is not ArrayToken numbers || numbers.Length != count)
                throw new UnsupportedContentException();
            foreach (var item in numbers.Data)
                if (Resolve(item, token) is not NumericToken number || !double.IsFinite(number.Data)) throw new UnsupportedContentException();
        }
    }

    private ReadOnlyMemory<byte> DecodeAppearance(StreamToken stream, Func<CancellationToken> token)
    {
        token().ThrowIfCancellationRequested();
        var filter = Get(stream.StreamDictionary, "Filter");
        bool flate = false;
        if (filter is not null)
        {
            if (filter is ArrayToken array && array.Length == 1) filter = array.Data[0];
            if (!IsName(filter, "FlateDecode") && !IsName(filter, "Fl")) throw new UnsupportedContentException();
            flate = true;
        }
        if (Get(stream.StreamDictionary, "DecodeParms") is { } parameters && parameters is not NullToken)
            throw new UnsupportedContentException();
        if (flate)
        {
            var encoded = stream.Data.Span;
            if (encoded.Length < 6 || (encoded[0] & 15) != 8 || encoded[0] >> 4 > 7 ||
                (encoded[0] * 256 + encoded[1]) % 31 != 0 || (encoded[1] & 32) != 0) throw new UnsupportedContentException();
        }
        ReadOnlyMemory<byte> decoded;
        try { decoded = stream.Decode(document.Structure.FilterProvider, document.Structure.TokenScanner); }
        catch (OperationCanceledException) { throw; }
        catch (InspectionLimitException) { throw; }
        catch (Exception) { throw new UnsupportedContentException(); }
        token().ThrowIfCancellationRequested();
        if (decoded.Length > MaximumAppearanceBytes - _appearanceBytes) throw new InspectionLimitException();
        if (flate)
        {
            // PdfPig 0.1.16 can return encoded bytes after a Flate failure, and
            // can ignore trailing bytes after the first DEFLATE end marker.
            if (decoded.Span.SequenceEqual(stream.Data.Span)) throw new UnsupportedContentException();
            ValidateFlateEnvelope(stream.Data, decoded, token);
        }
        return decoded;
    }

    private static void ValidateFlateEnvelope(ReadOnlyMemory<byte> encoded, ReadOnlyMemory<byte> expected, Func<CancellationToken> token)
    {
        try
        {
            // Inspection uses PdfPig's output. This second, bounded pass checks
            // zlib framing/checksum and exact consumption. One-byte input avoids
            // decoder read-ahead hiding a suffix; physical EOF throws so an
            // incomplete member cannot pass by returning partial output.
            using var input = new AppearanceEncodedStream(encoded, token);
            using var decoder = new ZLibStream(input, CompressionMode.Decompress);
            Span<byte> buffer = stackalloc byte[8192];
            int offset = 0, count;
            while ((count = decoder.Read(buffer)) != 0)
            {
                token().ThrowIfCancellationRequested();
                if (count > expected.Length - offset || !buffer[..count].SequenceEqual(expected.Span.Slice(offset, count)))
                    throw new UnsupportedContentException();
                offset += count;
            }
            if (offset != expected.Length || input.Position != encoded.Length) throw new UnsupportedContentException();
        }
        catch (OperationCanceledException) { throw; }
        catch (InspectionLimitException) { throw; }
        catch (Exception) { throw new UnsupportedContentException(); }
    }

    private sealed class AppearanceEncodedStream(ReadOnlyMemory<byte> bytes, Func<CancellationToken> token) : Stream
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
            token().ThrowIfCancellationRequested();
            if (buffer.IsEmpty) return 0;
            if (_position == bytes.Length) throw new UnsupportedContentException();
            buffer[0] = bytes.Span[_position++]; return 1;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static IToken? Get(DictionaryToken dictionary, string key) =>
        dictionary.TryGet(NameToken.Create(key), out IToken value) ? value : null;
    private static bool IsName(IToken? value, string name) => value is NameToken token && token.Data == name;
    private void RefusePayloads(DictionaryToken dictionary, Func<CancellationToken> token)
    {
        // Rich content remains refused; appearances use the separate strict
        // graphics-only route. A clean /Contents never covers another payload.
        foreach (string key in new[] { "EmbeddedFiles", "EF", "AF", "XFA", "RC", "RichMediaContent", "JS", "ActualText" })
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
