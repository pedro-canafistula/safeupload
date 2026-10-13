using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

internal static class OpenXmlAuxiliaryText
{
    internal static TextReader Create(IReadOnlyList<OpenXmlPart> parts) => new ChunkedTextReader(token => Read(parts, token));

    private static IEnumerable<ReadOnlyMemory<char>> Read(IReadOnlyList<OpenXmlPart> parts, Func<CancellationToken> token)
    {
        var buffer = new char[8192];
        foreach (var part in parts)
        {
            // Attributes are a separate pass so run formatting cannot interrupt
            // a number split across rich-text runs. No DOM or full value copies.
            foreach (bool attributes in new[] { false, true })
            {
                token().ThrowIfCancellationRequested();
                using var stream = part.GetStream(FileMode.Open, FileAccess.Read);
                using var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null, IgnoreWhitespace = true });
                var groups = new Stack<int>();
                int skipDepth = -1, cellDepth = -1, bodyDepth = -1;
                bool rootSeen = false, text = false;
                while (xml.Read())
                {
                    token().ThrowIfCancellationRequested();
                    if (xml.Depth > 256) throw new InspectionLimitException();
                    if (xml.NodeType == XmlNodeType.Element)
                    {
                        if (!rootSeen)
                        {
                            var root = OpenXmlInspectionGuard.Root(part);
                            if (xml.Depth != 0 || xml.LocalName != root.Root || !NamespaceMatches(xml.NamespaceURI, root.Namespace))
                                throw new InvalidDataException("The Office part has an invalid root.");
                            rootSeen = true;
                        }
                        if (attributes)
                        {
                            if (xml.MoveToFirstAttribute())
                            {
                                do
                                {
                                    token().ThrowIfCancellationRequested();
                                    // Namespace declarations and xml:space are XML syntax, not user text.
                                    if (xml.NamespaceURI == "http://www.w3.org/2000/xmlns/" ||
                                        xml.NamespaceURI == "http://www.w3.org/XML/1998/namespace" && xml.LocalName == "space") continue;
                                    int count;
                                    while ((count = xml.ReadValueChunk(buffer, 0, buffer.Length)) != 0)
                                    { token().ThrowIfCancellationRequested(); yield return buffer.AsMemory(0, count); }
                                    yield return "\n".AsMemory();
                                } while (xml.MoveToNextAttribute());
                                xml.MoveToElement();
                            }
                            continue;
                        }
                        if (part is WorksheetPart && NamespaceMatches(xml.NamespaceURI, OpenXmlInspectionGuard.Sheet) && xml.LocalName == "c" && !xml.IsEmptyElement)
                            cellDepth = xml.Depth;
                        if (part is MainDocumentPart && NamespaceMatches(xml.NamespaceURI, OpenXmlInspectionGuard.Word) && xml.LocalName == "body" && xml.Depth == 1 && !xml.IsEmptyElement)
                            bodyDepth = xml.Depth;
                        if (skipDepth < 0 && PrimaryContainer(part, xml, cellDepth, bodyDepth))
                        {
                            if (text) { text = false; yield return "\n".AsMemory(); }
                            if (!xml.IsEmptyElement) skipDepth = xml.Depth;
                            continue;
                        }
                        if (skipDepth >= 0) continue;
                        // Paragraphs and text boxes keep all inline text contiguous;
                        // nested block containers delimit their surrounding text.
                        if (IsGroup(xml))
                        {
                            if (text) { text = false; yield return "\n".AsMemory(); }
                            if (!xml.IsEmptyElement) groups.Push(xml.Depth);
                        }
                    }
                    else if (!attributes && xml.NodeType == XmlNodeType.EndElement)
                    {
                        if (xml.Depth == cellDepth) cellDepth = -1;
                        if (xml.Depth == bodyDepth) bodyDepth = -1;
                        if (xml.Depth == skipDepth) { skipDepth = -1; continue; }
                        if (skipDepth >= 0) continue;
                        bool groupEnd = groups.Count != 0 && groups.Peek() == xml.Depth;
                        if (groupEnd) groups.Pop();
                        if (text && (groupEnd || groups.Count == 0))
                        { text = false; yield return "\n".AsMemory(); }
                    }
                    else if (!attributes && skipDepth < 0 && xml.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
                    {
                        int count;
                        while ((count = xml.ReadValueChunk(buffer, 0, buffer.Length)) != 0)
                        { token().ThrowIfCancellationRequested(); text = true; yield return buffer.AsMemory(0, count); }
                    }
                }
                if (!rootSeen) throw new InvalidDataException("The Office part has no root.");
                if (text) yield return "\n".AsMemory();
            }
        }
    }

    internal static bool NamespaceMatches(string actual, string expected) => actual == expected ||
        expected.StartsWith("http://schemas.openxmlformats.org/", StringComparison.Ordinal) &&
        actual == expected.Replace("http://schemas.openxmlformats.org/", "http://purl.oclc.org/ooxml/", StringComparison.Ordinal)
            .Replace("/2006/", "/", StringComparison.Ordinal);

    private static bool PrimaryContainer(OpenXmlPart part, XmlReader xml, int cellDepth, int bodyDepth)
    {
        bool word = NamespaceMatches(xml.NamespaceURI, OpenXmlInspectionGuard.Word);
        bool sheet = NamespaceMatches(xml.NamespaceURI, OpenXmlInspectionGuard.Sheet);
        return part switch
        {
            MainDocumentPart or HeaderPart or FooterPart or FootnotesPart or EndnotesPart or WordprocessingCommentsPart =>
                word && xml.LocalName == "p" && (part is not MainDocumentPart || bodyDepth >= 0),
            WorkbookPart => sheet && xml.LocalName == "definedName",
            WorksheetPart => sheet && cellDepth >= 0 && xml.Depth == cellDepth + 1 && xml.LocalName is "f" or "v" or "is",
            SharedStringTablePart => sheet && xml.LocalName == "si" && xml.Depth == 1,
            WorksheetCommentsPart => sheet && xml.LocalName is "author" or "text",
            _ => false
        };
    }

    private static bool IsGroup(XmlReader xml) =>
        xml.LocalName == "p" && (NamespaceMatches(xml.NamespaceURI, OpenXmlInspectionGuard.Word) ||
            NamespaceMatches(xml.NamespaceURI, OpenXmlInspectionGuard.Drawing)) ||
        xml.NamespaceURI == "urn:schemas-microsoft-com:vml" && xml.LocalName == "textbox" ||
        xml.NamespaceURI is "" or "http://www.w3.org/1999/xhtml" && xml.LocalName is "div" or "p" or "li" ||
        xml.LocalName == "text" && xml.NamespaceURI == "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments";
}
