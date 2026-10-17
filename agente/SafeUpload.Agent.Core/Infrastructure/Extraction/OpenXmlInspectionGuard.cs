using System.IO.Compression;
using System.Xml;
using DocumentFormat.OpenXml.Packaging;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure.Extraction;

internal static class OpenXmlInspectionGuard
{
    private const int MaximumParts = 16_384;
    internal const string Word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    internal const string Sheet = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    internal const string Drawing = "http://schemas.openxmlformats.org/drawingml/2006/main";
    internal const string Presentation = "http://schemas.openxmlformats.org/presentationml/2006/main";
    private const string Diagram = "http://schemas.openxmlformats.org/drawingml/2006/diagram";
    private const string ModernPresentationComment = "http://schemas.microsoft.com/office/powerpoint/2018/8/main";

    // Every admitted type has a reader route and a required XML root (custom XML
    // alone permits an arbitrary well-formed root). Formatting
    // parts are READ too: style names, number formats, numbering labels, font
    // names and settings can contain user strings. There is no opaque/no-text
    // exception. In particular printer settings are binary and remain refused.
    internal static (string Root, string Namespace) Root(OpenXmlPart part) => part switch
    {
        MainDocumentPart => ("document", Word), // Body, nested text boxes, alternate branches.
        HeaderPart => ("hdr", Word), // Header paragraphs and drawings.
        FooterPart => ("ftr", Word), // Footer paragraphs and drawings.
        FootnotesPart => ("footnotes", Word), // Note paragraphs.
        EndnotesPart => ("endnotes", Word), // Note paragraphs.
        WordprocessingCommentsPart => ("comments", Word), // Comment paragraphs and authors.
        WorkbookPart => ("workbook", Sheet), // Defined names and sheet names.
        WorksheetPart => ("worksheet", Sheet), // Formulas, values, inline text and auxiliary strings.
        SharedStringTablePart => ("sst", Sheet), // All stored strings, even unused ones.
        WorksheetCommentsPart => ("comments", Sheet), // Classic comment text and authors.
        DrawingsPart => ("wsDr", "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"), // Shapes/groups and alt text.
        ChartPart => ("chartSpace", "http://schemas.openxmlformats.org/drawingml/2006/chart"), // Rich text, caches and references.
        VmlDrawingPart => ("xml", ""), // VML text boxes, including legacy HTML text.
        WorksheetThreadedCommentsPart => ("ThreadedComments", "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"), // Modern comment text.
        WorkbookPersonPart => ("personList", "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"), // Person names/identifiers.
        CoreFilePropertiesPart => ("coreProperties", "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"), // All core property text.
        ExtendedFilePropertiesPart => ("Properties", "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"), // Company, Manager, vectors and other text.
        StyleDefinitionsPart => ("styles", Word), // Style names and attribute text.
        StylesWithEffectsPart => ("styles", Word), // Extended style names and attribute text.
        WorkbookStylesPart => ("styleSheet", Sheet), // Number formats and named styles.
        FontTablePart => ("fonts", Word), // Font names and alternate names.
        NumberingDefinitionsPart => ("numbering", Word), // Numbering labels can be arbitrary strings.
        DocumentSettingsPart => ("settings", Word), // Variables and other string settings.
        WebSettingsPart => ("webSettings", Word), // String-valued web settings.
        ThemePart => ("theme", Drawing), // Theme/font/color names and values.
        ThemeOverridePart => ("themeOverride", Drawing), // Overrides have the same string-bearing structures.
        CalculationChainPart => ("calcChain", Sheet), // Normally references only; still parse/read instead of trusting opaque XML.
        TableDefinitionPart => ("table", Sheet), // Table/column names, formulas and labels.
        CellMetadataPart => ("metadata", Sheet), // Dynamic-array metadata and stored metadata strings.
        PivotTablePart => ("pivotTableDefinition", Sheet), // Pivot labels, captions and formulas.
        PivotTableCacheDefinitionPart => ("pivotCacheDefinition", Sheet), // Field names and shared cached values.
        PivotTableCacheRecordsPart => ("pivotCacheRecords", Sheet), // Independent stored copies of source data.
        QueryTablePart => ("queryTable", Sheet), // Query and field names.
        ConnectionsPart => ("connections", Sheet), // Connection strings, commands and descriptions.
        ExternalWorkbookPart => ("externalLink", Sheet), // External-workbook cached values; no network fetch.
        CustomXmlMappingsPart => ("MapInfo", Sheet), // Map names and inline schema text.
        WordprocessingPeoplePart => ("people", "http://schemas.microsoft.com/office/word/2012/wordml"), // Comment-author identities.
        WordprocessingCommentsExPart => ("commentsEx", "http://schemas.microsoft.com/office/word/2012/wordml"), // Extended comment metadata.
        WordprocessingCommentsIdsPart => ("commentsIds", "http://schemas.microsoft.com/office/word/2016/wordml/cid"), // Comment identity metadata.
        WordCommentsExtensiblePart => ("commentsExtensible", "http://schemas.microsoft.com/office/word/2018/wordml/cex"), // Extensible comment metadata.
        GlossaryDocumentPart => ("glossaryDocument", Word), // Stored building-block paragraphs and attributes.
        CustomFilePropertiesPart => ("Properties", "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"), // Enterprise labels and arbitrary property values.
        CustomXmlPart => ("*", ""), // Arbitrary well-formed XML root; all text and attributes are read.
        CustomXmlPropertiesPart => ("datastoreItem", "http://schemas.openxmlformats.org/officeDocument/2006/customXml"), // Data-store identity and schema references.
        PresentationPart => ("presentation", Presentation), // Slide/master lists and presentation strings.
        SlidePart => ("sld", Presentation), // All shapes, tables and hidden slides.
        SlideLayoutPart => ("sldLayout", Presentation), // Stored placeholder text, even when not displayed.
        SlideMasterPart => ("sldMaster", Presentation),
        NotesSlidePart => ("notes", Presentation),
        NotesMasterPart => ("notesMaster", Presentation),
        HandoutMasterPart => ("handoutMaster", Presentation),
        SlideCommentsPart => ("cmLst", Presentation), // Classic comments.
        CommentAuthorsPart => ("cmAuthorLst", Presentation),
        PowerPointCommentPart => ("cmLst", ModernPresentationComment), // Modern comments and replies.
        PowerPointAuthorsPart => ("authorLst", ModernPresentationComment),
        PresentationPropertiesPart => ("presentationPr", Presentation),
        ViewPropertiesPart => ("viewPr", Presentation),
        TableStylesPart => ("tblStyleLst", Drawing),
        DiagramDataPart => ("dataModel", Diagram), // SmartArt node text.
        DiagramLayoutDefinitionPart => ("layoutDef", Diagram),
        DiagramStylePart => ("styleDef", Diagram),
        DiagramColorsPart => ("colorsDef", Diagram),
        DiagramPersistLayoutPart => ("drawing", "http://schemas.microsoft.com/office/drawing/2008/diagram"),
        _ => throw new UnsupportedContentException()
    };

    // Presentation admission is deliberately independent of the Word/Excel
    // allowlist. Adding a presentation reader must not admit new parts there.
    private static bool PresentationOnly(OpenXmlPart part) => part is
        PresentationPart or SlidePart or SlideLayoutPart or SlideMasterPart or NotesSlidePart or NotesMasterPart or
        HandoutMasterPart or SlideCommentsPart or CommentAuthorsPart or PowerPointCommentPart or PowerPointAuthorsPart or
        PresentationPropertiesPart or ViewPropertiesPart or TableStylesPart or DiagramDataPart or DiagramLayoutDefinitionPart or
        DiagramStylePart or DiagramColorsPart or DiagramPersistLayoutPart;

    private static bool PresentationShared(OpenXmlPart part) => part is
        ChartPart or VmlDrawingPart or CoreFilePropertiesPart or ExtendedFilePropertiesPart or CustomFilePropertiesPart or
        ThemePart or ThemeOverridePart or CustomXmlPart or CustomXmlPropertiesPart;

    public static IReadOnlyList<OpenXmlPart> Inspect(OpenXmlPackage package, Stream content, CancellationToken cancellationToken)
    {
        var pending = new Stack<OpenXmlPartContainer>();
        var visited = new HashSet<Uri>();
        var parts = new List<OpenXmlPart>();
        pending.Push(package);
        while (pending.TryPop(out var container))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var relationship in container.Parts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var part = relationship.OpenXmlPart;
                if (!visited.Add(part.Uri)) continue;
                if (visited.Count > MaximumParts) throw new InspectionLimitException();
                // Owner decision 2026-10-16 (option A): PowerPoint writes a package-root thumbnail rendered from slide 1, whose
                // text is inspected; accept it without OCR. Images anywhere else stay refused until image inspection exists.
                if (package is PresentationDocument && ReferenceEquals(container, package) && part is ThumbnailPart) continue;
                if (package is PresentationDocument
                    ? !PresentationOnly(part) && !PresentationShared(part)
                    : PresentationOnly(part))
                    throw new UnsupportedContentException();
                _ = Root(part);
                bool wordPart = part is MainDocumentPart or HeaderPart or FooterPart or FootnotesPart or EndnotesPart or WordprocessingCommentsPart;
                bool sheetPart = part is WorkbookPart or WorksheetPart or SharedStringTablePart or WorksheetCommentsPart;
                if (package is SpreadsheetDocument && wordPart || package is WordprocessingDocument && sheetPart)
                    throw new UnsupportedContentException();
                parts.Add(part);
                pending.Push(part);
            }
        }

        // The SDK relationship walk cannot see unreferenced ZIP payloads. Check
        // the same held stream, leaving its position and ownership unchanged.
        var reachable = visited.Select(uri => Uri.UnescapeDataString(uri.OriginalString).TrimStart('/'))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        long position = content.Position;
        try
        {
            content.Position = 0;
            using var zip = new ZipArchive(content, ZipArchiveMode.Read, leaveOpen: true);
            var entries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in zip.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string name = entry.FullName;
                if (!entries.Add(Uri.UnescapeDataString(name))) throw new UnsupportedContentException();
                if (entries.Count > 2 * MaximumParts + 2) throw new InspectionLimitException();
                if (name.EndsWith("/", StringComparison.Ordinal) && entry.Length == 0) continue;
                if (name == "[Content_Types].xml" || name == "_rels/.rels" ||
                    name.Contains("/_rels/", StringComparison.Ordinal) && name.EndsWith(".rels", StringComparison.Ordinal))
                { ValidateInfrastructure(entry, cancellationToken); continue; }
                if (!reachable.Contains(Uri.UnescapeDataString(name))) throw new UnsupportedContentException();
            }
        }
        finally { content.Position = position; }
        return parts;
    }

    private static void ValidateInfrastructure(ZipArchiveEntry entry, CancellationToken token)
    {
        bool types = entry.FullName == "[Content_Types].xml";
        string ns = types ? "http://schemas.openxmlformats.org/package/2006/content-types"
            : "http://schemas.openxmlformats.org/package/2006/relationships";
        using var stream = entry.Open();
        using var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        bool root = false;
        while (xml.Read())
        {
            token.ThrowIfCancellationRequested();
            if (xml.Depth > 256) throw new InspectionLimitException();
            if (xml.NodeType == XmlNodeType.Element)
            {
                if (xml.NamespaceURI != ns || xml.Depth > 1 ||
                    xml.Depth == 0 && xml.LocalName != (types ? "Types" : "Relationships") ||
                    xml.Depth == 1 && !(types ? xml.LocalName is "Default" or "Override" : xml.LocalName == "Relationship"))
                    throw new UnsupportedContentException();
                root = true;
                if (xml.MoveToFirstAttribute())
                {
                    do
                    {
                        if (xml.NamespaceURI == "http://www.w3.org/2000/xmlns/") continue;
                        bool allowed = types ? xml.LocalName is "Extension" or "ContentType" or "PartName"
                            : xml.LocalName is "Id" or "Type" or "Target" or "TargetMode";
                        if (xml.NamespaceURI.Length != 0 || !allowed) throw new UnsupportedContentException();
                    } while (xml.MoveToNextAttribute());
                    xml.MoveToElement();
                }
            }
            else if (xml.NodeType is XmlNodeType.Text or XmlNodeType.CDATA) throw new UnsupportedContentException();
        }
        if (!root) throw new InvalidDataException("The package infrastructure has no root.");
    }
}
