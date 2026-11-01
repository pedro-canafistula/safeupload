using System.IO.Compression;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using static SafeUpload.Agent.Tests.PowerPointFixture;

namespace SafeUpload.Agent.Tests;

public sealed class PowerPointContentCoverageTests : IDisposable
{
    private const string Cpf = "529.982.247-25";
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("slide")]
    [InlineData("hidden-slide")]
    [InlineData("layout")]
    [InlineData("master")]
    [InlineData("notes")]
    [InlineData("notes-master")]
    [InlineData("handout-master")]
    [InlineData("comment")]
    [InlineData("comment-author")]
    [InlineData("modern-comment")]
    [InlineData("modern-reply")]
    [InlineData("modern-author")]
    [InlineData("chart-title")]
    [InlineData("chart-axis")]
    [InlineData("chart-series")]
    [InlineData("chart-formula")]
    [InlineData("chart-label")]
    [InlineData("chart-cache")]
    [InlineData("chart-number")]
    [InlineData("smartart")]
    [InlineData("diagram-layout")]
    [InlineData("diagram-style")]
    [InlineData("diagram-colors")]
    [InlineData("diagram-drawing")]
    [InlineData("table")]
    [InlineData("core")]
    [InlineData("app")]
    [InlineData("custom")]
    [InlineData("custom-xml")]
    [InlineData("custom-xml-properties")]
    [InlineData("presentation")]
    [InlineData("presentation-properties")]
    [InlineData("view-properties")]
    [InlineData("table-styles")]
    [InlineData("theme")]
    [InlineData("theme-override")]
    [InlineData("vml")]
    [InlineData("alt-text")]
    [InlineData("hyperlink")]
    [InlineData("external-target")]
    public async Task PowerPoint_each_admitted_payload_is_inspected_in_both_paths(string location)
    {
        await Check(Deck(location, Cpf), sensitive: true);
        await Check(Deck(location, "clean"));
    }

    [Theory]
    [InlineData(".pptx")]
    [InlineData(".pptm")]
    [InlineData(".potx")]
    [InlineData(".ppsx")]
    public async Task PowerPoint_container_variants_share_the_inspected_part_model(string extension)
    {
        Assert.IsType<OpenXmlPowerPointExtractor>(ExtractorRegistry.CreateDefault().Resolve(extension.ToUpperInvariant()));
        await Check(PowerPointFixture.Create(_workspace.Root, extension));
        string path = PowerPointFixture.Create(_workspace.Root, extension);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Write(zip, Slide, SlideXml(Shape(Rich(Cpf))));
        await Check(path, sensitive: true);
    }

    // Owner decision 2026-10-16 (option A): the package-root thumbnail PowerPoint renders from slide 1 is accepted without OCR;
    // the slide text is still inspected, and an image related from anywhere else still refuses the deck.
    [Theory]
    [InlineData("clean", false)]
    [InlineData("cpf-in-slide", true)]
    public async Task PowerPoint_package_thumbnail_is_accepted_and_the_slides_are_still_inspected(string slide, bool sensitive)
    {
        string path = PowerPointFixture.Create(_workspace.Root, ".pptx");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            if (slide == "cpf-in-slide") Write(zip, Slide, SlideXml(Shape(Rich(Cpf))));
            AddPng(zip, "", "docProps/thumbnail.png", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail");
        }
        await Check(path, sensitive: sensitive);
    }

    [Fact]
    public async Task PowerPoint_thumbnail_relationship_from_a_slide_still_refuses_the_deck()
    {
        string path = PowerPointFixture.Create(_workspace.Root, ".pptx");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            AddPng(zip, Slide, "ppt/media/thumbnail.png", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail");
        await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
    }

    private static void AddPng(ZipArchive zip, string parent, string name, string relation)
    {
        Add(zip, parent, name, relation, "image/png", "<placeholder/>");
        // A real one-pixel PNG, not XML masquerading as an image.
        zip.GetEntry(name)!.Delete();
        using var image = zip.CreateEntry(name).Open();
        image.Write(Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4//8/AAX+Av4N70a4AAAAAElFTkSuQmCC"));
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("orphan-xml")]
    [InlineData("orphan-slide")]
    [InlineData("image")]
    [InlineData("image-only")]
    [InlineData("media")]
    [InlineData("ole")]
    [InlineData("embedded-chart-workbook")]
    [InlineData("activex")]
    [InlineData("vba")]
    [InlineData("font")]
    [InlineData("word-part")]
    [InlineData("sheet-part")]
    public async Task PowerPoint_unconsumed_payloads_refuse_the_whole_deck(string location)
    {
        string path = PowerPointFixture.Create(_workspace.Root, location == "vba" ? ".pptm" : ".pptx");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            if (location.StartsWith("orphan-", StringComparison.Ordinal))
                Write(zip, location == "orphan-slide" ? "ppt/slides/unused.xml" : "unreferenced.xml", "<text>" + Cpf + "</text>");
            else
            {
                var (parent, name, relation, type) = location switch
                {
                    "image" or "image-only" => (Slide, "ppt/media/image1.png", Rel + "image", "image/png"),
                    "thumbnail" => ("", "docProps/thumbnail.png", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail", "image/png"),
                    "media" => (Slide, "ppt/media/video1.mp4", Rel + "video", "video/mp4"),
                    "ole" => (Slide, "ppt/embeddings/object1.bin", Rel + "oleObject", Ct + "oleObject"),
                    "embedded-chart-workbook" => ("ppt/charts/chart1.xml", "ppt/embeddings/book.xlsx", Rel + "package", Ct + "spreadsheetml.sheet"),
                    "activex" => (Slide, "ppt/activeX/activeX1.xml", Rel + "control", "application/vnd.ms-office.activeX+xml"),
                    "vba" => (Main, "ppt/vbaProject.bin", "http://schemas.microsoft.com/office/2006/relationships/vbaProject", "application/vnd.ms-office.vbaProject"),
                    "font" => (Main, "ppt/fonts/font1.fntdata", Rel + "font", "application/x-fontdata"),
                    "word-part" => (Slide, "word/header1.xml", Rel + "header", Ct + "wordprocessingml.header+xml"),
                    "sheet-part" => (Slide, "xl/worksheets/sheet1.xml", Rel + "worksheet", Ct + "spreadsheetml.worksheet+xml"),
                    _ => (Slide, "ppt/unknown.xml", "urn:safeupload:unknown", "application/xml")
                };
                if (location == "embedded-chart-workbook")
                    Add(zip, Slide, parent, Rel + "chart", Ct + "drawingml.chart+xml", ChartXml(""));
                string id = Add(zip, parent, name, relation, type, "<uninspected>" + Cpf + "</uninspected>");
                if (location is "image" or "image-only" or "thumbnail")
                {
                    // A real one-pixel PNG, not XML masquerading as an image.
                    zip.GetEntry(name)!.Delete();
                    using var image = zip.CreateEntry(name).Open();
                    image.Write(Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4//8/AAX+Av4N70a4AAAAAElFTkSuQmCC"));
                }
                if (location == "image-only")
                    Write(zip, Slide, SlideXml("<p:pic><p:blipFill><a:blip r:embed='" + id + "'/></p:blipFill></p:pic>"));
            }
        }
        await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData("slide")]
    [InlineData("shape")]
    [InlineData("paragraph")]
    [InlineData("notes")]
    [InlineData("comment")]
    [InlineData("modern-comment")]
    [InlineData("chart-cache")]
    [InlineData("smartart")]
    [InlineData("table")]
    [InlineData("property")]
    [InlineData("external-target")]
    public async Task PowerPoint_separate_items_cannot_assemble_a_cpf(string location)
    {
        string path = PowerPointFixture.Create(_workspace.Root);
        const string first = "529.982.", last = "247-25";
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            switch (location)
            {
                case "slide": case "notes":
                    Write(zip, Slide, SlideXml(Shape(Rich(first))));
                    Add(zip, location == "slide" ? Main : Slide, "ppt/other.xml", Rel + (location == "slide" ? "slide" : "notesSlide"),
                        Ct + "presentationml." + (location == "slide" ? "slide" : "notesSlide") + "+xml",
                        location == "slide" ? SlideXml(Shape(Rich(last))) : PartXml("notes", "<p:cSld><p:spTree>" + Shape(Rich(last)) + "</p:spTree></p:cSld>"));
                    break;
                case "paragraph": Write(zip, Slide, SlideXml(Shape(Rich(first) + Rich(last)))); break;
                case "shape": Write(zip, Slide, SlideXml(Shape(Rich(first)) + Shape(Rich(last)))); break;
                case "table": Write(zip, Slide, SlideXml(Table(first, last))); break;
                case "comment":
                    Add(zip, Slide, "ppt/comments/comment1.xml", Rel + "comments", Ct + "presentationml.comments+xml",
                        PartXml("cmLst", "<p:cm><p:text>" + first + "</p:text></p:cm><p:cm><p:text>" + last + "</p:text></p:cm>")); break;
                case "modern-comment": AddModernComment(zip, Rich(first) + Rich(last)); break;
                case "chart-cache": AddChart(zip, "<c:plotArea><c:barChart><c:ser><c:cat><c:strLit><c:pt idx='0'><c:v>" + first +
                    "</c:v></c:pt><c:pt idx='1'><c:v>" + last + "</c:v></c:pt></c:strLit></c:cat></c:ser></c:barChart></c:plotArea>"); break;
                case "smartart": AddDiagram(zip, DiagramNode(first) + DiagramNode(last)); break;
                case "property": AddCore(zip, "<dc:title>" + first + "</dc:title><dc:subject>" + last + "</dc:subject>"); break;
                default:
                    PowerPointFixture.Relationship(zip, Slide, Rel + "hyperlink", first, external: true);
                    PowerPointFixture.Relationship(zip, Slide, Rel + "hyperlink", last, external: true); break;
            }
        }
        await Check(path);
    }

    [Theory]
    [InlineData("slide", "empty")]
    [InlineData("slide", "wrong-root")]
    [InlineData("slide", "dtd")]
    [InlineData("slide", "late-corruption")]
    [InlineData("notes", "late-corruption")]
    [InlineData("comment", "late-corruption")]
    [InlineData("chart", "late-corruption")]
    [InlineData("smartart", "late-corruption")]
    [InlineData("presentation", "late-corruption")]
    public async Task PowerPoint_malformed_xml_never_returns_partial_approval(string location, string shape)
    {
        string path = Deck(location == "chart" ? "chart-label" : location, Cpf);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            string part = location switch
            {
                "notes" => "ppt/notesSlides/notes1.xml", "comment" => "ppt/comments/comment1.xml",
                "chart" => "ppt/charts/chart1.xml", "smartart" => "ppt/diagrams/data1.xml",
                "presentation" => Main, _ => Slide
            };
            Write(zip, part, shape switch
            {
                "empty" => "", "wrong-root" => "<wrong/>",
                "dtd" => "<!DOCTYPE sld [<!ENTITY text 'clean'>]>" + SlideXml(Shape(Rich("&text;"))),
                _ => Read(zip, part) + "<broken>"
            });
        }
        await Check(path, failure: InspectionFailureKind.ReadOrParse);
    }

    [Fact]
    public async Task PowerPoint_xml_depth_uses_the_existing_limit()
    {
        string path = PowerPointFixture.Create(_workspace.Root);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Write(zip, Slide, SlideXml(string.Concat(Enumerable.Repeat("<p:grpSp>", 257)) +
                string.Concat(Enumerable.Repeat("</p:grpSp>", 257))));
        await Check(path, failure: InspectionFailureKind.Limit);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Presentation_and_diagram_parts_remain_refused_in_other_Office_formats(bool word, bool diagram)
    {
        string path = word ? _workspace.WriteWordDocument("other.docx", "clean") : _workspace.WriteSpreadsheet("other.xlsx", "clean");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Add(zip, word ? "word/document.xml" : "xl/workbook.xml", "ppt/extra.xml", Rel + (diagram ? "diagramData" : "slide"),
                Ct + (diagram ? "drawingml.diagramData+xml" : "presentationml.slide+xml"), diagram
                    ? "<d:dataModel xmlns:d='" + D + "'/>" : SlideXml(Shape(Rich("clean"))));
        await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
    }

    private async Task Check(string path, bool sensitive = false, InspectionFailureKind? failure = null)
    {
        byte[] original = File.ReadAllBytes(path);
        var service = new InspectionService(InScopePolicy(_workspace), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.True(result.InScope);
            Assert.Equal(failure is not null ? staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection : sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Equal(failure, result.FailureKind);
            if (failure == InspectionFailureKind.UnsupportedFormat) Assert.Equal("unsupported_format", result.Reason);
            else if (failure == InspectionFailureKind.ReadOrParse) Assert.StartsWith("parse_error:", result.Reason);
            else if (failure == InspectionFailureKind.Limit) Assert.Equal("inspection_limit", result.Reason);
            else Assert.Null(result.Reason);
            if (sensitive && failure is null)
            {
                Assert.Equal(Category.Cpf, Assert.Single(result.Categories));
                Assert.NotEmpty(result.Findings);
                Assert.All(result.Findings, finding => { Assert.Equal(Category.Cpf, finding.Category); Assert.Equal("•••••••••25", finding.MaskedSnippet); });
            }
            else Assert.Empty(result.Findings);
            Assert.Equal(original, File.ReadAllBytes(path));
        }
    }

    private string Deck(string location, string text)
    {
        string path = PowerPointFixture.Create(_workspace.Root);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Update);
        void PresentationPart(string parent, string name, string relation, string root, string body) =>
            Add(zip, parent, name, Rel + relation, Ct + "presentationml." + relation + "+xml", PartXml(root, body));
        switch (location)
        {
            case "slide": case "hidden-slide": Write(zip, Slide, SlideXml(Shape(Rich(text)), location == "hidden-slide")); break;
            case "alt-text": Write(zip, Slide, SlideXml("<p:sp><p:nvSpPr><p:cNvPr id='2' name='Shape' descr='" + text + "'/></p:nvSpPr></p:sp>")); break;
            case "table": Write(zip, Slide, SlideXml(Table(text))); break;
            case "layout": case "master": case "notes": case "notes-master": case "handout-master":
                var (parent, name, relation, root) = location switch
                {
                    "layout" => (Slide, "ppt/slideLayouts/layout1.xml", "slideLayout", "sldLayout"),
                    "master" => (Main, "ppt/slideMasters/master1.xml", "slideMaster", "sldMaster"),
                    "notes" => (Slide, "ppt/notesSlides/notes1.xml", "notesSlide", "notes"),
                    "notes-master" => (Main, "ppt/notesMasters/master1.xml", "notesMaster", "notesMaster"),
                    _ => (Main, "ppt/handoutMasters/master1.xml", "handoutMaster", "handoutMaster")
                };
                PresentationPart(parent, name, relation, root, "<p:cSld><p:spTree>" +
                    Shape(Rich(text)).Replace("<p:nvPr/>", "<p:nvPr><p:ph/></p:nvPr>", StringComparison.Ordinal) + "</p:spTree></p:cSld>"); break;
            case "comment": PresentationPart(Slide, "ppt/comments/comment1.xml", "comments", "cmLst", "<p:cm authorId='0' idx='1'><p:text>" + text + "</p:text></p:cm>"); break;
            case "comment-author": PresentationPart(Main, "ppt/commentAuthors.xml", "commentAuthors", "cmAuthorLst", "<p:cmAuthor id='0' name='" + text + "' initials='A' lastIdx='1' clrIdx='0'/>"); break;
            case "modern-comment": AddModernComment(zip, Rich(text)); break;
            case "modern-reply": AddModernComment(zip, Rich("clean"), Rich(text)); break;
            case "modern-author": Add(zip, Main, "ppt/authors.xml", "http://schemas.microsoft.com/office/2018/10/relationships/authors", "application/vnd.ms-powerpoint.authors+xml",
                "<m:authorLst xmlns:m='" + PowerPointFixture.Modern + "'><m:author id='{11111111-1111-1111-1111-111111111111}' name='" + text + "' initials='A'/></m:authorLst>"); break;
            case "chart-title": AddChart(zip, "<c:title><c:tx><c:rich>" + Rich(text) + "</c:rich></c:tx></c:title>"); break;
            case "chart-axis": AddChart(zip, "<c:plotArea><c:catAx><c:title><c:tx><c:rich>" + Rich(text) + "</c:rich></c:tx></c:title></c:catAx></c:plotArea>"); break;
            case "chart-series": AddChart(zip, "<c:plotArea><c:barChart><c:ser><c:tx><c:v>" + text + "</c:v></c:tx></c:ser></c:barChart></c:plotArea>"); break;
            case "chart-formula": AddChart(zip, "<c:plotArea><c:barChart><c:ser><c:cat><c:strRef><c:f>" + text + "</c:f></c:strRef></c:cat></c:ser></c:barChart></c:plotArea>"); break;
            case "chart-label": AddChart(zip, "<c:plotArea><c:barChart><c:dLbls><c:dLbl><c:tx><c:rich>" + Rich(text) + "</c:rich></c:tx></c:dLbl></c:dLbls></c:barChart></c:plotArea>"); break;
            case "chart-cache": case "chart-number":
                bool number = location == "chart-number";
                string value = number ? text == Cpf ? "52998224725" : "42" : text;
                string cache = number ? "numCache" : "strCache", reference = number ? "numRef" : "strRef", field = number ? "val" : "cat";
                AddChart(zip, "<c:plotArea><c:barChart><c:ser><c:" + field + "><c:" + reference + "><c:f>Sheet1!$A$1</c:f><c:" + cache + "><c:ptCount val='1'/><c:pt idx='0'><c:v>" + value +
                    "</c:v></c:pt></c:" + cache + "></c:" + reference + "></c:" + field + "></c:ser></c:barChart></c:plotArea>"); break;
            case "smartart": AddDiagram(zip, DiagramNode(text)); break;
            case "diagram-layout": case "diagram-style": case "diagram-colors":
                var (part, rel, diagramRoot) = location switch
                {
                    "diagram-layout" => ("layout", "diagramLayout", "layoutDef"),
                    "diagram-style" => ("quickStyle", "diagramQuickStyle", "styleDef"),
                    _ => ("colors", "diagramColors", "colorsDef")
                };
                Add(zip, Slide, "ppt/diagrams/" + part + "1.xml", Rel + rel, Ct + "drawingml.diagram" + (part == "layout" ? "Layout" : part == "quickStyle" ? "Style" : "Colors") + "+xml",
                    "<d:" + diagramRoot + " xmlns:d='" + D + "'><d:title val='" + text + "'/></d:" + diagramRoot + ">"); break;
            case "diagram-drawing": Add(zip, Slide, "ppt/diagrams/drawing1.xml", "http://schemas.microsoft.com/office/2007/relationships/diagramDrawing", "application/vnd.ms-office.drawingml.diagramDrawing+xml",
                "<dsp:drawing xmlns:dsp='http://schemas.microsoft.com/office/drawing/2008/diagram' xmlns:a='" + PowerPointFixture.A + "'><dsp:spTree><dsp:sp><dsp:txBody>" + Rich(text) + "</dsp:txBody></dsp:sp></dsp:spTree></dsp:drawing>"); break;
            case "core": AddCore(zip, "<dc:title>" + text + "</dc:title>"); break;
            case "app": Add(zip, "", "docProps/app.xml", Rel + "extended-properties", Ct + "extended-properties+xml", "<Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'><Company>" + text + "</Company></Properties>"); break;
            case "custom": Add(zip, "", "docProps/custom.xml", Rel + "custom-properties", Ct + "custom-properties+xml", "<Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/custom-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'><property fmtid='{D5CDD505-2E9C-101B-9397-08002B2CF9AE}' pid='2' name='Label'><vt:lpwstr>" + text + "</vt:lpwstr></property></Properties>"); break;
            case "custom-xml": case "custom-xml-properties":
                Add(zip, Main, "customXml/item1.xml", Rel + "customXml", "application/xml", "<data>" + (location == "custom-xml" ? text : "clean") + "</data>");
                if (location == "custom-xml-properties") Add(zip, "customXml/item1.xml", "customXml/itemProps1.xml", Rel + "customXmlProps", Ct + "customXmlProperties+xml",
                    "<ds:datastoreItem xmlns:ds='http://schemas.openxmlformats.org/officeDocument/2006/customXml' ds:itemID='{11111111-1111-1111-1111-111111111111}'><ds:schemaRefs><ds:schemaRef ds:uri='" + text + "'/></ds:schemaRefs></ds:datastoreItem>"); break;
            case "presentation": Write(zip, Main, Read(zip, Main).Replace("<p:presentation ", "<p:presentation label='" + text + "' ", StringComparison.Ordinal)); break;
            case "presentation-properties": PresentationPart(Main, "ppt/presProps.xml", "presProps", "presentationPr", "<p:extLst><p:ext uri='" + text + "'/></p:extLst>"); break;
            case "view-properties": PresentationPart(Main, "ppt/viewProps.xml", "viewProps", "viewPr", "<p:extLst><p:ext uri='" + text + "'/></p:extLst>"); break;
            case "table-styles": Add(zip, Main, "ppt/tableStyles.xml", Rel + "tableStyles", Ct + "presentationml.tableStyles+xml", "<a:tblStyleLst xmlns:a='" + PowerPointFixture.A + "' def='{11111111-1111-1111-1111-111111111111}'><a:tblStyle styleId='{11111111-1111-1111-1111-111111111111}' styleName='" + text + "'/></a:tblStyleLst>"); break;
            case "theme": case "theme-override":
                bool theme = location == "theme";
                Add(zip, Main, "ppt/theme/theme1.xml", Rel + (theme ? "theme" : "themeOverride"), Ct + (theme ? "theme" : "themeOverride") + "+xml",
                    "<a:" + (theme ? "theme" : "themeOverride") + " xmlns:a='" + PowerPointFixture.A + "' name='" + text + "'/>"); break;
            case "vml": Add(zip, Slide, "ppt/drawings/vml1.vml", Rel + "vmlDrawing", Ct + "vmlDrawing", "<xml xmlns:v='urn:schemas-microsoft-com:vml'><v:shape><v:textbox><div>" + text + "</div></v:textbox></v:shape></xml>"); break;
            default:
                string id = PowerPointFixture.Relationship(zip, Slide, location == "hyperlink" ? Rel + "hyperlink" : "urn:safeupload:external", "https://example.test/" + text, external: true);
                if (location == "hyperlink") Write(zip, Slide, SlideXml(Shape("<a:p><a:r><a:rPr><a:hlinkClick r:id='" + id + "'/></a:rPr><a:t>clean link</a:t></a:r></a:p>"))); break;
        }
        return path;
    }

    private static string Table(params string[] values) => "<p:graphicFrame><a:graphic><a:graphicData uri='http://schemas.openxmlformats.org/drawingml/2006/table'><a:tbl><a:tr>" +
        string.Concat(values.Select(value => "<a:tc><a:txBody><a:bodyPr/><a:lstStyle/>" + Rich(value) + "</a:txBody></a:tc>")) + "</a:tr></a:tbl></a:graphicData></a:graphic></p:graphicFrame>";
    private static string DiagramNode(string text) => "<d:pt modelId='1'><d:t>" + Rich(text) + "</d:t></d:pt>";
    private static void AddDiagram(ZipArchive zip, string nodes) => Add(zip, Slide, "ppt/diagrams/data1.xml", Rel + "diagramData", Ct + "drawingml.diagramData+xml",
        "<d:dataModel xmlns:d='" + D + "' xmlns:a='" + PowerPointFixture.A + "'><d:ptLst>" + nodes + "</d:ptLst></d:dataModel>");
    private static void AddChart(ZipArchive zip, string body) => Add(zip, Slide, "ppt/charts/chart1.xml", Rel + "chart", Ct + "drawingml.chart+xml", ChartXml(body));
    private static void AddModernComment(ZipArchive zip, string paragraphs, string? reply = null) => Add(zip, Slide, "ppt/comments/modern1.xml", "http://schemas.microsoft.com/office/2018/10/relationships/comments", "application/vnd.ms-powerpoint.comments+xml",
        "<m:cmLst xmlns:m='" + PowerPointFixture.Modern + "' xmlns:a='" + PowerPointFixture.A + "'><m:cm id='{22222222-2222-2222-2222-222222222222}' authorId='{11111111-1111-1111-1111-111111111111}'><m:txBody><a:bodyPr/><a:lstStyle/>" + paragraphs + "</m:txBody>" +
        (reply is null ? "" : "<m:replyLst><m:reply id='{33333333-3333-3333-3333-333333333333}' authorId='{11111111-1111-1111-1111-111111111111}'><m:txBody><a:bodyPr/><a:lstStyle/>" + reply + "</m:txBody></m:reply></m:replyLst>") + "</m:cm></m:cmLst>");
    private static void AddCore(ZipArchive zip, string body) => Add(zip, "", "docProps/core.xml", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "application/vnd.openxmlformats-package.core-properties+xml",
        "<cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' xmlns:dc='http://purl.org/dc/elements/1.1/'>" + body + "</cp:coreProperties>");
}
