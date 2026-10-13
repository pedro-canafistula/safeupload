using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

// Fixtures are independent package XML, not Open XML SDK serialization.
public sealed class OfficeContentCoverageTests : IDisposable
{
    private const string Cpf = "529.982.247-25";
    private const string W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private const string S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private const string A = "http://schemas.openxmlformats.org/drawingml/2006/main";
    private const string C = "http://schemas.openxmlformats.org/drawingml/2006/chart";
    private const string Xdr = "http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing";
    private const string Rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";
    private const string Ct = "application/vnd.openxmlformats-officedocument.";
    private const string Modern = "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments";
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("shape")]
    [InlineData("group-shape")]
    [InlineData("drawing-descr")]
    [InlineData("drawing-title")]
    [InlineData("chart-title")]
    [InlineData("chart-axis")]
    [InlineData("chart-series")]
    [InlineData("chart-category")]
    [InlineData("chart-number")]
    [InlineData("chart-formula")]
    [InlineData("chart-label")]
    [InlineData("vml")]
    [InlineData("threaded-comment")]
    [InlineData("person")]
    public async Task Spreadsheet_drawing_chart_and_modern_comment_payloads_are_inspected(string location)
    {
        await Check(Fixture(location, Cpf), sensitive: true);
        await Check(Fixture(location, "clean"), sensitive: false);
    }

    [Theory]
    [InlineData("sheet-name")]
    [InlineData("defined-name")]
    [InlineData("core-title")]
    [InlineData("core-keywords")]
    [InlineData("app-company")]
    [InlineData("app-manager")]
    [InlineData("app-titles")]
    [InlineData("app-headings")]
    [InlineData("worksheet-header")]
    [InlineData("validation-prompt")]
    [InlineData("style-format")]
    public async Task Spreadsheet_metadata_and_other_admitted_strings_are_inspected(string location)
        => await Check(Fixture(location, Cpf), sensitive: true);

    [Theory]
    [InlineData("choice")]
    [InlineData("fallback")]
    [InlineData("docpr-descr")]
    [InlineData("docpr-title")]
    [InlineData("core-title")]
    [InlineData("app-company")]
    [InlineData("comment-author")]
    public async Task Word_alternate_textboxes_descriptions_and_properties_are_inspected(string location)
        => await Check(Fixture(location, Cpf, word: true), sensitive: true);

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Office_unknown_reachable_and_unreferenced_parts_are_refused(bool word, bool orphan)
    {
        string path = Clean(word);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            if (orphan) Write(zip, "unreferenced.xml", "<text>" + Cpf + "</text>");
            else Add(zip, word ? "word/document.xml" : "xl/workbook.xml", "unknown.xml", "urn:safeupload:unknown",
                "application/xml", "<text>" + Cpf + "</text>");
        }
        await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData("fake-relationships")]
    [InlineData("duplicate-entry")]
    public async Task Office_package_inventory_cannot_hide_content_as_infrastructure(string shape)
    {
        string path = Clean(word: false);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            if (shape == "fake-relationships") Write(zip, "xl/_rels/orphan.xml.rels", "<payload>" + Cpf + "</payload>");
            else
            {
                using var writer = new StreamWriter(zip.CreateEntry("xl/worksheets/sheet1.xml").Open());
                writer.Write("<worksheet xmlns='" + S + "'><sheetData/></worksheet>");
            }
        }
        // ZIP/OPC implementations may reject duplicate entries while opening the
        // package, before the explicit inventory. Neither path may approve it.
        if (shape == "fake-relationships") await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
        else
        {
            byte[] original = File.ReadAllBytes(path);
            var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache());
            foreach (bool staged in new[] { false, true })
            {
                var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                    : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
                Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
                Assert.True(result.FailureKind is InspectionFailureKind.UnsupportedFormat or InspectionFailureKind.ReadOrParse);
                if (result.FailureKind == InspectionFailureKind.UnsupportedFormat) Assert.Equal("unsupported_format", result.Reason);
                else Assert.StartsWith("parse_error:", result.Reason);
                Assert.Empty(result.Findings); Assert.Equal(original, File.ReadAllBytes(path));
            }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Office_allowlisted_clean_packages_are_approved(bool word)
    {
        string path = Fixture("app-company", "Clean Company", word);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            if (word)
            {
                Add(zip, "word/document.xml", "word/styles.xml", Rel + "styles", Ct + "wordprocessingml.styles+xml",
                    "<w:styles xmlns:w='" + W + "'><w:style w:type='paragraph' w:styleId='Normal'><w:name w:val='Normal'/></w:style></w:styles>");
                Add(zip, "word/document.xml", "word/numbering.xml", Rel + "numbering", Ct + "wordprocessingml.numbering+xml",
                    "<w:numbering xmlns:w='" + W + "'/>");
            }
            else Add(zip, "xl/workbook.xml", "xl/styles.xml", Rel + "styles", Ct + "spreadsheetml.styles+xml",
                "<styleSheet xmlns='" + S + "'><numFmts count='1'><numFmt numFmtId='164' formatCode='0.00'/></numFmts></styleSheet>");
        }
        await Check(path);
    }

    [Theory]
    [InlineData("shape")]
    [InlineData("chart-title")]
    [InlineData("vml")]
    public async Task Rich_runs_remain_contiguous_but_separate_items_cannot_invent_a_cpf(string location)
    {
        // Fixture splits shape/chart rich text and VML spans inside one item.
        await Check(Fixture(location, Cpf), sensitive: true);
        string path = Fixture(location, "clean");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            string name = location == "vml" ? "xl/drawings/vml1.vml" : location == "shape" ? "xl/drawings/drawing1.xml" : "xl/charts/chart1.xml";
            string xml = location == "vml"
                ? "<xml xmlns:v='urn:schemas-microsoft-com:vml'><v:shape><v:textbox><div>529.982.</div><div>247-25</div></v:textbox></v:shape></xml>"
                : location == "shape"
                    ? "<xdr:wsDr xmlns:xdr='" + Xdr + "' xmlns:a='" + A + "'><xdr:sp><xdr:txBody>" + Rich("529.982.") + Rich("247-25") + "</xdr:txBody></xdr:sp></xdr:wsDr>"
                    : "<c:chartSpace xmlns:c='" + C + "' xmlns:a='" + A + "'><c:chart><c:title><c:tx><c:rich>" + Rich("529.982.") + Rich("247-25") + "</c:rich></c:tx></c:title></c:chart></c:chartSpace>";
            Write(zip, name, xml);
        }
        await Check(path);
    }

    [Theory]
    [InlineData("shape", "")]
    [InlineData("shape", "<wrong/>")]
    [InlineData("chart-title", "<broken")]
    [InlineData("vml", "<xml><broken></xml>")]
    public async Task Malformed_auxiliary_xml_never_returns_partial_approval(string location, string xml)
    {
        string path = Fixture(location, "clean");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Write(zip, location == "vml" ? "xl/drawings/vml1.vml" : location == "shape" ? "xl/drawings/drawing1.xml" : "xl/charts/chart1.xml", xml);
        await Check(path, failure: InspectionFailureKind.ReadOrParse);
    }

    [Fact]
    public async Task Drawing_depth_limit_refuses_nested_groups()
    {
        string path = Fixture("group-shape", "clean");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Write(zip, "xl/drawings/drawing1.xml", "<xdr:wsDr xmlns:xdr='" + Xdr + "'>" +
                string.Concat(Enumerable.Repeat("<xdr:grpSp>", 257)) + string.Concat(Enumerable.Repeat("</xdr:grpSp>", 257)) + "</xdr:wsDr>");
        await Check(path, failure: InspectionFailureKind.Limit);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Auxiliary_streaming_and_legacy_extraction_are_identical(int chunk)
    {
        foreach (bool word in new[] { false, true })
        {
            string path = Fixture(word ? "choice" : "chart-title", Cpf, word);
            IStreamingTextExtractor extractor = word ? new OpenXmlWordExtractor() : new OpenXmlSheetExtractor();
            using var stream = File.OpenRead(path);
            var actual = new StringBuilder(); var buffer = new char[chunk]; int count;
            using (var reader = await extractor.OpenReaderAsync(stream, CancellationToken.None))
                while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) actual.Append(buffer, 0, count);
            Assert.True(stream.CanRead); stream.Position = 0;
            Assert.Equal(await extractor.ExtractAsync(stream, CancellationToken.None), actual.ToString());
            Assert.Contains(Cpf, actual.ToString());
        }
    }

    private string Fixture(string location, string text, bool word = false)
    {
        string path = Clean(word);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Update);
        string main = word ? "word/document.xml" : "xl/workbook.xml";
        if (location.StartsWith("core-", StringComparison.Ordinal))
        {
            string property = location[5..]; string ns = property == "title" ? "dc" : "cp";
            Add(zip, "", "docProps/core.xml", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
                "application/vnd.openxmlformats-package.core-properties+xml", "<cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/metadata/core-properties' " +
                "xmlns:dc='http://purl.org/dc/elements/1.1/'><" + ns + ":" + property + ">" + text + "</" + ns + ":" + property + "></cp:coreProperties>");
        }
        else if (location.StartsWith("app-", StringComparison.Ordinal))
        {
            string value = location switch
            {
                "app-company" => "<Company>" + text + "</Company>",
                "app-manager" => "<Manager>" + text + "</Manager>",
                "app-titles" => "<TitlesOfParts><vt:vector size='1' baseType='lpstr'><vt:lpstr>" + text + "</vt:lpstr></vt:vector></TitlesOfParts>",
                _ => "<HeadingPairs><vt:vector size='2' baseType='variant'><vt:variant><vt:lpstr>" + text + "</vt:lpstr></vt:variant><vt:variant><vt:i4>1</vt:i4></vt:variant></vt:vector></HeadingPairs>"
            };
            Add(zip, "", "docProps/app.xml", Rel + "extended-properties", Ct + "extended-properties+xml",
                "<Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/extended-properties' xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'>" + value + "</Properties>");
        }
        else if (word)
        {
            if (location == "comment-author")
                Add(zip, main, "word/comments.xml", Rel + "comments", Ct + "wordprocessingml.comments+xml",
                    "<w:comments xmlns:w='" + W + "'><w:comment w:id='0' w:author='" + text + "'><w:p><w:r><w:t>clean</w:t></w:r></w:p></w:comment></w:comments>");
            else
            {
                string Box(string value) => "<w:txbxContent><w:p><w:r><w:t>" + value + "</w:t></w:r></w:p></w:txbxContent>";
                string payload = location.StartsWith("docpr-", StringComparison.Ordinal)
                    ? "<w:drawing><wp:inline><wp:docPr id='1' name='Shape' " + location[6..] + "='" + text + "'/></wp:inline></w:drawing>"
                    : "<mc:AlternateContent><mc:Choice Requires='wps'><wps:wsp>" + Box(location == "choice" ? text : "clean choice") +
                        "</wps:wsp></mc:Choice><mc:Fallback><w:pict><v:shape><v:textbox>" + Box(location == "fallback" ? text : "clean fallback") +
                        "</v:textbox></v:shape></w:pict></mc:Fallback></mc:AlternateContent>";
                Write(zip, main, "<w:document xmlns:w='" + W + "' xmlns:mc='http://schemas.openxmlformats.org/markup-compatibility/2006' " +
                    "xmlns:wps='http://schemas.microsoft.com/office/word/2010/wordprocessingShape' xmlns:v='urn:schemas-microsoft-com:vml' " +
                    "xmlns:wp='http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'><w:body><w:p><w:r><w:t>clean</w:t>" + payload + "</w:r></w:p></w:body></w:document>");
            }
        }
        else if (location is "sheet-name" or "defined-name")
        {
            string xml = Read(zip, main);
            Write(zip, main, location == "sheet-name" ? xml.Replace("Plan1", text, StringComparison.Ordinal)
                : xml.Replace("</workbook>", "<definedNames><definedName name='Private'>" + text + "</definedName></definedNames></workbook>", StringComparison.Ordinal));
        }
        else if (location is "worksheet-header" or "validation-prompt")
        {
            string name = "xl/worksheets/sheet1.xml";
            Write(zip, name, Read(zip, name).Replace("</worksheet>", (location == "worksheet-header"
                ? "<headerFooter><oddHeader>" + text + "</oddHeader></headerFooter>"
                : "<dataValidations count='1'><dataValidation sqref='A1' prompt='" + text + "'/></dataValidations>") + "</worksheet>", StringComparison.Ordinal));
        }
        else if (location == "style-format")
            Add(zip, main, "xl/styles.xml", Rel + "styles", Ct + "spreadsheetml.styles+xml", "<styleSheet xmlns='" + S + "'><numFmts count='1'><numFmt numFmtId='164' formatCode='" + text + "'/></numFmts></styleSheet>");
        else if (location is "threaded-comment" or "person")
        {
            Add(zip, "xl/worksheets/sheet1.xml", "xl/threadedComments/threadedComment1.xml", "http://schemas.microsoft.com/office/2017/10/relationships/threadedComment",
                "application/vnd.ms-excel.threadedcomments+xml", "<ThreadedComments xmlns='" + Modern + "'><threadedComment ref='A1' personId='{11111111-1111-1111-1111-111111111111}' id='{22222222-2222-2222-2222-222222222222}'><text>" + (location == "person" ? "clean" : text) + "</text></threadedComment></ThreadedComments>");
            Add(zip, main, "xl/persons/person.xml", "http://schemas.microsoft.com/office/2017/10/relationships/person", "application/vnd.ms-excel.person+xml",
                "<personList xmlns='" + Modern + "'><person displayName='" + (location == "person" ? text : "Author") + "' id='{11111111-1111-1111-1111-111111111111}' userId='author@example.test' providerId='None'/></personList>");
        }
        else if (location == "vml")
            Add(zip, "xl/worksheets/sheet1.xml", "xl/drawings/vml1.vml", Rel + "vmlDrawing", Ct + "vmlDrawing",
                "<xml xmlns:v='urn:schemas-microsoft-com:vml'><v:shape><v:textbox><div><span>" + text[..(text.Length / 2)] + "</span><span>" + text[(text.Length / 2)..] + "</span></div></v:textbox></v:shape></xml>");
        else
        {
            string shape = location is "shape" or "group-shape" ? "<xdr:sp><xdr:txBody>" + Rich(text) + "</xdr:txBody></xdr:sp>"
                : location.StartsWith("drawing-", StringComparison.Ordinal) ? "<xdr:sp><xdr:nvSpPr><xdr:cNvPr id='1' name='Shape' " + location[8..] + "='" + text + "'/></xdr:nvSpPr></xdr:sp>" : "";
            if (location == "group-shape") shape = "<xdr:grpSp><xdr:grpSp>" + shape + "</xdr:grpSp></xdr:grpSp>";
            Add(zip, "xl/worksheets/sheet1.xml", "xl/drawings/drawing1.xml", Rel + "drawing", Ct + "drawing+xml",
                "<xdr:wsDr xmlns:xdr='" + Xdr + "' xmlns:a='" + A + "'>" + shape + "</xdr:wsDr>");
            if (location.StartsWith("chart-", StringComparison.Ordinal))
            {
                string title = "<c:title><c:tx><c:rich>" + Rich(text) + "</c:rich></c:tx></c:title>";
                string chart = location switch
                {
                    "chart-title" => title,
                    "chart-axis" => "<c:plotArea><c:catAx>" + title + "</c:catAx></c:plotArea>",
                    "chart-series" => "<c:plotArea><c:barChart><c:ser><c:tx><c:v>" + text + "</c:v></c:tx></c:ser></c:barChart></c:plotArea>",
                    "chart-label" => "<c:plotArea><c:barChart><c:dLbls><c:dLbl><c:tx><c:rich>" + Rich(text) + "</c:rich></c:tx></c:dLbl></c:dLbls></c:barChart></c:plotArea>",
                    "chart-formula" => "<c:plotArea><c:barChart><c:ser><c:cat><c:strRef><c:f>" + text + "</c:f></c:strRef></c:cat></c:ser></c:barChart></c:plotArea>",
                    "chart-number" => "<c:plotArea><c:barChart><c:ser><c:val><c:numRef><c:f>Plan1!$A$1</c:f><c:numCache><c:formatCode>General</c:formatCode><c:ptCount val='1'/><c:pt idx='0'><c:v>" +
                        (text == Cpf ? "52998224725" : "42") + "</c:v></c:pt></c:numCache></c:numRef></c:val></c:ser></c:barChart></c:plotArea>",
                    _ => "<c:plotArea><c:barChart><c:ser><c:cat><c:strRef><c:f>Plan1!$A$1</c:f><c:strCache><c:ptCount val='1'/><c:pt idx='0'><c:v>" + text +
                        "</c:v></c:pt></c:strCache></c:strRef></c:cat></c:ser></c:barChart></c:plotArea>"
                };
                Add(zip, "xl/drawings/drawing1.xml", "xl/charts/chart1.xml", Rel + "chart", Ct + "drawingml.chart+xml",
                    "<c:chartSpace xmlns:c='" + C + "' xmlns:a='" + A + "'><c:chart>" + chart + "</c:chart></c:chartSpace>");
            }
        }
        return path;
    }

    private static string Rich(string text) => "<a:p><a:r><a:t>" + text[..(text.Length / 2)] + "</a:t></a:r><a:r><a:t>" + text[(text.Length / 2)..] + "</a:t></a:r></a:p>";
    private string Clean(bool word) => word ? _workspace.WriteWordDocument(Guid.NewGuid() + ".docx", "clean body")
        : _workspace.WriteSpreadsheet(Guid.NewGuid() + ".xlsx", "clean cell");
    private async Task Check(string path, bool sensitive = false, InspectionFailureKind? failure = null)
    {
        byte[] original = File.ReadAllBytes(path);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        foreach (bool staged in new[] { false, true })
        {
            var operation = TestWorkspace.Operation(path);
            var result = staged ? await service.InspectStagedAsync(operation, CancellationToken.None) : await service.InspectAsync(operation, CancellationToken.None);
            Assert.Equal(failure is not null ? staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection : sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Equal(failure, result.FailureKind);
            if (failure == InspectionFailureKind.UnsupportedFormat) Assert.Equal("unsupported_format", result.Reason);
            else if (failure == InspectionFailureKind.Limit) Assert.Equal("inspection_limit", result.Reason);
            else if (failure == InspectionFailureKind.ReadOrParse) Assert.StartsWith("parse_error:", result.Reason);
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
    private static void Add(ZipArchive zip, string parent, string name, string relationship, string contentType, string xml)
    {
        var types = XDocument.Parse(Read(zip, "[Content_Types].xml"));
        types.Root!.Add(new XElement(types.Root.Name.Namespace + "Override", new XAttribute("PartName", "/" + name), new XAttribute("ContentType", contentType)));
        Write(zip, "[Content_Types].xml", types.ToString());
        string relPath = parent.Length == 0 ? "_rels/.rels" : parent[..(parent.LastIndexOf('/') + 1)] + "_rels/" + parent[(parent.LastIndexOf('/') + 1)..] + ".rels";
        XNamespace ns = "http://schemas.openxmlformats.org/package/2006/relationships";
        var relations = zip.GetEntry(relPath) is null ? new XDocument(new XElement(ns + "Relationships")) : XDocument.Parse(Read(zip, relPath));
        relations.Root!.Add(new XElement(ns + "Relationship", new XAttribute("Id", "coverage-" + Guid.NewGuid().ToString("N")), new XAttribute("Type", relationship), new XAttribute("Target", "/" + name)));
        Write(zip, relPath, relations.ToString()); Write(zip, name, xml);
    }
    private static string Read(ZipArchive zip, string name)
    { using var reader = new StreamReader(zip.GetEntry(name)!.Open()); return reader.ReadToEnd(); }
    private static void Write(ZipArchive zip, string name, string text)
    { zip.GetEntry(name)?.Delete(); using var writer = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(text); }
}
