using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

// Relationship/content-type XML is authored without the extractor's SDK writer.
public sealed class OfficeUnsupportedPayloadTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private const string OfficeRelationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";
    private static readonly XNamespace Relationships = "http://schemas.openxmlformats.org/package/2006/relationships";
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("word", "body", "image")]
    [InlineData("word", "header", "image")]
    [InlineData("word", "footnotes", "image")]
    [InlineData("word", "body", "oleObject")]
    [InlineData("word", "body", "package")]
    [InlineData("word", "body", "aFChunk")]
    [InlineData("word", "body", "control")]
    [InlineData("word", "package", "thumbnail")]
    [InlineData("sheet", "body", "image")]
    [InlineData("sheet", "drawing", "image")]
    [InlineData("sheet", "body", "oleObject")]
    [InlineData("sheet", "body", "package")]
    [InlineData("sheet", "body", "control")]
    [InlineData("sheet", "package", "thumbnail")]
    public async Task Clean_text_does_not_approve_uninspected_payloads(string format, string owner, string kind)
    {
        string path = Fixture(format, owner, kind);
        byte[] original = File.ReadAllBytes(path);
        ITextExtractor extractor = format == "word" ? new OpenXmlWordExtractor() : new OpenXmlSheetExtractor();
        using (var input = File.OpenRead(path))
            await Assert.ThrowsAsync<UnsupportedContentException>(() => extractor.ExtractAsync(input, CancellationToken.None));

        var service = Service();
        foreach (bool staged in new[] { false, true })
        {
            var result = staged
                ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal("unsupported_format", result.Reason);
            Assert.Equal(InspectionFailureKind.UnsupportedFormat, result.FailureKind);
            Assert.Empty(result.Findings);
        }
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData("word")]
    [InlineData("sheet")]
    public async Task Text_only_package_still_passes_the_payload_check(string format)
    {
        string path = CleanFixture(format);
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Approved, result.Verdict);
        Assert.Null(result.Reason);
    }

    private string CleanFixture(string format)
    {
        string stem = "payload-" + Guid.NewGuid().ToString("N");
        return format == "word" ? _workspace.WriteWordDocument(stem + ".docx", "Clean body.")
            : _workspace.WriteSpreadsheet(stem + ".xlsx", "Clean cell.");
    }

    private string Fixture(string format, string owner, string kind)
    {
        string path = CleanFixture(format);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Update);
        string parent = format == "word" ? "word/document.xml" : "xl/worksheets/sheet1.xml";
        if (owner is "header" or "footnotes")
        {
            string name = "word/" + owner + ".xml";
            AddPart(archive, parent, name, OfficeRelationships + owner,
                "application/vnd.openxmlformats-officedocument.wordprocessingml." + owner + "+xml",
                $"<w:{(owner == "header" ? "hdr" : "footnotes")} xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" />");
            parent = name;
        }
        else if (owner == "drawing")
        {
            string name = "xl/drawings/drawing1.xml";
            AddPart(archive, parent, name, OfficeRelationships + "drawing",
                "application/vnd.openxmlformats-officedocument.drawing+xml",
                "<xdr:wsDr xmlns:xdr=\"http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing\" />");
            parent = name;
        }
        else if (owner == "package") parent = "";

        var (contentType, extension) = kind switch
        {
            "image" or "thumbnail" => ("image/png", "png"),
            "oleObject" => ("application/vnd.openxmlformats-officedocument.oleObject", "bin"),
            "package" => ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
            "aFChunk" => ("text/html", "html"),
            "control" => ("application/vnd.ms-office.activeX+xml", "xml"),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        string relationship = kind == "thumbnail"
            ? "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail"
            : OfficeRelationships + kind;
        string payload = kind == "control"
            ? "<ax:ocx xmlns:ax=\"http://schemas.microsoft.com/office/2006/activeX\" />"
            : "<html><body>CPF: 529.982.247-25</body></html>";
        string payloadName = "payloads/secret." + extension;
        AddPart(archive, parent, payloadName, relationship, contentType, payload);
        if (kind is "image" or "thumbnail")
        {
            // A valid white RGB pixel, also used by the existing PDF image control.
            archive.GetEntry(payloadName)!.Delete();
            using var output = archive.CreateEntry(payloadName).Open();
            output.Write(Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4//8/AAX+Av4N70a4AAAAAElFTkSuQmCC"));
        }
        else if (kind == "package")
        {
            byte[] embedded = File.ReadAllBytes(_workspace.WriteWordDocument("embedded.docx", "CPF: 529.982.247-25"));
            archive.GetEntry(payloadName)!.Delete();
            using var output = archive.CreateEntry(payloadName).Open();
            output.Write(embedded);
        }
        return path;
    }

    private static void AddPart(ZipArchive archive, string parent, string name, string relationship, string contentType, string content)
    {
        var types = XDocument.Parse(Read(archive, "[Content_Types].xml"));
        types.Root!.Add(new XElement(types.Root.Name.Namespace + "Override",
            new XAttribute("PartName", "/" + name), new XAttribute("ContentType", contentType)));
        Write(archive, "[Content_Types].xml", types.ToString());
        string relPath = parent.Length == 0 ? "_rels/.rels"
            : parent[..(parent.LastIndexOf('/') + 1)] + "_rels/" + parent[(parent.LastIndexOf('/') + 1)..] + ".rels";
        var relations = archive.GetEntry(relPath) is null ? new XDocument(new XElement(Relationships + "Relationships"))
            : XDocument.Parse(Read(archive, relPath));
        relations.Root!.Add(new XElement(Relationships + "Relationship", new XAttribute("Id", "payload-" + Guid.NewGuid().ToString("N")),
            new XAttribute("Type", relationship), new XAttribute("Target", "/" + name)));
        Write(archive, relPath, relations.ToString());
        Write(archive, name, content);
    }

    private InspectionService Service() => new(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
        ExtractorRegistry.CreateDefault(), new VerdictCache());
    private static string Read(ZipArchive archive, string name)
    { using var reader = new StreamReader(archive.GetEntry(name)!.Open(), Encoding.UTF8); return reader.ReadToEnd(); }
    private static void Write(ZipArchive archive, string name, string text)
    { archive.GetEntry(name)?.Delete(); using var writer = new StreamWriter(archive.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(text); }
}
