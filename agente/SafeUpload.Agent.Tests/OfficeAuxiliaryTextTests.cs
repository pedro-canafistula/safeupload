using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

// Package XML is authored independently of the extractor's SDK object model.
public sealed class OfficeAuxiliaryTextTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();
    private const string Word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private const string Sheet = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    private string Fixture(string part, string first, string? second = null, bool damaged = false)
    {
        bool spreadsheet = part == "sheet-comments";
        string stem = "notes-" + Guid.NewGuid().ToString("N");
        string path = spreadsheet ? _workspace.WriteSpreadsheet(stem + ".xlsx", "Clean cell.")
            : _workspace.WriteWordDocument(stem + ".docx", "Clean body.");
        string name = spreadsheet ? "xl/comments1.xml" : "word/" + part + ".xml";
        string contentType = "application/vnd.openxmlformats-officedocument." +
            (spreadsheet ? "spreadsheetml.comments+xml" : "wordprocessingml." + part + "+xml");
        XNamespace ns = spreadsheet ? Sheet : Word;
        XElement Text(string value) => spreadsheet
            ? new XElement(ns + "text", new XElement(ns + "r", new XElement(ns + "t", value)))
            : new XElement(ns + "p", new XElement(ns + "r", new XElement(ns + "t", value)));
        string member = part switch { "footnotes" => "footnote", "endnotes" => "endnote", _ => "comment" };
        XElement Entry(string value, int id) => new(ns + member,
            spreadsheet ? new XAttribute("ref", "A" + id) : new XAttribute(ns + "id", id),
            spreadsheet ? new XAttribute("authorId", 0) : new XAttribute(ns + "author", "Author"), Text(value));
        var entries = new List<XElement> { Entry(first, 1) }; if (second is not null) entries.Add(Entry(second, 2));
        var root = spreadsheet ? new XElement(ns + "comments", new XElement(ns + "authors", new XElement(ns + "author", "Author")),
            new XElement(ns + "commentList", entries)) : new XElement(ns + part, entries);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Update);
        var types = XDocument.Parse(Read(archive, "[Content_Types].xml"));
        types.Root!.Add(new XElement(types.Root.Name.Namespace + "Override", new XAttribute("PartName", "/" + name),
            new XAttribute("ContentType", contentType)));
        Write(archive, "[Content_Types].xml", types.ToString());
        string relPath = spreadsheet ? "xl/worksheets/_rels/sheet1.xml.rels" : "word/_rels/document.xml.rels";
        XNamespace relationships = "http://schemas.openxmlformats.org/package/2006/relationships";
        Write(archive, relPath, new XElement(relationships + "Relationships", new XElement(relationships + "Relationship",
            new XAttribute("Id", "notes"), new XAttribute("Type", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/" +
                (spreadsheet ? "comments" : part)), new XAttribute("Target", spreadsheet ? "../comments1.xml" : part + ".xml"))).ToString());
        Write(archive, name, damaged ? "<broken" : root.ToString());
        return path;
    }

    [Theory]
    [InlineData("footnotes")]
    [InlineData("endnotes")]
    [InlineData("comments")]
    [InlineData("sheet-comments")]
    public async Task Sensitive_auxiliary_text_is_scanned_without_changing_the_package(string part)
    {
        string path = Fixture(part, "CPF: 529.982.247-25"); byte[] original = File.ReadAllBytes(path);
        var service = Service();
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Null(result.Reason);
            Assert.Equal(Category.Cpf, Assert.Single(result.Categories));
            Assert.DoesNotContain("529.982.247-25", Assert.Single(result.Findings).MaskedSnippet);
        }
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData("footnotes")]
    [InlineData("endnotes")]
    [InlineData("comments")]
    [InlineData("sheet-comments")]
    public async Task Adjacent_notes_do_not_invent_a_number_and_empty_text_remains_valid(string part)
    {
        string path = Fixture(part, "11222333", "000181");
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Approved, result.Verdict); Assert.Empty(result.Findings);
        string empty = Fixture(part, "");
        result = await Service().InspectStagedAsync(TestWorkspace.Operation(empty), CancellationToken.None);
        Assert.Equal(Verdict.Approved, result.Verdict); Assert.Null(result.Reason);
    }

    [Theory]
    [InlineData("footnotes")]
    [InlineData("endnotes")]
    [InlineData("comments")]
    [InlineData("sheet-comments")]
    public async Task Damaged_auxiliary_part_never_becomes_a_clean_partial_extraction(string part)
    {
        string path = Fixture(part, "CPF: 529.982.247-25", damaged: true); var service = Service();
        string original = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Empty(result.Findings); Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
            Assert.StartsWith("parse_error:", result.Reason);
        }
        Assert.Equal(original, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
    }

    private InspectionService Service() => new(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
        ExtractorRegistry.CreateDefault(), new VerdictCache());
    private static string Read(ZipArchive archive, string name)
    { using var reader = new StreamReader(archive.GetEntry(name)!.Open(), Encoding.UTF8); return reader.ReadToEnd(); }
    private static void Write(ZipArchive archive, string name, string xml)
    { archive.GetEntry(name)?.Delete(); using var writer = new StreamWriter(archive.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(xml); }
}
