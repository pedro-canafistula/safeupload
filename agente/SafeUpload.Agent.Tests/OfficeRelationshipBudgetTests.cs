using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

[Collection("Plaintext memory")]
public sealed class OfficeRelationshipBudgetTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Excessive_reachable_parts_fail_explicitly_before_clean_text_can_authorize_the_package()
    {
        string path = _workspace.WriteWordDocument("relationships.docx", "Clean main text.");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            XDocument types = Read(archive, "[Content_Types].xml");
            XNamespace relationships = "http://schemas.openxmlformats.org/package/2006/relationships";
            var links = new XDocument(new XElement(relationships + "Relationships"));
            for (int i = 0; i < 17_000; i++)
            {
                string name = "word/headers/part" + i + ".xml";
                types.Root!.Add(new XElement(types.Root.Name.Namespace + "Override", new XAttribute("PartName", "/" + name),
                    new XAttribute("ContentType", "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml")));
                links.Root!.Add(new XElement(relationships + "Relationship", new XAttribute("Id", "header" + i),
                    new XAttribute("Type", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header"),
                    new XAttribute("Target", "/" + name)));
                Write(archive, name, "<w:hdr xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" />");
            }
            Write(archive, "[Content_Types].xml", types.ToString());
            Write(archive, "word/_rels/document.xml.rels", links.ToString());
        }
        byte[] original = await File.ReadAllBytesAsync(path);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal("inspection_limit", result.Reason);
            Assert.Equal(InspectionFailureKind.Limit, result.FailureKind);
            Assert.Empty(result.Findings);
        }
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    private static XDocument Read(ZipArchive archive, string name)
    { using var input = archive.GetEntry(name)!.Open(); return XDocument.Load(input); }
    private static void Write(ZipArchive archive, string name, string text)
    { archive.GetEntry(name)?.Delete(); using var writer = new StreamWriter(archive.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(text); }
}
