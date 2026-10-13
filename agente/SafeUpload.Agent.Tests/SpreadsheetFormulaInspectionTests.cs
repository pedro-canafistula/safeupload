using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class SpreadsheetFormulaInspectionTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("formula-secret", false)]
    [InlineData("formula-secret", true)]
    [InlineData("cached-cpf", false)]
    [InlineData("cached-cpf", true)]
    [InlineData("both-cpf", false)]
    [InlineData("both-cpf", true)]
    [InlineData("clean", false)]
    [InlineData("clean", true)]
    [InlineData("empty-cache", false)]
    [InlineData("empty-cache", true)]
    [InlineData("split-values", false)]
    [InlineData("split-values", true)]
    [InlineData("shared-secret", false)]
    [InlineData("shared-secret", true)]
    [InlineData("missing-cache", false)]
    [InlineData("missing-cache", true)]
    [InlineData("missing-shared-cache", false)]
    [InlineData("missing-shared-cache", true)]
    [InlineData("ordinary-blank", false)]
    [InlineData("ordinary-blank", true)]
    public async Task Formula_text_and_cached_results_are_both_inspected_and_missing_results_refuse(string shape, bool staged)
    {
        string cells = shape switch
        {
            "formula-secret" => "<c r='A1' t='str'><f>&quot;AKIAIOSFODNN7EXAMPLE&quot;</f><v>clean display</v></c>",
            "cached-cpf" => "<c r='A1' t='str'><f>CONCAT(&quot;529.&quot;,&quot;982.&quot;,&quot;247-25&quot;)</f><v>529.982.247-25</v></c>",
            "both-cpf" => "<c r='A1' t='str'><f>&quot;529.982.247-25&quot;</f><v>529.982.247-25</v></c>",
            "clean" => "<c r='A1'><f>1+1</f><v>2</v></c>",
            "empty-cache" => "<c r='A1' t='str'><f>&quot;&quot;</f><v/></c>",
            "split-values" => "<c r='A1'><f>11222333</f><v>000181</v></c>",
            "shared-secret" => "<c r='A1' t='str'><f t='shared' si='0' ref='A1:A2'>&quot;AKIAIOSFODNN7EXAMPLE&quot;</f><v>clean</v></c>" +
                "</row><row r='2'><c r='A2' t='str'><f t='shared' si='0'/><v>clean</v></c>",
            "missing-cache" => "<c r='A1' t='str'><f>CONCAT(&quot;529.&quot;,&quot;982.&quot;,&quot;247-25&quot;)</f></c>",
            "missing-shared-cache" => "<c r='A1'><f t='shared' si='0' ref='A1:A2'>1+1</f><v>2</v></c>" +
                "</row><row r='2'><c r='A2'><f t='shared' si='0'/></c>",
            _ => "<c r='A1'/>"
        };
        string path = Fixture(cells), originalHash = Hash(path);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(path);
        var result = staged ? await service.InspectStagedAsync(operation, CancellationToken.None)
            : await service.InspectAsync(operation, CancellationToken.None);
        bool unsupported = shape is "missing-cache" or "missing-shared-cache";
        bool sensitive = shape is "formula-secret" or "shared-secret" or "cached-cpf" or "both-cpf";
        Assert.Equal(unsupported ? staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection
            : sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        Assert.True(result.InScope);
        if (unsupported)
        {
            Assert.Equal("unsupported_format", result.Reason);
            Assert.Equal(InspectionFailureKind.UnsupportedFormat, result.FailureKind);
            Assert.Empty(result.Findings);
        }
        else
        {
            Assert.Null(result.Reason); Assert.Null(result.FailureKind);
            if (sensitive)
            {
                Assert.Equal(shape == "both-cpf" ? 2 : 1, result.Findings.Count);
                Assert.All(result.Findings, finding => Assert.Equal(
                    shape.Contains("secret", StringComparison.Ordinal) ? Category.Secret : Category.Cpf, finding.Category));
            }
            else Assert.Empty(result.Findings);
        }
        if (staged)
            Assert.Equal(!unsupported && !sensitive,
                await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
        Assert.Equal(originalHash, Hash(path));
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", string.Join(" ", result.Findings.Select(f => f.MaskedSnippet)));
        var audit = await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(10, CancellationToken.None);
        Assert.Equal(staged ? 0 : 1, audit.Count);
    }

    // Author the ZIP and relationship XML independently of the extractor's SDK.
    private string Fixture(string cells)
    {
        string path = Path.Combine(_workspace.Root, "formula.xlsx");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        Write(archive, "[Content_Types].xml", """
            <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
              <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
              <Default Extension="xml" ContentType="application/xml"/>
              <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
              <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
            </Types>
            """);
        Write(archive, "_rels/.rels", """
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
            </Relationships>
            """);
        Write(archive, "xl/workbook.xml", """
            <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
              <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
            </workbook>
            """);
        Write(archive, "xl/_rels/workbook.xml.rels", """
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
            </Relationships>
            """);
        Write(archive, "xl/worksheets/sheet1.xml", "<worksheet xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'><sheetData><row r='1'>" +
            cells + "</row></sheetData></worksheet>");
        return path;
    }

    private static void Write(ZipArchive archive, string name, string xml)
    { using var writer = new StreamWriter(archive.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(xml); }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
