using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

[Collection("Plaintext memory")]
public sealed class SpreadsheetStreamingInspectionTests(ITestOutputHelper output) : IDisposable
{
    private const string Namespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Fragmented_reads_keep_rich_strings_cells_and_formulas_separate(int chunk)
    {
        string path = Fixture("<si><r><t>CPF: 529.</t></r><r><t>982.247-25</t></r></si><si><t>11222333</t></si><si><t>000181</t></si>",
            "<c r='A1' t='s'><v>0</v></c><c r='B1' t='inlineStr'><is><r><t>password</t></r><r><t>: abcde</t></r></is></c>" +
            "<c r='C1' t='str'><f>&quot;AKIAIOSFODNN7EXAMPLE&quot;</f><v>clean result</v></c>");
        string original = Hash(path);
        await using var input = File.OpenRead(path);
        using var reader = await new OpenXmlSheetExtractor().OpenReaderAsync(input, CancellationToken.None);
        var text = new StringBuilder(); var buffer = new char[chunk]; int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) text.Append(buffer, 0, count);
        Assert.Equal("CPF: 529.982.247-25\n11222333\n000181\npassword: abcde\n\"AKIAIOSFODNN7EXAMPLE\"\nclean result\n" +
            "Plan1\n1\nrId1\n1\nA1\ns\nB1\ninlineStr\nC1\nstr\n", text.ToString());
        var findings = ContentScanner.Scan(text.ToString(), Enum.GetValues<Category>().ToHashSet());
        Assert.Equal(new[] { Category.Cpf, Category.Password, Category.Secret }, findings.Select(f => f.Category));
        Assert.Equal(original, Hash(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Stored_shared_text_is_inspected_even_when_unused_and_references_do_not_duplicate_it(bool referenced)
    {
        string path = Fixture("<si><t>clean</t></si><si><t>CPF: 529.982.247-25</t></si>", referenced
            ? "<c r='A1' t='s'><v>1</v></c><c r='B1' t='s'><v>1</v></c>"
            : "<c r='A1' t='s'><v>0</v></c>");
        string original = Hash(path); var service = Service(); var operation = TestWorkspace.Operation(path);
        var staged = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Equal(Verdict.Blocked, staged.Verdict); Assert.Null(staged.Reason);
        Assert.Equal(Category.Cpf, Assert.Single(staged.Findings).Category);
        var legacy = await service.InspectAsync(operation, CancellationToken.None);
        // Legacy now consumes the same complete stored-text reader.
        Assert.Equal(Verdict.Blocked, legacy.Verdict); Assert.Null(legacy.Reason);
        Assert.Equal(Category.Cpf, Assert.Single(legacy.Findings).Category);
        Assert.Equal(original, Hash(path));
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("1")]
    [InlineData("2147483648")]
    [InlineData("not-an-index")]
    [InlineData("00000000000000000000000000000000000000000")]
    public async Task Invalid_reference_after_sensitive_table_never_returns_partial_findings(string index)
    {
        string path = Fixture("<si><t>CPF: 529.982.247-25</t></si>", "<c r='A1' t='s'><v>" + index + "</v></c>");
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Empty(result.Findings);
        Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
    }

    [Theory]
    [InlineData("table")]
    [InlineData("worksheet")]
    public async Task Corrupt_tail_after_stored_sensitive_text_refuses_the_complete_scan(string part)
    {
        string path = Fixture("<si><t>CPF: 529.982.247-25</t></si>", "<c r='A1' t='s'><v>0</v></c>");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            string entry = part == "table" ? "xl/sharedStrings.xml" : "xl/worksheets/sheet1.xml";
            string xml; using (var reader = new StreamReader(archive.GetEntry(entry)!.Open())) xml = reader.ReadToEnd();
            Write(archive, entry, xml + "<broken>");
        }
        string original = Hash(path);
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Empty(result.Findings);
        Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind); Assert.Equal(original, Hash(path));
    }

    [Theory]
    [InlineData("shared")]
    [InlineData("inline")]
    [InlineData("cached")]
    public async Task Large_stored_value_keeps_collected_live_reader_state_bounded(string shape)
    {
        const int length = 8 * 1024 * 1024; const string tail = " CPF: 529.982.247-25";
        string path = Fixture("", "");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            string entry = shape == "shared" ? "xl/sharedStrings.xml" : "xl/worksheets/sheet1.xml";
            archive.GetEntry(entry)!.Delete();
            using var writer = new StreamWriter(archive.CreateEntry(entry).Open(), new UTF8Encoding(false));
            writer.Write(shape == "shared" ? "<sst xmlns='" + Namespace + "'><si><t>"
                : "<worksheet xmlns='" + Namespace + "'><sheetData><row r='1'><c r='A1' t='" + (shape == "inline" ? "inlineStr'><is><t>" : "str'><v>"));
            var block = new char[8192]; Array.Fill(block, 'a');
            for (int position = 0; position < length; position += block.Length) writer.Write(block);
            writer.Write(tail);
            writer.Write(shape == "shared" ? "</t></si></sst>" : shape == "inline"
                ? "</t></is></c></row></sheetData></worksheet>" : "</v></c></row></sheetData></worksheet>");
        }
        string original = Hash(path);
        await using var input = File.OpenRead(path);
        long baseline = GC.GetTotalMemory(forceFullCollection: true), peak = baseline;
        using (var reader = await new OpenXmlSheetExtractor().OpenReaderAsync(input, CancellationToken.None))
        {
            var buffer = new char[8192]; long characters = 0, nextSample = 1024 * 1024; int count, samples = 0;
            while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0)
            {
                characters += count;
                if (characters >= nextSample)
                { peak = Math.Max(peak, GC.GetTotalMemory(forceFullCollection: true)); nextSample = characters + 1024 * 1024; samples++; }
            }
            string metadata = "Plan1\n1\nrId1\n1\n" + (shape == "shared" ? "" : "A1\n" + (shape == "inline" ? "inlineStr\n" : "str\n"));
            Assert.Equal((long)length + tail.Length + 1 + metadata.Length, characters);
            Assert.True(samples >= 8); Assert.InRange(peak - baseline, 0, 4L * 1024 * 1024);
            output.WriteLine($"SpreadsheetLive shape={shape} text_characters={length} collected_managed_delta_bytes={peak - baseline} samples={samples}");
        }
        Assert.True(input.CanRead); Assert.Equal(original, Hash(path));
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Null(result.Reason); Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal(Category.Cpf, Assert.Single(result.Findings).Category);
    }

    [Fact]
    public async Task Scalar_peek_cancellation_and_disposal_preserve_the_borrowed_source()
    {
        string path = Fixture("<si><t>clean</t></si>", "<c r='A1' t='s'><v>0</v></c>");
        await using var input = File.OpenRead(path);
        using (var reader = await new OpenXmlSheetExtractor().OpenReaderAsync(input, CancellationToken.None))
        {
            Assert.Equal((int)'c', reader.Peek()); Assert.Equal((int)'c', reader.Peek());
            Assert.Equal((int)'c', reader.Read());
            using var canceled = new CancellationTokenSource(); canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(new char[8].AsMemory(), canceled.Token).AsTask());
            Assert.Equal((int)'l', reader.Read());
        }
        Assert.True(input.CanRead); input.Position = 0; Assert.Equal((int)'P', input.ReadByte());
    }

    private InspectionService Service() => new(new LocalPolicyStore(_workspace.PolicyFile),
        new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
    private string Fixture(string strings, string cells)
    {
        string path = _workspace.WriteSpreadsheet("stream.xlsx", "placeholder");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Update);
        Write(archive, "xl/sharedStrings.xml", "<sst xmlns='" + Namespace + "'>" + strings + "</sst>");
        Write(archive, "xl/worksheets/sheet1.xml", "<worksheet xmlns='" + Namespace + "'><sheetData><row r='1'>" + cells + "</row></sheetData></worksheet>");
        return path;
    }
    private static void Write(ZipArchive archive, string name, string xml)
    { archive.GetEntry(name)?.Delete(); using var writer = new StreamWriter(archive.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(xml); }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
