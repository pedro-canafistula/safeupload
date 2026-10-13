using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

[Collection("Plaintext memory")]
public sealed class PdfStreamingInspectionTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Raw_pdf_content_order_and_page_boundaries_match_legacy_text(int chunk)
    {
        string path = RawPdf("first 11222333", "second 000181", "CPF: 529.982.247-25", "");
        string original = Hash(path);
        await using var input = File.OpenRead(path);
        string actual;
        using (var reader = await new PdfExtractor().OpenReaderAsync(input, CancellationToken.None))
        {
            var text = new StringBuilder(); var buffer = new char[chunk]; int count;
            while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) text.Append(buffer, 0, count);
            Assert.Equal(string.Join(Environment.NewLine, new[] { "first 11222333", "second 000181", "CPF: 529.982.247-25", "", "" }), text.ToString());
            Assert.Equal(Category.Cpf, Assert.Single(ContentScanner.Scan(text.ToString(), Enum.GetValues<Category>().ToHashSet())).Category);
            actual = text.ToString();
            Assert.Equal(-1, reader.Peek()); Assert.Equal(-1, reader.Read());
        }
        Assert.True(input.CanRead); Assert.Equal(original, Hash(path));
        await using var legacyInput = File.OpenRead(path);
        Assert.Equal(await new PdfExtractor().ExtractAsync(legacyInput, CancellationToken.None), actual);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Complete_staged_pdf_reads_sensitive_content_on_the_last_page(bool sensitive)
    {
        string path = RawPdf("clean first page", "", sensitive ? "CPF: 529.982.247-25" : "clean last page");
        string original = Hash(path);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(path);
        var result = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Null(result.Reason); Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        if (sensitive) Assert.Equal(Category.Cpf, Assert.Single(result.Findings).Category);
        else Assert.Empty(result.Findings);
        Assert.Equal(!sensitive, await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
        Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(10, CancellationToken.None));
        Assert.Equal(original, Hash(path));
    }

    [Fact]
    public async Task Scalar_peek_cancellation_and_disposal_leave_the_source_open()
    {
        string path = RawPdf("clean"); await using var input = File.OpenRead(path);
        using (var reader = await new PdfExtractor().OpenReaderAsync(input, CancellationToken.None))
        {
            Assert.Equal((int)'c', reader.Peek()); Assert.Equal((int)'c', reader.Peek()); Assert.Equal((int)'c', reader.Read());
            using var canceled = new CancellationTokenSource(); canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(new char[8].AsMemory(), canceled.Token).AsTask());
            Assert.Equal((int)'l', reader.Read());
        }
        Assert.True(input.CanRead); input.Position = 0; Assert.Equal((int)'%', input.ReadByte());
    }

    // Independently author the PDF object/xref structure, rather than using
    // the extraction library's writer. Helvetica keeps these ASCII fixtures simple.
    private string RawPdf(params string[] pages)
    {
        var objects = new List<string>
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Count " + pages.Length + " /Kids [" +
                string.Join(" ", Enumerable.Range(0, pages.Length).Select(i => (4 + 2 * i) + " 0 R")) + "] >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        };
        foreach (string text in pages)
        {
            int content = objects.Count + 2;
            objects.Add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents " + content + " 0 R >>");
            string escaped = text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal).Replace(")", "\\)", StringComparison.Ordinal);
            string stream = "BT /F1 12 Tf 40 740 Td (" + escaped + ") Tj ET\n";
            objects.Add("<< /Length " + Encoding.ASCII.GetByteCount(stream) + " >>\nstream\n" + stream + "endstream");
        }
        var pdf = new StringBuilder("%PDF-1.4\n"); var offsets = new List<int> { 0 };
        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(Encoding.ASCII.GetByteCount(pdf.ToString()));
            pdf.Append(i + 1).Append(" 0 obj\n").Append(objects[i]).Append("\nendobj\n");
        }
        int xref = Encoding.ASCII.GetByteCount(pdf.ToString());
        pdf.Append("xref\n0 ").Append(objects.Count + 1).Append("\n0000000000 65535 f \n");
        foreach (int offset in offsets.Skip(1)) pdf.Append(offset.ToString("D10", System.Globalization.CultureInfo.InvariantCulture)).Append(" 00000 n \n");
        pdf.Append("trailer\n<< /Size ").Append(objects.Count + 1).Append(" /Root 1 0 R >>\nstartxref\n").Append(xref).Append("\n%%EOF\n");
        string path = Path.Combine(_workspace.Root, "raw.pdf"); File.WriteAllBytes(path, Encoding.ASCII.GetBytes(pdf.ToString())); return path;
    }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
