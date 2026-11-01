using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed partial class PdfContentCoverageTests
{
    [Fact]
    public async Task Actual_Word_export_with_prev_and_xref_stream_is_completely_inspected()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "word-export-hybrid.pdf");
        await using var input = File.OpenRead(path);
        Assert.Contains("Relatorio em PDF", await new PdfExtractor().ExtractAsync(input, CancellationToken.None));
        await Check(path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Word_style_hybrid_with_identical_object_references_inspects_clean_and_cpf_text(bool sensitive)
        => await Check(MultiSectionPdf(sensitive ? "CPF: " + Cpf : "Relatorio em PDF", hybrid: true), sensitive);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Disjoint_cross_reference_sections_inspect_all_page_text(bool sensitive)
        => await Check(MultiSectionPdf(sensitive ? "CPF: " + Cpf : "clean", hybrid: false), sensitive);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Real_incremental_object_replacement_is_refused_even_for_identical_bytes(bool identicalBytes)
    {
        string path = RawPdf("", "", [], pageContent: "BT /F1 12 Tf 40 740 Td (CPF: " + Cpf + ") Tj ET");
        string text = File.ReadAllText(path);
        long previous = long.Parse(text[(text.LastIndexOf("startxref\n", StringComparison.Ordinal) + 10)..].Split('\n')[0], CultureInfo.InvariantCulture);
        using (var output = new FileStream(path, FileMode.Append))
        {
            long offset = output.Position;
            string content = identicalBytes ? "CPF: " + Cpf : "clean replacement";
            WriteAscii(output, "5 0 obj\n" + Stream("BT /F1 12 Tf 40 740 Td (" + content + ") Tj ET") + "\nendobj\n");
            long xref = output.Position;
            WriteAscii(output, "xref\n5 1\n" + Offset(offset) + " 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R /Prev " + previous +
                " >>\nstartxref\n" + xref + "\n%%EOF\n");
        }
        await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData("offset")]
    [InlineData("generation")]
    public async Task Hybrid_stream_cannot_hide_an_older_object_definition(string change)
        => await Check(MultiSectionPdf("clean", hybrid: true, change), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Tagged_structure_roles_are_not_actions_and_auxiliary_text_is_inspected(bool sensitive)
        => await Check(RawPdf("/StructTreeRoot 6 0 R", "",
            ["<< /Type /StructTreeRoot /K [7 0 R] /ParentTree << /Nums [0 [7 0 R]] >> >>",
             "<< /Type /StructElem /S /P /P 6 0 R /Pg 4 0 R /K 0 /Alt (" + (sensitive ? Cpf : "clean description") + ") >>"]), sensitive);

    [Theory]
    [InlineData("/OpenAction 7 0 R")]
    [InlineData("")]
    public async Task Structure_context_cannot_hide_actions_or_actual_text(string action)
        => await Check(RawPdf("/StructTreeRoot 6 0 R " + action, "",
            ["<< /Type /StructTreeRoot /K [7 0 R] >>",
             action.Length > 0 ? "<< /Type /StructElem /S /Launch /K 0 /F (file.txt) >>" :
                "<< /Type /StructElem /S /P /K 0 /ActualText (" + Cpf + ") >>"]), failure: InspectionFailureKind.UnsupportedFormat);

    // Independently authored table and binary xref stream, matching Word's
    // empty final table + /Prev + /XRefStm, with no PdfPig writer/repair API.
    private string MultiSectionPdf(string pageText, bool hybrid, string? change = null)
    {
        using var output = new MemoryStream();
        WriteAscii(output, "%PDF-1.5\n");
        var offsets = new List<long> { 0 };
        string[] objects =
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Count 1 /Kids [4 0 R] >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>",
            Stream("BT /F1 12 Tf 40 740 Td (" + pageText + ") Tj ET")
        ];
        for (int i = 0; i < objects.Length; i++)
        {
            offsets.Add(output.Position);
            WriteAscii(output, (i + 1) + " 0 obj\n" + objects[i] + "\nendobj\n");
        }
        long streamOffset = output.Position;
        if (hybrid)
        {
            if (change == "offset")
            {
                streamOffset = output.Position;
                WriteAscii(output, "5 0 obj\n" + Stream("BT /F1 12 Tf 40 740 Td (old " + Cpf + ") Tj ET") + "\nendobj\n");
            }
            offsets.Add(output.Position);
            byte[] entries = new byte[6 * 7];
            BinaryPrimitives.WriteUInt16BigEndian(entries.AsSpan(5, 2), ushort.MaxValue);
            for (int i = 1; i <= 5; i++)
            {
                entries[i * 7] = 1;
                BinaryPrimitives.WriteUInt32BigEndian(entries.AsSpan(i * 7 + 1, 4), checked((uint)(i == 5 && change == "offset" ? streamOffset : offsets[i])));
                if (i == 5 && change == "generation") BinaryPrimitives.WriteUInt16BigEndian(entries.AsSpan(i * 7 + 5, 2), 1);
            }
            using var compressed = new MemoryStream();
            using (var zlib = new ZLibStream(compressed, CompressionMode.Compress, leaveOpen: true)) zlib.Write(entries);
            WriteAscii(output, "6 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /Length " + compressed.Length + " >>\nstream\n");
            output.Write(compressed.ToArray()); WriteAscii(output, "\nendstream\nendobj\n");
        }
        long previous = output.Position;
        WriteAscii(output, "xref\n0 " + (hybrid ? 7 : 4) + "\n0000000000 65535 f \n");
        for (int i = 1; i <= (hybrid ? 6 : 3); i++) WriteAscii(output, Offset(offsets[i]) + " 00000 n \n");
        WriteAscii(output, "trailer\n<< /Size " + (hybrid ? 7 : 6) + " /Root 1 0 R >>\nstartxref\n" + previous + "\n%%EOF\n");
        long latest = output.Position;
        WriteAscii(output, hybrid ? "xref\n0 0\n" : "xref\n4 2\n" + Offset(offsets[4]) + " 00000 n \n" + Offset(offsets[5]) + " 00000 n \n");
        WriteAscii(output, "trailer\n<< /Size " + (hybrid ? 7 : 6) + " /Root 1 0 R /Prev " + previous + (hybrid ? " /XRefStm " + offsets[6] : "") +
            " >>\nstartxref\n" + latest + "\n%%EOF\n");
        string path = Path.Combine(_workspace.Root, Guid.NewGuid() + ".pdf");
        File.WriteAllBytes(path, output.ToArray()); return path;
    }

    private static string Offset(long value) => value.ToString("D10", CultureInfo.InvariantCulture);
    private static void WriteAscii(Stream output, string value) => output.Write(Encoding.ASCII.GetBytes(value));
}
