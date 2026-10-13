using System.Globalization;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

// Hand-authored object dictionaries, streams and xref bytes; no PdfPig writer.
public sealed partial class PdfContentCoverageTests : IDisposable
{
    private const string Cpf = "529.982.247-25";
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("annotation-contents")]
    [InlineData("annotation-author")]
    [InlineData("field-value")]
    [InlineData("field-numeric")]
    [InlineData("field-name-value")]
    [InlineData("field-name")]
    [InlineData("field-alternate-name")]
    [InlineData("field-default")]
    [InlineData("field-option")]
    [InlineData("bookmark")]
    [InlineData("info-title")]
    [InlineData("info-custom")]
    [InlineData("info-hex")]
    [InlineData("xmp")]
    [InlineData("xmp-attribute")]
    [InlineData("uri")]
    [InlineData("indirect-uri")]
    public async Task Pdf_auxiliary_strings_are_inspected_in_legacy_and_staged_paths(string location)
    {
        await Check(Fixture(location, Cpf), sensitive: true);
        await Check(Fixture(location, "clean"));
    }

    [Theory]
    [InlineData("attachment")]
    [InlineData("embedded-files")]
    [InlineData("xfa")]
    [InlineData("appearance")]
    [InlineData("rich-contents")]
    [InlineData("actual-text")]
    public async Task Pdf_unconsumed_payloads_are_explicitly_refused(string location)
        => await Check(Fixture(location, "clean"), failure: InspectionFailureKind.UnsupportedFormat);

    [Fact]
    public async Task Clean_pdf_with_clean_link_annotation_is_approved()
        => await Check(Fixture("uri", "https://example.test/clean"));

    [Theory]
    [InlineData("annotations")]
    [InlineData("fields")]
    public async Task Pdf_auxiliary_counts_over_the_limit_cannot_be_approved(string kind)
    {
        int count = kind == "annotations" ? PdfAuxiliaryText.MaximumAnnotations + 1 : PdfAuxiliaryText.MaximumFields + 1;
        string references = string.Join(" ", Enumerable.Repeat("6 0 R", count));
        string path = kind == "annotations"
            ? RawPdf("", "/Annots [" + references + "]", ["<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (clean) >>"])
            : RawPdf("/AcroForm << /Fields [" + references + "] >>", "", ["<< /FT /Tx /T (clean) /V (clean) >>"]);
        await Check(path, failure: InspectionFailureKind.Limit);
    }

    [Fact]
    public async Task Separate_annotation_items_cannot_assemble_a_cpf()
        => await Check(RawPdf("", "/Annots [6 0 R 7 0 R]",
            ["<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (529.982.) >>",
             "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (247-25) >>"]));

    [Fact]
    public async Task Nested_fields_and_bookmarks_are_inspected()
    {
        await Check(RawPdf("/AcroForm << /Fields [6 0 R] >>", "", ["<< /T (parent) /Kids [7 0 R] >>",
            "<< /Parent 6 0 R /FT /Tx /T (child) /V (" + Cpf + ") >>"]), sensitive: true);
        await Check(RawPdf("/Outlines 6 0 R", "", ["<< /Type /Outlines /First 7 0 R /Last 7 0 R /Count 2 >>",
            "<< /Title (parent) /Parent 6 0 R /First 8 0 R /Last 8 0 R /Count 1 >>",
            "<< /Title (" + Cpf + ") /Parent 7 0 R /Dest [4 0 R /Fit] >>"]), sensitive: true);
    }

    [Fact]
    public async Task Widget_inherits_values_from_a_parent_even_without_an_acroform_root()
        => await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Type /Annot /Subtype /Widget /Rect [0 0 10 10] /Parent 7 0 R >>",
            "<< /FT /Tx /T (parent) /V (" + Cpf + ") /Kids [6 0 R] >>"]), sensitive: true);

    [Fact]
    public async Task Nested_field_depth_is_bounded()
    {
        string field = "<< /FT /Tx /T (leaf) /V (clean) >>";
        for (int i = 0; i < 70; i++) field = "<< /T (parent) /Kids [" + field + "] >>";
        await Check(RawPdf("/AcroForm << /Fields [6 0 R] >>", "", [field]), failure: InspectionFailureKind.Limit);
    }

    [Fact]
    public async Task Malformed_xmp_and_annotation_entries_fail_the_entire_inspection()
    {
        await Check(RawPdf("/Metadata 6 0 R", "", [Stream("<broken", "/Type /Metadata /Subtype /XML")]), failure: InspectionFailureKind.ReadOrParse);
        await Check(RawPdf("", "/Annots [(not a dictionary)]", []), failure: InspectionFailureKind.ReadOrParse);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Pdf_auxiliary_fragmented_stream_matches_extract_async(int chunk)
    {
        string path = Fixture("xmp", Cpf); byte[] original = File.ReadAllBytes(path);
        using var stream = File.OpenRead(path);
        var extractor = new PdfExtractor(); var text = new StringBuilder(); var buffer = new char[chunk]; int count;
        using (var reader = await extractor.OpenReaderAsync(stream, CancellationToken.None))
            while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) text.Append(buffer, 0, count);
        Assert.True(stream.CanRead); stream.Position = 0;
        Assert.Equal(await extractor.ExtractAsync(stream, CancellationToken.None), text.ToString());
        Assert.Contains(Cpf, text.ToString()); Assert.Equal(original, File.ReadAllBytes(path));
    }

    private string Fixture(string location, string text)
    {
        string literal = Literal(text);
        if (location.StartsWith("annotation-", StringComparison.Ordinal))
            return RawPdf("", "/Annots [6 0 R]", ["<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] " +
                (location == "annotation-author" ? "/Contents (clean) /T " : "/Contents ") + literal + " >>"]);
        if (location.StartsWith("field-", StringComparison.Ordinal))
        {
            string values = location switch
            {
                "field-numeric" => "/T (field) /V " + (text == Cpf ? "52998224725" : "42"),
                "field-name-value" => "/T (field) /V /" + (text == Cpf ? "52998224725" : "clean"),
                "field-name" => "/T " + literal + " /V (clean)",
                "field-alternate-name" => "/T (field) /TU " + literal + " /V (clean)",
                "field-default" => "/T (field) /V (clean) /DV " + literal,
                "field-option" => "/T (field) /V (clean) /Opt [[(export) " + literal + "]]",
                _ => "/T (field) /V " + literal
            };
            return RawPdf("/AcroForm << /Fields [6 0 R] >>", "/Annots [6 0 R]",
                ["<< /Type /Annot /Subtype /Widget /FT " + (location == "field-option" ? "/Ch " : "/Tx ") +
                 "/Rect [0 0 10 10] /P 4 0 R " + values + " >>"]);
        }
        if (location == "bookmark")
            return RawPdf("/Outlines 6 0 R", "", ["<< /Type /Outlines /First 7 0 R /Last 7 0 R /Count 1 >>",
                "<< /Title " + literal + " /Parent 6 0 R /Dest [4 0 R /Fit] >>"]);
        if (location.StartsWith("info-", StringComparison.Ordinal))
            return RawPdf("", "", ["<< /" + (location == "info-custom" ? "Private" : "Title") + " " +
                (location == "info-hex" ? "<FEFF" + Convert.ToHexString(Encoding.BigEndianUnicode.GetBytes(text)) + ">" : literal) + " >>"], info: true);
        if (location.StartsWith("xmp", StringComparison.Ordinal))
        {
            string xml = "<x:xmpmeta xmlns:x='adobe:ns:meta/' xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#' xmlns:dc='http://purl.org/dc/elements/1.1/'>" +
                "<rdf:RDF><rdf:Description" + (location == "xmp-attribute" ? " dc:title='" + text + "'" : "") + ">" +
                (location == "xmp" ? "<dc:title><rdf:Alt><rdf:li>" + text + "</rdf:li></rdf:Alt></dc:title>" : "") + "</rdf:Description></rdf:RDF></x:xmpmeta>";
            return RawPdf("/Metadata 6 0 R", "", [Stream(xml, "/Type /Metadata /Subtype /XML")]);
        }
        if (location is "uri" or "indirect-uri")
            return location == "uri" ? RawPdf("", "/Annots [6 0 R]", ["<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /URI /URI " + literal + " >> >>"])
                : RawPdf("", "/Annots [6 0 R]", ["<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A 7 0 R >>", "<< /S /URI /URI 8 0 R >>", literal]);
        return location switch
        {
            "attachment" => RawPdf("", "/Annots [6 0 R]", ["<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /Contents (clean) /FS 7 0 R >>",
                "<< /Type /Filespec /F (payload.txt) /EF << /F 8 0 R >> >>", Stream(Cpf, "/Type /EmbeddedFile")]),
            "embedded-files" => RawPdf("/Names << /EmbeddedFiles << /Names [(payload.txt) 6 0 R] >> >>", "", ["<< /Type /Filespec /F (payload.txt) /EF << /F 7 0 R >> >>", Stream(Cpf, "/Type /EmbeddedFile")]),
            "xfa" => RawPdf("/AcroForm << /Fields [] /XFA 6 0 R >>", "", [Stream("<xfa>" + Cpf + "</xfa>")]),
            "appearance" => RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Text /Rect [0 0 10 10] /Contents (clean) /AP << /N 7 0 R >> >>", Stream("BT /F1 12 Tf (" + Cpf + ") Tj ET", "/Type /XObject /Subtype /Form /BBox [0 0 10 10]")]),
            "rich-contents" => RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Text /Rect [0 0 10 10] /Contents (clean) /RC (<p>" + Cpf + "</p>) >>"]),
            "actual-text" => RawPdf("", "", [], pageContent: "/Span << /ActualText (529.982.) >> BDC BT /F1 12 Tf 40 740 Td (clean) Tj ET EMC\n/Span << /ActualText (247-25) >> BDC BT /F1 12 Tf 40 720 Td (clean) Tj ET EMC\n"),
            _ => throw new ArgumentOutOfRangeException(nameof(location))
        };
    }

    private async Task Check(string path, bool sensitive = false, InspectionFailureKind? failure = null)
    {
        byte[] original = File.ReadAllBytes(path);
        var service = new InspectionService(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(failure is not null ? staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection : sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Equal(failure, result.FailureKind);
            if (failure == InspectionFailureKind.UnsupportedFormat) Assert.Equal("unsupported_format", result.Reason);
            else if (failure == InspectionFailureKind.Limit) Assert.Equal("inspection_limit", result.Reason);
            else if (failure == InspectionFailureKind.ReadOrParse) Assert.StartsWith("parse_error:", result.Reason);
            else Assert.Null(result.Reason);
            if (sensitive && failure is null)
            {
                Assert.Equal(Category.Cpf, Assert.Single(result.Categories)); Assert.NotEmpty(result.Findings);
                Assert.All(result.Findings, finding => { Assert.Equal(Category.Cpf, finding.Category); Assert.Equal("•••••••••25", finding.MaskedSnippet); });
            }
            else Assert.Empty(result.Findings);
            Assert.Equal(original, File.ReadAllBytes(path));
        }
    }

    private string RawPdf(string catalog, string page, IReadOnlyList<string> extra, bool info = false, string? pageContent = null,
        IReadOnlyDictionary<int, byte[]>? binaryObjects = null)
    {
        var objects = new List<string>
        {
            "<< /Type /Catalog /Pages 2 0 R " + catalog + " >>",
            "<< /Type /Pages /Count 1 /Kids [4 0 R] >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R " + page + " >>",
            Stream(pageContent ?? "BT /F1 12 Tf 40 740 Td (clean page) Tj ET\n")
        };
        objects.AddRange(extra);
        using var output = new MemoryStream();
        void Write(string value) => output.Write(Encoding.UTF8.GetBytes(value));
        Write("%PDF-1.4\n"); var offsets = new List<long> { 0 };
        for (int i = 0; i < objects.Count; i++)
        {
            offsets.Add(output.Position);
            Write((i + 1).ToString(CultureInfo.InvariantCulture) + " 0 obj\n");
            if (binaryObjects is not null && binaryObjects.TryGetValue(i + 1, out var bytes)) output.Write(bytes);
            else Write(objects[i]);
            Write("\nendobj\n");
        }
        long xref = output.Position;
        var pdf = new StringBuilder();
        pdf.Append("xref\n0 ").Append(objects.Count + 1).Append("\n0000000000 65535 f \n");
        foreach (long offset in offsets.Skip(1)) pdf.Append(offset.ToString("D10", CultureInfo.InvariantCulture)).Append(" 00000 n \n");
        pdf.Append("trailer\n<< /Size ").Append(objects.Count + 1).Append(" /Root 1 0 R").Append(info ? " /Info 6 0 R" : "")
            .Append(" >>\nstartxref\n").Append(xref).Append("\n%%EOF\n");
        Write(pdf.ToString());
        string path = Path.Combine(_workspace.Root, Guid.NewGuid() + ".pdf"); File.WriteAllBytes(path, output.ToArray()); return path;
    }
    private static string Stream(string value, string dictionary = "") => "<< /Length " + Encoding.UTF8.GetByteCount(value) + " " + dictionary + " >>\nstream\n" + value + "\nendstream";
    private static string Literal(string value) => "(" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("(", "\\(", StringComparison.Ordinal).Replace(")", "\\)", StringComparison.Ordinal) + ")";
}
