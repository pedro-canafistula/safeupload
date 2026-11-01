using System.Globalization;
using System.IO.Compression;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed partial class PdfContentCoverageTests
{
    private const string VectorAppearance = "q /GS0 gs 1 1 0 rg 0 0 10 10 re f Q\n";
    private const string VectorResources = "<< /ExtGState << /GS0 << /Type /ExtGState /ca .4 /BM /Multiply >> >> >>";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Highlight_with_graphics_only_appearance_is_inspected(bool compressed)
    {
        await Check(Appearance(VectorAppearance, compressed: compressed, resources: VectorResources));
        await Check(Appearance(VectorAppearance, compressed: compressed, resources: VectorResources, contents: Cpf), sensitive: true);
    }

    [Theory]
    [InlineData("Tj")]
    [InlineData("TJ")]
    [InlineData("'")]
    [InlineData("\"")]
    [InlineData("Do")]
    [InlineData("BI")]
    [InlineData("ID")]
    [InlineData("EI")]
    public async Task Appearance_text_showing_xobjects_and_inline_images_are_refused(string op)
    {
        string content = op switch
        {
            "Tj" or "'" => "BT /F1 12 Tf (" + Cpf + ") " + op + " ET",
            "TJ" => "BT /F1 12 Tf [(" + Cpf + ")] TJ ET",
            "\"" => "BT /F1 12 Tf 0 0 (" + Cpf + ") \" ET",
            "Do" => "/X1 Do",
            _ => op
        };
        foreach (bool compressed in new[] { false, true })
            await Check(Appearance(content, compressed: compressed, subtype: "FreeText",
                resources: "<< /Font << /F1 3 0 R >> >>"), failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Fact]
    public async Task Filled_text_field_with_painted_value_is_still_unsupported()
        => await Check(Appearance("BT /F1 12 Tf (clean value) Tj ET", subtype: "Widget",
            resources: "<< /Font << /F1 3 0 R >> >>", field: true), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData("N")]
    [InlineData("R")]
    [InlineData("D")]
    [InlineData("state")]
    public async Task Every_appearance_and_unselected_state_is_inspected(string location)
    {
        foreach (bool sensitive in new[] { false, true })
        {
            string ap = location == "state" ? "/N << /Off 7 0 R /On 8 0 R >>" : "/N 7 0 R /" + (location == "N" ? "R" : location) + " 8 0 R";
            string inspected = "/Span << /Alt (" + (sensitive ? Cpf : "clean") + ") >> BDC 0 0 m 1 1 l S EMC";
            string normal = location == "N" ? inspected : "q Q", other = location == "N" ? "q Q" : inspected;
            await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AS /Off /AP << " + ap + " >> >>",
                AppearanceStream(normal), AppearanceStream(other)]), sensitive);
        }
    }

    [Theory]
    [InlineData("literal")]
    [InlineData("octal")]
    [InlineData("hex")]
    [InlineData("utf16")]
    [InlineData("name")]
    [InlineData("comment")]
    public async Task Stored_appearance_strings_and_comments_are_read(string encoding)
    {
        foreach (bool sensitive in new[] { false, true })
        {
            string text = sensitive ? Cpf : "clean", value = encoding switch
            {
                "octal" => "(" + string.Concat(Encoding.ASCII.GetBytes(text).Select(octet => "\\" + Convert.ToString(octet, 8).PadLeft(3, '0'))) + ")",
                "hex" => "<" + Convert.ToHexString(Encoding.ASCII.GetBytes(text)) + ">",
                "utf16" => "<FEFF" + Convert.ToHexString(Encoding.BigEndianUnicode.GetBytes(text)) + ">",
                "name" => "/" + string.Concat(Encoding.ASCII.GetBytes(text).Select(octet => "#" + octet.ToString("X2", CultureInfo.InvariantCulture))),
                _ => Literal(text)
            };
            string content = encoding == "comment" ? "% " + text + " Tj Do\nq Q" : "/Span << /Alt " + value + " >> BDC q Q EMC";
            await Check(Appearance(content, compressed: true), sensitive);
        }
    }

    [Fact]
    public async Task Appearance_lexer_preserves_nested_strings_escapes_and_item_boundaries()
    {
        await Check(Appearance("/Span << /Alt (nested (Tj Do) \\(quoted\\) \\n clean) /Other <636c65616e> /Array [true false null 1 -2.5] >> BDC q Q EMC"));
        await Check(Appearance("/Span << /Alt (529.982.) /Other (247-25) >> BDC q Q EMC"));
        await Check(Appearance("/Span << /Alt (529.\\\n982.247-25) >> BDC q Q EMC"), sensitive: true);
    }

    [Theory]
    [InlineData("/Span << /ActualText (clean) >> BDC EMC")]
    [InlineData("/Span << /Actual#54ext (clean) >> BDC EMC")]
    [InlineData("/Span /P BDC EMC")]
    public async Task Appearance_actual_text_direct_encoded_and_named_properties_are_refused(string content)
        => await Check(Appearance(content, resources: content == "/Span /P BDC EMC" ? "<< /Properties << /P << /ActualText (" + Cpf + ") >> >> >>" : "<<>>"), failure: InspectionFailureKind.UnsupportedFormat);

    [Fact]
    public async Task Appearance_indirect_properties_and_resource_names_are_not_backlinks()
    {
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R >> >>",
            AppearanceStream("/Span /P BDC EMC", "<< /Properties << /P 8 0 R >> >>"), "<< /ActualText (" + Cpf + ") >>"]), failure: InspectionFailureKind.UnsupportedFormat);
        await Check(Appearance("/S gs", resources: "<< /ExtGState << /S << /ca .4 >> >> >>"));
        await Check(Appearance("/Span /P BDC EMC", resources: "<< /Properties << /P << /Alt (" + Cpf + ") >> >> >>"), sensitive: true);
    }

    [Theory]
    [InlineData("missing-resources")]
    [InlineData("unknown-entry")]
    [InlineData("non-stream-state")]
    [InlineData("cyclic-state")]
    public async Task Appearance_shape_and_local_resource_scope_must_be_complete(string shape)
    {
        string ap = shape == "unknown-entry" ? "/Other 7 0 R" : shape == "non-stream-state" ? "/N << /On (clean) >>" : shape == "cyclic-state" ? "/N << /On 6 0 R >>" : "/N 7 0 R";
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << " + ap + " >> >>",
            Stream("q Q", "/Type /XObject /Subtype /Form /BBox [0 0 10 10]")]), failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData("/Subtype /PS /BBox [0 0 10 10]")]
    [InlineData("/Subtype /Unknown /BBox [0 0 10 10]")]
    [InlineData("/BBox [0 0 10 10]")]
    [InlineData("/Type /Unknown /Subtype /Form /BBox [0 0 10 10]")]
    [InlineData("/Subtype /Form")]
    [InlineData("/Subtype /Form /BBox [0 0 (bad) 10]")]
    [InlineData("/Subtype /Form /BBox [0 0 10 10] /Matrix [1 0 0]")]
    [InlineData("/Subtype /Form /BBox [0 0 10 10] /FormType 2")]
    public async Task Appearance_stream_must_be_a_form_with_numeric_geometry(string dictionary)
        => await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R >> >>",
            Stream("q Q", dictionary + " /Resources <<>>")]), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData("/Span /P BDC EMC", "<< /Properties << /P null >> >>")]
    [InlineData("/GS0 gs", "<< /ExtGState << /GS0 1 >> >>")]
    [InlineData("/C cs", "<< /ColorSpace << /C (bad) >> >>")]
    [InlineData("BT /F 12 Tf ET", "<< /Font << /F /Bad >> >>")]
    public async Task Appearance_selected_resources_require_the_expected_token_shape(string content, string resources)
        => await Check(Appearance(content, resources: resources), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData("soft-mask")]
    [InlineData("pattern")]
    [InlineData("shading")]
    [InlineData("icc")]
    public async Task Appearance_nested_resource_streams_are_refused(string kind)
    {
        string resources = kind switch
        {
            "soft-mask" => "<< /ExtGState << /GS0 << /SMask << /S /Luminosity /G 8 0 R >> >> >> >>",
            "pattern" => "<< /Pattern << /P 8 0 R >> >>",
            "shading" => "<< /Shading << /S 8 0 R >> >>",
            _ => "<< /ColorSpace << /C [/ICCBased 8 0 R] >> >>"
        };
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R >> >>",
            AppearanceStream("q Q", resources), Stream(Cpf)]), failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData("/Span /Missing BDC EMC")]
    [InlineData("/Missing gs")]
    [InlineData("/Missing sh")]
    [InlineData("/Missing cs")]
    [InlineData("/Missing scn")]
    [InlineData("BT /Missing 12 Tf ET")]
    public async Task Appearance_named_resources_must_resolve_in_its_own_dictionary(string content)
        => await Check(Appearance(content), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData("/F (other.pdf)")]
    [InlineData("/FFilter /FlateDecode")]
    [InlineData("/FDecodeParms <<>>")]
    [InlineData("/Ref << /F (other.pdf) /Page 0 >>")]
    public async Task Appearance_external_stream_sources_and_reference_xobjects_are_refused(string dictionary)
        => await Check(Appearance("q Q", dictionary: dictionary), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData("(")]
    [InlineData("<xyz>")]
    [InlineData("/Span << /Alt (clean) BDC")]
    [InlineData("/Span << (key) (value) >> BDC EMC")]
    [InlineData("/Invalid#Z0 MP")]
    [InlineData("[1 2 >>")]
    [InlineData("Q")]
    [InlineData("q")]
    [InlineData("BT")]
    [InlineData("1 2 re")]
    [InlineData("1e2 w")]
    [InlineData("1 2")]
    [InlineData("mystery")]
    public async Task Malformed_appearance_streams_are_never_approved(string content)
        => await Check(Appearance(content), failure: InspectionFailureKind.UnsupportedFormat);

    [Theory]
    [InlineData("bad-header")]
    [InlineData("checksum")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("trailing-repeated-checksum")]
    [InlineData("concatenated-member")]
    [InlineData("concatenated-empty-member")]
    [InlineData("filter")]
    [InlineData("parameters")]
    public async Task Unsupported_or_failed_appearance_filters_are_refused(string fault)
    {
        byte[] bytes = Compress("q Q");
        string dictionary = "/Filter /FlateDecode";
        switch (fault)
        {
            case "bad-header": bytes = Encoding.ASCII.GetBytes("q Q"); break;
            case "checksum": bytes[^1] ^= 1; break;
            case "truncated": bytes = bytes[..^3]; break;
            case "trailing": bytes = [.. bytes, 1, 2, 3, 4]; break;
            case "trailing-repeated-checksum": bytes = [.. bytes, .. Encoding.ASCII.GetBytes("% " + Cpf + "\n"), .. bytes[^4..]]; break;
            case "concatenated-member": bytes = [.. bytes, .. Compress("% " + Cpf + "\n")]; break;
            // A real empty zlib member: .NET emits no bytes for Compress(""), which would leave the first stream alone.
            case "concatenated-empty-member": bytes = [.. bytes, 0x78, 0xDA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]; break;
            case "filter": dictionary = "/Filter /Unimplemented"; break;
            case "parameters": dictionary += " /DecodeParms << /Predictor 12 /Columns 1 >>"; break;
        }
        if (fault.StartsWith("concatenated", StringComparison.Ordinal) || fault.StartsWith("trailing", StringComparison.Ordinal))
            Assert.True(bytes.Length > Compress("q Q").Length, "the fault must add bytes after the first stream");
        await Check(AppearanceBytes(bytes, dictionary), failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData("/Filter [/FlateDecode]")]
    [InlineData("/Filter /Fl /DecodeParms null")]
    public async Task Direct_single_flate_filter_forms_are_supported(string dictionary)
        => await Check(AppearanceBytes(Compress("q Q"), dictionary));

    [Fact]
    public async Task Indirect_filter_parameters_and_filter_chains_are_refused()
    {
        await Check(AppearanceBytes(Compress("q Q"), "/Filter [/FlateDecode /FlateDecode]"), failure: InspectionFailureKind.UnsupportedFormat);
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R >> >>",
            Stream("q Q", "/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Resources <<>> /Filter 8 0 R"), "/FlateDecode"]), failure: InspectionFailureKind.UnsupportedFormat);
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R >> >>",
            Stream("q Q", "/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Resources <<>> /DecodeParms 8 0 R"), "<< /Predictor 12 >>"]), failure: InspectionFailureKind.UnsupportedFormat);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Appearance_token_budget_is_cumulative_and_exact(bool over)
    {
        // Each q/Q is two tokens; the final harmless n makes precisely +1.
        string half = string.Concat(Enumerable.Repeat("q Q ", PdfAuxiliaryText.MaximumAppearanceTokens / 4));
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R /R 8 0 R >> >>",
            AppearanceStream(half), AppearanceStream(half + (over ? "n" : ""))]), failure: over ? InspectionFailureKind.Limit : null);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Appearance_decoded_byte_budget_is_cumulative_and_exact(bool over)
    {
        string half = new(' ', PdfAuxiliaryText.MaximumAppearanceBytes / 2);
        await Check(RawPdf("", "/Annots [6 0 R]", ["<< /Subtype /Highlight /Rect [0 0 10 10] /AP << /N 7 0 R /R 8 0 R >> >>",
            AppearanceStream(half), AppearanceStream(half + (over ? " " : ""))]), failure: over ? InspectionFailureKind.Limit : null);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Appearance_container_depth_is_bounded(bool over)
    {
        int depth = over ? 65 : 64;
        // The property dictionary is one level; nested arrays fill the rest.
        string nested = new('[', depth - 1), close = new(']', depth - 1);
        await Check(Appearance("/Span << /Alt " + nested + "(clean)" + close + " >> BDC EMC"), failure: over ? InspectionFailureKind.Limit : null);
    }

    [Fact]
    public async Task Page_metadata_and_incremental_revisions_remain_refused()
    {
        await Check(RawPdf("", "/Metadata 6 0 R", [Stream("<clean/>", "/Type /Metadata /Subtype /XML")]), failure: InspectionFailureKind.UnsupportedFormat);
        string path = RawPdf("", "", []);
        string original = File.ReadAllText(path, Encoding.UTF8);
        long previous = long.Parse(original[(original.LastIndexOf("startxref\n", StringComparison.Ordinal) + 10)..].Split('\n')[0], CultureInfo.InvariantCulture);
        long update = new FileInfo(path).Length;
        string revision = "6 0 obj\n<< /Producer (clean edit) >>\nendobj\n";
        File.AppendAllText(path, revision + "xref\n6 1\n" + update.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \ntrailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev " + previous +
            " >>\nstartxref\n" + (update + Encoding.UTF8.GetByteCount(revision)) + "\n%%EOF\n", new UTF8Encoding(false));
        await Check(path, failure: InspectionFailureKind.UnsupportedFormat);
    }

    private string Appearance(string content, bool compressed = false, string resources = "<<>>", string subtype = "Highlight", string dictionary = "", bool field = false, string contents = "clean")
        => AppearanceBytes(compressed ? Compress(content) : Encoding.ASCII.GetBytes(content), (compressed ? "/Filter /FlateDecode " : "") + dictionary, resources, subtype, field, contents);

    private string AppearanceBytes(byte[] bytes, string dictionary, string resources = "<<>>", string subtype = "Highlight", bool field = false, string contents = "clean")
    {
        using var stream = new MemoryStream();
        stream.Write(Encoding.ASCII.GetBytes("<< /Length " + bytes.Length + " /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Resources " + resources + " " + dictionary + " >>\nstream\n"));
        stream.Write(bytes); stream.Write(Encoding.ASCII.GetBytes("\nendstream"));
        string annotation = "<< /Type /Annot /Subtype /" + subtype + " /Rect [0 0 10 10] /Contents " + Literal(contents) + " /AP << /N 7 0 R >> " +
            (subtype == "Highlight" ? "/QuadPoints [0 10 10 10 0 0 10 0] " : "") + (field ? "/FT /Tx /T (Field) /V (clean value) " : "") + ">>";
        return RawPdf(field ? "/AcroForm << /Fields [6 0 R] >>" : "", "/Annots [6 0 R]", [annotation, ""], binaryObjects: new Dictionary<int, byte[]> { [7] = stream.ToArray() });
    }
    private static string AppearanceStream(string content, string resources = "<<>>")
        => Stream(content, "/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Resources " + resources);
    private static byte[] Compress(string content)
    {
        using var output = new MemoryStream();
        using (var compressor = new ZLibStream(output, CompressionLevel.SmallestSize, leaveOpen: true)) compressor.Write(Encoding.ASCII.GetBytes(content));
        return output.ToArray();
    }
}
