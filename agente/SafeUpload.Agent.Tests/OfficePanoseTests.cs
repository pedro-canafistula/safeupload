using System.IO.Compression;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Tests;

public sealed partial class OfficeContentCoverageTests
{
    [Theory]
    [InlineData("theme")]
    [InlineData("fontTable")]
    public async Task Word_default_panose_codes_do_not_invent_payment_cards(string part)
    {
        // Word's default Calibri classification contains a Luhn-valid numeric window.
        await Check(Panose(part, "020F0502020204030204"));
    }

    [Theory]
    [InlineData("theme", "52998224725AAAAAAAAA")]
    [InlineData("fontTable", "52998224725AAAAAAAAA")]
    public async Task Exact_twenty_hex_panose_is_skipped_even_if_it_contains_a_cpf(string part, string value)
    {
        Assert.Equal(20, value.Length);
        await Check(Panose(part, value));
    }

    [Theory]
    [InlineData("theme", "CPF: 529.982.247-25")]
    [InlineData("fontTable", "CPF: 529.982.247-25")]
    [InlineData("theme", "52998224725ZZZZZZZZZ")]
    [InlineData("fontTable", "52998224725ZZZZZZZZZ")]
    [InlineData("theme", "52998224725")]
    [InlineData("fontTable", "52998224725")]
    [InlineData("theme", "52998224725AAAAAAAAAA")]
    [InlineData("fontTable", "52998224725AAAAAAAAAA")]
    public async Task Nonhex_or_non_twenty_character_panose_is_still_scanned(string part, string value)
    {
        await Check(Panose(part, value), sensitive: true);
    }

    [Theory]
    [InlineData("theme")]
    [InlineData("fontTable")]
    public async Task Panose_skip_does_not_hide_other_font_attributes_or_document_text(string part)
    {
        await Check(Panose(part, "020F0502020204030204", Cpf), sensitive: true);
    }

    private string Panose(string part, string value, string name = "Calibri")
    {
        string path = Clean(true);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Update);
        string xml = part == "theme"
            ? "<a:theme xmlns:a='" + A + "' name='Office'><a:themeElements><a:fontScheme name='Office'><a:majorFont><a:latin typeface='" + name + "' panose='" + value + "'/></a:majorFont></a:fontScheme></a:themeElements></a:theme>"
            : "<w:fonts xmlns:w='" + W + "'><w:font w:name='" + name + "'><w:panose1 w:val='" + value + "'/></w:font></w:fonts>";
        Add(zip, "word/document.xml", "word/" + part + ".xml", Rel + part,
            Ct + (part == "theme" ? "theme+xml" : "wordprocessingml.fontTable+xml"), xml);
        return path;
    }
}
