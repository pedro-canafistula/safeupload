using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

[Collection("Plaintext memory")]
public sealed class WordStreamingInspectionTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Fragmented_word_readers_preserve_paragraph_run_and_table_boundaries(int chunk)
    {
        string path = Fixture("""
            <w:p><w:r><w:t>CPF: 529.</w:t></w:r><w:r><w:t>982.247-25</w:t></w:r></w:p>
            <w:p><w:r><w:t>11222333</w:t></w:r></w:p><w:p><w:r><w:t>000181</w:t></w:r></w:p>
            <w:tbl><w:tr><w:tc><w:p><w:r><w:t>password: abcde</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
            """);
        byte[] original = await File.ReadAllBytesAsync(path);
        using var input = new MemoryStream(original, writable: false);
        using var reader = await new OpenXmlWordExtractor().OpenReaderAsync(input, CancellationToken.None);
        string actual = await ReadAsync(reader, chunk);
        input.Position = 0;
        string legacy = await new OpenXmlWordExtractor().ExtractAsync(input, CancellationToken.None);
        Assert.Equal(legacy, actual);
        Assert.Equal("CPF: 529.982.247-25\n11222333\n000181\npassword: abcde\n", actual);
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task Nested_textbox_paragraphs_are_emitted_once_with_real_boundaries()
    {
        string path = Fixture("""
            <w:p><w:r><w:t>11222333</w:t></w:r><w:r><w:pict><v:shape xmlns:v="urn:schemas-microsoft-com:vml"><v:textbox><w:txbxContent>
              <w:p><w:r><w:t>000181</w:t></w:r></w:p>
              <w:p><w:r><w:t>CPF: 529.982.247-25</w:t></w:r></w:p>
            </w:txbxContent></v:textbox></v:shape></w:pict></w:r><w:r><w:t>tail</w:t></w:r></w:p>
            """);
        await using var input = File.OpenRead(path);
        using var reader = await new OpenXmlWordExtractor().OpenReaderAsync(input, CancellationToken.None);
        string text = await ReadAsync(reader, 7);
        Assert.Equal("11222333\n000181\nCPF: 529.982.247-25\ntail\n", text);
        var findings = ContentScanner.Scan(text, Enum.GetValues<Category>().ToHashSet());
        Assert.Equal(Category.Cpf, Assert.Single(findings).Category);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Large_single_text_node_reaches_eof_without_full_node_materialization(bool sensitive)
    {
        const int count = 8 * 1024 * 1024;
        string path = _workspace.WriteWordDocument("large.docx", "placeholder");
        string tail = sensitive ? " CPF: 529.982.247-25" : " clean tail";
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            archive.GetEntry("word/document.xml")!.Delete();
            using var writer = new StreamWriter(archive.CreateEntry("word/document.xml").Open(), new UTF8Encoding(false));
            writer.Write("<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body><w:p><w:r><w:t>");
            var buffer = new char[8192]; Array.Fill(buffer, 'a');
            for (int written = 0; written < count; written += buffer.Length) writer.Write(buffer);
            writer.Write(tail); writer.Write("</w:t></w:r></w:p></w:body></w:document>");
        }
        string original = Hash(path);
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Null(result.Reason);
        Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        if (sensitive) Assert.Equal(Category.Cpf, Assert.Single(result.Findings).Category);
        else Assert.Empty(result.Findings);
        Assert.Equal(original, Hash(path));
    }

    [Theory]
    [InlineData("missing-body")]
    [InlineData("wrong-root")]
    [InlineData("late-corruption")]
    [InlineData("dtd")]
    public async Task Incomplete_or_unsafe_xml_cannot_return_a_partial_staged_approval(string shape)
    {
        string xml = shape switch
        {
            "missing-body" => "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'/>",
            "wrong-root" => "<w:hdr xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'/>",
            "dtd" => "<!DOCTYPE document [<!ENTITY body 'clean'>]><w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body><w:p><w:r><w:t>&body;</w:t></w:r></w:p></w:body></w:document>",
            _ => "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body><w:p><w:r><w:t>CPF: 529.982.247-25</w:t></w:r></w:p><broken></w:body></w:document>"
        };
        string path = Fixture("", xml); string original = Hash(path);
        var result = await Service().InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
        Assert.Empty(result.Findings); Assert.Equal(original, Hash(path));
    }

    [Fact]
    public async Task Reader_cancellation_and_disposal_preserve_the_borrowed_source_stream()
    {
        string path = Fixture("<w:p><w:r><w:t>clean</w:t></w:r></w:p>");
        await using var input = File.OpenRead(path);
        using var cancellation = new CancellationTokenSource();
        using (var reader = await new OpenXmlWordExtractor().OpenReaderAsync(input, CancellationToken.None))
        {
            Assert.Equal((int)'c', reader.Peek()); Assert.Equal((int)'c', reader.Peek());
            var first = new char[1];
            Assert.Equal(1, reader.Read(first, 0, 1)); Assert.Equal('c', first[0]);
            Assert.Equal((int)'l', reader.Read());
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(new char[8].AsMemory(), cancellation.Token).AsTask());
        }
        Assert.True(input.CanRead); input.Position = 0; Assert.Equal((int)'P', input.ReadByte());
    }

    private InspectionService Service() => new(new LocalPolicyStore(_workspace.PolicyFile),
        new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
    private string Fixture(string body, string? xml = null)
    {
        string path = _workspace.WriteWordDocument("word.docx", "placeholder");
        using var archive = ZipFile.Open(path, ZipArchiveMode.Update);
        archive.GetEntry("word/document.xml")!.Delete();
        using var writer = new StreamWriter(archive.CreateEntry("word/document.xml").Open(), new UTF8Encoding(false));
        writer.Write(xml ?? "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'><w:body>" + body + "</w:body></w:document>");
        return path;
    }
    private static async Task<string> ReadAsync(TextReader reader, int chunk)
    {
        var text = new StringBuilder(); var buffer = new char[chunk]; int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) text.Append(buffer, 0, count);
        return text.ToString();
    }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
