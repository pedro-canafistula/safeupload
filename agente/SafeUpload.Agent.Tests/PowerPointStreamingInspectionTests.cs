using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using Xunit.Abstractions;
using static SafeUpload.Agent.Tests.PowerPointFixture;

namespace SafeUpload.Agent.Tests;

[Collection("Plaintext memory")]
public sealed class PowerPointStreamingInspectionTests(ITestOutputHelper output) : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Fragmented_presentation_readers_preserve_runs_and_match_legacy_extraction(int chunk)
    {
        string path = Create(_workspace.Root);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Write(zip, Slide, SlideXml(Shape(Rich("CPF: 529.982.247-25") + Rich("529.982.") + Rich("247-25"))));
        byte[] original = File.ReadAllBytes(path);
        using var input = new MemoryStream(original, writable: false);
        var extractor = new OpenXmlPowerPointExtractor();
        var actual = new StringBuilder(); var buffer = new char[chunk]; int count;
        using (var reader = await extractor.OpenReaderAsync(input, CancellationToken.None))
            while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) actual.Append(buffer, 0, count);
        Assert.True(input.CanRead); input.Position = 0;
        Assert.Equal(await extractor.ExtractAsync(input, CancellationToken.None), actual.ToString());
        Assert.Contains("CPF: 529.982.247-25\n529.982.\n247-25\n", actual.ToString());
        var findings = ContentScanner.Scan(actual.ToString(), Enum.GetValues<Category>().ToHashSet());
        Assert.Equal(Category.Cpf, Assert.Single(findings).Category);
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Large_slide_text_reaches_eof_in_both_inspection_paths(bool sensitive)
    {
        string path = Large(8 * 1024 * 1024, sensitive ? " CPF: 529.982.247-25" : " clean tail");
        string original = Hash(path);
        var service = new InspectionService(InScopePolicy(_workspace), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.True(result.InScope);
            Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Null(result.FailureKind); Assert.Null(result.Reason);
            if (sensitive) Assert.Equal(Category.Cpf, Assert.Single(result.Findings).Category);
            else Assert.Empty(result.Findings);
            Assert.Equal(original, Hash(path));
        }
    }

    [Theory]
    [InlineData(8)]
    [InlineData(32)]
    public async Task Large_slide_node_keeps_collected_live_reader_state_bounded(int megabytes)
    {
        int length = megabytes * 1024 * 1024;
        const string tail = " CPF: 529.982.247-25";
        string path = Large(length, tail), original = Hash(path);
        using var input = File.OpenRead(path);
        long baseline = GC.GetTotalMemory(forceFullCollection: true), peak = baseline;
        using (var reader = await new OpenXmlPowerPointExtractor().OpenReaderAsync(input, CancellationToken.None))
        {
            var buffer = new char[8192]; long characters = 0, nextSample = 1024 * 1024; int count, samples = 0;
            var suffix = new StringBuilder();
            while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0)
            {
                characters += count;
                suffix.Append(buffer, 0, count);
                if (suffix.Length > 128) suffix.Remove(0, suffix.Length - 128);
                if (characters >= nextSample)
                {
                    peak = Math.Max(peak, GC.GetTotalMemory(forceFullCollection: true));
                    nextSample = characters + 1024 * 1024; samples++;
                }
            }
            Assert.Equal((long)length + tail.Length + "\n256\nrId1\n".Length, characters);
            Assert.Contains(tail + "\n", suffix.ToString());
            Assert.True(samples >= megabytes); Assert.InRange(peak - baseline, 0, 4L * 1024 * 1024);
            Assert.Equal(-1, reader.Peek()); Assert.Equal(-1, reader.Read());
            output.WriteLine($"PowerPointLive text_characters={length} collected_managed_delta_bytes={peak - baseline} samples={samples}");
        }
        Assert.True(input.CanRead); Assert.Equal(original, Hash(path));
    }

    [Fact]
    public async Task Presentation_reader_cancellation_and_disposal_preserve_the_borrowed_source()
    {
        string path = Create(_workspace.Root);
        using var input = File.OpenRead(path);
        var reader = await new OpenXmlPowerPointExtractor().OpenReaderAsync(input, CancellationToken.None);
        try
        {
            // Presentation attributes precede slide text in the relationship walk.
            int first = reader.Peek(); Assert.True(first >= 0);
            Assert.Equal(first, reader.Peek()); Assert.Equal(first, reader.Read());
            using var canceled = new CancellationTokenSource(); canceled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(new char[8].AsMemory(), canceled.Token).AsTask());
            Assert.Equal(1, reader.Read(new char[1], 0, 1));
        }
        finally { reader.Dispose(); }
        Assert.Throws<ObjectDisposedException>(() => reader.Read());
        Assert.True(input.CanRead); input.Position = 0; Assert.Equal((int)'P', input.ReadByte());
    }

    private string Large(int length, string tail)
    {
        string path = Create(_workspace.Root);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Update);
        zip.GetEntry(Slide)!.Delete();
        using var writer = new StreamWriter(zip.CreateEntry(Slide).Open(), new UTF8Encoding(false));
        writer.Write("<p:sld xmlns:p='" + P + "' xmlns:a='" + A + "'><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>");
        var buffer = new char[8192]; Array.Fill(buffer, 'a');
        for (int position = 0; position < length; position += buffer.Length) writer.Write(buffer);
        writer.Write(tail); writer.Write("</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>");
        return path;
    }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
}
