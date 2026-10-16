using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using static SafeUpload.Agent.Tests.ArchiveFixture;

namespace SafeUpload.Agent.Tests;

public sealed partial class ArchiveInspectionTests : IDisposable
{
    private const string Cpf = "529.982.247-25";
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(".txt", false)]
    [InlineData(".docx", false)]
    [InlineData(".xlsx", false)]
    [InlineData(".pptx", false)]
    [InlineData(".pdf", false)]
    [InlineData(".txt", true)]
    [InlineData(".docx", true)]
    [InlineData(".xlsx", true)]
    [InlineData(".pptx", true)]
    [InlineData(".pdf", true)]
    public async Task Every_existing_inspector_reads_clean_and_sensitive_archive_members(string extension, bool nested)
    {
        foreach (bool sensitive in new[] { false, true })
        {
            string text = sensitive ? "CPF: " + Cpf : "clean member";
            byte[] bytes = Member(extension, text);
            byte[] archive = Zip(new Item("folder/document" + extension, bytes) { Method = 8 });
            if (nested) archive = Zip(new Item("nested.zip", archive) { Method = 8 });
            await Check(Write(archive), sensitive: sensitive,
                memberName: (nested ? "nested.zip!/" : "") + "folder/document" + extension);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Empty_archive_and_empty_supported_members_are_inspected(bool member)
        => await Check(Write(member ? Zip(Text("empty.txt", "")) : Zip()));

    [Theory]
    [InlineData("image.png", "archive_unsupported_member")]
    [InlineData("unknown.bin", "archive_unsupported_member")]
    [InlineData("unknown", "archive_unsupported_member")]
    [InlineData("empty.unknown", "archive_unsupported_member")]
    [InlineData("nested.7z", "archive_7z_unavailable")]
    public async Task An_unsupported_member_refuses_the_whole_archive_without_partial_findings(string name, string reason)
        => await Check(Write(Zip(Text("first.txt", Cpf), Text(name, name == "empty.unknown" ? "" : "opaque"))), reason: reason);

    [Fact]
    public async Task Refused_payloads_inside_an_Office_member_refuse_the_whole_archive()
    {
        string path = PowerPointFixture.Create(_workspace.Root);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            PowerPointFixture.Add(zip, PowerPointFixture.Slide, "ppt/media/image.png", PowerPointFixture.Rel + "image", "image/png", "uninspected");
        await Check(Write(Zip(Text("first.txt", Cpf), new Item("image-deck.pptx", File.ReadAllBytes(path)))), reason: "unsupported_format");
    }

    [Theory]
    [InlineData("zip")]
    [InlineData("7z")]
    [InlineData("7z-plain")]
    public async Task Encrypted_archives_and_all_7z_are_explicitly_refused(string format)
    {
        // Independent tools: zip -P fixture-password; 7-Zip 26.03 -t7z,
        // with -pfixture-password -mhe=on for the encrypted-header fixture.
        string data = format switch
        {
            "zip" => "UEsDBAoACQAAAGsIUF1fI+17GQAAAA0AAAAJABwAY2xlYW4udHh0VVQJAAMKotFqCqLRanV4CwABBOgDAAAE6AMAAGQ8Twb0b8Wky1g3WPj8zSdKicZrl2iAFN1QSwcIXyPtexkAAAANAAAAUEsBAh4DCgAJAAAAawhQXV8j7XsZAAAADQAAAAkAGAAAAAAAAQAAAKSBAAAAAGNsZWFuLnR4dFVUBQADCqLRanV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAE8AAABsAAAAAAA=",
            "7z" => "N3q8ryccAAS9yIzAkAAAAAAAAAAuAAAAAAAAAKPRGqBBMdW+vxTKpYn+DQ2xdpNmT/18Tv3CFrip0+aBDttybJqjcYClyEFWQtJSCUMRkGGIW//RuRdvLcpuBjpbxRn8zBj6D1ieSvv+CYPR9/Y1G9pvEZXmCN7G4pN8+sZYloicrgLMKunt3VxpccnzSO2YggxJBLo12RaDsEr2mmVaJlSlwC2f9BKHSm9hahoMIVQXBiABCXAABwsBAAEkBvEHARJTD3oLKNcGa5lVvPdrnIDMEkIMagoBtG8AIgAA",
            _ => "N3q8ryccAATGe4TjEQAAAAAAAABaAAAAAAAAALSySGcBAAxjbGVhbiBmaXh0dXJlAAEEBgABCREABwsBAAEhIQEADA0ACAoBXyPtewAABQEZDAAAAAAAAAAAAAAAABEVAGMAbABlAGEAbgAuAHQAeAB0AAAAFAoBACQ0OkkjXd0BFQYBACCApIEAAA=="
        };
        await Check(Write(Convert.FromBase64String(data), format == "zip" ? ".zip" : ".7z"),
            reason: format == "zip" ? "archive_encrypted" : "archive_7z_unavailable");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Archive_depth_is_cumulative_and_exact(int depth)
    {
        byte[] bytes = Zip(Text("document.txt", Cpf));
        string name = "document.txt";
        for (int i = 1; i < depth; i++) { bytes = Zip(new Item("nested.zip", bytes)); name = "nested.zip!/" + name; }
        await Check(Write(bytes), sensitive: depth <= 3, memberName: name, reason: depth > 3 ? "inspection_limit" : null);
    }

    [Theory]
    [InlineData("exact")]
    [InlineData("member-over")]
    [InlineData("siblings-over")]
    [InlineData("nested-over")]
    public async Task Actual_expansion_shares_the_unchanged_policy_size_limit(string shape)
    {
        const int maximum = 1024 * 1024;
        byte[] bytes = shape switch
        {
            "siblings-over" => Zip(new Item("one.txt", Letters(600_000)) { Method = 8 }, new Item("two.txt", Letters(600_000)) { Method = 8 }),
            "nested-over" => Zip(new Item("nested.zip", Zip(new Item("data.txt", Letters(900_000)) { Method = 8 })) { Method = 8 }),
            _ => Zip(new Item("data.txt", Letters(maximum + (shape == "member-over" ? 1 : 0))) { Method = 8 })
        };
        Assert.True(bytes.Length < maximum); // Prove this tests expansion, not the top-level file-size gate.
        await Check(Write(bytes), reason: shape == "exact" ? null : "file_too_large", policy: Policy() with { MaxFileSizeMb = 1 });
    }

    [Theory]
    [InlineData(16_384)]
    [InlineData(16_385)]
    public void Entry_inventory_is_bounded_before_the_BCL_parser(int count)
    {
        byte[] bytes = Zip(Enumerable.Range(0, count).Select(i => Text(i + ".txt", "")).ToArray());
        using var source = new MemoryStream(bytes, writable: false);
        var budget = new ArchiveInspectionBudget(20L * 1024 * 1024);
        if (count == 16_384) Assert.Equal(count, ZipInspectionGuard.Inspect(source, budget, 1, CancellationToken.None).Count);
        else Assert.Throws<InspectionLimitException>(() => ZipInspectionGuard.Inspect(source, budget, 1, CancellationToken.None));
    }

    [Fact]
    public void Entry_accounting_does_not_reset_or_refund_between_nested_containers()
    {
        byte[] bytes = Zip(Enumerable.Range(0, 8192).Select(i => Text(i + ".txt", "")).ToArray());
        var budget = new ArchiveInspectionBudget(20L * 1024 * 1024);
        using var first = new MemoryStream(bytes, writable: false);
        using var second = new MemoryStream(bytes, writable: false);
        Assert.Equal(8192, ZipInspectionGuard.Inspect(first, budget, 2, CancellationToken.None).Count);
        Assert.Equal(8192, ZipInspectionGuard.Inspect(second, budget, 2, CancellationToken.None).Count);
        using var extra = new MemoryStream(Zip(Text("extra.txt", "")), writable: false);
        Assert.Throws<InspectionLimitException>(() => ZipInspectionGuard.Inspect(extra, budget, 1, CancellationToken.None));
    }

    [Fact]
    public async Task Huge_member_count_and_high_ratio_refuse_before_inspection()
    {
        await Check(Write(Zip(Enumerable.Range(0, 16_385).Select(i => Text(i + ".txt", "")).ToArray())), reason: "inspection_limit");
        await Check(Write(Zip(new Item("bomb.txt", new byte[2 * 1024 * 1024]) { Method = 8 })), reason: "inspection_limit");
    }

    [Theory]
    [InlineData("paragraph")]
    [InlineData("names")]
    [InlineData("name-content")]
    public async Task Separate_members_and_metadata_cannot_assemble_a_cpf(string shape)
    {
        byte[] bytes = shape switch
        {
            "names" => Zip(Text("529.982.", ""), Text("247-25.txt", "")),
            "name-content" => Zip(Text("529.982..txt", "247-25")),
            _ => Zip(Text("one.txt", "529.982."), Text("two.txt", "247-25"))
        };
        // The first names-only entry has no supported suffix and must refuse;
        // this is independent of the numeric-boundary controls below.
        await Check(Write(bytes), reason: shape == "names" ? "archive_unsupported_member" : null);
    }

    [Fact]
    public async Task Names_are_opaque_and_sensitive_name_components_are_redacted()
    {
        await Check(Write(Zip(Text("../outside.txt", Cpf))), sensitive: true, memberName: "../outside.txt");
        await Check(Write(Zip(Text("C:\\other\\document.txt", Cpf))), sensitive: true, memberName: "C:\\other\\document.txt");
        await Check(Write(Zip(Text("line\nname.txt", Cpf))), sensitive: true, memberName: "line\\u000Aname.txt");
        // Slash is an allowed CPF separator: scan the complete entry name,
        // not filesystem-like segments, before diagnostic redaction.
        await Check(Write(Zip(Text("529/982/247-25.txt", "clean"))), sensitive: true, memberName: "[sensitive name]");
        await Check(Write(Zip(new Item("529.982.247-25.zip", Zip(Text("document.txt", Cpf))))),
            sensitive: true, memberName: "[sensitive name]", additionalMember: "[sensitive name]!/document.txt");
        Assert.False(File.Exists(Path.Combine(_workspace.Root, "outside.txt")));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task All_members_share_the_existing_candidate_limit(bool over)
    {
        string half = string.Concat(Enumerable.Repeat(Cpf + ";", 8192));
        byte[] archive = Zip(Text("first.txt", half), Text("second.txt", half + (over ? Cpf : "")));
        var policy = Policy() with { ActiveCategories = new HashSet<Category> { Category.Cpf } };
        if (over) await Check(Write(archive), reason: "inspection_limit", policy: policy);
        else
        {
            string path = Write(archive);
            foreach (bool staged in new[] { false, true })
            {
                var result = await Inspect(path, staged, policy);
                Assert.Equal(Verdict.Blocked, result.Verdict); Assert.Null(result.Reason); Assert.Equal(16_384, result.Findings.Count);
                Assert.All(result.Findings, finding => Assert.Equal("•••••••••25", finding.MaskedSnippet));
                Assert.Equal(8192, result.Findings.Count(finding => finding.MemberName == "first.txt"));
                Assert.Equal(8192, result.Findings.Count(finding => finding.MemberName == "second.txt"));
            }
        }
    }

    [Fact]
    public async Task Repeated_long_diagnostic_prefixes_are_charged_before_materialization()
    {
        byte[] nested = Zip(Enumerable.Range(0, 100).Select(i => Text(i + ".txt", Cpf)).ToArray());
        byte[] bytes = Zip(new Item(new string('a', 8000) + ".zip", nested));
        await Check(Write(bytes), reason: "inspection_limit", policy: Policy() with { MaxFileSizeMb = 1 });
        var budget = new ArchiveInspectionBudget(16);
        budget.RetainDiagnostic(8);
        Assert.Throws<InspectionLimitException>(() => budget.RetainDiagnostic(1));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8192)]
    public async Task Streaming_and_legacy_extraction_have_identical_member_boundaries(int chunk)
    {
        byte[] bytes = Zip(Text("one.txt", Cpf), new Item("nested.zip", Zip(Text("two.txt", "529.982."), Text("three.txt", "247-25"))));
        using var input = new MemoryStream(bytes, writable: false);
        var extractor = new ZipArchiveExtractor(); var actual = new StringBuilder(); var buffer = new char[chunk]; int count;
        using (var reader = await extractor.OpenReaderAsync(input, CancellationToken.None))
            while ((count = await reader.ReadAsync(buffer.AsMemory())) != 0) actual.Append(buffer, 0, count);
        Assert.True(input.CanRead); input.Position = 0;
        Assert.Equal(await extractor.ExtractAsync(input, CancellationToken.None), actual.ToString());
        Assert.Equal(Category.Cpf, Assert.Single(ContentScanner.Scan(actual.ToString(), Enum.GetValues<Category>().ToHashSet())).Category);
        Assert.Contains("529.982.\nthree.txt\n247-25\n", actual.ToString());
        Assert.Equal(bytes, input.ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BCL_seekable_and_descriptor_writers_are_interoperable(bool descriptor)
    {
        using var memory = new MemoryStream();
        using (var output = new NonSeekingWriter(memory, descriptor))
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var writer = new StreamWriter(zip.CreateEntry("ação.txt").Open(), new UTF8Encoding(false));
            writer.Write(Cpf);
        }
        await Check(Write(memory.ToArray()), sensitive: true, memberName: "ação.txt");
    }

    [Fact]
    public async Task Reader_cancellation_and_disposal_leave_the_original_source_open()
    {
        using var input = new MemoryStream(Zip(Text("member.txt", "clean")), writable: false);
        var reader = await new ZipArchiveExtractor().OpenReaderAsync(input, CancellationToken.None);
        Assert.Equal((int)'m', reader.Peek()); Assert.Equal((int)'m', reader.Read());
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ReadAsync(new char[8].AsMemory(), canceled.Token).AsTask());
        reader.Dispose(); Assert.Throws<ObjectDisposedException>(() => reader.Read());
        Assert.True(input.CanRead); input.Position = 0; Assert.Equal((int)'P', input.ReadByte());
    }

    private byte[] Member(string extension, string text)
    {
        string path = extension switch
        {
            ".docx" => _workspace.WriteWordDocument(Guid.NewGuid() + extension, text),
            ".xlsx" => _workspace.WriteSpreadsheet(Guid.NewGuid() + extension, text),
            ".pdf" => _workspace.WritePdf(Guid.NewGuid() + extension, text),
            ".pptx" => PowerPointFixture.Create(_workspace.Root),
            _ => _workspace.WriteText(Guid.NewGuid() + extension, text)
        };
        if (extension == ".pptx")
        {
            using var zip = ZipFile.Open(path, ZipArchiveMode.Update);
            PowerPointFixture.Write(zip, PowerPointFixture.Slide, PowerPointFixture.SlideXml(PowerPointFixture.Shape(PowerPointFixture.Rich(text))));
        }
        return File.ReadAllBytes(path);
    }
    private string Write(byte[] bytes, string extension = ".zip")
    { string path = Path.Combine(_workspace.Root, Guid.NewGuid() + extension); File.WriteAllBytes(path, bytes); return path; }
    private static Policy Policy()
    {
        var policy = LocalPolicyStore.CreateDefault();
        return policy with { MonitoredScopes = policy.MonitoredScopes with { Extensions = policy.MonitoredScopes.Extensions.Concat(new[] { ".zip", ".7z" }).ToHashSet(StringComparer.OrdinalIgnoreCase) } };
    }
    private Task<InspectionResult> Inspect(string path, bool staged, Policy? policy = null)
    {
        var service = new InspectionService(new FixedPolicyStore(policy ?? Policy()), new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        return staged ? service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None) : service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
    }
    private async Task Check(string path, bool sensitive = false, string? reason = null, string? memberName = null, Policy? policy = null, string? additionalMember = null)
    {
        byte[] original = File.ReadAllBytes(path);
        foreach (bool staged in new[] { false, true })
        {
            var result = await Inspect(path, staged, policy);
            Assert.True(result.InScope);
            Assert.Equal(reason is not null ? staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection : sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Equal(reason, result.Reason);
            Assert.Equal(reason switch { null => (InspectionFailureKind?)null, "file_too_large" => InspectionFailureKind.TooLarge, "inspection_limit" => InspectionFailureKind.Limit, _ => InspectionFailureKind.UnsupportedFormat }, result.FailureKind);
            if (sensitive && reason is null)
            {
                Assert.NotEmpty(result.Findings);
                Assert.Equal(Category.Cpf, Assert.Single(result.Categories));
                Assert.All(result.Findings, finding => { Assert.Equal("•••••••••25", finding.MaskedSnippet); Assert.True(finding.MemberName == memberName || additionalMember is not null && finding.MemberName == additionalMember); });
                Assert.Contains(result.Findings, finding => finding.MemberName == memberName);
                if (additionalMember is not null) Assert.Contains(result.Findings, finding => finding.MemberName == additionalMember);
            }
            else Assert.Empty(result.Findings);
            Assert.Equal(original, File.ReadAllBytes(path));
        }
    }
    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
    }
    private sealed class NonSeekingWriter(Stream inner, bool nonSeeking) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => !nonSeeking;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => nonSeeking ? throw new NotSupportedException() : inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    }
}
