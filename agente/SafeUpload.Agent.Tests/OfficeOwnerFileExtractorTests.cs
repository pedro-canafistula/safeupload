using System.Text;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class OfficeOwnerFileExtractorTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(".docx")]
    [InlineData(".xlsx")]
    [InlineData(".pptx")]
    public async Task Ordinary_owner_name_is_clean(string extension)
    {
        byte[] bytes = new byte[162];
        Encoding.Latin1.GetBytes("Maria Silva").CopyTo(bytes, 1);
        Encoding.Unicode.GetBytes("Maria Silva").CopyTo(bytes, 56);
        await Check("~$report" + extension, bytes, sensitive: false);
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 56)]
    [InlineData(true, 57)]
    public async Task Cpf_in_ansi_or_either_utf16_alignment_is_found(bool unicode, int offset)
    {
        byte[] bytes = new byte[162];
        (unicode ? Encoding.Unicode : Encoding.Latin1).GetBytes("529.982.247-25").CopyTo(bytes, offset);
        await Check("~$x.docx", bytes, sensitive: true);
    }

    [Fact]
    public async Task Owner_file_over_four_kib_keeps_package_reader_and_refuses_nonpackage()
    {
        byte[] bytes = Enumerable.Repeat((byte)'x', OfficeOwnerFileExtractor.MaxBytes + 1).ToArray();
        string path = Path.Combine(_workspace.Root, "~$x.docx");
        File.WriteAllBytes(path, bytes);
        Assert.False(OfficeOwnerFileExtractor.Matches("~$x.docx", ".docx", bytes.Length));
        var service = Service();
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
            Assert.StartsWith("parse_error:", result.Reason);
            Assert.Empty(result.Findings);
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => OfficeOwnerFileExtractor.Instance.ExtractAsync(
            new MemoryStream(bytes), CancellationToken.None));
        Assert.Equal(bytes, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData("~$x.docx", ".docx", 4096, true)]
    [InlineData("~$x.DOCX", ".DOCX", 162, true)]
    [InlineData("x.docx", ".docx", 162, false)]
    [InlineData("~$x.pdf", ".pdf", 162, false)]
    [InlineData("~$x.docx", ".docx", -1, false)]
    public void Only_bounded_office_owner_files_use_text_reader(string name, string extension, long length, bool expected)
        => Assert.Equal(expected, OfficeOwnerFileExtractor.Matches(name, extension, length));

    private async Task Check(string name, byte[] bytes, bool sensitive)
    {
        string path = Path.Combine(_workspace.Root, name);
        File.WriteAllBytes(path, bytes);
        var policies = new LocalPolicyStore(_workspace.PolicyFile);
        await policies.LoadAsync(CancellationToken.None);
        var policy = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(_workspace.PolicyFile))!;
        policy["monitoredScopes"]!["extensions"]!.AsArray().Add(Path.GetExtension(name));
        File.WriteAllText(_workspace.PolicyFile, policy.ToJsonString());
        var service = Service();
        foreach (bool staged in new[] { false, true })
        {
            var result = staged ? await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None)
                : await service.InspectAsync(TestWorkspace.Operation(path), CancellationToken.None);
            Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
            Assert.Null(result.Reason);
            if (sensitive) Assert.Contains(Category.Cpf, result.Categories);
            else Assert.Empty(result.Findings);
        }
        Assert.Equal(bytes, File.ReadAllBytes(path));
    }

    private InspectionService Service() => new(new LocalPolicyStore(_workspace.PolicyFile), new LocalQueueAuditSink(_workspace.QueueFile),
        ExtractorRegistry.CreateDefault(), new VerdictCache());
}
