using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class InspectionInputSizeTests
{
    [Theory]
    [InlineData(".txt")]
    [InlineData(".csv")]
    [InlineData(".pdf")]
    [InlineData(".docx")]
    public async Task Legacy_reads_actual_size_before_capturing_or_parsing_stale_metadata(string extension)
    {
        using var workspace = new TestWorkspace();
        string path = Path.Combine(workspace.Root, "grown" + extension);
        File.WriteAllBytes(path, new byte[1024 * 1024 + 1]);
        var extractor = new CountingExtractor(extension);
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var engine = Engine(extractor, queue);
        var operation = TestWorkspace.Operation(path, sizeBytes: 1);
        var result = await engine.InspectAsync(operation, default);
        Assert.Equal(Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.Equal("file_too_large", result.Reason);
        Assert.False(result.FromCache);
        Assert.Equal(0, extractor.Calls);
        Assert.Equal("file_too_large", Assert.Single(await queue.ReadPendingAsync(10, default)).NotInspectedReason);
        // A refused large file must not install a reusable clean verdict.
        File.WriteAllBytes(path, [(byte)'x']);
        var retried = await engine.InspectAsync(operation, default);
        Assert.Equal(Verdict.Approved, retried.Verdict);
        Assert.False(retried.FromCache);
        Assert.Equal(1, extractor.Calls);
    }

    [Theory]
    [InlineData(false, 8, 7)]
    [InlineData(false, 7, 8)]
    [InlineData(false, 0, 1)]
    [InlineData(false, 1, 0)]
    [InlineData(true, 8, 7)]
    [InlineData(true, 7, 8)]
    [InlineData(true, 0, 1)]
    [InlineData(true, 1, 0)]
    public async Task Staged_path_and_read_lease_both_reject_a_different_measured_version(bool lease, int actual, int declared)
    {
        using var workspace = new TestWorkspace();
        string path = Path.Combine(workspace.Root, "snapshot.txt");
        File.WriteAllBytes(path, Enumerable.Repeat((byte)'x', actual).ToArray());
        var extractor = new CountingExtractor(".txt");
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        var engine = Engine(extractor, queue);
        var operation = TestWorkspace.Operation(path, sizeBytes: declared);
        FileStream? opened = null;
        var result = lease ? await engine.InspectStagedAsync(operation,
            () => opened = File.OpenRead(path), default) : await engine.InspectStagedAsync(operation, default);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
        Assert.Equal(0, extractor.Calls);
        Assert.False(result.FromCache);
        Assert.Null(result.RecordedEvent);
        Assert.Empty(await queue.ReadPendingAsync(10, default));
        if (opened is not null) Assert.False(opened.CanRead);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(true, 0)]
    [InlineData(true, 1)]
    public async Task Staged_actual_size_limit_precedes_version_mismatch_even_when_declared_empty(bool lease, int declared)
    {
        using var workspace = new TestWorkspace();
        string path = Path.Combine(workspace.Root, "grown.txt");
        File.WriteAllBytes(path, new byte[1024 * 1024 + 1]);
        var extractor = new CountingExtractor(".txt");
        var engine = Engine(extractor, new LocalQueueAuditSink(workspace.QueueFile));
        var operation = TestWorkspace.Operation(path, sizeBytes: declared);
        FileStream? opened = null;
        var result = lease ? await engine.InspectStagedAsync(operation,
            () => opened = File.OpenRead(path), default) : await engine.InspectStagedAsync(operation, default);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.Equal("file_too_large", result.Reason);
        Assert.Equal(0, extractor.Calls);
        if (opened is not null) Assert.False(opened.CanRead);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Exact_policy_limit_still_allows_a_complete_inspection(bool staged)
    {
        using var workspace = new TestWorkspace();
        string path = Path.Combine(workspace.Root, "boundary.txt");
        File.WriteAllBytes(path, new byte[1024 * 1024]);
        var extractor = new CountingExtractor(".txt");
        var engine = Engine(extractor, new LocalQueueAuditSink(workspace.QueueFile));
        var operation = TestWorkspace.Operation(path);
        var result = staged ? await engine.InspectStagedAsync(operation, default) : await engine.InspectAsync(operation, default);
        Assert.Equal(Verdict.Approved, result.Verdict);
        Assert.Null(result.Reason);
        Assert.Equal(1, extractor.Calls);
    }

    private static InspectionService Engine(ITextExtractor extractor, IAuditSink queue) => new(
        new Policies(), queue, new ExtractorRegistry([extractor]), new VerdictCache());
    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(
            LocalPolicyStore.CreateDefault() with { MaxFileSizeMb = 1 });
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
    }
    private sealed class CountingExtractor(string extension) : ITextExtractor
    {
        public int Calls;
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { extension };
        public Task<string> ExtractAsync(Stream content, CancellationToken token)
        { Interlocked.Increment(ref Calls); return Task.FromResult("clean fixture"); }
    }
}
