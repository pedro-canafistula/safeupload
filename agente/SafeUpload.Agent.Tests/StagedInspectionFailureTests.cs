using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class StagedInspectionFailureTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Trivial_empty_inspection_measures_content_instead_of_trusting_declared_size(bool forgedZero)
    {
        var policy = LocalPolicyStore.CreateDefault() with { Version = 7 };
        var service = new InspectionService(new FixedPolicyStore(policy),
            new LocalQueueAuditSink(_workspace.QueueFile), new ExtractorRegistry([]), new VerdictCache());
        string path = _workspace.WriteText("placeholder.unknown", forgedZero ? "CPF: 529.982.247-25" : string.Empty);
        if (!forgedZero) await File.WriteAllBytesAsync(path, []); // WriteText uses UTF-8 with a BOM.
        FileOperation operation = TestWorkspace.Operation(path, sizeBytes: 0);
        InspectionResult result = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Equal(forgedZero ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        Assert.Equal(!forgedZero, await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
        Assert.True(result.InScope);
        Assert.Equal(7, result.PolicyVersion);
        Assert.False(result.FromCache);
        if (forgedZero) Assert.Equal(InspectionFailureKind.ReadOrParse, result.FailureKind);
        else Assert.Null(result.FailureKind);
    }

    [Theory]
    [InlineData("size", "file_too_large", false)]
    [InlineData("size", "file_too_large", true)]
    [InlineData("format", "unsupported_format", false)]
    [InlineData("format", "unsupported_format", true)]
    [InlineData("parser", "parse_error:InvalidDataException", false)]
    [InlineData("parser", "parse_error:InvalidDataException", true)]
    [InlineData("read", "parse_error:FileNotFoundException", false)]
    [InlineData("read", "parse_error:FileNotFoundException", true)]
    [InlineData("timeout", "inspection_timeout", false)]
    [InlineData("timeout", "inspection_timeout", true)]
    public async Task Staged_inspection_failures_are_blocked_and_legacy_failure_contract_is_preserved(
        string failure, string reason, bool staged)
    {
        var policy = LocalPolicyStore.CreateDefault() with
        {
            Version = 7, MaxFileSizeMb = 1,
            // Only the timeout fixture has a one-second policy. Other cases
            // test their own failure reason under the normal five-second policy.
            InspectionTimeoutSeconds = failure == "timeout" ? 1 : 5, OverrideAllowed = true
        };
        using var release = new CancellationTokenSource();
        var registry = failure switch
        {
            "format" => new ExtractorRegistry([]),
            "parser" => new ExtractorRegistry([new FailingExtractor(false, release.Token)]),
            "timeout" => new ExtractorRegistry([new FailingExtractor(true, release.Token)]),
            _ => ExtractorRegistry.CreateDefault()
        };
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var service = new InspectionService(new FixedPolicyStore(policy), sink, registry, new VerdictCache());
        var path = _workspace.WriteText("failure.txt", failure == "size"
            ? new string('x', 1024 * 1024 + 1) : "fixture bytes");
        var operation = TestWorkspace.Operation(path);
        if (failure == "read") File.Delete(path);

        try
        {
            var result = staged
                ? await service.InspectStagedAsync(operation, CancellationToken.None)
                : await service.InspectAsync(operation, CancellationToken.None);

            Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
            Assert.Equal(staged, result.IsBlocked);
            Assert.Equal(reason, result.Reason);
            Assert.Equal(failure switch
            {
                "size" => InspectionFailureKind.TooLarge,
                "format" => InspectionFailureKind.UnsupportedFormat,
                "timeout" => InspectionFailureKind.Timeout,
                _ => InspectionFailureKind.ReadOrParse
            }, result.FailureKind);
            Assert.Equal(7, result.PolicyVersion);
            Assert.True(result.InScope);
            Assert.False(result.FromCache);
            Assert.Empty(result.Findings);
            Assert.False(await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
            Assert.Equal(staged, await service.IsCurrentStagedJustificationAllowedAsync(
                operation, result, CancellationToken.None));
            var audit = await sink.ReadRecentAsync(10, CancellationToken.None);
            Assert.Equal(staged ? 0 : 1, audit.Count);
            if (!staged) Assert.Equal(Verdict.AllowedWithoutInspection, audit[0].Verdict);
        }
        finally { release.Cancel(); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task The_exact_inspection_limit_is_scanned_including_sensitive_content_at_eof(bool sensitive)
    {
        const int length = 1024 * 1024;
        const string cpf = " CPF: 529.982.247-25";
        var bytes = Enumerable.Repeat((byte)'x', length).ToArray();
        if (sensitive) System.Text.Encoding.ASCII.GetBytes(cpf).CopyTo(bytes, length - cpf.Length);
        var path = Path.Combine(_workspace.Root, "at-limit.txt");
        await File.WriteAllBytesAsync(path, bytes);
        var policy = LocalPolicyStore.CreateDefault() with { MaxFileSizeMb = 1 };
        var service = new InspectionService(new FixedPolicyStore(policy),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());

        var result = await service.InspectStagedAsync(TestWorkspace.Operation(path), CancellationToken.None);

        Assert.Equal(sensitive ? Verdict.Blocked : Verdict.Approved, result.Verdict);
        Assert.Null(result.Reason);
        Assert.True(result.InScope);
        if (sensitive) Assert.Equal(Category.Cpf, Assert.Single(result.Categories));
        else Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Caller_cancellation_propagates_in_both_inspection_modes(bool staged)
    {
        var service = new InspectionService(new FixedPolicyStore(LocalPolicyStore.CreateDefault()),
            new LocalQueueAuditSink(_workspace.QueueFile), ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(_workspace.WriteText("cancel.txt", "fixture bytes"));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => staged
            ? service.InspectStagedAsync(operation, cancellation.Token)
            : service.InspectAsync(operation, cancellation.Token));
        Assert.Empty(await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(10, CancellationToken.None));
    }

    private sealed class FixedPolicyStore(Policy policy) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken cancellationToken) => Task.FromResult(policy);
        public Task<Policy> LoadCurrentAsync(CancellationToken cancellationToken) => LoadAsync(cancellationToken);
    }

    private sealed class FailingExtractor(bool timeout, CancellationToken release) : ITextExtractor
    {
        public IReadOnlySet<string> SupportedExtensions { get; } = new HashSet<string> { ".txt" };
        public async Task<string> ExtractAsync(Stream content, CancellationToken cancellationToken)
        {
            if (timeout) await Task.Delay(Timeout.Infinite, release);
            throw new InvalidDataException("Sensitive parser diagnostic: 529.982.247-25");
        }
    }
}
