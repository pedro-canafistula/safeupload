using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyFailureModeContractTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    public static IEnumerable<object[]> Cases()
    {
        foreach (bool failOpen in new[] { false, true })
        foreach (bool staged in new[] { false, true })
        foreach (string failure in new[] { "size", "unsupported", "parse" })
            yield return [failOpen, staged, failure];
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Failure_mode_is_defined_by_inspection_path_not_document_flag(
        bool failOpen, bool staged, string failure)
    {
        _workspace.WritePolicy($$"""
            { "version": 7, "activeCategories": ["Cpf"],
              "monitoredScopes": { "extensions": [".txt", ".docx"],
                "destinationPaths": ["C:\\PolicyFailureTest"],
                "removableDrives": false, "networkPaths": false },
              "maxFileSizeMb": 1, "inspectionTimeoutSeconds": 5,
              "failOpen": {{(failOpen ? "true" : "false")}}, "excludedProcesses": [] }
            """);
        var store = new LocalPolicyStore(_workspace.PolicyFile);
        Assert.Equal(failOpen, (await store.LoadCurrentAsync(CancellationToken.None)).FailOpen);
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var registry = failure == "unsupported"
            ? new ExtractorRegistry([new OpenXmlWordExtractor()]) : ExtractorRegistry.CreateDefault();
        var service = new InspectionService(store, sink, registry, new VerdictCache());
        var path = _workspace.WriteText(failure == "parse" ? "invalid.docx" : "private.txt", "not an Office document");
        // Cloud is the existing domain enum for a policy-selected local path;
        // this component test does not qualify any cloud client or volume.
        var operation = TestWorkspace.Operation(path, destination: DestinationKind.Cloud,
            destinationPath: @"C:\PolicyFailureTest\result.txt",
            sizeBytes: failure == "size" ? 2L * 1024 * 1024 : null);
        var result = staged
            ? await service.InspectStagedAsync(operation, CancellationToken.None)
            : await service.InspectAsync(operation, CancellationToken.None);

        Assert.True(result.InScope);
        Assert.Equal(7, result.PolicyVersion);
        Assert.Equal(staged ? Verdict.Blocked : Verdict.AllowedWithoutInspection, result.Verdict);
        Assert.Empty(result.Findings);
        Assert.False(result.FromCache);
        if (failure == "parse") Assert.StartsWith("parse_error:", result.Reason, StringComparison.Ordinal);
        else Assert.Equal(failure == "size" ? "file_too_large" : "unsupported_format", result.Reason);
        Assert.False(await service.IsCurrentStagedApprovalAsync(operation, result, CancellationToken.None));
        // Inspection is not a staged transfer outcome. Only the legacy path logs here.
        var events = await sink.ReadRecentAsync(10, CancellationToken.None);
        if (staged) Assert.Empty(events);
        else Assert.Equal(result.Verdict, Assert.Single(events).Verdict);
    }
}
