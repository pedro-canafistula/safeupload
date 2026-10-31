using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class NewAuditMetadataTests
{
    [Theory]
    [InlineData("https://synthetic:secret@example.test/private/secret?token=secret#secret", "https://example.test")]
    [InlineData("http://example.test:8080/private", "http://example.test:8080")]
    [InlineData("https://[::1]:8443/private", "https://[::1]:8443")]
    [InlineData("not a URL secret", "")]
    [InlineData("file:///C:/private/secret", "")]
    [InlineData("//example.test/private/secret", "")]
    public async Task New_web_producer_stores_and_dispatches_only_the_origin(string destination, string expected)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var policies = new LocalPolicyStore(workspace.PolicyFile);
        var service = new WebInspectionService(policies, sink, ExtractorRegistry.CreateDefault());
        var result = await service.InspectAsync(new WebUpload(destination, "chrome", 42,
            [new WebUploadPart(@"C:\private\secret\synthetic.txt", Encoding.UTF8.GetBytes("CPF: 529.982.247-25"), true)]), CancellationToken.None);
        var created = Assert.Single(result.Records).Event;
        Assert.NotEqual(Guid.Empty, created.EventId);
        Assert.Equal(expected, created.DestinationPath);
        Assert.Equal("synthetic.txt", created.FileName);
        var persisted = Assert.Single(await new LocalQueueAuditSink(workspace.QueueFile).ReadPendingAsync(20, CancellationToken.None));
        Assert.Equal(created.EventId, persisted.EventId);
        Assert.Equal(created.DestinationPath, persisted.DestinationPath);
        Assert.Equal(created.FileName, persisted.FileName);
        Assert.DoesNotContain("secret", await File.ReadAllTextAsync(workspace.QueueFile));
        var wire = new CaptureWire();
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://central.invalid/agent/") };
        var dispatcher = new HttpAgentDispatcher(sink, policies, http, "test", TimeSpan.FromHours(1), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(CancellationToken.None);
        using var json = JsonDocument.Parse(wire.Body!);
        var sent = json.RootElement.GetProperty("events")[0];
        Assert.Equal(created.EventId, sent.GetProperty("eventId").GetGuid());
        Assert.Equal(expected, sent.GetProperty("destinationPath").GetString());
        Assert.DoesNotContain("secret", wire.Body!);
        Assert.Empty(await sink.ReadPendingAsync(20, CancellationToken.None));
    }

    [Fact]
    public async Task Fresh_file_identity_uses_basename_without_changing_operational_path_or_existing_transfer_identity()
    {
        using var workspace = new TestWorkspace();
        string path = workspace.WriteText("synthetic.txt", "CPF: 529.982.247-25");
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var service = new InspectionService(new LocalPolicyStore(workspace.PolicyFile), sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var operation = TestWorkspace.Operation(path) with { FileName = @"C:\private\synthetic.txt" };
        var result = await service.InspectAsync(operation, CancellationToken.None);
        Assert.True(result.IsBlocked);
        var fresh = Assert.Single(await sink.ReadPendingAsync(10, CancellationToken.None));
        Assert.Equal("synthetic.txt", fresh.FileName);
        Assert.Equal(path, operation.FilePath);
        Assert.True(File.Exists(path));
        var existingId = Guid.NewGuid();
        await service.RecordTransferOutcomeAsync(operation, result, Verdict.Retained, "publication_failed", CancellationToken.None, existingId);
        var existing = (await sink.ReadPendingAsync(10, CancellationToken.None)).Single(e => e.EventId == existingId);
        Assert.Equal(operation.FileName, existing.FileName);
        Assert.NotEqual(fresh.EventId, existing.EventId);
    }

    private sealed class CaptureWire : HttpMessageHandler
    {
        internal string? Body;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/events"))
            {
                Body = await request.Content!.ReadAsStringAsync(token);
                return new(HttpStatusCode.OK) { Content = new StringContent("{\"acceptedEvents\":1,\"acceptedOverrides\":0}", Encoding.UTF8, "application/json") };
            }
            return new(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        }
    }
}
