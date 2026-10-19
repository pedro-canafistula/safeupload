using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class AgentAuditIntegrationTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    [Theory]
    [InlineData("S-1-5-21-123-456-789-1001", "S-1-5-21-123-456-789-1001")]
    [InlineData("S-1-5-18", "S-1-5-18")]
    [InlineData(null, "Não identificado")]
    [InlineData("", "Não identificado")]
    [InlineData(" ", "Não identificado")]
    [InlineData("not-a-sid", "Não identificado")]
    public async Task Staged_caller_attribution_survives_queue_reopen_and_HTTP_without_using_the_service_account(
        string? callerSid, string expectedUser)
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var inspection = new InspectionService(new Policies(), sink, ExtractorRegistry.CreateDefault(),
            new VerdictCache(), "TEST", "synthetic-service-account");
        var stageRoot = Path.Combine(_workspace.Root, "audit-only-stage");
        var hub = NotificationTestHub.Create();
        int sessionLookups = 0;
        var publisher = new StagedTransferPublisher(inspection, hub,
            new StagedTransferJournal(Path.Combine(_workspace.Root, "audit-only-journal")),
            stageRoot, new NoPublication(), sessionUserSidResolver: _ =>
            {
                sessionLookups++;
                return "S-1-5-21-999-999-999-9999";
            });
        var operation = TestWorkspace.Operation(_workspace.WriteText("audit-only.txt", "synthetic"));
        var transfer = new StagedTransfer(Guid.NewGuid(), operation.FilePath, operation.DestinationPath,
            operation.Destination, operation.ProcessName, operation.ProcessId, 7) { RequestorSid = callerSid };
        const string hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var result = new InspectionResult(Verdict.Approved, [], null, 1, false, 7, true);
        await publisher.RecordTransferAuditAsync(transfer, operation, result, Verdict.Approved,
            null, CancellationToken.None, transfer.TransferId, hash);

        var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
        var queued = Assert.Single(await reopened.ReadPendingAsync(10, CancellationToken.None));
        Assert.Equal(expectedUser, queued.UserName);
        Assert.Equal("TEST", queued.EndpointId);
        using var accepted = new Handler(Acknowledge);
        await CycleAsync(reopened, accepted);
        using var payload = JsonDocument.Parse(Assert.Single(accepted.Payloads));
        var sent = payload.RootElement.GetProperty("events")[0];
        Assert.Equal(expectedUser, sent.GetProperty("userName").GetString());
        Assert.Equal(transfer.TransferId, sent.GetProperty("eventId").GetGuid());
        Assert.Equal(hash, sent.GetProperty("publishedSha256Hex").GetString());
        Assert.Equal(0, sessionLookups);
        Assert.Null(hub.CurrentStatus);
        Assert.False(Directory.Exists(stageRoot));
        Assert.Empty(await reopened.ReadPendingAsync(10, CancellationToken.None));
    }

    private sealed class NoPublication : IStagedPublicationGate
    {
        public IDisposable Authorize(StagedTransfer transfer, string temporaryDestination, string digest)
            => throw new InvalidOperationException("Attribution must never request publication.");
        public bool DisposeStage(Guid transferId, uint outcome, uint committedRenames)
            => throw new InvalidOperationException("Attribution must never dispose a stage.");
    }

    [Fact]
    public async Task Inspected_event_and_verified_service_identity_survive_offline_restart_and_dispatch()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var id = await InspectAndRecordAsync(sink);
        const string sid = "S-1-5-21-123-456-789-1001";
        using (var server = new JustificationPipeServer(new PendingOverrides(), new Policies(), sink,
            new OverrideGrantDispatcher(), new StagedJustifications(), NullLogger<JustificationPipeServer>.Instance))
            await server.RecordJustificationAsync(new JustificationRequest(id.ToString(), "Finalidade autorizada"),
                sid, CancellationToken.None);

        using var failed = new Handler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        await CycleAsync(sink, failed);
        var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
        Assert.Equal(id, Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None)).EventId);
        Assert.Equal("writer", Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None)).UserName);
        Assert.Equal(sid, Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None)).UserName);

        using var accepted = new Handler(Acknowledge);
        await CycleAsync(reopened, accepted);
        using var payload = JsonDocument.Parse(Assert.Single(accepted.Payloads));
        Assert.Equal(id, payload.RootElement.GetProperty("events")[0].GetProperty("eventId").GetGuid());
        Assert.Equal(sid, payload.RootElement.GetProperty("overrides")[0].GetProperty("userName").GetString());
        Assert.Equal(Environment.MachineName,
            payload.RootElement.GetProperty("overrides")[0].GetProperty("endpointId").GetString());
        Assert.DoesNotContain("529.982.247-25", accepted.Payloads[0]);
        Assert.DoesNotContain("52998224725", accepted.Payloads[0]);
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
        Assert.Equal(2, (await File.ReadAllLinesAsync(_workspace.QueueFile)).Length);
    }

    [Fact]
    public async Task Records_appended_while_HTTP_is_pending_remain_pending_after_snapshot_acknowledgement()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var first = Event();
        await sink.WriteAsync(first, CancellationToken.None);
        await sink.RecordOverrideAsync(first.EventId.ToString(), "first", CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler = new Handler(async json =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(5));
            return await Acknowledge(json);
        });
        var cycle = CycleAsync(sink, handler);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var later = Event();
            await sink.WriteAsync(later, CancellationToken.None);
            await sink.RecordOverrideAsync(first.EventId.ToString(), "later", CancellationToken.None);
            const string future = "{\"type\":\"future\",\"receipt\":123}";
            await File.AppendAllTextAsync(_workspace.QueueFile, future + Environment.NewLine);
            release.SetResult();
            await cycle.WaitAsync(TimeSpan.FromSeconds(5));
            var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
            Assert.Equal(later.EventId, Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None)).EventId);
            Assert.Equal("later", Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None)).Justification);
            Assert.Contains(future, await File.ReadAllLinesAsync(_workspace.QueueFile));
        }
        finally { release.TrySetResult(); await cycle.WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    [Fact]
    public async Task Cancellation_during_HTTP_keeps_both_record_types_for_the_next_cycle()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var audit = Event();
        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "pending", CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var handler = new Handler(_ => throw new InvalidOperationException("must use cancellable responder"))
        {
            Pending = async token =>
            {
                entered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException("must cancel");
            }
        };
        using var cancellation = new CancellationTokenSource();
        var cycle = CycleAsync(sink, handler, cancellation.Token);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cycle.WaitAsync(TimeSpan.FromSeconds(5)));
            var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
            Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None));
            Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
            using var accepted = new Handler(Acknowledge);
            await CycleAsync(reopened, accepted);
            Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
            Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
            Assert.Empty(Directory.GetFiles(_workspace.Root, "*.tmp"));
        }
        finally
        {
            cancellation.Cancel();
            try { await cycle.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public async Task Batch_limit_and_confirmation_preserve_M2_metadata_and_unknown_event_fields()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        const string hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var first = Event() with { PublishedSha256Hex = hash };
        await sink.WriteAsync(first, CancellationToken.None);
        // A future producer's extra field must survive acknowledgement as well.
        string original = await File.ReadAllTextAsync(_workspace.QueueFile);
        await File.WriteAllTextAsync(_workspace.QueueFile, original.Replace("\"dispatched\":false", "\"futureField\":42,\"dispatched\":false"));
        await sink.RecordOverrideAsync(first.EventId.ToString(), "first", CancellationToken.None);
        for (int i = 0; i < 100; i++)
        {
            var audit = Event();
            await sink.WriteAsync(audit, CancellationToken.None);
            await sink.RecordOverrideAsync(audit.EventId.ToString(), "reason " + i, CancellationToken.None);
        }
        using var handler = new Handler(Acknowledge);
        await CycleAsync(sink, handler);
        using (var batch = JsonDocument.Parse(handler.Payloads[0]))
        {
            Assert.Equal(100, batch.RootElement.GetProperty("events").GetArrayLength());
            Assert.Equal(100, batch.RootElement.GetProperty("overrides").GetArrayLength());
            Assert.Equal(hash, batch.RootElement.GetProperty("events")[0].GetProperty("publishedSha256Hex").GetString());
        }
        Assert.Single(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        await CycleAsync(sink, handler);
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        using var retained = JsonDocument.Parse((await File.ReadAllLinesAsync(_workspace.QueueFile))[0]);
        Assert.Equal(42, retained.RootElement.GetProperty("futureField").GetInt32());
        Assert.Equal(hash, retained.RootElement.GetProperty("publishedSha256Hex").GetString());
        Assert.Equal("File", retained.RootElement.GetProperty("channel").GetString());
        Assert.Equal(202, (await File.ReadAllLinesAsync(_workspace.QueueFile)).Length);
    }

    private async Task<Guid> InspectAndRecordAsync(LocalQueueAuditSink sink)
    {
        var service = new InspectionService(new Policies(), sink, ExtractorRegistry.CreateDefault(), new VerdictCache(),
            "TEST", "writer");
        var operation = TestWorkspace.Operation(_workspace.WriteText("private.txt", "CPF: 529.982.247-25"));
        var result = await service.InspectStagedAsync(operation, CancellationToken.None);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        var id = Guid.NewGuid();
        await service.RecordTransferOutcomeAsync(operation, result, Verdict.Blocked, "synthetic blocked outcome",
            CancellationToken.None, eventId: id);
        return id;
    }

    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "TEST", "writer", "synthetic.txt", ".txt", 10,
        Verdict.Blocked, [Category.Cpf], ["masked"], "test", 1, @"C:\Synthetic", null, 7, 1, false);

    private static async Task CycleAsync(LocalQueueAuditSink sink, Handler handler, CancellationToken token = default)
    {
        using var client = new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri("http://audit.invalid/agent/") };
        using var dispatcher = new HttpAgentDispatcher(sink, new Policies(), client, "TEST", TimeSpan.FromHours(1),
            NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(token);
    }

    private static Task<HttpResponseMessage> Acknowledge(string json)
    {
        using var document = JsonDocument.Parse(json);
        int events = document.RootElement.GetProperty("events").GetArrayLength();
        int overrides = document.RootElement.GetProperty("overrides").GetArrayLength();
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent($"{{\"acceptedEvents\":{events},\"acceptedOverrides\":{overrides}}}") });
    }

    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
    }

    private sealed class Handler(Func<string, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public List<string> Payloads = [];
        public Func<CancellationToken, Task<HttpResponseMessage>>? Pending;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("heartbeat")) throw new HttpRequestException("heartbeat unavailable");
            string json = await request.Content!.ReadAsStringAsync(token);
            Payloads.Add(json);
            return Pending is { } pending ? await pending(token) : await respond(json);
        }
    }
}
