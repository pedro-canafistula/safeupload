using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class DispatcherReliabilityTests
{
    [Theory]
    [InlineData("{\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":0}")]
    [InlineData("{}")]
    [InlineData("{\"acceptedEvents\":\"0\",\"acceptedOverrides\":1}")]
    public async Task Contagens_ausentes_ou_textuais_nao_confirmam_lote_so_de_justificativa(string body)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "Justificativa sintética", CancellationToken.None);
        var bytes = await File.ReadAllBytesAsync(workspace.QueueFile);
        await RunOneCycle(sink, new Handler(200, body));
        Assert.Equal(bytes, await File.ReadAllBytesAsync(workspace.QueueFile));
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
        await RunOneCycle(reopened, new Handler(200, "{\"acceptedEvents\":0,\"acceptedOverrides\":1}"));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    [Theory]
    [InlineData("{\"acceptedEvents\":1,\"acceptedOverrides\":1}")]
    [InlineData("{\"AcceptedEvents\":1,\"ACCEPTEDOVERRIDES\":1}")]
    [InlineData("{\"accepted\\u0045vents\":1,\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":1,\"acceptedOverrides\":1,\"futureMetadata\":{\"acceptedEvents\":0}}")]
    [InlineData("{\"acceptedOverrides\":1,\"futureMetadata\":null,\"acceptedEvents\":1}")]
    [InlineData("{\"acceptedEvents\":1,\"acceptedOverrides\":1,\"futureHint\":0,\"futureHint\":1}")]
    public async Task Recibo_inequivoco_preserva_compatibilidade_de_nomes_e_campos_futuros(string body)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-TESTE", "usuario",
            "synthetic.txt", ".txt", 10, Verdict.Blocked, [], [], "teste", 1, "sintetico", null, 7, 1, false);
        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "Justificativa sintética", CancellationToken.None);
        await RunOneCycle(sink, new Handler(200, body));
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        Assert.Equal(2, (await File.ReadAllLinesAsync(workspace.QueueFile)).Length);
    }

    [Theory]
    [InlineData("{\"acceptedEvents\":0,\"acceptedEvents\":1,\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":1,\"acceptedOverrides\":0,\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":0,\"ACCEPTEDEVENTS\":1,\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":1,\"acceptedOverrides\":0,\"AcceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":1,\"acceptedEvents\":1,\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":0,\"accepted\\u0045vents\":1,\"acceptedOverrides\":1}")]
    public async Task Recibo_ambiguo_preserva_bytes_e_reabertura_reenvia_o_mesmo_payload(string body)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-TESTE", "usuario",
            "synthetic.txt", ".txt", 10, Verdict.Blocked, [Category.Cpf], [], "teste", 1,
            @"E:\destino", null, 7, 1, false);
        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "Justificativa sintética", CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var rejected = new Handler(200, body);
        await RunOneCycle(sink, rejected);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));

        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(audit.EventId, Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None)).EventId);
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
        var accepted = new Handler(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":1}");
        await RunOneCycle(reopened, accepted);
        Assert.Equal(rejected.Payload, accepted.Payload);
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    [Theory]
    [InlineData(503, "{}")]
    [InlineData(200, "{\"acceptedEvents\":0,\"acceptedOverrides\":0}")]
    [InlineData(200, "null")]
    [InlineData(200, "invalid json")]
    [InlineData(200, "{\"acceptedEvents\":-1,\"acceptedOverrides\":1}")]
    [InlineData(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":2}")]
    public async Task Falha_nao_confirma_registros_e_reinicio_reenvia_evento_e_justificativa(int status, string body)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-TESTE", "usuario",
            "synthetic.txt", ".txt", 10, Verdict.Blocked, [Category.Cpf], [], "teste", 1,
            @"E:\destino", null, 1, 1, false);
        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "Envio autorizado de teste", CancellationToken.None);

        var failed = new Handler(status, body);
        await RunOneCycle(sink, failed);
        Assert.Single(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));

        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var accepted = new Handler(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":1}");
        await RunOneCycle(reopened, accepted);
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
        using var payload = JsonDocument.Parse(accepted.Payload!);
        Assert.Equal(audit.EventId, payload.RootElement.GetProperty("events")[0].GetProperty("eventId").GetGuid());
        Assert.Equal("Envio autorizado de teste", payload.RootElement.GetProperty("overrides")[0].GetProperty("justification").GetString());
        Assert.Equal(2, (await File.ReadAllLinesAsync(workspace.QueueFile)).Length);
    }

    private static async Task RunOneCycle(LocalQueueAuditSink sink, Handler handler)
    {
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/agent/") };
        using var dispatcher = new HttpAgentDispatcher(sink, new Policies(), client, "PC-TESTE",
            TimeSpan.FromHours(1), NullLogger<HttpAgentDispatcher>.Instance);
        try { await dispatcher.DispatchPendingAsync(CancellationToken.None); }
        catch (JsonException) { /* O laço de produção registra a falha e tenta novamente. */ }
    }

    [Fact]
    public async Task Heartbeat_indisponivel_nao_impede_envio_de_justificativas_pendentes()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "Justificativa pendente", CancellationToken.None);
        var handler = new Handler(200, "{\"acceptedEvents\":0,\"acceptedOverrides\":1}") { FailHeartbeat = true };
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/agent/") };
        using var dispatcher = new HttpAgentDispatcher(sink, new Policies(), client, "PC-TESTE",
            TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(CancellationToken.None);
        Assert.NotNull(handler.Payload);
        Assert.Empty(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }

    [Theory]
    [InlineData(200, "{\"status\":\"OK\"}")]
    [InlineData(404, "{}")]
    [InlineData(200, "{\"status\":\"WRONG\"}")]
    public async Task Registered_heartbeat_is_independent_from_policy_and_pending_audit(int status, string body)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "Justificativa de teste", CancellationToken.None);
        var auditHandler = new Handler(200, "{\"acceptedEvents\":0,\"acceptedOverrides\":1}");
        using var auditClient = new HttpClient(auditHandler) { BaseAddress = new Uri("http://localhost/agent/") };
        var heartbeatHandler = new RegisteredHeartbeatHandler(status, body);
        using var heartbeatClient = new HttpClient(heartbeatHandler) { BaseAddress = new Uri("http://localhost/agent/") };
        using var dispatcher = new HttpAgentDispatcher(sink, new UnavailablePolicy(), auditClient, "PC-TESTE",
            TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance)
        {
            HeartbeatSender = new RegisteredAgentHeartbeat(new AgentApiClient(heartbeatClient), 23)
        };
        await dispatcher.RunCycleAsync(CancellationToken.None);
        Assert.Equal("/agent/heartbeat", heartbeatHandler.Path);
        Assert.Equal("{\"id_host\":23}", heartbeatHandler.Body);
        Assert.Empty(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        Assert.NotNull(auditHandler.Payload);
    }

    [Fact]
    public async Task Failed_host_heartbeat_and_ambiguous_audit_receipt_preserve_batch_until_reopen_and_retry()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-TESTE", "usuario",
            "synthetic.txt", ".txt", 10, Verdict.Blocked, [Category.Cpf], [], "teste", 1,
            @"E:\destino", null, 7, 1, false);
        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "Justificativa sintética", CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);

        var rejectedAudit = new Handler(200,
            "{\"acceptedEvents\":0,\"acceptedEvents\":1,\"acceptedOverrides\":1}");
        var failedHeartbeat = new RegisteredHeartbeatHandler(503, "{}");
        await Cycle(sink, rejectedAudit, failedHeartbeat);
        Assert.Equal("/agent/heartbeat", failedHeartbeat.Path);
        Assert.Equal("{\"id_host\":7}", failedHeartbeat.Body);
        Assert.NotNull(rejectedAudit.Payload);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));

        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(audit.EventId, Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None)).EventId);
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
        var acceptedAudit = new Handler(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":1}");
        var recoveredHeartbeat = new RegisteredHeartbeatHandler(200, "{\"status\":\"OK\"}");
        await Cycle(reopened, acceptedAudit, recoveredHeartbeat);
        Assert.Equal("{\"id_host\":7}", recoveredHeartbeat.Body);
        Assert.Equal(rejectedAudit.Payload, acceptedAudit.Payload);
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));

        static async Task Cycle(LocalQueueAuditSink queue, Handler auditHandler, RegisteredHeartbeatHandler heartbeatHandler)
        {
            using var auditClient = new HttpClient(auditHandler) { BaseAddress = new Uri("http://localhost/agent/") };
            using var heartbeatClient = new HttpClient(heartbeatHandler) { BaseAddress = new Uri("http://localhost/agent/") };
            using var dispatcher = new HttpAgentDispatcher(queue, new UnavailablePolicy(), auditClient, "PC-TESTE",
                TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance)
            {
                HeartbeatSender = new RegisteredAgentHeartbeat(new AgentApiClient(heartbeatClient), 7)
            };
            await dispatcher.RunCycleAsync(CancellationToken.None);
        }
    }

    private sealed class UnavailablePolicy : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => throw new InvalidOperationException("Heartbeat AgentApi não deve consultar política.");
    }

    private sealed class RegisteredHeartbeatHandler(int status, string body) : HttpMessageHandler
    {
        public string? Path { get; private set; }
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Path = request.RequestUri!.AbsolutePath;
            Body = await request.Content!.ReadAsStringAsync(token);
            return new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Handler(int status, string body) : HttpMessageHandler
    {
        public TaskCompletionSource Sent { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string? Payload { get; private set; }
        public bool FailHeartbeat { get; init; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("heartbeat"))
            {
                if (FailHeartbeat) throw new HttpRequestException("Heartbeat indisponível");
                return new HttpResponseMessage(HttpStatusCode.OK);
            }
            Payload = await request.Content!.ReadAsStringAsync(token);
            Sent.TrySetResult();
            return new HttpResponseMessage((HttpStatusCode)status)
                { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }
}
