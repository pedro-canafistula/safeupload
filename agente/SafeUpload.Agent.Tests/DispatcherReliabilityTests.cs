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
        public Task<Policy> LoadCurrentAsync(CancellationToken token) => LoadAsync(token);
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
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
