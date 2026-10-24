using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AgentAuditDispatchTests
{
    [Fact]
    public async Task Bloqueio_envia_metadados_host_e_versao_sem_trechos_e_preserva_auditoria_local()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = Event() with { FileName = @"C:\privado\sintético.txt", MaskedSnippets = ["SYNTHETIC_CONTENT_DO_NOT_SEND"] };
        await sink.WriteAsync(audit, CancellationToken.None);
        var wire = new Wire();
        await Cycle(sink, wire);
        using var payload = JsonDocument.Parse(wire.Events!);
        var root = payload.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(Environment.MachineName, root.GetProperty("hostname").GetString());
        var version = typeof(HttpAgentDispatcher).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion;
        Assert.Equal(version, root.GetProperty("agentVersion").GetString());
        using var heartbeat = JsonDocument.Parse(wire.Heartbeat!);
        Assert.Equal(version, heartbeat.RootElement.GetProperty("agentVersion").GetString());
        Assert.Equal("PC-ORIGEM", heartbeat.RootElement.GetProperty("endpointId").GetString());
        var item = root.GetProperty("events")[0];
        Assert.Equal(audit.EventId, item.GetProperty("eventId").GetGuid());
        Assert.Equal(audit.OccurredAtUtc.ToUniversalTime(), item.GetProperty("occurredAtUtc").GetDateTimeOffset());
        Assert.Equal(TimeSpan.Zero, item.GetProperty("occurredAtUtc").GetDateTimeOffset().Offset);
        Assert.Equal("PC-ORIGEM", item.GetProperty("endpointId").GetString());
        Assert.Equal("sintético.txt", item.GetProperty("fileName").GetString());
        Assert.Equal("Blocked", item.GetProperty("verdict").GetString());
        Assert.Equal(7, item.GetProperty("policyVersion").GetInt32());
        Assert.Equal("usuario-sintetico", item.GetProperty("userName").GetString());
        Assert.Equal(42, item.GetProperty("sizeBytes").GetInt64());
        Assert.Equal("File", item.GetProperty("channel").GetString());
        Assert.Equal(0, item.GetProperty("maskedSnippets").GetArrayLength());
        Assert.DoesNotContain("SYNTHETIC_CONTENT_DO_NOT_SEND", wire.Events!);
        Assert.False(item.TryGetProperty("content", out _));
        var local = Assert.Single(await sink.ReadRecentAsync(10, CancellationToken.None));
        Assert.Equal(audit.MaskedSnippets, local.MaskedSnippets);
        Assert.True(local.Dispatched);
    }

    [Theory]
    [InlineData("https://synthetic:secret@example.test/private/token?access_token=secret#secret", "https://example.test")]
    [InlineData("https://example.test:8443/path/secret", "https://example.test:8443")]
    [InlineData("not a URI secret", "")]
    [InlineData("file:///C:/private/secret", "")]
    public async Task Destino_web_envia_apenas_origem_http(string destination, string expected)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.WriteAsync(Event() with { Channel = AuditChannel.Web, DestinationPath = destination }, CancellationToken.None);
        var wire = new Wire();
        await Cycle(sink, wire);
        using var payload = JsonDocument.Parse(wire.Events!);
        Assert.Equal(expected, payload.RootElement.GetProperty("events")[0].GetProperty("destinationPath").GetString());
        Assert.DoesNotContain("secret", wire.Events!);
        Assert.Equal(destination, Assert.Single(await sink.ReadRecentAsync(10, CancellationToken.None)).DestinationPath);
    }

    [Theory]
    [InlineData("{\"acceptedOverrides\":1}")]
    [InlineData("{\"acceptedEvents\":0}")]
    [InlineData("{}")]
    public async Task Resposta_sem_ambas_contagens_nao_confirma_justificativa(string reply)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.RecordOverrideAsync(Event().EventId.ToString(), "Justificativa sintética", CancellationToken.None);
        await Cycle(sink, new Wire(reply: reply));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Falha_de_rede_preserva_id_e_horario_apos_reabrir_fila()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = Event();
        await sink.WriteAsync(audit, CancellationToken.None);
        await Assert.ThrowsAsync<HttpRequestException>(() => Cycle(sink, new Wire(failEvents: true)));
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(audit.EventId, Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None)).EventId);
        var wire = new Wire();
        await Cycle(reopened, wire);
        using var payload = JsonDocument.Parse(wire.Events!);
        var item = payload.RootElement.GetProperty("events")[0];
        Assert.Equal(audit.EventId, item.GetProperty("eventId").GetGuid());
        Assert.Equal(audit.OccurredAtUtc, item.GetProperty("occurredAtUtc").GetDateTimeOffset());
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Lotes_limitados_nao_confirmam_eventos_fora_do_envio()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        for (var i = 0; i < 101; i++) await sink.WriteAsync(Event(), CancellationToken.None);
        var wire = new Wire();
        await Cycle(sink, wire);
        using var payload = JsonDocument.Parse(wire.Events!);
        Assert.Equal(100, payload.RootElement.GetProperty("events").GetArrayLength());
        Assert.Single(await sink.ReadPendingAsync(100, CancellationToken.None));
        await Cycle(sink, new Wire());
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Rota_de_heartbeat_ausente_na_api_nao_impede_auditoria()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.WriteAsync(Event(), CancellationToken.None);
        var wire = new Wire(heartbeatStatus: HttpStatusCode.NotFound);

        await Cycle(sink, wire);

        Assert.NotNull(wire.Heartbeat);
        Assert.NotNull(wire.Events);
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task Recusa_de_autenticacao_preserva_evento_e_justificativa_para_reenvio(HttpStatusCode status)
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var audit = Event();
        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(), "Revisão sintética", CancellationToken.None);
        await Cycle(sink, new Wire(eventsStatus: status));

        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var pending = Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Equal(audit.EventId, pending.EventId);
        Assert.Equal(audit.OccurredAtUtc, pending.OccurredAtUtc);
        Assert.Single(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));

        await Cycle(reopened, new Wire());
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Empty(await reopened.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    private static AuditEvent Event() => new(Guid.NewGuid(),
        new DateTimeOffset(2026, 10, 20, 13, 15, 0, TimeSpan.FromHours(-3)),
        "PC-ORIGEM", "usuario-sintetico", "sintético.txt", ".txt", 42, Verdict.Blocked,
        [Category.Cpf], [], "processo-teste", 123, @"E:\Destino", null, 7, 15, false);

    private static async Task Cycle(LocalQueueAuditSink sink, Wire wire)
    {
        using var client = new HttpClient(wire) { BaseAddress = new Uri("http://127.0.0.1/agent/") };
        using var dispatcher = new HttpAgentDispatcher(sink, new Policies(), client, "PC-ORIGEM",
            TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.RunCycleAsync(CancellationToken.None);
    }

    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }

    private sealed class Wire(string? reply = null, bool failEvents = false,
        HttpStatusCode heartbeatStatus = HttpStatusCode.OK,
        HttpStatusCode eventsStatus = HttpStatusCode.OK) : HttpMessageHandler
    {
        public string? Events { get; private set; }
        public string? Heartbeat { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            var body = await request.Content!.ReadAsStringAsync(token);
            if (request.RequestUri!.AbsolutePath == "/agent/heartbeat")
            {
                Heartbeat = body;
                return new HttpResponseMessage(heartbeatStatus);
            }
            Assert.Equal("/agent/events", request.RequestUri.AbsolutePath);
            if (failEvents) throw new HttpRequestException("Synthetic offline failure");
            Events = body;
            using var json = JsonDocument.Parse(body);
            var response = reply ?? JsonSerializer.Serialize(new {
                acceptedEvents = json.RootElement.GetProperty("events").GetArrayLength(),
                acceptedOverrides = json.RootElement.GetProperty("overrides").GetArrayLength()
            });
            return new HttpResponseMessage(eventsStatus) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
