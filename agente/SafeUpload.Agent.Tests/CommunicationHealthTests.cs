using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class CommunicationHealthTests
{
    [Theory]
    [InlineData(false, "not_configured")]
    [InlineData(true, "not_attempted")]
    public void Estado_inicial_nao_inventa_conexao_ou_qualificacao(bool configured, string state)
    {
        var health = new CommunicationHealth(configured);
        var before = JsonSerializer.Serialize(health.Read());
        Assert.All(health.Read().Operations, o => { Assert.Equal(state, o.State); Assert.Equal(0, o.Attempts); });
        Assert.Equal(3, health.Read().Operations.Count);
        Assert.False(health.Read().ProtectionQualified);
        Assert.False(health.Read().ApiPersistenceQualified);
        Assert.False(health.Read().PolicyAppliedToDriverQualified);
        Assert.Equal(before, JsonSerializer.Serialize(health.Read()));
        Assert.All(new CommunicationHealth(configured).Read().Operations, o => Assert.Equal(0, o.Attempts));
    }

    [Fact]
    public void Recuperacao_e_independente_e_observacao_so_termina_uma_vez()
    {
        var health = new CommunicationHealth(true);
        using (var attempt = new CommunicationObservation(health, CommunicationOperation.Heartbeat))
        {
            Assert.Equal("in_progress", State(health, CommunicationOperation.Heartbeat).State);
            attempt.Failure(CommunicationFailure.HttpRejected, 401);
            attempt.Success(); // Must not change a completed failure.
        }
        using (var audit = new CommunicationObservation(health, CommunicationOperation.Audit)) audit.Success(200);
        Assert.Equal("Failure", State(health, CommunicationOperation.Heartbeat).State);
        using (var heartbeat = new CommunicationObservation(health, CommunicationOperation.Heartbeat)) heartbeat.Success(204);
        var state = State(health, CommunicationOperation.Heartbeat);
        Assert.Equal(2, state.Attempts); Assert.Equal(1, state.Failures); Assert.Equal(1, state.Successes);
        Assert.Equal(0, state.InFlight); Assert.Equal("Success", state.State); Assert.Equal("HttpRejected", state.LastFailureKind);
        Assert.NotNull(state.LastFailureUtc); Assert.NotNull(state.LastSuccessUtc);
    }

    [Fact]
    public void Conclusao_antiga_nao_substitui_resultado_de_tentativa_mais_nova()
    {
        var health = new CommunicationHealth(true);
        using var older = new CommunicationObservation(health, CommunicationOperation.Policy);
        using var newer = new CommunicationObservation(health, CommunicationOperation.Policy);
        newer.Success(200, PolicyLoadSource.Remote, true);
        older.Failure(CommunicationFailure.HttpRejected, 503, PolicyLoadSource.Memory);
        var state = State(health, CommunicationOperation.Policy);
        Assert.Equal("Success", state.State); Assert.Equal("Remote", state.LastPolicySource);
        Assert.Equal(1, state.Successes); Assert.Equal(1, state.Failures); Assert.Equal(0, state.InFlight);
    }

    [Fact]
    public void Contadores_concorrentes_preservam_invariante_sem_guardar_historico_ilimitado()
    {
        var health = new CommunicationHealth(true);
        Parallel.For(0, 1000, i =>
        {
            using var observation = new CommunicationObservation(health, CommunicationOperation.Audit);
            if (i % 2 == 0) observation.Success(200); else observation.Failure(CommunicationFailure.TransportError);
            var s = State(health, CommunicationOperation.Audit);
            Assert.Equal(s.Attempts, s.Successes + s.Failures + s.Cancellations + s.InFlight);
        });
        var final = State(health, CommunicationOperation.Audit);
        Assert.Equal(1000, final.Attempts); Assert.Equal(500, final.Successes); Assert.Equal(500, final.Failures);
        Assert.Equal(0, final.InFlight); Assert.Equal(3, health.Read().Operations.Count);
    }

    [Theory]
    [InlineData(401, "{}", "HttpRejected")]
    [InlineData(403, "{}", "HttpRejected")]
    [InlineData(200, "INVALID-SENSITIVE", "InvalidResponse")]
    [InlineData(200, "{\"activeCategories\":[]}", "InvalidResponse")]
    public async Task Consulta_de_politica_falha_sem_perder_fallback_e_sem_expor_dados(int status, string body, string kind)
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        using var client = Client(new Handler(_ => Reply(status, body)));
        var store = new DurableHttpPolicyStore(client, "SENSITIVE", workspace.PolicyFile, false, health);
        var policy = await store.LoadAsync(CancellationToken.None);
        Assert.NotEmpty(policy.ActiveCategories);
        var s = State(health, CommunicationOperation.Policy);
        Assert.Equal(kind, s.LastFailureKind); Assert.Equal(status, s.LastHttpStatus);
        Assert.Equal("Default", s.LastPolicySource); Assert.Equal(1, s.Failures); Assert.Equal(0, s.Successes);
        Assert.DoesNotContain("SENSITIVE", JsonSerializer.Serialize(health.Read()));
    }

    [Fact]
    public async Task Politica_remota_validada_e_cache_persistido_nao_equivalem_a_aplicacao_no_driver()
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        string body = "{\"version\":7,\"activeCategories\":[\"Cpf\"]}";
        using var client = Client(new Handler(_ => Reply(200, body)));
        var store = new DurableHttpPolicyStore(client, "PC", workspace.PolicyFile, false, health);
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
        Assert.True(State(health, CommunicationOperation.Policy).LastRemoteCachePersisted);
        body = "invalid";
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
        Assert.Equal("Memory", State(health, CommunicationOperation.Policy).LastPolicySource);
        Assert.Equal(1, State(health, CommunicationOperation.Policy).Successes);
        Assert.Equal(1, State(health, CommunicationOperation.Policy).Failures);
        Assert.False(health.Read().PolicyAppliedToDriverQualified);
        var otherHealth = new CommunicationHealth(true);
        var reopened = new DurableHttpPolicyStore(client, "PC", workspace.PolicyFile, false, otherHealth);
        Assert.Equal(7, (await reopened.LoadAsync(CancellationToken.None)).Version);
        Assert.Equal("Disk", State(otherHealth, CommunicationOperation.Policy).LastPolicySource);
        await reopened.LoadCachedOrDefaultAsync(CancellationToken.None);
        Assert.Equal(1, State(otherHealth, CommunicationOperation.Policy).Attempts);
    }

    [Fact]
    public async Task Falha_de_cache_nao_transforma_politica_remota_valida_em_falha_HTTP()
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        Directory.CreateDirectory(workspace.PolicyFile); // The destination is a directory, not a policy file.
        using var client = Client(new Handler(_ => Reply(200, "{\"version\":9,\"activeCategories\":[\"Cpf\"]}")));
        var store = new DurableHttpPolicyStore(client, "PC", workspace.PolicyFile, false, health);
        Assert.Equal(9, (await store.LoadAsync(CancellationToken.None)).Version);
        var s = State(health, CommunicationOperation.Policy);
        Assert.Equal("Success", s.State); Assert.False(s.LastRemoteCachePersisted); Assert.Equal(0, s.Failures);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Timeout_e_cancelamento_solicitado_sao_distintos(bool requested)
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        using var cancel = new CancellationTokenSource();
        using var client = Client(new Handler(_ =>
        {
            if (requested) cancel.Cancel();
            throw new TaskCanceledException("SENSITIVE");
        }));
        var store = new DurableHttpPolicyStore(client, "PC", workspace.PolicyFile, false, health);
        if (requested) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadAsync(cancel.Token));
        else await store.LoadAsync(cancel.Token);
        var s = State(health, CommunicationOperation.Policy);
        Assert.Equal(requested ? 1 : 0, s.Cancellations); Assert.Equal(requested ? 0 : 1, s.Failures);
        Assert.Equal(requested ? null : "Timeout", s.LastFailureKind); Assert.Equal(0, s.InFlight);
    }

    [Theory]
    [InlineData(401, "{}", "HttpRejected")]
    [InlineData(200, "{\"acceptedEvents\":0,\"acceptedEvents\":1,\"acceptedOverrides\":0}", "InvalidResponse")]
    [InlineData(200, "invalid", "InvalidResponse")]
    public async Task Auditoria_recusada_ou_invalida_preserva_fila_e_diagnostica_falha(int status, string body, string failure)
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        var queue = new LocalQueueAuditSink(workspace.QueueFile); await queue.WriteAsync(Event(), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        using var client = Client(new Handler(_ => Reply(status, body)));
        using var dispatcher = Dispatcher(queue, client, health);
        try { await dispatcher.DispatchPendingAsync(CancellationToken.None); } catch (JsonException) { }
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        var s = State(health, CommunicationOperation.Audit);
        Assert.Equal(failure, s.LastFailureKind); Assert.Equal(status, s.LastHttpStatus); Assert.Equal(1, s.Failures);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Heartbeat_recusado_nao_bloqueia_auditoria_e_fila_vazia_nao_inventa_envio(bool transportError)
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        var queue = new LocalQueueAuditSink(workspace.QueueFile); await queue.WriteAsync(Event(), CancellationToken.None);
        using var client = Client(new Handler(request =>
        {
            if (!request.RequestUri!.AbsolutePath.EndsWith("heartbeat")) return Reply(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":0}");
            if (transportError) throw new HttpRequestException("SENSITIVE");
            return Reply(403, "SENSITIVE");
        }));
        using var dispatcher = Dispatcher(queue, client, health);
        await dispatcher.RunCycleAsync(CancellationToken.None);
        Assert.Equal(transportError ? null : (int?)403, State(health, CommunicationOperation.Heartbeat).LastHttpStatus);
        Assert.Equal(transportError ? "TransportError" : "HttpRejected", State(health, CommunicationOperation.Heartbeat).LastFailureKind);
        Assert.Equal("Success", State(health, CommunicationOperation.Audit).State);
        Assert.Empty(await queue.ReadPendingAsync(100, CancellationToken.None));
        await dispatcher.DispatchPendingAsync(CancellationToken.None);
        Assert.Equal(1, State(health, CommunicationOperation.Audit).Attempts);
        Assert.DoesNotContain("SENSITIVE", JsonSerializer.Serialize(health.Read()));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Observador_com_falha_nao_altera_politica_ou_confirmacao(bool throwOnStart)
    {
        using var workspace = new TestWorkspace(); var observer = new BrokenObserver(throwOnStart);
        using var client = Client(new Handler(request => request.RequestUri!.AbsolutePath.EndsWith("policy")
            ? Reply(200, "{\"version\":7,\"activeCategories\":[\"Cpf\"]}")
            : Reply(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":0}")));
        var store = new DurableHttpPolicyStore(client, "PC", workspace.PolicyFile, false, observer);
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
        var queue = new LocalQueueAuditSink(workspace.QueueFile); await queue.WriteAsync(Event(), CancellationToken.None);
        using var dispatcher = Dispatcher(queue, client, observer);
        await dispatcher.DispatchPendingAsync(CancellationToken.None);
        Assert.Empty(await queue.ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Recibo_valido_com_confirmacao_local_recusada_nao_vira_falha_de_comunicacao()
    {
        using var workspace = new TestWorkspace(); var health = new CommunicationHealth(true);
        var queue = new LocalQueueAuditSink(workspace.QueueFile); await queue.WriteAsync(Event(), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        using var locked = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var client = Client(new Handler(_ => Reply(200, "{\"acceptedEvents\":1,\"acceptedOverrides\":0}")));
        using var dispatcher = Dispatcher(queue, client, health);
        var error = await Record.ExceptionAsync(() => dispatcher.DispatchPendingAsync(CancellationToken.None));
        Assert.True(error is IOException or UnauthorizedAccessException);
        Assert.Equal("Success", State(health, CommunicationOperation.Audit).State);
        Assert.Equal(1, State(health, CommunicationOperation.Audit).Successes);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pipe_sem_driver_responde_sem_mutar_contadores_e_indica_monitor_ausente(bool available)
    {
        var health = new CommunicationHealth(false);
        string pipeName = "SafeUpload.Communication.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(),
            NullLogger<DiagnosticsPipeServer>.Instance, pipeName, communicationHealth: available ? health : null);
        await server.StartAsync(CancellationToken.None);
        try
        {
            string before = JsonSerializer.Serialize(health.Read());
            using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(cancel.Token);
            await client.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"communication-health\"}\n"), cancel.Token);
            await client.FlushAsync(cancel.Token);
            using var reader = new StreamReader(client, Encoding.UTF8, false, 1024, true);
            var reply = JsonNode.Parse((await reader.ReadLineAsync(cancel.Token))!)!;
            Assert.Equal(available, reply["ok"]!.GetValue<bool>());
            if (available) Assert.False(reply["data"]!["configured"]!.GetValue<bool>());
            Assert.Equal(before, JsonSerializer.Serialize(health.Read()));
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }

    private static CommunicationOperationHealth State(CommunicationHealth health, CommunicationOperation op) => health.Read().Operations.Single(x => x.Operation == op.ToString());
    private static HttpClient Client(HttpMessageHandler handler) => new(handler) { BaseAddress = new Uri("http://localhost/SENSITIVE/") };
    private static HttpResponseMessage Reply(int status, string body) => new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    private static HttpAgentDispatcher Dispatcher(LocalQueueAuditSink queue, HttpClient client, ICommunicationObserver observer) =>
        new(queue, new Policies(), client, "PC", TimeSpan.FromHours(1), NullLogger<HttpAgentDispatcher>.Instance, observer);
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC", "synthetic", "file.txt", ".txt", 1, Verdict.Approved, [], [], "synthetic", 1, "synthetic", null, 7, 1, false);
    private sealed class Policies : IPolicyStore { public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault()); }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> action) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => Task.FromResult(action(request)); }
    private sealed class BrokenObserver(bool start) : ICommunicationObserver
    {
        public long Started(CommunicationOperation operation) => start ? throw new IOException("SENSITIVE") : 1;
        public void Completed(CommunicationOperation operation, long attempt, CommunicationOutcome outcome, CommunicationFailure? failure, int? httpStatus, PolicyLoadSource? source, bool? persisted) => throw new IOException("SENSITIVE");
    }
}
