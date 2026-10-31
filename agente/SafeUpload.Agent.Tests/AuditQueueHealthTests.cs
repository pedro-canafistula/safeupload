using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueueHealthTests
{
    [Fact]
    public async Task Inspecao_com_fila_real_ocupada_mantem_veredito_sinaliza_falha_e_nao_inventa_recuperacao()
    {
        using var workspace = new TestWorkspace();
        var inner = new LocalQueueAuditSink(workspace.QueueFile);
        await inner.WriteAsync(Event(), CancellationToken.None);
        var health = new AuditQueueHealth();
        var log = new RecordingLogger();
        var sink = new MonitoredAuditSink(inner, health, log);
        var policy = LocalPolicyStore.CreateDefault() with { AuditOnly = false,
            MonitoredScopes = new MonitoredScopes(new HashSet<string> { ".txt" }, [], true, true) };
        var service = new InspectionService(new Policies(policy), sink, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var file = workspace.WriteText("arquivo-sintetico.txt", "CPF: 529.982.247-25");
        using (var locked = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var result = await service.InspectAsync(TestWorkspace.Operation(file), CancellationToken.None);
            Assert.Equal(Verdict.Blocked, result.Verdict);
            Assert.True(health.Read().Degraded);
            Assert.Equal(1, health.Read().FailedWriteAttempts);
        }
        var after = await service.InspectAsync(TestWorkspace.Operation(file), CancellationToken.None);
        Assert.Equal(Verdict.Blocked, after.Verdict);
        Assert.False(health.Read().Degraded);
        Assert.Equal(1, health.Read().FailedWriteAttempts);
        Assert.Equal(2, (await inner.ReadRecentAsync(0, CancellationToken.None)).Count);
        Assert.Equal(new[] { 3101, 3102 }, log.Messages.Select(m => m.Id));
        Assert.DoesNotContain(file, string.Join(" ", log.Messages.Select(m => m.Text)));
        Assert.DoesNotContain("529.982.247-25", string.Join(" ", log.Messages.Select(m => m.Text)));
    }

    [Fact]
    public async Task Falhas_repetidas_sao_contadas_sem_tempestade_de_logs_e_sem_vazar_excecao()
    {
        var failure = new IOException("SENSITIVE_PATH_AND_CONTENT", unchecked((int)0x80070070));
        var inner = new Stub(); inner.Failures[AuditQueueOperation.WriteEvent] = failure;
        var health = new AuditQueueHealth(); var log = new RecordingLogger();
        var sink = new MonitoredAuditSink(inner, health, log);
        for (var i = 0; i < 20; i++)
            Assert.Same(failure, await Record.ExceptionAsync(() => sink.WriteAsync(Event(), CancellationToken.None)));
        await sink.ReadRecentAsync(1, CancellationToken.None);
        Assert.True(health.Read().Degraded); // A successful read cannot clear a failed write.
        Assert.Equal(20, health.Read().FailedWriteAttempts);
        Assert.Single(log.Messages);
        var state = health.Read().Operations.Single(o => o.Operation == "WriteEvent");
        Assert.Equal("disk_full", state.FailureKind);
        Assert.Equal(failure.HResult, state.FailureHResult);
        Assert.NotNull(state.LastFailureUtc);
        Assert.DoesNotContain("SENSITIVE", JsonSerializer.Serialize(health.Read()));
        Assert.DoesNotContain("SENSITIVE", log.Messages[0].Text);
        Assert.Null(log.Messages[0].Exception);
        inner.Failures.Clear();
        await sink.WriteAsync(Event(), CancellationToken.None);
        Assert.False(health.Read().Degraded);
        Assert.Equal(20, health.Read().FailedWriteAttempts);
        Assert.NotNull(health.Read().Operations.Single(o => o.Operation == "WriteEvent").LastSuccessUtc);
        Assert.Equal(new[] { 3101, 3102 }, log.Messages.Select(m => m.Id));
    }

    [Fact]
    public async Task Cancelamento_solicitado_nao_vira_falha_de_disco_mas_cancelamento_inesperado_e_sinalizado()
    {
        var inner = new Stub(); var health = new AuditQueueHealth();
        var sink = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.WriteAsync(Event(), cancel.Token));
        Assert.False(health.Read().Degraded);
        Assert.Equal(0, health.Read().FailedWriteAttempts);
        inner.Failures[AuditQueueOperation.WriteEvent] = new OperationCanceledException("SENSITIVE");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.WriteAsync(Event(), CancellationToken.None));
        Assert.True(health.Read().Degraded);
        Assert.Equal("unexpected_cancellation", health.Read().Operations.Single(o => o.Operation == "WriteEvent").FailureKind);
    }

    [Fact]
    public async Task Provedor_de_log_com_falha_nao_substitui_excecao_nem_faz_gravacao_bem_sucedida_falhar()
    {
        var inner = new Stub(); var failure = new UnauthorizedAccessException("SENSITIVE");
        inner.Failures[AuditQueueOperation.WriteEvent] = failure;
        var health = new AuditQueueHealth();
        var sink = new MonitoredAuditSink(inner, health, new RecordingLogger { Throw = true });
        Assert.Same(failure, await Record.ExceptionAsync(() => sink.WriteAsync(Event(), CancellationToken.None)));
        Assert.True(health.Read().Degraded);
        inner.Failures.Clear();
        await sink.WriteAsync(Event(), CancellationToken.None);
        Assert.False(health.Read().Degraded);
        Assert.Equal(1, health.Read().FailedWriteAttempts);
    }

    [Fact]
    public async Task Decorador_preserva_justificativas_identidade_e_confirmacao_separada()
    {
        using var workspace = new TestWorkspace(); var inner = new LocalQueueAuditSink(workspace.QueueFile);
        var health = new AuditQueueHealth();
        var sink = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        var item = Event(); var reason = new AuditOverride(item.EventId, "SINTETICA", item.OccurredAtUtc, "DOMINIO\\sintetico", "PC-SINTETICO");
        await sink.WriteAsync(item, CancellationToken.None);
        await sink.RecordOverrideAsync(reason, CancellationToken.None);
        Assert.Equal(reason, Assert.Single(await ((IOverrideQueue)sink).ReadPendingOverridesAsync(100, CancellationToken.None)));
        await sink.MarkDispatchedAsync([item.EventId], CancellationToken.None);
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        await sink.MarkOverridesDispatchedAsync([reason], CancellationToken.None);
        Assert.Empty(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        Assert.True(Assert.Single(await sink.ReadRecentAsync(100, CancellationToken.None)).Dispatched);
        Assert.False(health.Read().Degraded);
    }

    [Theory]
    [InlineData(AuditQueueOperation.WriteOverride)]
    [InlineData(AuditQueueOperation.ReadRecent)]
    [InlineData(AuditQueueOperation.ReadPending)]
    [InlineData(AuditQueueOperation.ReadPendingOverrides)]
    [InlineData(AuditQueueOperation.ConfirmEvents)]
    [InlineData(AuditQueueOperation.ConfirmOverrides)]
    public async Task Estado_de_cada_operacao_so_recupera_apos_sucesso_da_propria_operacao(AuditQueueOperation op)
    {
        var inner = new Stub(); inner.Failures[op] = new IOException("SENSITIVE");
        var health = new AuditQueueHealth(); var sink = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        await Assert.ThrowsAsync<IOException>(() => Invoke(sink, op));
        await sink.WriteAsync(Event(), CancellationToken.None);
        Assert.True(health.Read().Degraded);
        inner.Failures.Clear(); await Invoke(sink, op);
        Assert.False(health.Read().Degraded);
        Assert.Equal(1, health.Read().Operations.Single(o => o.Operation == op.ToString()).Failures);
    }

    [Fact]
    public async Task Pipe_administrativo_expoe_estado_sem_driver_sem_conteudo_e_sem_acesso_ao_arquivo_da_fila()
    {
        var inner = new Stub(); inner.Failures[AuditQueueOperation.WriteEvent] = new IOException("SENSITIVE");
        var health = new AuditQueueHealth(); var sink = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        await Assert.ThrowsAsync<IOException>(() => sink.WriteAsync(Event(), CancellationToken.None));
        var name = "SafeUpload.Agent.Diagnostics.Test." + Guid.NewGuid().ToString("N");
        var before = JsonSerializer.Serialize(health.Read());
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(), NullLogger<DiagnosticsPipeServer>.Instance, name, auditHealth: health);
        await server.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"audit-health\"}\n"), timeout.Token);
            using var reader = new StreamReader(pipe);
            var line = await reader.ReadLineAsync(timeout.Token);
            Assert.NotNull(line); Assert.DoesNotContain("SENSITIVE", line);
            using var json = JsonDocument.Parse(line);
            Assert.True(json.RootElement.GetProperty("ok").GetBoolean());
            var data = json.RootElement.GetProperty("data");
            Assert.True(data.GetProperty("degraded").GetBoolean());
            Assert.Equal(1, data.GetProperty("failedWriteAttempts").GetInt64());
            Assert.Equal(7, data.GetProperty("operations").GetArrayLength());
            Assert.Equal(before, JsonSerializer.Serialize(health.Read()));
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }

    [Fact]
    public async Task Composicao_do_servico_compartilha_fila_e_monitor_sem_criar_segunda_instancia()
    {
        using var workspace = new TestWorkspace();
        var inner = new LocalQueueAuditSink(workspace.QueueFile);
        var services = new ServiceCollection();
        services.AddLogging();
        SafeUpload.Agent.Service.Program.ConfigureAuditStorage(services);
        services.AddSingleton(inner); // Override only the data path; exercise actual service registrations.
        using var provider = services.BuildServiceProvider();
        var sink = provider.GetRequiredService<IAuditSink>();
        Assert.Same(sink, provider.GetRequiredService<MonitoredAuditSink>());
        Assert.Same(inner, provider.GetRequiredService<LocalQueueAuditSink>());
        Assert.IsAssignableFrom<IOverrideQueue>(sink);
        await sink.WriteAsync(Event(), CancellationToken.None);
        Assert.Single(await inner.ReadPendingAsync(100, CancellationToken.None));
        var health = provider.GetRequiredService<AuditQueueHealth>();
        Assert.Same(health, provider.GetRequiredService<AuditQueueHealth>());
        Assert.Equal(1, health.Read().Operations.Single(o => o.Operation == "WriteEvent").Successes);
        Assert.Equal(0, health.Read().Operations.Single(o => o.Operation == "ReadPending").Successes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Dispatcher_com_monitor_preserva_recibo_integral_e_confirmacao_de_evento_e_justificativa(bool complete)
    {
        using var workspace = new TestWorkspace();
        var inner = new LocalQueueAuditSink(workspace.QueueFile);
        var health = new AuditQueueHealth();
        var sink = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        var item = Event();
        await sink.WriteAsync(item, CancellationToken.None);
        await sink.RecordOverrideAsync(new AuditOverride(item.EventId, "Justificativa sintética", item.OccurredAtUtc,
            item.UserName, item.EndpointId), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        using var client = new HttpClient(new ReceiptHandler(complete)) { BaseAddress = new Uri("http://127.0.0.1/agent/") };
        using var dispatcher = new HttpAgentDispatcher(sink, new Policies(LocalPolicyStore.CreateDefault()), client,
            "PC-SINTETICO", TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance);
        await dispatcher.DispatchPendingAsync(CancellationToken.None);
        Assert.Equal(complete ? 0 : 1, (await inner.ReadPendingAsync(100, CancellationToken.None)).Count);
        Assert.Equal(complete ? 0 : 1, (await inner.ReadPendingOverridesAsync(100, CancellationToken.None)).Count);
        if (!complete) Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        foreach (var operation in new[] { "ConfirmEvents", "ConfirmOverrides" })
        {
            var state = health.Read().Operations.Single(o => o.Operation == operation);
            Assert.Equal(complete ? 1 : 0, state.Successes);
            Assert.Equal(0, state.Failures);
        }
    }

    [Fact]
    public async Task Contagens_concorrentes_sao_exatas_e_novo_monitor_nao_herda_historico()
    {
        var failure = new IOException("SENSITIVE");
        var inner = new Stub(); inner.Failures[AuditQueueOperation.WriteEvent] = failure;
        var health = new AuditQueueHealth(); var log = new RecordingLogger();
        var sink = new MonitoredAuditSink(inner, health, log);
        await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(async () =>
            Assert.Same(failure, await Record.ExceptionAsync(() => sink.WriteAsync(Event(), CancellationToken.None))))));
        Assert.Equal(64, health.Read().FailedWriteAttempts);
        Assert.Single(log.Messages);
        inner.Failures.Clear();
        await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(() => sink.WriteAsync(Event(), CancellationToken.None))));
        var state = health.Read().Operations.Single(o => o.Operation == "WriteEvent");
        Assert.Equal(64, state.Failures); Assert.Equal(64, state.Successes);
        Assert.False(state.Degraded);
        Assert.Equal(new[] { 3101, 3102 }, log.Messages.Select(m => m.Id));
        var fresh = new AuditQueueHealth().Read();
        Assert.False(fresh.Degraded); Assert.Equal(0, fresh.FailedWriteAttempts);
        Assert.All(fresh.Operations, o => { Assert.Equal(0, o.Failures); Assert.Equal(0, o.Successes); });
    }

    [Fact]
    public async Task Pipe_sem_monitor_retorna_indisponibilidade_sem_inventar_estado_saudavel()
    {
        var name = "SafeUpload.Agent.Health.Unavailable." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(), NullLogger<DiagnosticsPipeServer>.Instance, name);
        await server.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"audit-health\"}\n"), timeout.Token);
            using var reader = new StreamReader(pipe);
            using var json = JsonDocument.Parse((await reader.ReadLineAsync(timeout.Token))!);
            Assert.False(json.RootElement.GetProperty("ok").GetBoolean());
            Assert.Equal("Audit monitoring is unavailable.", json.RootElement.GetProperty("error").GetString());
            Assert.False(json.RootElement.TryGetProperty("data", out _));
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }

    private sealed class ReceiptHandler(bool complete) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(
                new { acceptedEvents = 1, acceptedOverrides = complete ? 1 : 0 }), Encoding.UTF8, "application/json") });
    }

    private static Task Invoke(MonitoredAuditSink sink, AuditQueueOperation op) => op switch
    {
        AuditQueueOperation.WriteOverride => sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "SINTETICA", CancellationToken.None),
        AuditQueueOperation.ReadRecent => sink.ReadRecentAsync(1, CancellationToken.None),
        AuditQueueOperation.ReadPending => sink.ReadPendingAsync(1, CancellationToken.None),
        AuditQueueOperation.ReadPendingOverrides => sink.ReadPendingOverridesAsync(1, CancellationToken.None),
        AuditQueueOperation.ConfirmEvents => sink.MarkDispatchedAsync([Guid.NewGuid()], CancellationToken.None),
        AuditQueueOperation.ConfirmOverrides => sink.MarkOverridesDispatchedAsync([], CancellationToken.None),
        _ => throw new ArgumentOutOfRangeException(nameof(op))
    };
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SINTETICO", "usuario-sintetico",
        "arquivo-sintetico.txt", ".txt", 42, Verdict.Blocked, [Category.Cpf], [], "sintetico", 123, "SINTETICO", null, 1, 1, false);
    private sealed class Policies(Policy policy) : IPolicyStore
    { public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(policy); }
    private sealed class Stub : IAuditSink, IOverrideQueue
    {
        public Dictionary<AuditQueueOperation, Exception> Failures { get; } = [];
        private Task Check(AuditQueueOperation op, CancellationToken token) { token.ThrowIfCancellationRequested(); if (Failures.TryGetValue(op, out var e)) throw e; return Task.CompletedTask; }
        public Task WriteAsync(AuditEvent e, CancellationToken t) => Check(AuditQueueOperation.WriteEvent, t);
        public Task RecordOverrideAsync(string id, string reason, CancellationToken t) => Check(AuditQueueOperation.WriteOverride, t);
        public async Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int n, CancellationToken t) { await Check(AuditQueueOperation.ReadRecent, t); return []; }
        public async Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int n, CancellationToken t) { await Check(AuditQueueOperation.ReadPending, t); return []; }
        public async Task<IReadOnlyList<AuditOverride>> ReadPendingOverridesAsync(int n, CancellationToken t) { await Check(AuditQueueOperation.ReadPendingOverrides, t); return []; }
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken t) => Check(AuditQueueOperation.ConfirmEvents, t);
        public Task MarkOverridesDispatchedAsync(IReadOnlyCollection<AuditOverride> rows, CancellationToken t) => Check(AuditQueueOperation.ConfirmOverrides, t);
    }
    private sealed class RecordingLogger : ILogger<MonitoredAuditSink>
    {
        public bool Throw { get; init; }
        public List<(int Id, string Text, Exception? Exception)> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        { if (Throw) throw new IOException("LOGGER_SYNTHETIC"); Messages.Add((id.Id, formatter(state, exception), exception)); }
    }
}
