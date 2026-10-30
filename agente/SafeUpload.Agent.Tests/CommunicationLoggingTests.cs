using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Policies;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class CommunicationLoggingTests
{
    private const string Secret = "SEGREDO-SINTETICO-NAO-REGISTRAR";

    [Theory]
    [InlineData("http_status", 401, "HttpRejected")]
    [InlineData("timeout", null, "Timeout")]
    public void Erro_sanitizado_do_cliente_atual_preserva_categoria_e_status(string code, int? status, string failure)
    {
        var log = new Capture<HttpAgentDispatcher>(1);
        CommunicationLog.Warning(log, CommunicationLogStage.Heartbeat, new AgentApiException(code, status));
        AssertSafe(log);
        var entry = Assert.Single(log.Entries);
        Assert.Contains(entry.Values, value => value.Key == "Failure" && value.Value?.ToString() == failure);
        Assert.Contains(entry.Values, value => value.Key == "Status" && Equals(value.Value, status));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cliente_nomeado_nao_emite_logs_HTTP_padrao_sem_alterar_requisicao_ou_outros_clientes(bool fail)
    {
        var log = new Capture<object>(1);
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.SetMinimumLevel(LogLevel.Trace).AddProvider(new Provider(log)));
        Uri? received = null;
        SafeUpload.Agent.Service.Program.ConfigureAdministrationHttpClient(services,
                new Uri($"https://example.test/{Secret}/"), 7)
            .ConfigurePrimaryHttpMessageHandler(() => new Handler(request =>
            {
                received = request.RequestUri;
                return fail ? throw Failure() : new HttpResponseMessage(HttpStatusCode.OK);
            }));
        services.AddHttpClient("Unrelated").ConfigurePrimaryHttpMessageHandler(() =>
            new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        using var client = factory.CreateClient(SafeUpload.Agent.Service.Program.HttpClientName);
        Assert.Equal(TimeSpan.FromSeconds(7), client.Timeout);
        if (fail) await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"policy?endpointId={Secret}"));
        else using (await client.GetAsync($"policy?endpointId={Secret}")) { }
        Assert.Equal($"https://example.test/{Secret}/policy?endpointId={Secret}", received!.AbsoluteUri);
        Assert.Empty(log.Entries);
        using var other = factory.CreateClient("Unrelated");
        using var response = await other.GetAsync("https://example.test/plain");
        Assert.NotEmpty(log.Entries); // Only the administration client loses its default loggers.
    }

    [Fact]
    public async Task Inicio_e_falhas_do_ciclo_nao_registram_URL_identidade_ou_excecao_bruta()
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        await queue.WriteAsync(Event(), CancellationToken.None);
        var bytes = await File.ReadAllBytesAsync(workspace.QueueFile);
        using var client = new HttpClient(new Handler(_ => throw Failure()))
            { BaseAddress = new Uri($"https://{Secret}@example.test/{Secret}/?token={Secret}") };
        var log = new Capture<HttpAgentDispatcher>(2);
        using var dispatcher = new HttpAgentDispatcher(queue, new Policies(), client, Secret,
            TimeSpan.FromHours(1), log);
        await dispatcher.StartAsync(CancellationToken.None);
        try { await log.WarningsReady.Task.WaitAsync(TimeSpan.FromSeconds(10)); }
        finally { await dispatcher.StopAsync(CancellationToken.None); }
        AssertSafe(log);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Single(await new LocalQueueAuditSink(workspace.QueueFile).ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Falha_sanitizada_de_heartbeat_mantem_envio_independente_da_auditoria()
    {
        using var workspace = new TestWorkspace();
        var queue = new LocalQueueAuditSink(workspace.QueueFile);
        await queue.WriteAsync(Event(), CancellationToken.None);
        using var client = new HttpClient(new Handler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("heartbeat") ? throw Failure() :
                new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                    "{\"acceptedEvents\":1,\"acceptedOverrides\":0}", Encoding.UTF8, "application/json") }))
            { BaseAddress = new Uri("https://example.test/agent/") };
        var log = new Capture<HttpAgentDispatcher>(1);
        using var dispatcher = new HttpAgentDispatcher(queue, new Policies(), client, Secret,
            TimeSpan.FromHours(1), log);
        await dispatcher.RunCycleAsync(CancellationToken.None);
        AssertSafe(log);
        var warning = Assert.Single(log.Entries, e => e.Values.Any(v => v.Key == "Stage"));
        Assert.Contains(warning.Values, v => v.Key == "Stage" && v.Value?.ToString() == "Heartbeat");
        Assert.Contains(warning.Values, v => v.Key == "Failure" && v.Value?.ToString() == "TransportError");
        Assert.Contains(warning.Values, v => v.Key == "HResult" && v.Value is int);
        Assert.Empty(await queue.ReadPendingAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Falhas_inicial_e_periodica_da_politica_preservam_snapshot_sem_expor_excecao()
    {
        var policy = LocalPolicyStore.CreateDefault() with { Version = 7 };
        var log = new Capture<RefreshingPolicyStore>(2);
        using var store = new RefreshingPolicyStore(new Policies(fail: true), _ => Task.FromResult(policy),
            TimeSpan.FromMilliseconds(1), log);
        await store.StartAsync(CancellationToken.None);
        try { await log.WarningsReady.Task.WaitAsync(TimeSpan.FromSeconds(10)); }
        finally { await store.StopAsync(CancellationToken.None); }
        AssertSafe(log);
        Assert.Equal(7, (await store.LoadAsync(CancellationToken.None)).Version);
    }

    private static void AssertSafe<T>(Capture<T> log)
    {
        Assert.NotEmpty(log.Entries);
        Assert.All(log.Entries, entry =>
        {
            Assert.Null(entry.Exception);
            Assert.DoesNotContain(Secret, entry.Text);
            Assert.DoesNotContain(Secret, string.Join(";", entry.Values.Select(x => $"{x.Key}={x.Value}")));
        });
    }
    private static Exception Failure() => new HttpRequestException($"https://example.test/{Secret}?token={Secret}",
        new IOException($"C:\\{Secret}\\queue.jsonl"));
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC", "synthetic", "file.txt", ".txt", 1,
        Verdict.Approved, [], [], "synthetic", 1, "synthetic", null, 7, 1, false);
    private sealed class Policies(bool fail = false) : IPolicyStore
    { public Task<Policy> LoadAsync(CancellationToken token) => fail ? Task.FromException<Policy>(Failure()) : Task.FromResult(LocalPolicyStore.CreateDefault()); }
    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> action) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => Task.FromResult(action(request)); }
    private sealed record Entry(string Text, Exception? Exception, KeyValuePair<string, object?>[] Values);
    private sealed class Provider(Capture<object> log) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => log;
        public void Dispose() { }
    }
    private sealed class Capture<T>(int expectedWarnings) : ILogger<T>
    {
        public ConcurrentQueue<Entry> Entries { get; } = new();
        public TaskCompletionSource WarningsReady { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _warnings;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Entries.Enqueue(new(formatter(state, exception), exception,
                state is IEnumerable<KeyValuePair<string, object?>> values ? values.ToArray() : []));
            if (level == LogLevel.Warning && Interlocked.Increment(ref _warnings) >= expectedWarnings) WarningsReady.TrySetResult();
        }
    }
}
