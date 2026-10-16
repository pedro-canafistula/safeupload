using System.Net;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class DurableHttpPolicyStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(),
        "safeupload-policy-test-" + Guid.NewGuid().ToString("N"));

    private string Cache => Path.Combine(_root, "server-policy-cache.json");

    [Fact]
    public async Task Recupera_ultima_politica_valida_apos_reinicio_offline()
    {
        using (var online = Store(HttpStatusCode.OK,
            """{"version":23,"activeCategories":["Cpf"],"maxFileSizeMb":11}"""))
        {
            var policy = await online.LoadAsync(CancellationToken.None);
            Assert.Equal(23, policy.Version);
            Assert.True(File.Exists(Cache));
        }

        using var offline = Store(HttpStatusCode.ServiceUnavailable, "sem conexão");
        var recovered = await offline.LoadAsync(CancellationToken.None);
        Assert.Equal(23, recovered.Version);
        Assert.Equal(11, recovered.MaxFileSizeMb);
        Assert.Equal([Category.Cpf], recovered.ActiveCategories.ToArray());
    }

    [Fact]
    public async Task Resposta_invalida_nao_substitui_politica_valida()
    {
        using (var online = Store(HttpStatusCode.OK,
            """{"version":9,"activeCategories":["Cnpj"]}"""))
            Assert.Equal(9, (await online.LoadAsync(CancellationToken.None)).Version);

        using (var invalid = Store(HttpStatusCode.OK,
            """{"version":10,"activeCategories":[]}"""))
            Assert.Equal(9, (await invalid.LoadAsync(CancellationToken.None)).Version);

        using var offline = Store(HttpStatusCode.ServiceUnavailable, "sem conexão");
        Assert.Equal(9, (await offline.LoadAsync(CancellationToken.None)).Version);
    }

    [Fact]
    public async Task Sem_cache_e_sem_rede_utiliza_politica_padrao()
    {
        using var offline = Store(HttpStatusCode.ServiceUnavailable, "sem conexão");
        var policy = await offline.LoadAsync(CancellationToken.None);
        Assert.Equal(LocalPolicyStore.CreateDefault().Version, policy.Version);
        Assert.NotEmpty(policy.ActiveCategories);
    }

    [Fact]
    public async Task Cache_corrompido_nao_e_aplicado()
    {
        Directory.CreateDirectory(_root);
        await File.WriteAllTextAsync(Cache, "{arquivo-json-invalido}");
        using var offline = Store(HttpStatusCode.ServiceUnavailable, "sem conexão");
        var policy = await offline.LoadAsync(CancellationToken.None);
        Assert.Equal(LocalPolicyStore.CreateDefault().Version, policy.Version);
    }

    private TestStore Store(HttpStatusCode status, string json) =>
        new(new HttpClient(new ResponseHandler(status, json))
            { BaseAddress = new Uri("http://127.0.0.1:18080/agent/") }, Cache);

    [Fact]
    public async Task Falha_de_disco_preserva_politica_em_memoria_e_cancelamento_nao_vira_fallback()
    {
        Directory.CreateDirectory(_root);
        Directory.CreateDirectory(Cache); // O destino não pode ser substituído por arquivo.
        var handler = new SwitchHandler();
        using var client = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/agent/") };
        var store = new DurableHttpPolicyStore(client, "PC-TESTE", Cache, false);
        Assert.Equal(42, (await store.LoadAsync(CancellationToken.None)).Version);
        handler.Offline = true;
        Assert.Equal(42, (await store.LoadAsync(CancellationToken.None)).Version);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadAsync(cancelled.Token));
    }

    [Fact]
    public async Task Timeout_de_rede_e_json_invalido_preservam_cache_apos_reinicio()
    {
        using (var online = Store(HttpStatusCode.OK, """{"version":42,"activeCategories":["Secret"],"overrideAllowed":true,"failOpen":false}"""))
            await online.LoadAsync(CancellationToken.None);
        var before = await File.ReadAllTextAsync(Cache);
        using (var invalid = Store(HttpStatusCode.OK, "null"))
            Assert.Equal(42, (await invalid.LoadAsync(CancellationToken.None)).Version);
        using var client = new HttpClient(new SwitchHandler { Offline = true })
            { BaseAddress = new Uri("http://localhost/agent/") };
        var recovered = await new DurableHttpPolicyStore(client, "PC-TESTE", Cache, false)
            .LoadAsync(CancellationToken.None);
        Assert.Equal(42, recovered.Version);
        Assert.True(recovered.OverrideAllowed);
        Assert.False(recovered.FailOpen);
        Assert.Equal(before, await File.ReadAllTextAsync(Cache));
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    private sealed class SwitchHandler : HttpMessageHandler
    {
        public bool Offline { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (Offline) throw new TaskCanceledException("Timeout simulado sem cancelamento do chamador.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent("""{"version":42,"activeCategories":["Secret"]}""") });
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    private sealed class TestStore(HttpClient client, string path) : IDisposable
    {
        private readonly DurableHttpPolicyStore _store = new(client, "PC-TESTE", path, enforceProtectedAcl: false);
        public Task<Policy> LoadAsync(CancellationToken token) => _store.LoadAsync(token);
        public void Dispose() => client.Dispose();
    }

    private sealed class ResponseHandler(HttpStatusCode status, string content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken token) => Task.FromResult(
                new HttpResponseMessage(status)
                { Content = new StringContent(content, Encoding.UTF8, "application/json") });
    }
}
