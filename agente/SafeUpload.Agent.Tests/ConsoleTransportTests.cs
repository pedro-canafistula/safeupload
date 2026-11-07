using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

/// <summary>Contrato console ↔ agente do lado do agente (docs/console-agente.md).</summary>
public sealed class ConsoleTransportTests : IDisposable
{
    private static readonly Uri Server = new("https://console.test/agent/");
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();

    // ---- assinatura ----

    [Fact]
    public void Shared_vector_matches_the_backend_test()
    {
        // Mesmo vetor de web/back/.../AgentSignatureTest.java.
        byte[] body = Encoding.UTF8.GetBytes("{\"x\":1}");
        string message = SignedRequestHandler.Message("POST", "heartbeat", 7, 1700000000, "AAECAwQFBgcICQoLDA0ODw==", body);
        Assert.Equal("SafeUpload-v1\nPOST\nheartbeat\n7\n1700000000\nAAECAwQFBgcICQoLDA0ODw==\n" +
            "5041bf1f713df204784353e82f6a4a535931cb64f1f4b4a5aeaffcb720918b22", message);
        Assert.Equal("MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", Ed25519AgentKey.PublicKey(TestPolicies.Seed));
        Assert.Equal("od2YTB6n1/a6PcmQjfqNYi4tR8Zz4wd8JYSxKvT87p2mneOCUIiC52aFVPjn46i5jqpiUXIHgQUp5JnwWCr3CQ==",
            TestPolicies.Identity(Server).Sign(Encoding.UTF8.GetBytes(message)));
    }

    [Fact]
    public async Task Handler_signs_the_exact_bytes_sent_with_a_fresh_nonce()
    {
        var wire = new Wire(_ => Reply(HttpStatusCode.OK, "{}"));
        using var client = new HttpClient(new SignedRequestHandler(TestPolicies.Identity(new Uri("https://h.test/base/agent/")),
            new FixedTime(1700000000)) { InnerHandler = wire }) { BaseAddress = new Uri("https://h.test/base/agent/") };
        using (await client.PostAsync("events", new StringContent("{\"a\":1}", Encoding.UTF8, "application/json"))) { }
        using (await client.PostAsync("events", new StringContent("{\"a\":1}", Encoding.UTF8, "application/json"))) { }
        Assert.Equal(2, wire.Requests.Count);
        var first = wire.Requests[0];
        Assert.Equal("7", first.Headers[SignedRequestHandler.HostHeader]);
        Assert.Equal("1700000000", first.Headers[SignedRequestHandler.TimeHeader]);
        Assert.NotEqual(first.Headers[SignedRequestHandler.NonceHeader], wire.Requests[1].Headers[SignedRequestHandler.NonceHeader]);
        string message = SignedRequestHandler.Message("POST", "events", 7, 1700000000,
            first.Headers[SignedRequestHandler.NonceHeader], first.Body);
        Assert.Equal(TestPolicies.Identity(Server).Sign(Encoding.UTF8.GetBytes(message)), first.Headers[SignedRequestHandler.SignatureHeader]);
        Assert.Equal("{\"a\":1}", Encoding.UTF8.GetString(first.Body));
        Assert.Equal("application/json", first.ContentType);
        Assert.Equal("policy?x=1", SignedRequestHandler.Route(new Uri("https://h.test/p/agent/policy?x=1")));
    }

    [Theory]
    [InlineData("http://192.168.0.10/agent/")]
    [InlineData("https://h.test/api/")]
    [InlineData("ftp://h.test/agent/")]
    public void Server_address_must_be_https_agent_route(string address) =>
        Assert.Throws<ArgumentException>(() => AgentHttp.ServerUri(address));

    [Fact]
    public void Server_address_accepts_loopback_http_and_normalizes()
    {
        Assert.Equal("http://127.0.0.1:18080/agent/", AgentHttp.ServerUri("http://127.0.0.1:18080/agent").AbsoluteUri);
        Assert.Equal(new string('a', 64), AgentHttp.NormalizePin(string.Join(':', Enumerable.Repeat("AA", 32))));
    }

    // ---- cadastro e heartbeat ----

    [Fact]
    public async Task Enroll_and_heartbeat_follow_the_contract()
    {
        var wire = new Wire(request => request.Path.EndsWith("enroll")
            ? Reply(HttpStatusCode.Created, "{\"id_host\":42}") : Reply(HttpStatusCode.OK, "{\"id_host\":42}"));
        using var http = new HttpClient(wire) { BaseAddress = Server };
        var client = new AgentApiClient(http);
        var host = new AgentHeartbeatHost("10.0.0.5", 24, "PC-01", "Windows 10 Pro", "22H2 build 19045", "00:11:22:33:44:55");
        Assert.Equal(42, await client.EnrollAsync("ABCD1234", "PUBLIC", host, default));
        await client.HeartbeatAsync(42, host, 17, "0.2.0", default);
        using var enroll = JsonDocument.Parse(wire.Requests[0].Body);
        Assert.Equal("ABCD1234", enroll.RootElement.GetProperty("token").GetString());
        Assert.Equal("PUBLIC", enroll.RootElement.GetProperty("chave_publica").GetString());
        Assert.Equal("PC-01", enroll.RootElement.GetProperty("host").GetProperty("hostname").GetString());
        using var heartbeat = JsonDocument.Parse(wire.Requests[1].Body);
        Assert.Equal(17, heartbeat.RootElement.GetProperty("politica_aplicada").GetInt32());
        Assert.Equal("0.2.0", heartbeat.RootElement.GetProperty("versao_agente").GetString());
        Assert.Equal("10.0.0.5", heartbeat.RootElement.GetProperty("host").GetProperty("ip").GetString());
    }

    [Fact]
    public async Task Rejected_token_surfaces_the_status()
    {
        using var http = new HttpClient(new Wire(_ => Reply(HttpStatusCode.Unauthorized, "{}"))) { BaseAddress = Server };
        var error = await Assert.ThrowsAsync<AgentApiException>(() => new AgentApiClient(http).EnrollAsync("x", "k",
            new AgentHeartbeatHost(null, null, "PC", "Windows", "1", null), default));
        Assert.Equal(401, error.StatusCode);
    }

    [Fact]
    public void Detected_host_fits_the_contract() => AgentHeartbeatHost.Detect().EnsureValid();

    // ---- política do console ----

    private const string ConsoleDocument = """
        {"version":42,"activeCategories":["Cpf","Rg"],"alertCategories":["Rg"],
         "monitoredScopes":{"extensions":[".txt"],"destinationPaths":["C:\\Dados"],"removableDrives":true,"networkPaths":false},
         "maxFileSizeMb":50,"inspectionTimeoutSeconds":600,"overrideAllowed":true,"failOpen":false,
         "excludedProcesses":["System"],"clipboard":{"mode":"Block"}}
        """;

    [Fact]
    public async Task Console_document_is_applied_as_is_and_cached_for_offline_use()
    {
        string? body = ConsoleDocument;
        var wire = new Wire(_ => body is null ? throw new HttpRequestException("offline") : Reply(HttpStatusCode.OK, body));
        using var http = new HttpClient(wire) { BaseAddress = Server };
        var store = new DurableHttpPolicyStore(http, _workspace.PolicyFile, TestPolicies.Local, false);

        var policy = await store.LoadAsync(default);
        Assert.Equal("policy", wire.Requests[0].Path.Split('/').Last());
        Assert.Equal(42, policy.Version);
        Assert.Equal(42, store.ConsoleVersion);
        Assert.Equal(new[] { Category.Rg }, policy.AlertOnlyCategories.ToArray());
        Assert.True(policy.ReleasesWithAlert([Category.Rg]));
        Assert.False(policy.ReleasesWithAlert([Category.Rg, Category.Cpf]));
        Assert.Equal(["C:\\Dados"], policy.MonitoredScopes.DestinationPaths);
        Assert.Equal(ClipboardMode.Block, policy.EffectiveClipboard.Mode);
        Assert.NotEmpty(policy.EffectiveClipboard.EgressDestinations); // Lista padrão: o console só envia o modo.

        body = null;
        Assert.Same(policy, await store.LoadAsync(default));
        Assert.Equal("memory", store.LastSource);
        var restarted = new DurableHttpPolicyStore(http, _workspace.PolicyFile, TestPolicies.Local, false);
        Assert.Equal(42, (await restarted.LoadAsync(default)).Version);
        Assert.Equal("disk", restarted.LastSource);
        Assert.Equal(42, restarted.ConsoleVersion);

        // Cache de outro servidor (máquina cadastrada de novo) não vale.
        using var other = new HttpClient(wire) { BaseAddress = new Uri("https://outro.test/agent/") };
        var elsewhere = new DurableHttpPolicyStore(other, _workspace.PolicyFile, TestPolicies.Local, false);
        Assert.Equal(LocalPolicyStore.CreateDefault().Version, (await elsewhere.LoadAsync(default)).Version);
        Assert.Null(elsewhere.ConsoleVersion);
    }

    [Fact]
    public async Task No_assigned_policy_falls_back_to_the_local_file_and_drops_the_cache()
    {
        var status = HttpStatusCode.OK;
        var wire = new Wire(_ => Reply(status, status == HttpStatusCode.OK ? ConsoleDocument : "{}"));
        using var http = new HttpClient(wire) { BaseAddress = Server };
        var store = new DurableHttpPolicyStore(http, _workspace.PolicyFile, TestPolicies.Local, false);
        Assert.Equal(42, (await store.LoadAsync(default)).Version);
        Assert.True(File.Exists(_workspace.PolicyFile));
        status = HttpStatusCode.NotFound;
        Assert.Equal(LocalPolicyStore.CreateDefault().Version, (await store.LoadAsync(default)).Version);
        Assert.Null(store.ConsoleVersion);
        Assert.Equal("local", store.LastSource);
        Assert.False(File.Exists(_workspace.PolicyFile));
    }

    [Fact]
    public async Task Invalid_console_document_keeps_the_last_good_policy()
    {
        string body = ConsoleDocument;
        using var http = new HttpClient(new Wire(_ => Reply(HttpStatusCode.OK, body))) { BaseAddress = Server };
        var store = new DurableHttpPolicyStore(http, _workspace.PolicyFile, TestPolicies.Local, false);
        await store.LoadAsync(default);
        body = """{"version":43,"activeCategories":["Cpf"],"alertCategories":["Rg"]}"""; // alerta fora das ativas
        Assert.Equal(42, (await store.LoadAsync(default)).Version);
        body = """{"version":44,"activeCategories":[]}""";
        Assert.Equal(42, (await store.LoadAsync(default)).Version);
    }

    // ---- configuração ----

    [Fact]
    public void Configuration_comes_from_the_enrollment_not_from_appsettings()
    {
        var withUrl = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CentroAdministracao:BaseUrl"] = "https://old.test/agent/", ["CentroAdministracao:TimeoutSeconds"] = "9"
        }).Build();
        var standalone = AdministrationConfiguration.Parse(withUrl, () => null);
        Assert.Null(standalone.Identity);
        Assert.Equal(TimeSpan.FromSeconds(9), standalone.Timeout);
        Assert.Contains("cadastrar", standalone.Problem);

        var broken = AdministrationConfiguration.Parse(new ConfigurationBuilder().Build(),
            () => throw new AgentIdentityException("registration_pending"));
        Assert.Null(broken.Identity);
        Assert.Contains("registration_pending", broken.Problem);

        var enrolled = AdministrationConfiguration.Parse(new ConfigurationBuilder().Build(), () => TestPolicies.Identity(Server));
        Assert.Equal(Server, enrolled.BaseUri);
        Assert.Null(enrolled.Problem);
        Assert.Equal(TimeSpan.FromSeconds(30), enrolled.DispatchInterval);
    }

    // ---- domínio ----

    [Fact]
    public void Alert_categories_must_be_active_and_change_the_fingerprint()
    {
        var policy = LocalPolicyStore.CreateDefault();
        var alerting = policy with { AlertCategories = new HashSet<Category> { Category.Cpf } };
        alerting.EnsureValid();
        Assert.NotEqual(PolicyContentFingerprint.Compute(policy), PolicyContentFingerprint.Compute(alerting));
        Assert.False(policy.ReleasesWithAlert([Category.Cpf]));
        Assert.True((policy with { AuditOnly = true }).ReleasesWithAlert([Category.Cpf]));
        Assert.False((policy with { AuditOnly = true }).ReleasesWithAlert([]));
        Assert.Throws<InvalidPolicyException>(() =>
            (policy with { AlertCategories = new HashSet<Category> { Category.HealthData } }).EnsureValid());
    }

    // ---- utilitários ----

    private static HttpResponseMessage Reply(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed record Seen(string Path, byte[] Body, Dictionary<string, string> Headers, string? ContentType);

    private sealed class Wire(Func<Seen, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Seen> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
            var seen = new Seen(request.RequestUri!.AbsolutePath, body,
                request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value)),
                request.Content?.Headers.ContentType?.MediaType);
            Requests.Add(seen);
            return respond(seen);
        }
    }

    private sealed class FixedTime(long seconds) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(seconds);
    }
}
