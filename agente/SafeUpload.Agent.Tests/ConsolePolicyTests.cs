using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Dispatch;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class ConsolePolicyTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private string Cache => Path.Combine(_workspace.Root, "console-cache.json");
    private static readonly ConsolePolicyOptions Options = new(23, "192.0.2.10");
    private static Policy Operational => LocalPolicyStore.CreateDefault() with
    {
        MaxFileSizeMb = 13, InspectionTimeoutSeconds = 7, FailOpen = false,
        MonitoredScopes = new(new HashSet<string> { ".txt" }, [@"C:\Teste\Protegido"], false, false),
        OverrideAllowed = true
    };

    [Fact]
    public async Task Consulta_contrato_real_confere_host_e_preserva_operacao_local()
    {
        var handler = new Handler { Body = Document(101, "cpf", "cnpj", "cartao_credito", "credenciais",
            "rg", "dados_bancarios", "dados_saude", "documentos_confidenciais", "dados_pessoais") };
        using var client = Client(handler);
        var store = Store(client);
        var result = await store.LoadAsync(default);
        Assert.Equal("https://example.test/context/agent/api/policy?ip=192.0.2.10", handler.Path);
        Assert.Equal(101, result.Version);
        Assert.True(result.ActiveCategories.SetEquals([Category.Cpf, Category.Cnpj, Category.PaymentCard, Category.Password, Category.Secret,
            Category.Rg, Category.BankData, Category.HealthData, Category.ConfidentialDocument, Category.PersonalData]));
        Assert.False(result.AuditOnly);
        // A console não publica a permissão de justificar: vale a do policy.json local.
        Assert.True(result.OverrideAllowed);
        Assert.False(result.FailOpen);
        Assert.Equal(13, result.MaxFileSizeMb);
        Assert.Equal(7, result.InspectionTimeoutSeconds);
        Assert.Equal(Operational.MonitoredScopes.DestinationPaths, result.MonitoredScopes.DestinationPaths);
        Assert.False(result.MonitoredScopes.RemovableDrives);
        Assert.False(result.MonitoredScopes.NetworkPaths);
        Assert.False(result.EffectiveClipboard.IsEnabled);
        Assert.Equal("remote", store.LastSource);
    }

    [Fact]
    public async Task Duas_publicacoes_mudam_inspecao_e_politica_persiste_no_reinicio_offline()
    {
        var handler = new Handler { Body = Document(101, "cpf") };
        using var client = Client(handler);
        using var snapshots = new RefreshingPolicyStore(Store(client), TimeSpan.FromSeconds(30),
            NullLogger<RefreshingPolicyStore>.Instance);
        var audit = new LocalQueueAuditSink(_workspace.QueueFile);
        var inspection = new InspectionService(snapshots, audit, ExtractorRegistry.CreateDefault(), new VerdictCache());
        var path = _workspace.WriteText("sintetico.txt", "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path, DestinationKind.Cloud, destinationPath: @"C:\Teste\Protegido\arquivo.txt");
        await snapshots.RefreshAsync(default);
        var first = await inspection.InspectAsync(operation, default);
        Assert.Equal(Verdict.Blocked, first.Verdict);
        Assert.Equal(101, first.PolicyVersion);
        // Mesmo arquivo/hash e mesmo cache de vereditos; uma nova publicação deve mudar o resultado.
        handler.Body = Document(102, "cnpj");
        await snapshots.RefreshAsync(default);
        var second = await inspection.InspectAsync(operation, default);
        Assert.Equal(Verdict.Approved, second.Verdict);
        Assert.Equal(102, second.PolicyVersion);
        handler.Status = HttpStatusCode.ServiceUnavailable;
        var restarted = Store(client);
        var recovered = await restarted.LoadCachedOrDefaultAsync(default);
        Assert.Equal(102, recovered.Version);
        Assert.True(recovered.ActiveCategories.SetEquals([Category.Cnpj]));
        Assert.Equal("disk", restarted.LastSource);
        Assert.Equal(102, (await restarted.LoadAsync(default)).Version);
        Assert.Equal("memory", restarted.LastSource);
    }

    [Fact]
    public async Task Primeira_publicacao_com_numero_igual_ao_local_invalida_veredito_e_permissao_antigos()
    {
        using var client = Client(new Handler { Body = Document(1, "cpf") });
        var local = Operational with { Version = 1, ActiveCategories = new HashSet<Category> { Category.Cnpj } };
        var remote = new DurableHttpPolicyStore(client, "PC-SINTETICO", Cache, false,
            consolePolicy: Options, operationalPolicy: new FixedPolicy(local));
        using var snapshots = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30),
            NullLogger<RefreshingPolicyStore>.Instance);
        var inspection = new InspectionService(snapshots, new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        var path = _workspace.WriteText("sintetico.txt", "CPF: 529.982.247-25");
        var operation = TestWorkspace.Operation(path, DestinationKind.Cloud, destinationPath: @"C:\Teste\Protegido\arquivo.txt");
        Assert.Equal(Verdict.Approved, (await inspection.InspectAsync(operation, default)).Verdict);
        var localInspection = new InspectionService(new FixedPolicy(local), new LocalQueueAuditSink(_workspace.QueueFile),
            ExtractorRegistry.CreateDefault(), new VerdictCache());
        var oldApproval = await localInspection.InspectStagedAsync(operation, default);
        Assert.True(await localInspection.IsCurrentStagedApprovalAsync(operation, oldApproval, default));
        await snapshots.RefreshAsync(default);
        var result = await inspection.InspectAsync(operation, default);
        Assert.Equal(1, result.PolicyVersion);
        Assert.Equal(Verdict.Blocked, result.Verdict);
        Assert.False(result.FromCache);
        Assert.False(await inspection.IsCurrentStagedApprovalAsync(operation, oldApproval, default));
    }

    [Fact]
    public async Task Alertar_apenas_audita_e_a_justificativa_segue_a_politica_local()
    {
        var handler = new Handler { Body = Document(101, "cpf").Replace("\"bloquear\"", "\"alertar\"") };
        using var client = Client(handler);
        var policy = await Store(client).LoadAsync(default);
        Assert.True(policy.AuditOnly);
        Assert.Equal(Operational.OverrideAllowed, policy.OverrideAllowed);
    }

    [Theory]
    [InlineData("host")]
    [InlineData("ip")]
    [InlineData("action")]
    [InlineData("rule")]
    [InlineData("mixed_rules")]
    [InlineData("empty")]
    [InlineData("version")]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("nested_duplicate")]
    [InlineData("large")]
    [InlineData("rollback")]
    [InlineData("same_revision_changed")]
    public async Task Documento_incompativel_nao_substitui_memoria_ou_cache(string mutation)
    {
        var handler = new Handler { Body = Document(101, "cpf") };
        using var client = Client(handler);
        await Store(client).LoadAsync(default);
        var before = await File.ReadAllBytesAsync(Cache);
        var changed = JsonNode.Parse(Document(102, "cnpj"))!;
        switch (mutation)
        {
            case "host": changed["destino"]!["idHost"] = 24; break;
            case "ip": changed["destino"]!["ip"] = "192.0.2.11"; break;
            case "action": changed["acao"] = "permitir"; break;
            case "rule": changed["regras"] = new JsonArray(new JsonObject { ["tipo"] = "biometria" }); break;
            case "mixed_rules": changed["regras"]!.AsArray().Add(new JsonObject { ["tipo"] = "biometria" }); break;
            case "empty": changed["regras"] = new JsonArray(); break;
            case "version": changed["versao"] = "2.0"; break;
            case "missing": changed.AsObject().Remove("idPolitica"); break;
            case "rollback": changed["idPolitica"] = 100; break;
            case "same_revision_changed": changed["idPolitica"] = 101; break;
        }
        handler.Body = mutation switch
        {
            "duplicate" => Document(102, "cnpj").Replace("\"idPolitica\":102", "\"idPolitica\":102,\"IDPOLITICA\":103"),
            "nested_duplicate" => Document(102, "cnpj").Replace("\"idHost\":23", "\"idHost\":23,\"idHost\":24"),
            "large" => new string(' ', 65537),
            _ => changed.ToJsonString()
        };
        var restarted = Store(client); // Recusa regressão também antes da primeira carga HTTP após reiniciar.
        var retained = await restarted.LoadAsync(default);
        Assert.Equal(101, retained.Version);
        Assert.True(retained.ActiveCategories.SetEquals([Category.Cpf]));
        Assert.Equal("memory", restarted.LastSource);
        Assert.Equal(before, await File.ReadAllBytesAsync(Cache));
    }

    [Theory]
    [InlineData("server")]
    [InlineData("host")]
    [InlineData("ip")]
    public async Task Cache_de_outro_vinculo_nao_e_aplicado(string changed)
    {
        using var online = Client(new Handler { Body = Document(101, "cpf") });
        await Store(online).LoadAsync(default);
        var before = await File.ReadAllBytesAsync(Cache);
        var handler = new Handler { Status = HttpStatusCode.ServiceUnavailable };
        using var offline = Client(handler);
        if (changed == "server") offline.BaseAddress = new Uri("https://other.test/context/agent/");
        var options = new ConsolePolicyOptions(changed == "host" ? 24 : 23, changed == "ip" ? "192.0.2.11" : "192.0.2.10");
        var store = Store(offline, options);
        var result = await store.LoadCachedOrDefaultAsync(default);
        Assert.Equal(Operational.Version, result.Version);
        Assert.Equal("default", store.LastSource);
        Assert.Equal(0, handler.Calls);
        Assert.Equal(before, await File.ReadAllBytesAsync(Cache));
    }

    [Fact]
    public async Task Resposta_identica_e_repetivel_e_cancelamento_preserva_cache()
    {
        using var client = Client(new Handler { Body = Document(101, "cpf") });
        var store = Store(client);
        await store.LoadAsync(default);
        Assert.Equal(101, (await store.LoadAsync(default)).Version);
        var before = await File.ReadAllBytesAsync(Cache);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.LoadAsync(stop.Token));
        Assert.Equal(before, await File.ReadAllBytesAsync(Cache));
    }

    [Fact]
    public void Configuracao_explicitamente_separada_do_heartbeat_e_legado()
    {
        var values = new Dictionary<string, string?>
        {
            ["CentroAdministracao:BaseUrl"] = "https://example.test/context/agent/",
            ["CentroAdministracao:HeartbeatProtocol"] = "AgentApi",
            ["CentroAdministracao:RegisteredHostId"] = "23"
        };
        AdministrationConfiguration Read() => AdministrationConfiguration.Parse(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        Assert.Null(Read().ConsolePolicy);
        values["CentroAdministracao:PolicyProtocol"] = "ConsoleByIp";
        values["CentroAdministracao:PolicyHostIp"] = "192.0.2.10";
        Assert.Equal(Options, Read().ConsolePolicy);
        foreach (string invalid in new[] { "127.1", "localhost", "::1", "192.0.2.10?x=SENSITIVE" })
        {
            values["CentroAdministracao:PolicyHostIp"] = invalid;
            var error = Assert.Throws<InvalidOperationException>(() => Read());
            Assert.DoesNotContain(invalid, error.ToString());
        }
        values["CentroAdministracao:PolicyHostIp"] = "192.0.2.10";
        values["CentroAdministracao:HeartbeatProtocol"] = null;
        values["CentroAdministracao:RegisteredHostId"] = null;
        Assert.Throws<InvalidOperationException>(() => Read());
        values["CentroAdministracao:PolicyProtocol"] = "Legacy";
        Assert.Throws<InvalidOperationException>(() => Read());
    }

    [Fact]
    public async Task Origem_indisponivel_mantem_a_ultima_politica_valida_para_as_unidades()
    {
        // Servidor fora do ar não bloqueia o trabalho: as inspeções das unidades usam a última política validada
        // (renovada a cada 30 s e guardada em disco), não uma consulta à rede por arquivo salvo.
        var handler = new Handler { Body = Document(101, "cpf") };
        using var client = Client(handler);
        var remote = Store(client);
        using var snapshots = new RefreshingPolicyStore(remote, TimeSpan.FromSeconds(30),
            NullLogger<RefreshingPolicyStore>.Instance);
        await snapshots.RefreshAsync(default);
        Assert.Equal(101, (await ((IPolicyStore)snapshots).LoadCurrentAsync(default)).Version);
        handler.Status = HttpStatusCode.ServiceUnavailable;
        await snapshots.RefreshAsync(default);
        Assert.Equal(101, (await ((IPolicyStore)snapshots).LoadCurrentAsync(default)).Version);
        Assert.Equal(101, (await snapshots.LoadAsync(default)).Version);
        Assert.Equal(101, (await remote.LoadAsync(default)).Version);
    }

    [Fact]
    public async Task Leitura_atual_rejeita_regressao_apos_reinicio_sem_apagar_cache()
    {
        var handler = new Handler { Body = Document(101, "cpf") };
        using var client = Client(handler);
        await Store(client).LoadAsync(default);
        var before = await File.ReadAllBytesAsync(Cache);
        handler.Body = Document(100, "cnpj");
        await Assert.ThrowsAsync<InvalidPolicyException>(() => Store(client).LoadCurrentAsync(default));
        Assert.Equal(before, await File.ReadAllBytesAsync(Cache));
    }

    [Fact]
    public async Task Origem_operacional_invalida_nao_autoriza_publicacao_com_fallback()
    {
        using var client = Client(new Handler { Body = Document(101, "cpf") });
        var store = new DurableHttpPolicyStore(client, "PC-SINTETICO", Cache, false,
            consolePolicy: Options, operationalPolicy: new UnavailableCurrentPolicy());
        Assert.Equal(101, (await store.LoadAsync(default)).Version);
        var before = await File.ReadAllBytesAsync(Cache);
        await Assert.ThrowsAsync<InvalidPolicyException>(() => store.LoadCurrentAsync(default));
        Assert.Equal(before, await File.ReadAllBytesAsync(Cache));
    }

    private sealed class UnavailableCurrentPolicy : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(Operational);
        public Task<Policy> LoadCurrentAsync(CancellationToken token) =>
            throw new InvalidPolicyException("Synthetic current policy failure");
    }

    private DurableHttpPolicyStore Store(HttpClient client, ConsolePolicyOptions? options = null) =>
        new(client, "PC-SINTETICO", Cache, false, consolePolicy: options ?? Options, operationalPolicy: new FixedPolicy());
    private static HttpClient Client(Handler handler) => new(handler) { BaseAddress = new Uri("https://example.test/context/agent/") };
    internal static string Document(int revision, params string[] rules) =>
        $$"""{"idPolitica":{{revision}},"versao":"1.0","nome":"Teste sintético","destino":{"idHost":23,"ip":"192.0.2.10"},"acao":"bloquear","regras":[{{string.Join(",", rules.Select(r => "{\"tipo\":\"" + r + "\"}"))}}],"origem":"console-administrativo"}""";

    private sealed class FixedPolicy(Policy? policy = null) : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.FromResult(policy ?? Operational); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        public string Body = "";
        public HttpStatusCode Status = HttpStatusCode.OK;
        public string? Path;
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Calls++;
            Path = request.RequestUri!.AbsoluteUri;
            return Task.FromResult(new HttpResponseMessage(Status) { Content = new StringContent(Body, Encoding.UTF8, "application/json") });
        }
    }
    public void Dispose() => _workspace.Dispose();
}
