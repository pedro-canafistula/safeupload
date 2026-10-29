using System.Net;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class RegisteredHostIdentityTests
{
    private static readonly Uri Server = new("https://example.test/agent/");

    [Fact]
    public void Primeiro_ID_e_persistido_e_reabertura_recupera_sem_reescrever()
    {
        using var state = new State();
        Assert.Equal(23, state.Store().Resolve(Server, 23));
        var bytes = File.ReadAllBytes(state.File);
        Assert.Equal(23, state.Store().Resolve(Server, null));
        Assert.Equal(23, state.Store().Resolve(Server, 23));
        Assert.Equal(bytes, File.ReadAllBytes(state.File));
        using var json = JsonDocument.Parse(bytes);
        Assert.Equal(3, json.RootElement.EnumerateObject().Count());
        Assert.Equal(1, json.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(Server.AbsoluteUri, json.RootElement.GetProperty("serverBaseUrl").GetString());
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(state.File)!, "*.tmp"));
    }

    [Theory]
    [InlineData("http://example.test/agent/")]
    [InlineData("https://other.test/agent/")]
    [InlineData("https://example.test:8080/agent/")]
    [InlineData("https://example.test/context/agent/")]
    [InlineData("https://example.test/CONTEXT/agent/")]
    public void Outro_servidor_esquema_porta_ou_contexto_nao_reutiliza_ID(string server)
    {
        using var state = new State();
        state.Store().Resolve(Server, 23);
        var before = File.ReadAllBytes(state.File);
        foreach (int? supplied in new int?[] { null, 23, 99 })
        {
            var error = Assert.Throws<HostIdentityException>(() => state.Store().Resolve(new Uri(server), supplied));
            Assert.Equal("server_mismatch", error.Code);
            Assert.Null(error.InnerException);
            Assert.DoesNotContain("example.test", error.ToString());
        }
        Assert.Equal(before, File.ReadAllBytes(state.File));
    }

    [Fact]
    public void Canonicaliza_host_e_porta_padrao_mas_preserva_caixa_do_contexto()
    {
        using var state = new State();
        state.Store().Resolve(new Uri("https://EXAMPLE.TEST:443/Context/agent/"), 23);
        Assert.Equal(23, state.Store().Resolve(new Uri("https://example.test/Context/agent/"), null));
        Assert.Equal("server_mismatch", Assert.Throws<HostIdentityException>(() =>
            state.Store().Resolve(new Uri("https://example.test/context/agent/"), null)).Code);
    }

    [Theory]
    [InlineData(0, "invalid_host")]
    [InlineData(-1, "invalid_host")]
    [InlineData(99, "host_mismatch")]
    public void ID_configurado_invalido_ou_diferente_nao_substitui_identidade(int id, string code)
    {
        using var state = new State();
        state.Store().Resolve(Server, 23);
        var before = File.ReadAllBytes(state.File);
        Assert.Equal(code, Assert.Throws<HostIdentityException>(() => state.Store().Resolve(Server, id)).Code);
        Assert.Equal(before, File.ReadAllBytes(state.File));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("SENSITIVE-SYNTHETIC")]
    [InlineData("{")]
    [InlineData("{\"schemaVersion\":2,\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":23}")]
    [InlineData("{\"schemaVersion\":1,\"schemaVersion\":1,\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":23}")]
    [InlineData("{\"schemaVersion\":\"1\",\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":23}")]
    [InlineData("{\"schemaVersion\":1,\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":\"23\"}")]
    [InlineData("{\"schemaVersion\":1,\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":0}")]
    [InlineData("{\"schemaVersion\":1,\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":23,\"registeredHostId\":99}")]
    [InlineData("{\"schemaVersion\":1,\"serverBaseUrl\":\"https://example.test/agent/\",\"registeredHostId\":23,\"secret\":\"SENSITIVE-SYNTHETIC\"}")]
    [InlineData("{\"schemaVersion\":1,\"serverBaseUrl\":\"https://example.test/agent/?token=SENSITIVE-SYNTHETIC\",\"registeredHostId\":23}")]
    public void Arquivo_invalido_nao_causa_novo_provisionamento_e_nao_expoe_conteudo(string contents)
    {
        using var state = new State();
        state.Write(contents);
        var before = File.ReadAllBytes(state.File);
        foreach (int? supplied in new int?[] { null, 23 })
        {
            var error = Assert.Throws<HostIdentityException>(() => state.Store().Resolve(Server, supplied));
            Assert.DoesNotContain("SENSITIVE-SYNTHETIC", error.ToString());
            Assert.DoesNotContain("example.test", error.ToString());
            Assert.Null(error.InnerException);
        }
        Assert.Equal(before, File.ReadAllBytes(state.File));
    }

    [Fact]
    public void Arquivo_grande_e_diretorio_no_lugar_do_arquivo_sao_recusados()
    {
        using var state = new State();
        state.Write(new string('x', 16385));
        Assert.Equal("invalid_file", Assert.Throws<HostIdentityException>(() => state.Store().Resolve(Server, 23)).Code);
        using var directoryState = new State();
        Directory.CreateDirectory(directoryState.File);
        Assert.Equal("invalid_file", Assert.Throws<HostIdentityException>(() => directoryState.Store().Resolve(Server, 23)).Code);
    }

    [Fact]
    public void Sem_cache_e_sem_ID_nao_inventa_identidade()
    {
        using var state = new State();
        Assert.Equal("missing", Assert.Throws<HostIdentityException>(() => state.Store().Resolve(Server, null)).Code);
        Assert.False(File.Exists(state.File));
    }

    [Fact]
    public async Task Provisionamentos_concorrentes_do_mesmo_host_conservam_um_arquivo_completo()
    {
        using var state = new State();
        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() => state.Store().Resolve(Server, 23)));
        Assert.All(await Task.WhenAll(tasks), id => Assert.Equal(23, id));
        Assert.Equal(23, state.Store().Resolve(Server, null));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(state.File)!, "*.tmp"));
    }

    [Fact]
    public async Task Provisionamentos_concorrentes_diferentes_nao_sobrescrevem_o_primeiro()
    {
        using var state = new State();
        var results = await Task.WhenAll(new[] { 23, 99 }.Select(id => Task.Run(() =>
        {
            try { return (Id: state.Store().Resolve(Server, id), Error: (string?)null); }
            catch (HostIdentityException error) { return (Id: 0, Error: error.Code); }
        })));
        var accepted = Assert.Single(results, result => result.Error is null);
        Assert.Equal("host_mismatch", Assert.Single(results, result => result.Error is not null).Error);
        Assert.Equal(accepted.Id, state.Store().Resolve(Server, null));
    }

    [Fact]
    public void Arquivo_bloqueado_nao_e_tratado_como_ausente()
    {
        using var state = new State();
        state.Store().Resolve(Server, 23);
        var before = File.ReadAllBytes(state.File);
        using (File.Open(state.File, FileMode.Open, FileAccess.Read, FileShare.None))
            Assert.Equal("storage_error", Assert.Throws<HostIdentityException>(() => state.Store().Resolve(Server, 23)).Code);
        Assert.Equal(before, File.ReadAllBytes(state.File));
    }

    [Fact]
    public void Construtor_de_producao_recusa_pasta_sem_ACL_exata_sem_reparar()
    {
        using var state = new State();
        Directory.CreateDirectory(Path.GetDirectoryName(state.File)!);
        var directory = new DirectoryInfo(Path.GetDirectoryName(state.File)!);
        string before = directory.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Equal("unsafe_permissions", Assert.Throws<HostIdentityException>(() =>
            new RegisteredHostIdentityStore(state.File).Resolve(Server, 23)).Code);
        Assert.Equal(before, directory.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        Assert.False(File.Exists(state.File));
    }

    [Fact]
    public async Task Configuracao_reaberta_sem_ID_usa_o_host_salvo_no_corpo_do_heartbeat()
    {
        using var state = new State();
        var initial = AdministrationConfiguration.Parse(Settings("23"), state.Store());
        Assert.Equal(23, initial.Heartbeat.RegisteredHostId);
        var recovered = AdministrationConfiguration.Parse(Settings(null), state.Store());
        var handler = new HeartbeatHandler();
        using var client = new HttpClient(handler) { BaseAddress = recovered.BaseUri };
        await recovered.Heartbeat.CreateSender(client)!.SendAsync(CancellationToken.None);
        Assert.Equal(new[] { "/agent/heartbeat" }, handler.Paths);
        Assert.Equal("{\"id_host\":23}", handler.Body);
    }

    [Theory]
    [InlineData("bad-url", "23", "AgentApi", null, null)]
    [InlineData("https://example.test/agent/", "0", "AgentApi", null, null)]
    [InlineData("https://example.test/agent/", "23", "AgentApi", "wrong", null)]
    [InlineData("https://example.test/agent/", "23", "AgentApi", null, "23")]
    public void Configuracao_invalida_nao_grava_identidade(string url, string hostId, string protocol, string? timeout, string? legacyUser)
    {
        using var state = new State();
        var configuration = Settings(hostId, url, protocol, timeout, legacyUser);
        Assert.ThrowsAny<InvalidOperationException>(() => AdministrationConfiguration.Parse(configuration, state.Store()));
        Assert.False(File.Exists(state.File));
    }

    [Fact]
    public void Modo_local_ou_Legacy_nao_le_nem_altera_identidade_salva()
    {
        using var state = new State();
        state.Write("SENSITIVE-SYNTHETIC");
        var before = File.ReadAllBytes(state.File);
        Assert.Null(AdministrationConfiguration.Parse(Settings(null, protocol: "Legacy"), state.Store()).Heartbeat.RegisteredHostId);
        Assert.Null(AdministrationConfiguration.Parse(Settings(null, url: ""), state.Store()).BaseUri);
        Assert.Equal(before, File.ReadAllBytes(state.File));
    }

    private static IConfiguration Settings(string? hostId, string url = "https://example.test/agent/",
        string protocol = "AgentApi", string? timeout = null, string? legacyUser = null) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CentroAdministracao:BaseUrl"] = url,
            ["CentroAdministracao:HeartbeatProtocol"] = string.IsNullOrEmpty(url) ? null : protocol,
            ["CentroAdministracao:RegisteredHostId"] = hostId,
            ["CentroAdministracao:TimeoutSeconds"] = timeout,
            ["CentroAdministracao:RegisteredUserId"] = legacyUser
        }).Build();

    private sealed class State : IDisposable
    {
        private readonly TestWorkspace _workspace = new();
        public string File => Path.Combine(_workspace.Root, "identity", "host-registration.json");
        public RegisteredHostIdentityStore Store() => new(File, enforceProtectedAcl: false);
        public void Write(string contents)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(File)!);
            System.IO.File.WriteAllText(File, contents, Encoding.UTF8);
        }
        public void Dispose() => _workspace.Dispose();
    }

    private sealed class HeartbeatHandler : HttpMessageHandler
    {
        public List<string> Paths { get; } = [];
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            Body = await request.Content!.ReadAsStringAsync(token);
            return new(HttpStatusCode.OK) { Content = new StringContent("{\"status\":\"OK\"}") };
        }
    }
}
