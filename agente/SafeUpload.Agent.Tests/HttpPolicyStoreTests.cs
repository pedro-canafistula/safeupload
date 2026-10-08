using System.Net;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// A política vinda do Centro de Administração (HU-10).
///
/// O que estes testes guardam não é o caminho feliz — é a garantia de que uma
/// indisponibilidade do painel jamais deixa o endpoint sem política. É o mesmo
/// fail-open da RN-013 aplicado à origem da configuração: servidor fora do ar
/// não pode virar frota inteira sem proteção ao mesmo tempo.
/// </summary>
public sealed class HttpPolicyStoreTests
{
    private const string PolicyJson = """
        {
          "version": 7,
          "activeCategories": ["Cpf", "Secret"],
          "monitoredScopes": {
            "extensions": [".txt", "docx"],
            "destinationPaths": ["C:\\Publicado"],
            "sourcePaths": ["C:\\Origem"],
            "removableDrives": false,
            "networkPaths": true
          },
          "maxFileSizeMb": 33,
          "inspectionTimeoutSeconds": 9,
          "auditOnly": true,
          "overrideAllowed": true,
          "failOpen": true,
          "excludedProcesses": ["System"]
        }
        """;

    [Fact]
    public async Task Politica_publicada_pelo_painel_e_aplicada_campo_a_campo()
    {
        var store = CreateStore(StubHandler.RespondingWith(HttpStatusCode.OK, PolicyJson));

        var policy = await store.LoadAsync(CancellationToken.None);

        Assert.Equal(7, policy.Version);
        Assert.Equal([Category.Cpf, Category.Secret], policy.ActiveCategories.Order().ToArray());
        Assert.Equal(33, policy.MaxFileSizeMb);
        Assert.Equal(9, policy.InspectionTimeoutSeconds);
        Assert.True(policy.AuditOnly);
        Assert.True(policy.OverrideAllowed);
        Assert.False(policy.MonitoredScopes.RemovableDrives);
        Assert.True(policy.MonitoredScopes.NetworkPaths);
        Assert.Contains(@"C:\Publicado", policy.MonitoredScopes.DestinationPaths);
        Assert.Contains(@"C:\Origem", policy.MonitoredScopes.SourcePaths);

        // Extensão sem ponto no documento continua chegando com ponto ao
        // domínio — mesma normalização da origem local.
        Assert.Contains(".docx", policy.MonitoredScopes.Extensions);
    }

    [Fact]
    public async Task Servidor_fora_do_ar_cai_no_padrao_em_vez_de_lancar()
    {
        var store = CreateStore(StubHandler.Throwing(new HttpRequestException("sem rota para o host")));

        var policy = await store.LoadAsync(CancellationToken.None);

        AssertIsDefault(policy);
    }

    [Fact]
    public async Task Erro_do_servidor_cai_no_padrao_em_vez_de_lancar()
    {
        var store = CreateStore(StubHandler.RespondingWith(HttpStatusCode.InternalServerError, "falhou"));

        var policy = await store.LoadAsync(CancellationToken.None);

        AssertIsDefault(policy);
    }

    [Fact]
    public async Task Resposta_ilegivel_cai_no_padrao_em_vez_de_lancar()
    {
        // Um proxy no caminho devolvendo HTML, ou uma resposta truncada: 200 na
        // linha de status não significa que o corpo seja a política.
        var store = CreateStore(StubHandler.RespondingWith(HttpStatusCode.OK, "<html>login</html>"));

        var policy = await store.LoadAsync(CancellationToken.None);

        AssertIsDefault(policy);
    }

    private static void AssertIsDefault(Policy policy)
    {
        var expected = LocalPolicyStore.CreateDefault();

        Assert.Equal(expected.Version, policy.Version);
        Assert.Equal(expected.MaxFileSizeMb, policy.MaxFileSizeMb);
        Assert.Equal(expected.InspectionTimeoutSeconds, policy.InspectionTimeoutSeconds);
        Assert.Equal(expected.ActiveCategories.Order(), policy.ActiveCategories.Order());
    }

    private static HttpPolicyStore CreateStore(StubHandler handler) =>
        new(
            new HttpClient(handler) { BaseAddress = new Uri("http://painel.invalido/agent/") },
            "PC-DE-TESTE");

    /// <summary>
    /// Respondedor HTTP de teste. Escrito à mão porque a suíte não usa
    /// framework de dublê — o mesmo motivo pelo qual as outras classes de teste
    /// usam arquivos temporários de verdade em vez de um sistema de arquivos
    /// simulado.
    /// </summary>
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpResponseMessage> _respond;

        private StubHandler(Func<HttpResponseMessage> respond) => _respond = respond;

        public static StubHandler RespondingWith(HttpStatusCode status, string body) =>
            new(() => new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });

        public static StubHandler Throwing(Exception exception) =>
            new(() => throw exception);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(_respond());
    }
}
