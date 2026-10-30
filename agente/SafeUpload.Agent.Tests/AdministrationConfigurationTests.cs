using Microsoft.Extensions.Configuration;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class AdministrationConfigurationTests
{
    private const string Sensitive = "SENSITIVE-SYNTHETIC";

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Sem_servidor_mantem_operacao_local_sem_exigir_prazos_de_rede(string? address)
    {
        var result = Parse(address, timeout: "unused", interval: "unused");
        Assert.Null(result.BaseUri);
        Assert.Null(result.Heartbeat.RegisteredHostId);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080/agent/", "http://127.0.0.1:8080/agent/")]
    [InlineData("http://127.0.0.1:8080/agent", "http://127.0.0.1:8080/agent/")]
    [InlineData(" https://example.test/context/agent ", "https://example.test/context/agent/")]
    public void Mantem_contrato_por_endpoint_e_normaliza_barra_final(string address, string expected)
    {
        var result = Parse(address);
        Assert.Equal(expected, result.BaseUri!.AbsoluteUri);
        Assert.Equal(TimeSpan.FromSeconds(5), result.Timeout);
        Assert.Equal(TimeSpan.FromSeconds(30), result.DispatchInterval);
        Assert.Null(result.Heartbeat.RegisteredHostId);
    }

    [Theory]
    [InlineData("/agent/")]
    [InlineData("http://[broken/agent/")]
    [InlineData("ftp://example.test/agent/")]
    [InlineData("https://example.test/")]
    [InlineData("https://example.test/agent/events/")]
    [InlineData("https://example.test/Agent/")]
    [InlineData("https://example.test/agent/../")]
    [InlineData("https://SENSITIVE-SYNTHETIC@example.test/agent/")]
    [InlineData("https://example.test/agent/?token=SENSITIVE-SYNTHETIC")]
    [InlineData("https://example.test/agent/#SENSITIVE-SYNTHETIC")]
    public void URL_invalida_e_recusada_sem_expor_valor_ou_excecao_interna(string address)
    {
        var error = Assert.Throws<InvalidOperationException>(() => Parse(address));
        Assert.Contains("CentroAdministracao:BaseUrl", error.Message);
        Assert.DoesNotContain("example.test", error.ToString());
        Assert.DoesNotContain(Sensitive, error.ToString());
        Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("0", "30", "TimeoutSeconds")]
    [InlineData("-1", "30", "TimeoutSeconds")]
    [InlineData("SENSITIVE-SYNTHETIC", "30", "TimeoutSeconds")]
    [InlineData("2147484", "30", "TimeoutSeconds")]
    [InlineData("999999999999", "30", "TimeoutSeconds")]
    [InlineData("5", "0", "DispatchIntervalSeconds")]
    [InlineData("5", "-1", "DispatchIntervalSeconds")]
    [InlineData("5", "SENSITIVE-SYNTHETIC", "DispatchIntervalSeconds")]
    [InlineData("5", "4294968", "DispatchIntervalSeconds")]
    public void Prazo_invalido_nao_vira_padrao_silenciosamente(string timeout, string interval, string field)
    {
        var error = Assert.Throws<InvalidOperationException>(() => Parse("https://example.test/agent/", timeout, interval));
        Assert.Contains("CentroAdministracao:" + field, error.Message);
        Assert.DoesNotContain(Sensitive, error.ToString());
        Assert.Null(error.InnerException);
    }

    [Fact]
    public void Prazos_validos_e_limites_do_transporte_sao_preservados()
    {
        var result = Parse("https://example.test/agent/", "2147483", "4294967");
        using var client = new HttpClient { Timeout = result.Timeout };
        Assert.Equal(TimeSpan.FromSeconds(2147483), client.Timeout);
        using var cancellation = new CancellationTokenSource();
        var delay = Task.Delay(result.DispatchInterval, cancellation.Token);
        cancellation.Cancel();
        Assert.True(delay.IsCanceled);
    }

    [Fact]
    public void AgentApi_continua_explicito_e_exige_host_previamente_cadastrado()
    {
        var result = Parse("http://127.0.0.1:8080/agent/", "7", "31", "AgentApi", "23");
        Assert.Equal(23, result.Heartbeat.RegisteredHostId);
        Assert.Equal(TimeSpan.FromSeconds(7), result.Timeout);
        Assert.Equal(TimeSpan.FromSeconds(31), result.DispatchInterval);
        Assert.Throws<InvalidOperationException>(() => Parse(null, protocol: "AgentApi", hostId: "23"));
        Assert.Throws<InvalidOperationException>(() => Parse("https://example.test/agent/", protocol: "AgentApi"));
        Assert.Throws<InvalidOperationException>(() => Parse("https://example.test/agent/", hostId: "23"));
        Assert.Throws<InvalidOperationException>(() => Parse("https://example.test/agent/", protocol: "automatic"));
        Assert.Throws<InvalidOperationException>(() => Parse("https://example.test/agent/", legacyUserId: "23"));
    }

    private static AdministrationConfiguration Parse(string? address, string? timeout = null, string? interval = null,
        string? protocol = null, string? hostId = null, string? legacyUserId = null) =>
        AdministrationConfiguration.Parse(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CentroAdministracao:BaseUrl"] = address,
            ["CentroAdministracao:TimeoutSeconds"] = timeout,
            ["CentroAdministracao:DispatchIntervalSeconds"] = interval,
            ["CentroAdministracao:HeartbeatProtocol"] = protocol,
            ["CentroAdministracao:RegisteredHostId"] = hostId,
            ["CentroAdministracao:RegisteredUserId"] = legacyUserId
        }).Build());
}
