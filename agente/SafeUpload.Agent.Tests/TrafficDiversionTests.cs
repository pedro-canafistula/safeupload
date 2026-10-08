using System.Diagnostics;
using System.Net.Sockets;
using SafeUpload.Agent.Network.Diversion;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// Desvio do tráfego dos navegadores (Fase 3): políticas e filtros WFP.
///
/// Mexem no registro e na filtragem de rede da máquina e exigem
/// administrador, por isso só rodam com SAFEUPLOAD_MACHINE_TESTS=1 (na VM).
/// O teste de WFP também precisa de internet.
/// </summary>
public class TrafficDiversionTests
{
    [MachineFact]
    public void Politicas_dos_navegadores_sao_aplicadas_e_removidas()
    {
        try
        {
            BrowserProxyPolicies.Apply(8877);
            Assert.True(BrowserProxyPolicies.IsApplied(8877));
            Assert.False(BrowserProxyPolicies.IsApplied(9999));
        }
        finally
        {
            BrowserProxyPolicies.Remove();
        }

        Assert.False(BrowserProxyPolicies.IsApplied(8877));
    }

    /// <summary>
    /// O próprio processo de teste faz o papel do navegador: com o filtro,
    /// conectar direto na porta 443 é recusado pelo Windows; sem o filtro,
    /// funciona de novo. Também prova que descartar o objeto desfaz tudo.
    /// </summary>
    [MachineFact]
    public async Task Filtro_bloqueia_saida_direta_do_navegador_e_some_ao_descartar()
    {
        string self = Process.GetCurrentProcess().MainModule!.FileName;

        using (BrowserEgressFilter filter = BrowserEgressFilter.Install([self]))
        {
            Assert.Equal([self], filter.BlockedApplications);

            SocketException blocked = await Assert.ThrowsAsync<SocketException>(() => ConnectAsync("example.com", 443));
            Assert.Equal(SocketError.AccessDenied, blocked.SocketErrorCode);
        }

        await ConnectAsync("example.com", 443);
    }

    [MachineFact]
    public void Executaveis_inexistentes_sao_ignorados()
    {
        using BrowserEgressFilter filter = BrowserEgressFilter.Install([@"C:\nao\existe\navegador.exe"]);

        Assert.Empty(filter.BlockedApplications);
    }

    private static async Task ConnectAsync(string host, int port)
    {
        using var client = new TcpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await client.ConnectAsync(host, port, timeout.Token);
    }
}
