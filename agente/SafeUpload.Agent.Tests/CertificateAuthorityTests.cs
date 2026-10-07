using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SafeUpload.Agent.Network.Certificates;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// CA de inspeção e certificados por host (Fase 1 da inspeção TLS).
///
/// Cada teste cria uma CA descartável, com nome de chave próprio, no
/// repositório do usuário e sem confiança em Root: nada aqui mexe na lista de
/// raízes da máquina. O teste que mexe está em <see cref="MachineCertificateAuthorityTests"/>
/// e só roda quando pedido.
/// </summary>
public class CertificateAuthorityTests : IDisposable
{
    private readonly MachineCertificateAuthority _authority;

    public CertificateAuthorityTests()
    {
        string id = Guid.NewGuid().ToString("N");
        _authority = new MachineCertificateAuthority(new CertificateAuthorityOptions(
            KeyName: $"SafeUpload Test CA {id}",
            SubjectName: $"CN=SafeUpload Test CA {id}",
            Location: StoreLocation.CurrentUser,
            MachineKey: false,
            TrustInRoot: false));
    }

    /// <inheritdoc />
    public void Dispose() => _authority.Remove();

    [Fact]
    public void Cria_uma_CA_de_um_nivel_so_com_chave_privada()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();

        Assert.True(ca.HasPrivateKey);

        var constraints = ca.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(constraints.CertificateAuthority);
        Assert.True(constraints.HasPathLengthConstraint);
        Assert.Equal(0, constraints.PathLengthConstraint);

        var usage = ca.Extensions.OfType<X509KeyUsageExtension>().Single();
        Assert.True(usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign));
    }

    /// <summary>
    /// A CA é criada uma vez e reaproveitada: uma CA nova a cada início do
    /// serviço deixaria um rastro de raízes confiáveis abandonadas.
    /// </summary>
    [Fact]
    public void Segunda_chamada_reaproveita_a_mesma_CA()
    {
        using X509Certificate2 first = _authority.LoadOrCreate();
        using X509Certificate2 second = _authority.LoadOrCreate();

        Assert.Equal(first.Thumbprint, second.Thumbprint);
    }

    /// <summary>
    /// A propriedade de segurança central: a chave assina, mas não sai.
    /// </summary>
    [Fact]
    public void Chave_da_CA_nao_pode_ser_exportada()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();

        Assert.ThrowsAny<CryptographicException>(() => ca.Export(X509ContentType.Pkcs12));

        using ECDsa key = ca.GetECDsaPrivateKey()!;
        Assert.ThrowsAny<CryptographicException>(() => key.ExportParameters(includePrivateParameters: true));
        Assert.ThrowsAny<CryptographicException>(() => key.ExportPkcs8PrivateKey());
    }

    [Fact]
    public void Remover_apaga_o_certificado_e_a_chave()
    {
        using (_authority.LoadOrCreate())
        {
        }

        _authority.Remove();

        Assert.Null(_authority.Find());
    }

    [Fact]
    public void Certificado_do_site_e_assinado_pela_CA_e_serve_para_o_host()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();
        using var factory = new HostCertificateFactory(ca);

        X509Certificate2 site = factory.GetCertificate("drive.google.com");

        Assert.True(site.HasPrivateKey);
        Assert.True(BuildsChainTo(ca, site));
        Assert.True(site.MatchesHostname("drive.google.com"));
        Assert.False(site.MatchesHostname("mail.google.com"));

        var purposes = site.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages;
        Assert.Contains(purposes.Cast<Oid>(), oid => oid.Value == "1.3.6.1.5.5.7.3.1");

        Assert.False(site.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
        Assert.True(site.NotAfter - DateTime.Now <= TimeSpan.FromDays(8));
    }

    [Fact]
    public void Endereco_IP_vira_IP_no_certificado()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();
        using var factory = new HostCertificateFactory(ca);

        X509Certificate2 site = factory.GetCertificate("192.168.0.10");

        Assert.True(site.MatchesHostname("192.168.0.10"));
    }

    /// <summary>
    /// Um certificado por host, emitido uma vez: o navegador abre várias
    /// conexões para o mesmo site, e cada emissão é uma assinatura.
    /// </summary>
    [Fact]
    public void Mesmo_host_reaproveita_o_certificado_do_cache()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();
        using var factory = new HostCertificateFactory(ca);

        X509Certificate2 first = factory.GetCertificate("chatgpt.com");
        X509Certificate2 again = factory.GetCertificate("ChatGPT.com.");
        X509Certificate2 other = factory.GetCertificate("mail.google.com");

        Assert.Same(first, again);
        Assert.NotEqual(first.Thumbprint, other.Thumbprint);
        Assert.Equal(2, factory.CachedCount);
    }

    [Fact]
    public async Task Varias_conexoes_simultaneas_para_o_mesmo_host_recebem_o_mesmo_certificado()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();
        using var factory = new HostCertificateFactory(ca);

        X509Certificate2[] results = await Task.WhenAll(
            Enumerable.Range(0, 16).Select(_ => Task.Run(() => factory.GetCertificate("drive.google.com"))));

        Assert.All(results, certificate => Assert.Same(results[0], certificate));
    }

    /// <summary>
    /// O teste que importa para a Fase 2: um handshake TLS de verdade, com o
    /// SslStream do servidor apresentando o certificado emitido. Pega o
    /// problema clássico do Windows, em que o SChannel recusa chave que só
    /// existe na memória do .NET.
    /// </summary>
    [Fact]
    public async Task Handshake_TLS_funciona_com_o_certificado_emitido()
    {
        using X509Certificate2 ca = _authority.LoadOrCreate();
        using var factory = new HostCertificateFactory(ca);

        X509Certificate2? presented = await HandshakeAsync(
            factory,
            "drive.google.com",
            (_, certificate, _, errors) =>
                certificate is not null
                && !errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)
                && BuildsChainTo(ca, X509CertificateLoader.LoadCertificate(certificate.GetRawCertData())));

        Assert.NotNull(presented);
        Assert.True(presented.MatchesHostname("drive.google.com"));
    }

    /// <summary>
    /// Sobe um servidor TLS local que escolhe o certificado pelo nome pedido
    /// (SNI), como o proxy vai fazer, conecta um cliente e devolve o
    /// certificado que o cliente recebeu.
    /// </summary>
    internal static async Task<X509Certificate2?> HandshakeAsync(
        HostCertificateFactory factory, string host, RemoteCertificateValidationCallback? validation)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;

            Task server = Task.Run(async () =>
            {
                using TcpClient accepted = await listener.AcceptTcpClientAsync();
                await using var tls = new SslStream(accepted.GetStream());
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificateSelectionCallback = (_, name) => factory.GetCertificate(name ?? host),
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                });
            });

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            await using var clientTls = new SslStream(client.GetStream());
            await clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                RemoteCertificateValidationCallback = validation,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
            });

            await server;

            Assert.Equal(SslApplicationProtocol.Http11, clientTls.NegotiatedApplicationProtocol);

            return clientTls.RemoteCertificate is null
                ? null
                : X509CertificateLoader.LoadCertificate(clientTls.RemoteCertificate.GetRawCertData());
        }
        finally
        {
            listener.Stop();
        }
    }

    private static bool BuildsChainTo(X509Certificate2 ca, X509Certificate2 site)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(site);
    }
}

/// <summary>
/// A CA de verdade, na configuração da máquina: chave da máquina, confiança em
/// LocalMachine\Root e validação TLS padrão do Windows, a mesma que Chrome e
/// Edge usam.
///
/// Mexe na lista de raízes da máquina e exige administrador, por isso só roda
/// com SAFEUPLOAD_MACHINE_TESTS=1 (na VM de testes). Cria uma CA de nome
/// próprio e a remove no fim.
/// </summary>
public class MachineCertificateAuthorityTests
{
    [MachineFact]
    public async Task CA_da_maquina_e_aceita_pela_validacao_padrao_e_some_ao_remover()
    {
        string id = Guid.NewGuid().ToString("N");
        var authority = new MachineCertificateAuthority(new CertificateAuthorityOptions(
            KeyName: $"SafeUpload Machine Test CA {id}",
            SubjectName: $"CN=SafeUpload Machine Test CA {id}",
            Location: StoreLocation.LocalMachine,
            MachineKey: true,
            TrustInRoot: true));

        try
        {
            using X509Certificate2 ca = authority.LoadOrCreate();
            Assert.True(authority.IsTrusted(ca));

            using var factory = new HostCertificateFactory(ca);

            // Sem callback de validação: vale a decisão padrão do Windows. Se a
            // CA não estivesse em Root, o handshake falharia aqui.
            X509Certificate2? presented = await CertificateAuthorityTests.HandshakeAsync(factory, "drive.google.com", validation: null);
            Assert.NotNull(presented);

            authority.Remove();

            Assert.False(authority.IsTrusted(ca));
            Assert.Null(authority.Find());
        }
        finally
        {
            authority.Remove();
        }
    }
}

/// <summary>Teste que só roda com SAFEUPLOAD_MACHINE_TESTS=1.</summary>
public sealed class MachineFactAttribute : FactAttribute
{
    public MachineFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("SAFEUPLOAD_MACHINE_TESTS") != "1")
        {
            Skip = "Mexe na lista de raízes da máquina; defina SAFEUPLOAD_MACHINE_TESTS=1 para rodar (VM de testes).";
        }
    }
}
