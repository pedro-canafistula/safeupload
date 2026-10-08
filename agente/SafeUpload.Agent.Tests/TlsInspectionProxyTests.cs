using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SafeUpload.Agent.Network.Certificates;
using SafeUpload.Agent.Network.Http;
using SafeUpload.Agent.Network.Proxy;

namespace SafeUpload.Agent.Tests;

/// <summary>
/// O proxy de inspeção de ponta a ponta (Fase 2): um HttpClient no papel do
/// navegador, o proxy no meio e um servidor HTTPS local no papel do site.
///
/// Duas CAs de teste, para separar os papéis como no mundo real: a "CA de
/// inspeção" (a do agente, em que o navegador confia) e a "CA da internet"
/// (que assinou o certificado do site, e em que o proxy confia ao validar o
/// servidor de verdade). Nada é instalado na máquina.
/// </summary>
public sealed class TlsInspectionProxyTests : IAsyncLifetime
{
    private const string SiteHost = "localhost";

    private readonly MachineCertificateAuthority _inspectionAuthority = TestAuthority("Inspecao");
    private readonly MachineCertificateAuthority _internetAuthority = TestAuthority("Internet");
    private X509Certificate2 _inspectionCa = null!;
    private X509Certificate2 _internetCa = null!;
    private HostCertificateFactory _inspectionCertificates = null!;
    private HostCertificateFactory _siteCertificates = null!;
    private TestSite _site = null!;

    private static MachineCertificateAuthority TestAuthority(string role)
    {
        string id = Guid.NewGuid().ToString("N");
        return new MachineCertificateAuthority(new CertificateAuthorityOptions(
            $"SafeUpload {role} Test {id}", $"CN=SafeUpload {role} Test {id}", StoreLocation.CurrentUser, MachineKey: false, TrustInRoot: false));
    }

    public Task InitializeAsync()
    {
        _inspectionCa = _inspectionAuthority.LoadOrCreate();
        _internetCa = _internetAuthority.LoadOrCreate();
        _inspectionCertificates = new HostCertificateFactory(_inspectionCa);
        _siteCertificates = new HostCertificateFactory(_internetCa);
        _site = new TestSite(_siteCertificates.GetCertificate(SiteHost));
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _site.DisposeAsync();
        _inspectionCertificates.Dispose();
        _siteCertificates.Dispose();
        _inspectionCa.Dispose();
        _internetCa.Dispose();
        _inspectionAuthority.Remove();
        _internetAuthority.Remove();
    }

    [Fact]
    public async Task GET_passa_pelo_proxy_e_o_navegador_ve_o_certificado_da_CA_de_inspecao()
    {
        var inspector = new RecordingInspector();
        await using TlsInspectionProxy proxy = StartProxy(inspector);
        using HttpClient browser = Browser(proxy, out Func<X509Certificate2?> seen);

        string body = await browser.GetStringAsync(_site.Url("/ola"));

        Assert.Equal("GET /ola 0", body);
        Assert.Equal(_inspectionCa.Subject, seen()!.Issuer);
        Assert.Empty(inspector.Requests); // sem corpo, nada a inspecionar
    }

    [Fact]
    public async Task POST_e_entregue_inteiro_ao_inspetor_e_depois_ao_site()
    {
        var inspector = new RecordingInspector();
        await using TlsInspectionProxy proxy = StartProxy(inspector);
        using HttpClient browser = Browser(proxy, out _);

        HttpResponseMessage response = await browser.PostAsync(
            _site.Url("/upload"), new StringContent("CPF 529.982.247-25", Encoding.UTF8, "text/plain"));

        Assert.Equal("POST /upload 18", await response.Content.ReadAsStringAsync());

        UploadRequest seenByInspector = Assert.Single(inspector.Requests);
        Assert.Equal(SiteHost, seenByInspector.Host);
        Assert.Equal("CPF 529.982.247-25", Encoding.UTF8.GetString(seenByInspector.Body.Span));
        Assert.True(seenByInspector.Encrypted);
        Assert.Equal(Environment.ProcessId, seenByInspector.ProcessId);
    }

    [Fact]
    public async Task Requisicao_bloqueada_recebe_403_e_nunca_chega_ao_site()
    {
        var inspector = new RecordingInspector(block: true);
        await using TlsInspectionProxy proxy = StartProxy(inspector);
        using HttpClient browser = Browser(proxy, out _);

        HttpResponseMessage response = await browser.PostAsync(_site.Url("/upload"), new StringContent("CPF 529.982.247-25"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("bloqueado no teste", await response.Content.ReadAsStringAsync());
        Assert.Empty(_site.Requests);
    }

    /// <summary>
    /// Corpo em pedaços (tamanho desconhecido): o inspetor recebe os dados
    /// decodificados, e o site recebe com tamanho fixo.
    /// </summary>
    [Fact]
    public async Task Corpo_em_pedacos_e_decodificado_para_o_inspetor()
    {
        var inspector = new RecordingInspector();
        await using TlsInspectionProxy proxy = StartProxy(inspector);
        using HttpClient browser = Browser(proxy, out _);

        var content = new StreamContent(new NonSeekableStream(Encoding.UTF8.GetBytes(new string('x', 70_000) + "529.982.247-25")));
        HttpResponseMessage response = await browser.PostAsync(_site.Url("/chunked-up"), content);

        Assert.Equal("POST /chunked-up 70014", await response.Content.ReadAsStringAsync());
        Assert.EndsWith("529.982.247-25", Encoding.UTF8.GetString(Assert.Single(inspector.Requests).Body.Span));
        Assert.Equal("70014", _site.Requests.Single().Headers.Get("Content-Length"));
        Assert.Null(_site.Requests.Single().Headers.Get("Transfer-Encoding"));
    }

    [Fact]
    public async Task Expect_100_continue_e_respondido_pelo_proprio_proxy()
    {
        var inspector = new RecordingInspector();
        await using TlsInspectionProxy proxy = StartProxy(inspector);
        using HttpClient browser = Browser(proxy, out _);
        browser.DefaultRequestHeaders.ExpectContinue = true;

        HttpResponseMessage response = await browser.PostAsync(_site.Url("/upload"), new StringContent("abc"));

        Assert.Equal("POST /upload 3", await response.Content.ReadAsStringAsync());
        Assert.Null(_site.Requests.Single().Headers.Get("Expect"));
    }

    /// <summary>
    /// Keep-alive: várias requisições na mesma conexão TLS, sem reabrir nem
    /// refazer o handshake com o site.
    /// </summary>
    [Fact]
    public async Task Varias_requisicoes_reaproveitam_a_mesma_conexao()
    {
        await using TlsInspectionProxy proxy = StartProxy(new RecordingInspector());
        using HttpClient browser = Browser(proxy, out _);

        for (int i = 0; i < 5; i++)
        {
            Assert.Equal($"POST /n{i} 1", await (await browser.PostAsync(_site.Url($"/n{i}"), new StringContent("x"))).Content.ReadAsStringAsync());
        }

        Assert.Equal(5, _site.Requests.Count);
        Assert.Equal(1, _site.Connections);
    }

    [Fact]
    public async Task Resposta_em_pedacos_do_site_chega_inteira()
    {
        await using TlsInspectionProxy proxy = StartProxy(new RecordingInspector());
        using HttpClient browser = Browser(proxy, out _);

        Assert.Equal("um-dois-tres", await browser.GetStringAsync(_site.Url("/chunked-down")));
    }

    /// <summary>
    /// Exceções (bancos, saúde...): túnel cego. O navegador vê o certificado
    /// do próprio site, e o inspetor não vê nada.
    /// </summary>
    [Fact]
    public async Task Host_em_excecao_passa_por_tunel_sem_interceptar()
    {
        var inspector = new RecordingInspector();
        await using TlsInspectionProxy proxy = StartProxy(inspector, intercept: false);
        using HttpClient browser = Browser(proxy, out Func<X509Certificate2?> seen, trust: _internetCa);

        HttpResponseMessage response = await browser.PostAsync(_site.Url("/upload"), new StringContent("CPF 529.982.247-25"));

        Assert.Equal("POST /upload 18", await response.Content.ReadAsStringAsync());
        Assert.Equal(_internetCa.Subject, seen()!.Issuer);
        Assert.Empty(inspector.Requests);
    }

    /// <summary>
    /// Se o certificado do site de verdade não passa na validação, o
    /// navegador recebe erro, e não um certificado "bom" da CA de inspeção.
    /// </summary>
    [Fact]
    public async Task Certificado_invalido_do_site_derruba_a_conexao()
    {
        await using TlsInspectionProxy proxy = StartProxy(new RecordingInspector(), upstreamTrust: _inspectionCa);
        using HttpClient browser = Browser(proxy, out _);

        await Assert.ThrowsAsync<HttpRequestException>(() => browser.GetStringAsync(_site.Url("/ola")));
        Assert.Empty(_site.Requests);
    }

    /// <summary>
    /// Corpo acima do limite: segue sem inspeção, para o proxy não segurar
    /// gigabytes em memória.
    /// </summary>
    [Fact]
    public async Task Corpo_acima_do_limite_segue_sem_passar_pelo_inspetor()
    {
        var inspector = new RecordingInspector(block: true);
        await using TlsInspectionProxy proxy = StartProxy(inspector, maxBody: 1024);
        using HttpClient browser = Browser(proxy, out _);

        HttpResponseMessage response = await browser.PostAsync(_site.Url("/grande"), new ByteArrayContent(new byte[5000]));

        Assert.Equal("POST /grande 5000", await response.Content.ReadAsStringAsync());
        Assert.Empty(inspector.Requests);
    }

    /// <summary>
    /// O que o curl, o Outlook e o Teams fazem (TLS do Windows): verificação
    /// de revogação online. Sem lista de revogação o certificado é recusado;
    /// com a lista servida pelo proxy, aceito.
    /// </summary>
    [Fact]
    public async Task Verificacao_de_revogacao_do_Windows_passa_com_a_lista_servida_pelo_proxy()
    {
        int port = FreePort();
        var revocationList = new RevocationListPublisher(
            _inspectionCa, new Uri($"http://127.0.0.1:{port}{RevocationListPublisher.Path}"));
        using var withList = new HostCertificateFactory(_inspectionCa, revocationList);

        await using var proxy = new TlsInspectionProxy(withList, new RecordingInspector(), new TlsInspectionProxyOptions
        {
            Listen = new IPEndPoint(IPAddress.Loopback, port),
            RevocationList = revocationList,
        });
        proxy.Start();

        Assert.False(BuildsWithOnlineRevocation(_inspectionCertificates.GetCertificate("drive.google.com"), out string without));
        Assert.Contains("RevocationStatusUnknown", without);

        Assert.True(BuildsWithOnlineRevocation(withList.GetCertificate("drive.google.com"), out string with), with);
    }

    private bool BuildsWithOnlineRevocation(X509Certificate2 certificate, out string status)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_inspectionCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

        bool built = chain.Build(certificate);
        status = string.Join(", ", chain.ChainStatus.Select(s => s.Status));
        return built;
    }

    private static int FreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    [Fact]
    public void Interpreta_host_e_porta_do_CONNECT()
    {
        Assert.True(TlsInspectionProxy.TryParseAuthority("drive.google.com:443", 443, out string host, out int port));
        Assert.Equal(("drive.google.com", 443), (host, port));

        Assert.True(TlsInspectionProxy.TryParseAuthority("[::1]:8443", 443, out host, out port));
        Assert.Equal(("::1", 8443), (host, port));

        Assert.False(TlsInspectionProxy.TryParseAuthority("x:99999", 443, out _, out _));
    }

    private TlsInspectionProxy StartProxy(
        IUploadInspector inspector, bool intercept = true, int maxBody = 1024 * 1024, X509Certificate2? upstreamTrust = null)
    {
        X509Certificate2 trusted = upstreamTrust ?? _internetCa;

        var proxy = new TlsInspectionProxy(_inspectionCertificates, inspector, new TlsInspectionProxyOptions
        {
            Listen = new IPEndPoint(IPAddress.Loopback, 0),
            ShouldIntercept = _ => intercept,
            MaxInspectableBodyBytes = maxBody,
            UpstreamCertificateValidation = (_, certificate, _, errors) =>
                certificate is not null
                && !errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)
                && ChainsTo(trusted, certificate),
        });

        proxy.Start();
        return proxy;
    }

    /// <summary>"Navegador": HttpClient com o proxy e confiando numa CA específica.</summary>
    private HttpClient Browser(TlsInspectionProxy proxy, out Func<X509Certificate2?> seen, X509Certificate2? trust = null)
    {
        X509Certificate2 trusted = trust ?? _inspectionCa;
        X509Certificate2? last = null;
        seen = () => last;

        var handler = new SocketsHttpHandler
        {
            Proxy = new FixedProxy(new Uri($"http://127.0.0.1:{proxy.LocalEndpoint.Port}")),
            UseProxy = true,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                {
                    last = certificate is null ? null : X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                    return certificate is not null
                        && !errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)
                        && ChainsTo(trusted, certificate);
                },
            },
        };

        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    }

    private static bool ChainsTo(X509Certificate2 authority, X509Certificate certificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(authority);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));
    }

    /// <summary>Proxy fixo que nunca é ignorado (o WebProxy ignora endereços locais).</summary>
    private sealed class FixedProxy(Uri address) : IWebProxy
    {
        public ICredentials? Credentials { get; set; }

        public Uri GetProxy(Uri destination) => address;

        public bool IsBypassed(Uri host) => false;
    }

    private sealed class RecordingInspector(bool block = false) : IUploadInspector
    {
        public ConcurrentQueue<UploadRequest> Requests { get; } = new();

        public ValueTask<UploadDecision> InspectAsync(UploadRequest request, CancellationToken cancellationToken)
        {
            // Cópia do corpo: o buffer do proxy é reaproveitado depois.
            Requests.Enqueue(request with { Body = request.Body.ToArray() });
            return ValueTask.FromResult(block ? UploadDecision.Block("bloqueado no teste") : UploadDecision.Allow);
        }
    }

    /// <summary>Força o HttpClient a mandar o corpo em pedaços (tamanho desconhecido).</summary>
    private sealed class NonSeekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }

    /// <summary>
    /// "Site" HTTPS local: responde "MÉTODO caminho tamanho-do-corpo" e
    /// registra o que recebeu e quantas conexões abriu.
    /// </summary>
    private sealed class TestSite : IAsyncDisposable
    {
        // IPv4 e IPv6: "localhost" resolve primeiro para ::1, e uma conexão
        // recusada custa ~2 s no Windows antes de tentar 127.0.0.1.
        private readonly TcpListener _listener = TcpListener.Create(0);
        private readonly X509Certificate2 _certificate;
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;
        private int _connections;

        public TestSite(X509Certificate2 certificate)
        {
            _certificate = certificate;
            _listener.Start();
            _loop = AcceptAsync();
        }

        public ConcurrentQueue<HttpRequestHead> Requests { get; } = new();

        public int Connections => _connections;

        public string Url(string path) => $"https://{SiteHost}:{((IPEndPoint)_listener.LocalEndpoint).Port}{path}";

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            await _loop.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(_stop.Token);
                Interlocked.Increment(ref _connections);
                _ = Task.Run(() => ServeAsync(client));
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    await using var tls = new SslStream(client.GetStream());
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate });
                    var reader = new HttpStreamReader(tls);

                    while (await reader.ReadRequestHeadAsync(_stop.Token) is { } request)
                    {
                        long length = await reader.ReadBodyAsync(request.Framing, request.ContentLength, (_, _) => ValueTask.CompletedTask, _stop.Token);
                        Requests.Enqueue(request);

                        if (request.Target == "/chunked-down")
                        {
                            await tls.WriteAsync(Encoding.ASCII.GetBytes(
                                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\num-\r\n5\r\ndois-\r\n4\r\ntres\r\n0\r\n\r\n"));
                            continue;
                        }

                        byte[] body = Encoding.ASCII.GetBytes($"{request.Method} {request.Target} {length.ToString(CultureInfo.InvariantCulture)}");
                        await tls.WriteAsync(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n"));
                        await tls.WriteAsync(body);
                    }
                }
                catch (Exception)
                {
                    // Conexão encerrada pelo outro lado ou handshake recusado.
                }
            }
        }
    }
}
