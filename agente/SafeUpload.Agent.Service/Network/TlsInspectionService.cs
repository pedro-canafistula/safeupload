using System.Net;
using System.Security.Cryptography.X509Certificates;
using SafeUpload.Agent.Network.Bypass;
using SafeUpload.Agent.Network.Certificates;
using SafeUpload.Agent.Network.Diversion;
using SafeUpload.Agent.Network.Proxy;

namespace SafeUpload.Agent.Service.Network;

/// <summary>
/// Sobe o proxy de inspeção TLS junto com o serviço.
///
/// Desligado por padrão, como o minifiltro: só sobe com
/// <c>"InspecaoTls": { "Habilitada": true }</c> em appsettings.json. Ligar
/// cria a CA da máquina se ela ainda não existir (ver
/// <see cref="MachineCertificateAuthority.LoadOrCreate"/>).
///
/// Com o proxy no ar, desvia o tráfego dos navegadores para ele (Fase 3):
/// políticas de proxy do Chrome, Edge e Firefox e filtros WFP que impedem os
/// navegadores de sair direto. Ao parar, desfaz os dois. Se o serviço morrer
/// sem parar, os filtros somem sozinhos (sessão dinâmica da WFP), mas as
/// políticas ficam apontando para um proxy fora do ar e os navegadores ficam
/// sem internet até o serviço voltar; para esse caso existe o comando
/// <c>desvio remove</c> (ver <see cref="DiversionCommand"/>). O desvio pode ser
/// desligado com <c>"InspecaoTls": { "DesviarNavegadores": false }</c>, e aí o
/// navegador precisa ser apontado para o proxy à mão.
///
/// As exceções da Fase 4 também saem da configuração, em
/// <c>"InspecaoTls": { "Excecoes": ... }</c>: as categorias iniciais (bancos,
/// saúde, governo) ligadas ou desligadas, domínios acrescentados à mão e a
/// detecção de pinning. Ver <see cref="LoadExceptions"/>.
/// </summary>
public sealed class TlsInspectionService(
    IConfiguration configuration,
    ILogger<TlsInspectionService> logger,
    ILogger<TlsInspectionProxy> proxyLogger,
    WebUploadInspector inspector) : IHostedService, IAsyncDisposable
{
    private X509Certificate2? _authority;
    private HostCertificateFactory? _certificates;
    private TlsInspectionProxy? _proxy;
    private BrowserEgressFilter? _egressFilter;
    private bool _policiesApplied;

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        int port = int.TryParse(configuration["InspecaoTls:Porta"], out int configured) ? configured : 8877;

        _authority = new MachineCertificateAuthority().LoadOrCreate();

        // A lista de revogação é servida pelo próprio proxy; sem ela, os
        // programas que usam o TLS do Windows recusam os certificados.
        var revocationList = new RevocationListPublisher(
            _authority, new Uri($"http://127.0.0.1:{port}{RevocationListPublisher.Path}"));

        _certificates = new HostCertificateFactory(_authority, revocationList);

        InterceptionExceptions exceptions = LoadExceptions();
        bool detectPinning = !string.Equals(
            configuration["InspecaoTls:Excecoes:DetectarPinning"], "false", StringComparison.OrdinalIgnoreCase);

        _proxy = new TlsInspectionProxy(
            _certificates,
            inspector,
            new TlsInspectionProxyOptions
            {
                Listen = new IPEndPoint(IPAddress.Loopback, port),
                RevocationList = revocationList,
                Exceptions = exceptions,
                PinningDetector = detectPinning ? new PinningDetector() : null,
            },
            proxyLogger);

        _proxy.Start();
        logger.LogInformation("Inspeção TLS ativa com a CA {Thumbprint}.", _authority.Thumbprint);
        logger.LogInformation(
            "Exceções de inspeção (túnel, sem leitura): {Categories}. Detecção de pinning {Pinning}.",
            exceptions.Count == 0
                ? "nenhuma"
                : string.Join(", ", exceptions.CountByCategory().Select(pair => $"{pair.Key} ({pair.Value} domínios)")),
            detectPinning ? "ligada" : "desligada");

        if (exceptions.Ignored.Count > 0)
        {
            logger.LogWarning(
                "Entradas de exceção descartadas por não serem um domínio: {Entries}.", string.Join(", ", exceptions.Ignored));
        }

        // O desvio só depois do proxy no ar: apontar os navegadores para um
        // proxy que ainda não escuta é deixá-los sem internet.
        if (!string.Equals(configuration["InspecaoTls:DesviarNavegadores"], "false", StringComparison.OrdinalIgnoreCase))
        {
            BrowserProxyPolicies.Apply(port);
            _policiesApplied = true;

            _egressFilter = BrowserEgressFilter.Install();
            logger.LogInformation(
                "Navegadores desviados para o proxy; saída direta bloqueada para: {Browsers}.",
                _egressFilter.BlockedApplications.Count == 0 ? "nenhum navegador encontrado" : string.Join(", ", _egressFilter.BlockedApplications));
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // Ordem inversa da subida: primeiro libera os navegadores, depois
        // derruba o proxy.
        _egressFilter?.Dispose();
        _egressFilter = null;

        if (_policiesApplied)
        {
            BrowserProxyPolicies.Remove();
            _policiesApplied = false;
            logger.LogInformation("Desvio dos navegadores desfeito.");
        }

        if (_proxy is not null)
        {
            await _proxy.StopAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        _egressFilter?.Dispose();

        if (_proxy is not null)
        {
            await _proxy.DisposeAsync().ConfigureAwait(false);
        }

        _certificates?.Dispose();
        _authority?.Dispose();
    }

    /// <summary>
    /// Monta as exceções: as categorias iniciais que a configuração não
    /// desligou, mais os domínios de <c>InspecaoTls:Excecoes:Dominios</c>.
    ///
    /// As categorias são chaves com verdadeiro ou falso, e não uma lista,
    /// porque a configuração do .NET junta listas de arquivos diferentes pela
    /// posição: não haveria como um arquivo tirar um item que outro pôs.
    /// </summary>
    private InterceptionExceptions LoadExceptions()
    {
        var categories = new List<KeyValuePair<string, IEnumerable<string>>>();

        foreach ((string category, string[] domains) in DefaultExceptionLists.Categories)
        {
            if (!string.Equals(
                    configuration[$"InspecaoTls:Excecoes:Categorias:{category}"], "false", StringComparison.OrdinalIgnoreCase))
            {
                categories.Add(new(category, domains));
            }
        }

        string[] configured =
        [
            .. configuration.GetSection("InspecaoTls:Excecoes:Dominios").GetChildren()
                .Select(entry => entry.Value)
                .OfType<string>(),
        ];

        categories.Add(new(DefaultExceptionLists.Configured, configured));

        return new InterceptionExceptions(categories);
    }
}
