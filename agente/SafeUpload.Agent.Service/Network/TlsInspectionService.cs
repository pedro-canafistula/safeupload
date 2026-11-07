using SafeUpload.Agent.Service.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Network.Bypass;
using SafeUpload.Agent.Network.Certificates;
using SafeUpload.Agent.Network.Diversion;
using SafeUpload.Agent.Network.Proxy;

namespace SafeUpload.Agent.Service.Network;

/// <summary>
/// Liga e desliga a inspeção TLS conforme a política (bloco <c>web</c>, que o console publica).
///
/// A cada 30 segundos, como o drive, relê a política. Ligada: cria a CA da máquina se ela ainda não existir (ver
/// <see cref="MachineCertificateAuthority.LoadOrCreate"/>), sobe o proxy e só então desvia os navegadores para ele
/// (políticas de proxy do Chrome, Edge e Firefox e filtros WFP que os impedem de sair direto). Desligada, ou com o
/// serviço parando: desfaz o desvio primeiro e depois derruba o proxy. A CA fica instalada; quem a remove é a
/// desinstalação (<c>ca remove</c>). Se só as exceções mudam, só o proxy é refeito e o desvio continua.
///
/// Se o serviço morrer sem parar, os filtros somem sozinhos (sessão dinâmica da WFP), mas as políticas ficam
/// apontando para um proxy fora do ar até o serviço voltar; para esse caso existe <c>desvio remove</c> (ver
/// <see cref="DiversionCommand"/>). Se a política não puder ser lida, o estado atual é mantido.
///
/// Fica na configuração local o que é operação da máquina: a porta (<c>InspecaoTls:Porta</c>), o desvio
/// (<c>InspecaoTls:DesviarNavegadores</c> = false para apontar o navegador à mão), as listas fixas de exceção
/// (<c>InspecaoTls:Excecoes:Categorias</c>) e a detecção de pinning (<c>InspecaoTls:Excecoes:DetectarPinning</c>).
/// </summary>
public sealed class TlsInspectionService(
    IConfiguration configuration,
    IPolicyStore policies,
    ILogger<TlsInspectionService> logger,
    ILogger<TlsInspectionProxy> proxyLogger,
    WebUploadInspector inspector) : BackgroundService
{
    private static readonly TimeSpan PolicyCheckInterval = TimeSpan.FromSeconds(30);

    private X509Certificate2? _authority;
    private HostCertificateFactory? _certificates;
    private RevocationListPublisher? _revocationList;
    private TlsInspectionProxy? _proxy;
    private string? _exceptionsKey;
    private BrowserEgressFilter? _egressFilter;
    private bool _policiesApplied;

    private int Port => int.TryParse(configuration["InspecaoTls:Porta"], out int configured) ? configured : 8877;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    Policy policy = await policies.LoadAsync(stoppingToken).ConfigureAwait(false);
                    await ApplyAsync(policy.Web).ConfigureAwait(false);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    logger.LogSafeWarning(error, "Não foi possível aplicar a inspeção web da política; o estado atual foi mantido.");
                }
                try { await Task.Delay(PolicyCheckInterval, stoppingToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
        finally
        {
            await TurnOffAsync().ConfigureAwait(false);
        }
    }

    internal async Task ApplyAsync(WebInspectionPolicy web)
    {
        if (!web.Enabled)
        {
            if (_proxy is not null)
            {
                await TurnOffAsync().ConfigureAwait(false);
                logger.LogSafeInformation("Inspeção web desligada pela política.");
            }
            return;
        }
        if (_proxy is null)
        {
            StartProxy(web);
        }
        else if (!string.Equals(_exceptionsKey, web.ExceptionsKey, StringComparison.Ordinal))
        {
            // Só o proxy muda: os navegadores continuam desviados e esperam a nova escuta por um instante.
            await StopProxyAsync().ConfigureAwait(false);
            StartProxy(web);
        }
        // A cada volta: um desvio que falhou pela metade é refeito na próxima.
        Divert();
    }

    private void StartProxy(WebInspectionPolicy web)
    {
        int port = Port;
        if (_authority is null)
        {
            _authority = new MachineCertificateAuthority().LoadOrCreate();
            // A lista de revogação é servida pelo próprio proxy; sem ela, os programas que usam o TLS do Windows
            // recusam os certificados.
            _revocationList = new RevocationListPublisher(
                _authority, new Uri($"http://127.0.0.1:{port}{RevocationListPublisher.Path}"));
            _certificates = new HostCertificateFactory(_authority, _revocationList);
        }

        InterceptionExceptions exceptions = LoadExceptions(web.ExceptionDomains);
        bool detectPinning = !string.Equals(
            configuration["InspecaoTls:Excecoes:DetectarPinning"], "false", StringComparison.OrdinalIgnoreCase);

        _proxy = new TlsInspectionProxy(
            _certificates!,
            inspector,
            new TlsInspectionProxyOptions
            {
                Listen = new IPEndPoint(IPAddress.Loopback, port),
                RevocationList = _revocationList!,
                Exceptions = exceptions,
                PinningDetector = detectPinning ? new PinningDetector() : null,
            },
            proxyLogger);
        _proxy.Start();
        _exceptionsKey = web.ExceptionsKey;

        logger.LogSafeInformation("Inspeção TLS ativa com a CA {Thumbprint}.", _authority.Thumbprint);
        logger.LogSafeInformation(
            "Exceções de inspeção (túnel, sem leitura): {Categories}. Detecção de pinning {Pinning}.",
            exceptions.Count == 0
                ? "nenhuma"
                : string.Join(", ", exceptions.CountByCategory().Select(pair => $"{pair.Key} ({pair.Value} domínios)")),
            detectPinning ? "ligada" : "desligada");
        if (exceptions.Ignored.Count > 0)
            logger.LogSafeWarning("Entradas de exceção descartadas por não serem um domínio: {Count}.", exceptions.Ignored.Count);
    }

    private void Divert()
    {
        // O desvio só depois do proxy no ar: apontar os navegadores para um proxy que ainda não escuta é deixá-los
        // sem internet.
        if (string.Equals(configuration["InspecaoTls:DesviarNavegadores"], "false", StringComparison.OrdinalIgnoreCase))
            return;
        if (!_policiesApplied)
        {
            BrowserProxyPolicies.Apply(Port);
            _policiesApplied = true;
        }
        if (_egressFilter is null)
        {
            _egressFilter = BrowserEgressFilter.Install();
            logger.LogSafeInformation(
                "Navegadores desviados para o proxy; saída direta bloqueada para {Count} aplicativo(s).",
                _egressFilter.BlockedApplications.Count);
        }
    }

    private async Task TurnOffAsync()
    {
        // Ordem inversa da subida: primeiro libera os navegadores, depois derruba o proxy.
        _egressFilter?.Dispose();
        _egressFilter = null;
        if (_policiesApplied)
        {
            BrowserProxyPolicies.Remove();
            _policiesApplied = false;
            logger.LogSafeInformation("Desvio dos navegadores desfeito.");
        }
        await StopProxyAsync().ConfigureAwait(false);
    }

    private async Task StopProxyAsync()
    {
        if (_proxy is null) return;
        await _proxy.StopAsync().ConfigureAwait(false);
        await _proxy.DisposeAsync().ConfigureAwait(false);
        _proxy = null;
        _exceptionsKey = null;
    }

    public override void Dispose()
    {
        _egressFilter?.Dispose();
        _certificates?.Dispose();
        _authority?.Dispose();
        base.Dispose();
    }

    /// <summary>
    /// As listas fixas (bancos, saúde, governo) que a configuração local não desligou, mais os domínios da política.
    ///
    /// As categorias são chaves com verdadeiro ou falso, e não uma lista, porque a configuração do .NET junta listas de
    /// arquivos diferentes pela posição: não haveria como um arquivo tirar um item que outro pôs.
    /// </summary>
    private InterceptionExceptions LoadExceptions(IReadOnlyList<string> policyDomains)
    {
        var categories = new List<KeyValuePair<string, IEnumerable<string>>>();
        foreach ((string category, string[] domains) in DefaultExceptionLists.Categories)
        {
            if (!string.Equals(
                    configuration[$"InspecaoTls:Excecoes:Categorias:{category}"], "false", StringComparison.OrdinalIgnoreCase))
                categories.Add(new(category, domains));
        }
        categories.Add(new(DefaultExceptionLists.Configured, policyDomains));
        return new InterceptionExceptions(categories);
    }
}
