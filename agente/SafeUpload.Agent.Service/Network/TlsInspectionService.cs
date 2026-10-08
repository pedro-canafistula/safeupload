using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using SafeUpload.Agent.Network.Certificates;
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
/// Nesta fase o proxy ainda não desvia o tráfego sozinho: é preciso apontar o
/// navegador para ele (127.0.0.1 e a porta configurada). O desvio automático,
/// pelo proxy do sistema, é a Fase 3.
/// </summary>
public sealed class TlsInspectionService(
    IConfiguration configuration,
    ILogger<TlsInspectionService> logger,
    ILogger<TlsInspectionProxy> proxyLogger) : IHostedService, IAsyncDisposable
{
    private X509Certificate2? _authority;
    private HostCertificateFactory? _certificates;
    private TlsInspectionProxy? _proxy;

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

        _proxy = new TlsInspectionProxy(
            _certificates,
            new LoggingInspector(logger),
            new TlsInspectionProxyOptions
            {
                Listen = new IPEndPoint(IPAddress.Loopback, port),
                RevocationList = revocationList,
            },
            proxyLogger);

        _proxy.Start();
        logger.LogInformation("Inspeção TLS ativa com a CA {Thumbprint}.", _authority.Thumbprint);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_proxy is not null)
        {
            await _proxy.StopAsync().ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync().ConfigureAwait(false);
        }

        _certificates?.Dispose();
        _authority?.Dispose();
    }

    /// <summary>
    /// Inspetor provisório da Fase 2: registra o que passaria pela inspeção
    /// e libera. Nunca registra o conteúdo, só os metadados (RN-006). A Fase 5
    /// troca por um que chama o motor de inspeção.
    /// </summary>
    private sealed class LoggingInspector(ILogger logger) : IUploadInspector
    {
        public ValueTask<UploadDecision> InspectAsync(UploadRequest request, CancellationToken cancellationToken)
        {
            logger.LogInformation(
                "Envio visto: {Method} {Host}{Path} ({Bytes} bytes, {ContentType}) por {Process}.",
                request.Head.Method,
                request.Host,
                PathOnly(request.Head.Target),
                request.Body.Length,
                request.Head.Headers.Get("Content-Type") ?? "sem tipo",
                ProcessName(request.ProcessId));

            return ValueTask.FromResult(UploadDecision.Allow);
        }

        /// <summary>Sem a query string, que pode carregar tokens e dados.</summary>
        private static string PathOnly(string target)
        {
            int query = target.IndexOf('?');
            return query < 0 ? target : target[..query];
        }

        private static string ProcessName(int? processId)
        {
            if (processId is not { } pid)
            {
                return "processo desconhecido";
            }

            try
            {
                using var process = Process.GetProcessById(pid);
                return $"{process.ProcessName} (PID {pid})";
            }
            catch (ArgumentException)
            {
                return $"PID {pid}";
            }
        }
    }
}
