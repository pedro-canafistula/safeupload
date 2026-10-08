using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Network.Certificates;
using SafeUpload.Agent.Network.Http;

namespace SafeUpload.Agent.Network.Proxy;

/// <summary>
/// O proxy de inspeção TLS (Fase 2 do plano).
///
/// Fluxo de uma conexão:
///
/// 1. O navegador, configurado com o proxy, conecta em 127.0.0.1 e manda
///    <c>CONNECT drive.google.com:443</c>, em texto claro. É o único momento
///    em que o proxy sabe o destino antes de qualquer criptografia.
/// 2. Pelo host, <see cref="TlsInspectionProxyOptions.ShouldIntercept"/> decide:
///    - <b>túnel</b> (exceções: bancos, saúde, governo, pinning): o proxy só
///      conecta no servidor e copia bytes nos dois sentidos, sem entender nada;
///    - <b>interceptação</b>: o proxy responde 200 e faz duas conexões TLS
///      separadas, uma com o navegador (com o certificado emitido pela CA local)
///      e outra com o servidor de verdade (validando o certificado real).
/// 3. Com as duas pontas abertas, o proxy lê cada requisição HTTP do navegador,
///    segura o corpo, pergunta ao <see cref="IUploadInspector"/> se pode sair
///    e repassa (ou responde 403). As respostas do servidor voltam sem
///    inspeção.
///
/// Só HTTP/1.1: o proxy anuncia apenas "http/1.1" no ALPN, e os sites aceitam,
/// porque todos ainda falam HTTP/1.1. HTTP/2 multiplexa várias requisições numa
/// conexão e exigiria um parser bem maior; fica para depois (ver o plano).
/// </summary>
public sealed class TlsInspectionProxy : IAsyncDisposable
{
    private static readonly byte[] ConnectEstablished =
        Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");

    private static readonly byte[] Continue100 = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");

    private readonly HostCertificateFactory _certificates;
    private readonly IUploadInspector _inspector;
    private readonly TlsInspectionProxyOptions _options;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _stopping = new();
    private readonly ConcurrentDictionary<Task, byte> _connections = new();
    private TcpListener? _listener;
    private Task? _acceptLoop;

    public TlsInspectionProxy(
        HostCertificateFactory certificates,
        IUploadInspector inspector,
        TlsInspectionProxyOptions options,
        ILogger<TlsInspectionProxy>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(inspector);
        ArgumentNullException.ThrowIfNull(options);

        _certificates = certificates;
        _inspector = inspector;
        _options = options;
        _logger = logger ?? NullLogger<TlsInspectionProxy>.Instance;
    }

    /// <summary>Endereço em que o proxy está escutando (com a porta real, se a configurada era 0).</summary>
    public IPEndPoint LocalEndpoint =>
        (IPEndPoint)(_listener?.LocalEndpoint ?? throw new InvalidOperationException("O proxy não foi iniciado."));

    /// <summary>Começa a aceitar conexões.</summary>
    public void Start()
    {
        if (!IPAddress.IsLoopback(_options.Listen.Address))
        {
            throw new InvalidOperationException("O proxy de inspeção só escuta em loopback.");
        }

        _listener = new TcpListener(_options.Listen);
        _listener.Start();
        _acceptLoop = AcceptLoopAsync(_stopping.Token);

        _logger.LogInformation("Proxy de inspeção TLS escutando em {Endpoint}.", LocalEndpoint);
    }

    /// <summary>Para de aceitar conexões e encerra as abertas.</summary>
    public async Task StopAsync()
    {
        if (_stopping.IsCancellationRequested)
        {
            return;
        }

        await _stopping.CancelAsync().ConfigureAwait(false);
        _listener?.Stop();

        List<Task> pending = [.. _connections.Keys];

        if (_acceptLoop is not null)
        {
            pending.Add(_acceptLoop);
        }

        await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _stopping.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;

            try
            {
                client = await _listener!.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException
                                       && cancellationToken.IsCancellationRequested)
            {
                return;
            }

            Task connection = Task.Run(() => HandleClientAsync(client, cancellationToken), CancellationToken.None);
            _connections.TryAdd(connection, 0);
            _ = connection.ContinueWith(task => _connections.TryRemove(task, out _), TaskScheduler.Default);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            client.NoDelay = true;
            var remote = (IPEndPoint)client.Client.RemoteEndPoint!;

            // Descobrir o processo agora, com a conexão certamente viva.
            int? processId = null;

            try
            {
                processId = TcpConnectionOwner.FindProcessId(remote, (IPEndPoint)client.Client.LocalEndPoint!);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Não foi possível descobrir o processo da conexão {Remote}.", remote);
            }

            NetworkStream clientStream = client.GetStream();
            var clientReader = new HttpStreamReader(clientStream);
            string target = "?";

            try
            {
                HttpRequestHead? first = await ReadWithIdleTimeoutAsync(clientReader, cancellationToken).ConfigureAwait(false);

                if (first is null)
                {
                    return;
                }

                target = first.Target;

                if (IsRevocationListRequest(first))
                {
                    await ServeRevocationListAsync(first, clientStream, cancellationToken).ConfigureAwait(false);
                }
                else if (first.IsConnect)
                {
                    await HandleConnectAsync(first, clientStream, clientReader, processId, cancellationToken).ConfigureAwait(false);
                }
                else if (Uri.TryCreate(first.Target, UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttp)
                {
                    await HandlePlainHttpAsync(first, uri, clientStream, clientReader, processId, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await clientStream.WriteAsync(
                        HttpResponseHead.Simple(400, "Bad Request", "Requisição inválida para um proxy."), cancellationToken).ConfigureAwait(false);
                }
            }
            catch (HttpMessageException ex)
            {
                _logger.LogDebug("Mensagem HTTP inválida em {Target}: {Message}", target, ex.Message);
            }
            catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or OperationCanceledException or ObjectDisposedException)
            {
                // Conexões caem o tempo todo (aba fechada, rede trocada). Não é
                // erro do proxy; só fica registrado para diagnóstico.
                _logger.LogDebug("Conexão encerrada em {Target}: {Message}", target, ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha inesperada no proxy em {Target}.", target);
            }
        }
    }

    /// <summary>
    /// Pedido da lista de revogação: direto ao proxy (<c>GET /safeupload-ca.crl</c>)
    /// ou via proxy (<c>GET http://127.0.0.1:porta/safeupload-ca.crl</c>), que é
    /// como o Windows pede quando o proxy do sistema aponta para cá.
    /// </summary>
    private bool IsRevocationListRequest(HttpRequestHead request)
    {
        if (_options.RevocationList is null
            || !(request.Method is "GET" or "HEAD"))
        {
            return false;
        }

        if (request.Target == RevocationListPublisher.Path)
        {
            return true;
        }

        return Uri.TryCreate(request.Target, UriKind.Absolute, out Uri? uri)
            && uri.IsLoopback
            && uri.Port == LocalEndpoint.Port
            && uri.AbsolutePath == RevocationListPublisher.Path;
    }

    private async Task ServeRevocationListAsync(HttpRequestHead request, Stream client, CancellationToken cancellationToken)
    {
        byte[] crl = _options.RevocationList!.GetCurrent();

        var headers = new HttpHeaders();
        headers.Add("Content-Type", "application/pkix-crl");
        headers.Add("Content-Length", crl.Length.ToString(CultureInfo.InvariantCulture));
        headers.Add("Connection", "close");

        await client.WriteAsync(new HttpResponseHead("HTTP/1.1", 200, "OK", headers).Serialize(), cancellationToken).ConfigureAwait(false);

        if (request.Method == "GET")
        {
            await client.WriteAsync(crl, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleConnectAsync(
        HttpRequestHead connect, NetworkStream clientStream, HttpStreamReader clientReader, int? processId, CancellationToken cancellationToken)
    {
        if (!TryParseAuthority(connect.Target, 443, out string host, out int port))
        {
            await clientStream.WriteAsync(HttpResponseHead.Simple(400, "Bad Request", "Destino inválido."), cancellationToken).ConfigureAwait(false);
            return;
        }

        if (!_options.ShouldIntercept(host))
        {
            await TunnelAsync(host, port, clientStream, clientReader, cancellationToken).ConfigureAwait(false);
            return;
        }

        await clientStream.WriteAsync(ConnectEstablished, cancellationToken).ConfigureAwait(false);

        // A partir daqui a conexão é do TLS. Bytes que já tenham chegado junto
        // com o CONNECT são o começo do handshake e precisam ir junto.
        byte[] leftover = clientReader.TakeBuffered();
        Stream transport = leftover.Length > 0 ? new PrefixedStream(leftover, clientStream) : clientStream;

        await using var clientTls = new SslStream(transport, leaveInnerStreamOpen: false);
        SslStream? upstreamTls = null;
        TcpClient? upstreamClient = null;

        try
        {
            // O certificado apresentado ao navegador só é escolhido depois de
            // abrir a conexão com o servidor real e validar o certificado dele.
            // Se o servidor real for inválido (certificado vencido, de outro
            // site, ataque na rede), o handshake com o navegador falha e ele
            // mostra erro de conexão: o proxy nunca transforma um certificado
            // ruim num certificado "bom" emitido pela CA local.
            await clientTls.AuthenticateAsServerAsync(
                async (_, hello, _, ct) =>
                {
                    string name = string.IsNullOrEmpty(hello.ServerName) ? host : hello.ServerName;
                    (upstreamClient, upstreamTls) = await ConnectUpstreamTlsAsync(host, port, name, ct).ConfigureAwait(false);

                    return new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificates.GetCertificate(name),
                        ApplicationProtocols = [SslApplicationProtocol.Http11],
                    };
                },
                null,
                cancellationToken).ConfigureAwait(false);

            await ExchangeAsync(
                clientTls, new HttpStreamReader(clientTls), upstreamTls!, host, port, processId,
                encrypted: true, first: null, closeAfterFirst: false, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (upstreamTls is not null)
            {
                await upstreamTls.DisposeAsync().ConfigureAwait(false);
            }

            upstreamClient?.Dispose();
        }
    }

    private async Task HandlePlainHttpAsync(
        HttpRequestHead first, Uri uri, NetworkStream clientStream, HttpStreamReader clientReader, int? processId, CancellationToken cancellationToken)
    {
        using TcpClient upstream = await ConnectAsync(uri.Host, uri.Port, cancellationToken).ConfigureAwait(false);

        // Pela convenção de proxy, o navegador manda a URL inteira; o servidor
        // de destino espera só o caminho.
        var rewritten = first with { Target = uri.PathAndQuery };

        // HTTP sem TLS pode trocar de site a cada requisição na mesma conexão.
        // Fechar depois de cada troca é mais simples e é raro o bastante para
        // não pesar: quase todo upload hoje é HTTPS.
        await ExchangeAsync(
            clientStream, clientReader, upstream.GetStream(), uri.Host, uri.Port, processId,
            encrypted: false, first: rewritten, closeAfterFirst: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task TunnelAsync(
        string host, int port, NetworkStream clientStream, HttpStreamReader clientReader, CancellationToken cancellationToken)
    {
        TcpClient upstream;

        try
        {
            upstream = await ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            await clientStream.WriteAsync(
                HttpResponseHead.Simple(502, "Bad Gateway", $"Não foi possível conectar a {host}."), cancellationToken).ConfigureAwait(false);
            return;
        }

        using (upstream)
        {
            NetworkStream upstreamStream = upstream.GetStream();
            await clientStream.WriteAsync(ConnectEstablished, cancellationToken).ConfigureAwait(false);
            await clientReader.FlushBufferedAsync(upstreamStream, cancellationToken).ConfigureAwait(false);
            await PipeAsync(clientStream, upstreamStream, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Troca requisições e respostas entre as duas pontas até uma delas fechar.
    /// </summary>
    private async Task ExchangeAsync(
        Stream client,
        HttpStreamReader clientReader,
        Stream upstream,
        string host,
        int port,
        int? processId,
        bool encrypted,
        HttpRequestHead? first,
        bool closeAfterFirst,
        CancellationToken cancellationToken)
    {
        var upstreamReader = new HttpStreamReader(upstream);
        HttpRequestHead? request = first;

        while (true)
        {
            request ??= await ReadWithIdleTimeoutAsync(clientReader, cancellationToken).ConfigureAwait(false);

            if (request is null)
            {
                return;
            }

            if (request.IsConnect)
            {
                await client.WriteAsync(HttpResponseHead.Simple(400, "Bad Request", "CONNECT dentro de túnel."), cancellationToken).ConfigureAwait(false);
                return;
            }

            request.Headers.Remove("Proxy-Connection");

            bool? forwarded = await ForwardRequestAsync(
                request, client, clientReader, upstream, host, port, processId, encrypted, cancellationToken).ConfigureAwait(false);

            if (forwarded is not { } handledContinue)
            {
                // Bloqueada: o 403 já foi enviado, e a conexão termina aqui.
                return;
            }

            HttpResponseHead response;

            while (true)
            {
                response = await upstreamReader.ReadResponseHeadAsync(cancellationToken).ConfigureAwait(false);

                if (!response.IsInterim)
                {
                    break;
                }

                // O 100 Continue do servidor já foi respondido pelo proxy ao
                // navegador; repassar seria um segundo 100 fora de hora.
                if (!(handledContinue && response.StatusCode == 100))
                {
                    await client.WriteAsync(response.Serialize(), cancellationToken).ConfigureAwait(false);
                }
            }

            if (response.IsSwitchingProtocols)
            {
                // WebSocket: depois do 101 a conexão deixa de ser HTTP. Nesta
                // versão passa sem inspeção (ver o plano).
                await client.WriteAsync(response.Serialize(), cancellationToken).ConfigureAwait(false);
                await upstreamReader.FlushBufferedAsync(client, cancellationToken).ConfigureAwait(false);
                await clientReader.FlushBufferedAsync(upstream, cancellationToken).ConfigureAwait(false);
                await PipeAsync(client, upstream, cancellationToken).ConfigureAwait(false);
                return;
            }

            BodyFraming responseFraming = response.FramingFor(request);

            if (closeAfterFirst)
            {
                response.Headers.Set("Connection", "close");
            }

            await client.WriteAsync(response.Serialize(), cancellationToken).ConfigureAwait(false);
            await CopyBodyAsync(upstreamReader, responseFraming, ContentLengthOf(response.Headers), client, cancellationToken).ConfigureAwait(false);

            if (closeAfterFirst || request.WantsClose || response.WantsClose || responseFraming == BodyFraming.UntilClose)
            {
                return;
            }

            request = null;
        }
    }

    /// <summary>
    /// Repassa uma requisição ao servidor, segurando e inspecionando o corpo
    /// quando houver. Devolve se o proxy já respondeu "100 Continue" ao
    /// navegador, ou nulo se a requisição foi bloqueada (e já respondida com 403).
    /// </summary>
    private async Task<bool?> ForwardRequestAsync(
        HttpRequestHead request,
        Stream client,
        HttpStreamReader clientReader,
        Stream upstream,
        string host,
        int port,
        int? processId,
        bool encrypted,
        CancellationToken cancellationToken)
    {
        BodyFraming framing = request.Framing;
        long? contentLength = request.ContentLength;

        if (framing == BodyFraming.None)
        {
            await upstream.WriteAsync(request.Serialize(), cancellationToken).ConfigureAwait(false);
            return false;
        }

        // O navegador que manda "Expect: 100-continue" espera autorização
        // antes de enviar o corpo. Como o proxy precisa do corpo inteiro para
        // decidir, ele mesmo autoriza, e o pedido segue ao servidor sem o Expect.
        bool handledContinue = false;

        if (request.ExpectsContinue)
        {
            await client.WriteAsync(Continue100, cancellationToken).ConfigureAwait(false);
            request.Headers.Remove("Expect");
            handledContinue = true;
        }

        // Corpo declarado maior que o limite: segue direto, sem inspeção.
        if (framing == BodyFraming.ContentLength && contentLength > _options.MaxInspectableBodyBytes)
        {
            _logger.LogInformation(
                "Corpo de {Bytes} bytes para {Host} acima do limite de inspeção; seguiu sem inspeção.", contentLength, host);

            await upstream.WriteAsync(request.Serialize(), cancellationToken).ConfigureAwait(false);
            await clientReader.ReadBodyAsync(framing, contentLength, (data, ct) => upstream.WriteAsync(data, ct), cancellationToken).ConfigureAwait(false);
            return handledContinue;
        }

        using var body = new MemoryStream(contentLength is { } declared ? (int)declared : 0);
        bool streaming = false;

        await clientReader.ReadBodyAsync(
            framing,
            contentLength,
            async (data, ct) =>
            {
                if (!streaming && body.Length + data.Length <= _options.MaxInspectableBodyBytes)
                {
                    body.Write(data.Span);
                    return;
                }

                if (!streaming)
                {
                    // Só acontece com corpo em pedaços, cujo tamanho não é
                    // conhecido de antemão: passou do limite no meio. O que já
                    // foi segurado sai como um pedaço, e o resto segue em
                    // pedaços conforme chega, sem inspeção.
                    streaming = true;
                    _logger.LogInformation("Corpo em pedaços para {Host} passou do limite de inspeção; seguiu sem inspeção.", host);
                    await upstream.WriteAsync(request.Serialize(), ct).ConfigureAwait(false);
                    await WriteChunkAsync(upstream, body.GetBuffer().AsMemory(0, (int)body.Length), ct).ConfigureAwait(false);
                }

                await WriteChunkAsync(upstream, data, ct).ConfigureAwait(false);
            },
            cancellationToken).ConfigureAwait(false);

        if (streaming)
        {
            await upstream.WriteAsync("0\r\n\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            return handledContinue;
        }

        ReadOnlyMemory<byte> content = body.GetBuffer().AsMemory(0, (int)body.Length);
        UploadDecision decision;

        try
        {
            decision = await _inspector.InspectAsync(
                new UploadRequest(host, port, request, content, processId, encrypted), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Falha da inspeção libera, como no resto do produto (RN-013,
            // fail-open). Está entre as decisões em aberto do plano.
            _logger.LogWarning(ex, "Falha ao inspecionar requisição para {Host}; liberada.", host);
            decision = UploadDecision.Allow;
        }

        if (!decision.Allowed)
        {
            _logger.LogInformation("Requisição {Method} para {Host} bloqueada: {Reason}", request.Method, host, decision.Reason);

            await client.WriteAsync(
                HttpResponseHead.Simple(403, "Forbidden", $"SafeUpload bloqueou este envio. {decision.Reason}"), cancellationToken).ConfigureAwait(false);
            return null;
        }

        // O corpo já está inteiro na mão: segue com tamanho fixo, mesmo que
        // tenha chegado em pedaços.
        if (framing == BodyFraming.Chunked)
        {
            request.Headers.Remove("Transfer-Encoding");
        }

        request.Headers.Set("Content-Length", content.Length.ToString(CultureInfo.InvariantCulture));

        await upstream.WriteAsync(request.Serialize(), cancellationToken).ConfigureAwait(false);
        await upstream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
        return handledContinue;
    }

    private static async Task CopyBodyAsync(
        HttpStreamReader reader, BodyFraming framing, long? contentLength, Stream destination, CancellationToken cancellationToken)
    {
        if (framing == BodyFraming.Chunked)
        {
            // A moldura de pedaços é refeita na saída: o leitor entrega só os
            // dados, e cada trecho volta a ser um pedaço.
            await reader.ReadBodyAsync(framing, null, (data, ct) => WriteChunkAsync(destination, data, ct), cancellationToken).ConfigureAwait(false);
            await destination.WriteAsync("0\r\n\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
            return;
        }

        await reader.ReadBodyAsync(framing, contentLength, (data, ct) => destination.WriteAsync(data, ct), cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask WriteChunkAsync(Stream destination, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        if (data.IsEmpty)
        {
            return;
        }

        byte[] size = Encoding.ASCII.GetBytes(data.Length.ToString("x", CultureInfo.InvariantCulture) + "\r\n");
        await destination.WriteAsync(size, cancellationToken).ConfigureAwait(false);
        await destination.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        await destination.WriteAsync("\r\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async Task<(TcpClient Client, SslStream Tls)> ConnectUpstreamTlsAsync(
        string host, int port, string serverName, CancellationToken cancellationToken)
    {
        TcpClient upstream = await ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        var tls = new SslStream(upstream.GetStream(), leaveInnerStreamOpen: false);

        try
        {
            await tls.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = serverName,
                    ApplicationProtocols = [SslApplicationProtocol.Http11],
                    RemoteCertificateValidationCallback = _options.UpstreamCertificateValidation,
                },
                cancellationToken).ConfigureAwait(false);

            return (upstream, tls);
        }
        catch (AuthenticationException ex)
        {
            _logger.LogWarning("Certificado do servidor {Host} recusado: {Message}", serverName, ex.Message);
            await tls.DisposeAsync().ConfigureAwait(false);
            upstream.Dispose();
            throw;
        }
        catch
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            upstream.Dispose();
            throw;
        }
    }

    private async Task<TcpClient> ConnectAsync(string host, int port, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.ConnectTimeout);

        var upstream = new TcpClient { NoDelay = true };

        try
        {
            await upstream.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false);
            return upstream;
        }
        catch
        {
            upstream.Dispose();
            throw;
        }
    }

    private async Task<HttpRequestHead?> ReadWithIdleTimeoutAsync(HttpStreamReader reader, CancellationToken cancellationToken)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        idle.CancelAfter(_options.IdleTimeout);

        try
        {
            return await reader.ReadRequestHeadAsync(idle.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    /// <summary>Copia bytes nos dois sentidos até um dos lados fechar.</summary>
    private static async Task PipeAsync(Stream a, Stream b, CancellationToken cancellationToken)
    {
        Task first = await Task.WhenAny(
            a.CopyToAsync(b, cancellationToken),
            b.CopyToAsync(a, cancellationToken)).ConfigureAwait(false);

        await first.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
    }

    private static long? ContentLengthOf(HttpHeaders headers) =>
        long.TryParse(headers.Get("Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture, out long length) ? length : null;

    /// <summary>Interpreta "host:porta" e "[ipv6]:porta".</summary>
    internal static bool TryParseAuthority(string authority, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;

        if (string.IsNullOrWhiteSpace(authority))
        {
            return false;
        }

        string hostPart = authority;
        int colon = authority.LastIndexOf(':');
        int bracket = authority.LastIndexOf(']');

        if (colon > bracket)
        {
            if (!int.TryParse(authority[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535)
            {
                return false;
            }

            hostPart = authority[..colon];
        }

        host = hostPart.Trim('[', ']');
        return host.Length > 0;
    }
}
