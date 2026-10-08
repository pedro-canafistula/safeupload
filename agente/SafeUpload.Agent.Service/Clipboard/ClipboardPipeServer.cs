using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Clipboard;

/// <summary>
/// O pipe do canal de clipboard: recebe o pedido do aplicativo, entrega à
/// <see cref="ClipboardService"/> e devolve a resposta.
///
/// <para>Uma conexão, um pedido, uma resposta, e a conexão fecha. O aplicativo
/// pergunta numa cadência humana (uma cópia, uma troca de foco), então abrir
/// uma conexão por pergunta custa pouco e elimina o estado de conexão: nada a
/// reconectar, nada a travar se um lado cair no meio.</para>
///
/// <para>Em qualquer falha — linha malformada, linha acima do teto, cliente que
/// fica calado — o servidor fecha sem responder. O aplicativo trata a falta de
/// resposta como "libera" (RN-013), então calar é a resposta segura, e não há
/// motivo para devolver ao cliente o que deu errado.</para>
/// </summary>
public sealed class ClipboardPipeServer : BackgroundService
{
    private const int MaxServerInstances = 16;

    /// <summary>
    /// Quanto o servidor espera por um cliente que já conectou. Bem acima do
    /// prazo do aplicativo: quem chega aqui depois disso já desistiu, e esta é
    /// só a guarda contra um cliente que conecta e nunca escreve.
    /// </summary>
    private static readonly TimeSpan ServeTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Espera inicial entre tentativas de recriar o pipe.</summary>
    private static readonly TimeSpan DefaultRetryDelay = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Teto da espera. O pipe pode ficar indisponível por muito tempo; sem teto,
    /// o intervalo cresceria até o canal levar minutos para voltar.
    /// </summary>
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(30);

    private readonly ClipboardService _service;
    private readonly ILogger<ClipboardPipeServer> _logger;
    private readonly string _pipeName;
    private readonly TimeSpan _initialRetryDelay;

    /// <summary>Compõe o servidor.</summary>
    /// <param name="service">Quem decide.</param>
    /// <param name="logger">Log.</param>
    /// <param name="pipeName">Nome do pipe; só os testes usam outro que não o do protocolo.</param>
    /// <param name="retryDelay">Espera inicial ao falhar; só os testes usam outra que não a padrão.</param>
    public ClipboardPipeServer(
        ClipboardService service,
        ILogger<ClipboardPipeServer> logger,
        string? pipeName = null,
        TimeSpan? retryDelay = null)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _pipeName = pipeName ?? ClipboardProtocol.PipeName;
        _initialRetryDelay = retryDelay ?? DefaultRetryDelay;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan retryDelay = _initialRetryDelay;

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;

            // Criar o pipe pode falhar (nome ocupado, acesso negado, sem
            // recursos), e a exceção NÃO pode sair daqui: uma exceção não tratada
            // num BackgroundService derruba o host inteiro por padrão, e com ele
            // a proteção de arquivos. O clipboard é um canal à parte e desligado
            // por padrão; falhar não pode custar mais do que o próprio canal. Sem
            // pipe, o aplicativo não recebe resposta e libera (RN-013).
            try
            {
                pipe = CreatePipe(_pipeName);
                retryDelay = _initialRetryDelay;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Nao foi possivel criar o pipe do canal de clipboard. Nova tentativa em {Espera}.",
                    retryDelay);

                if (!await WaitBeforeRetryAsync(retryDelay, stoppingToken).ConfigureAwait(false))
                {
                    return;
                }

                retryDelay = NextRetryDelay(retryDelay);
                continue;
            }

            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao aceitar conexao no canal de clipboard.");
                await pipe.DisposeAsync().ConfigureAwait(false);

                // Sem esperar, uma falha que se repete viraria um laço apertado
                // gastando CPU e enchendo o log.
                if (!await WaitBeforeRetryAsync(retryDelay, stoppingToken).ConfigureAwait(false))
                {
                    return;
                }

                retryDelay = NextRetryDelay(retryDelay);
                continue;
            }

            retryDelay = _initialRetryDelay;

            // Sem await: um cliente lento não pode impedir o próximo de conectar.
            _ = ServeAsync(pipe, stoppingToken);
        }
    }

    /// <returns><c>false</c> se o serviço foi parado durante a espera.</returns>
    private static async Task<bool> WaitBeforeRetryAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static TimeSpan NextRetryDelay(TimeSpan current) =>
        TimeSpan.FromMilliseconds(Math.Min(current.TotalMilliseconds * 2, MaxRetryDelay.TotalMilliseconds));

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        uint? sessionId = SessionResolver.TryGetClientSessionId(pipe.SafePipeHandle);

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            timeout.CancelAfter(ServeTimeout);

            using var reader = new StreamReader(pipe, ClipboardProtocol.Encoding, false, 4096, leaveOpen: true);

            string? line = await ClipboardProtocol.ReadLineAsync(reader, timeout.Token).ConfigureAwait(false);

            ClipboardRequest? request = ClipboardProtocol.DeserializeRequest(line);

            if (request is null)
            {
                // Sem o conteúdo da linha no log: ela pode ser o texto copiado.
                _logger.LogWarning("Pedido de clipboard malformado ou acima do teto, descartado.");
                return;
            }

            ClipboardResponse response = await _service
                .HandleAsync(request, sessionId, timeout.Token)
                .ConfigureAwait(false);

            // O escritor tem escopo próprio: descartá-lo só no fim do método
            // tentaria um último Flush depois de o cliente já ter fechado, e
            // isso lançaria "Pipe is broken" numa conversa que deu certo.
            await using (var writer = new StreamWriter(pipe, ClipboardProtocol.Encoding, 1024, leaveOpen: true))
            {
                await writer.WriteLineAsync(ClipboardProtocol.Serialize(response).AsMemory(), timeout.Token)
                    .ConfigureAwait(false);
                await writer.FlushAsync(timeout.Token).ConfigureAwait(false);
            }

            // Só fecha depois que o cliente fechar. Descartar o pipe do lado do
            // servidor com a resposta ainda no buffer pode perdê-la, e
            // WaitForPipeDrain bloquearia uma thread para sempre diante de um
            // cliente que nunca lê. Esta leitura devolve 0 quando o cliente
            // desconecta, e o prazo da conexão a limita.
            await pipe.ReadAsync(new byte[1].AsMemory(), timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            // O log leva a exceção, que não carrega o texto: ela vem do pipe
            // ou da política, nunca do conteúdo do pedido.
            _logger.LogWarning(ex, "Falha ao atender o canal de clipboard.");
        }
        finally
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Cria o pipe. A ACL segue a dos outros dois canais: usuários locais leem
    /// e escrevem, e a conta que executa tem controle total — sem ele a segunda
    /// instância falha com acesso negado.
    /// </summary>
    private static NamedPipeServerStream CreatePipe(string pipeName)
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, domainSid: null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, domainSid: null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        using var current = WindowsIdentity.GetCurrent();

        if (current.User is { } owner)
        {
            security.AddAccessRule(new PipeAccessRule(
                owner,
                PipeAccessRights.FullControl,
                AccessControlType.Allow));
        }

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            MaxServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 64 * 1024,
            outBufferSize: 8 * 1024,
            security);
    }
}
