using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Entrega as notificações aos aplicativos de bandeja conectados, por named
/// pipe.
///
/// Este canal é de mão única: o servidor escreve e o cliente lê. O pedido de
/// justificativa usa outro pipe, onde o serviço valida o ID e a sessão do
/// bloqueio antes de enviar uma concessão ao driver.
/// </summary>
public sealed class NotificationPipeServer : BackgroundService
{
    /// <summary>
    /// Quantas conexões simultâneas o pipe aceita.
    ///
    /// Uma por sessão interativa, mais folga. Num terminal com várias sessões
    /// abertas, cada usuário tem seu próprio aplicativo de bandeja, e um
    /// servidor de instância única atenderia só o primeiro que conectasse.
    /// </summary>
    private const int MaxServerInstances = 16;

    /// <summary>
    /// Prazo para escrever uma mensagem num cliente antes de desistir dele.
    ///
    /// Curto de propósito: um cliente que não consome em um segundo está
    /// travado ou morto, e a alternativa a derrubá-lo é deixar a fila de
    /// notificações crescer atrás dele.
    /// </summary>
    private static readonly TimeSpan WriteTimeout = TimeSpan.FromSeconds(1);

    private readonly NotificationHub _hub;
    private readonly ILogger<NotificationPipeServer> _logger;
    private readonly string _pipeName;

    /// <summary>Compõe o servidor.</summary>
    public NotificationPipeServer(NotificationHub hub, ILogger<NotificationPipeServer> logger)
        : this(hub, logger, NotificationProtocol.PipeName)
    {
    }

    /// <summary>Tests use a private pipe name; production uses <see cref="NotificationProtocol.PipeName"/>.</summary>
    internal NotificationPipeServer(NotificationHub hub, ILogger<NotificationPipeServer> logger, string pipeName)
    {
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _pipeName = string.IsNullOrEmpty(pipeName) ? throw new ArgumentException("Pipe name required.", nameof(pipeName)) : pipeName;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Canal de notificacao em \\\\.\\pipe\\{Pipe}", _pipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreatePipe(_pipeName);

                try
                {
                    await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    // A client that connected and left before the accept finished.
                    // Not a server failure: release this instance (it was leaked
                    // until finalization before) and accept the next client.
                    _logger.LogDebug(ex, "Cliente saiu antes de a conexao ser aceita");
                    pipe.Dispose();
                    pipe = null;
                    await Task.Delay(TimeSpan.FromMilliseconds(50), stoppingToken).ConfigureAwait(false);
                    continue;
                }

                // Cada cliente é atendido em sua própria tarefa. O laço volta
                // imediatamente a aceitar: se ele esperasse o cliente terminar,
                // o segundo aplicativo a abrir ficaria sem conexão até o
                // primeiro fechar.
                var accepted = pipe;
                pipe = null; // ServeAsync owns and disposes it
                _ = ServeAsync(accepted, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                pipe?.Dispose();
                // O laço de accept nunca pode morrer por causa de uma falha de
                // um cliente: seria o serviço parar de notificar até ser
                // reiniciado. Registra, respira e continua aceitando.
                _logger.LogError(ex, "Falha ao aceitar conexao no canal de notificacao");

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    /// <summary>
    /// Cria o pipe com a lista de controle de acesso explícita.
    ///
    /// Este é o detalhe que quebra a integração se for esquecido. O serviço
    /// roda como LocalSystem e o aplicativo roda como usuário comum; o
    /// descritor de segurança padrão de um named pipe criado por LocalSystem
    /// <b>não</b> concede acesso a usuários comuns, e o cliente recebe acesso
    /// negado sem nenhuma pista do motivo.
    ///
    /// A concessão a <c>Users</c> usa o SID bem conhecido, e não o nome do
    /// grupo, porque o nome muda com o idioma do Windows.
    ///
    /// A segunda regra é a que custa caro descobrir. Informar uma
    /// <see cref="PipeSecurity"/> <b>substitui</b> a DACL padrão inteira, e
    /// criar uma nova instância do pipe exige o direito
    /// <see cref="PipeAccessRights.CreateNewInstance"/>. Sem ele, a primeira
    /// instância nasce — o criador sempre consegue criar a primeira — e a
    /// <b>segunda</b> falha com acesso negado: o primeiro aplicativo conecta e
    /// o canal morre logo depois, quando o laço tenta preparar a próxima. Por
    /// isso a conta que executa o processo recebe controle total explícito, o
    /// que cobre tanto LocalSystem em produção quanto o usuário interativo
    /// durante a depuração em console.
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

        // Duplex only so the server can hold one pending read per client and
        // learn of its disconnection at once (see ServeAsync); clients still
        // open the pipe for reading and never write.
        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            MaxServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            inBufferSize: 0,
            outBufferSize: 64 * 1024,
            security);
    }

    /// <summary>
    /// Atende um cliente até ele desconectar.
    /// </summary>
    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        // A sessao do aplicativo que conectou, para nao entregar a uma sessao
        // o bloqueio ocorrido em outra.
        SessionResolver.ProcessIdentity? client = SessionResolver.TryGetClientIdentity(pipe.SafePipeHandle);
        uint? sessionId = client?.SessionId;

        using var subscription = _hub.Subscribe(sessionId, client?.UserSid.Value);

        // A client that disconnects is otherwise noticed only by the next failed
        // write. With a quiet status no write comes, and departed clients kept
        // all 16 instances: new clients, including the tray, could never connect
        // (m2t5boot5: "All pipe instances are busy" every second). Clients never
        // write, so one pending read ends this connection when it completes.
        using var connection = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        Task watcher = WatchClientAsync(pipe, connection);

        try
        {
            await using (pipe)
            {
                await using var writer = new StreamWriter(pipe, NotificationProtocol.Encoding, leaveOpen: true)
                {
                    AutoFlush = false
                };

                _logger.LogInformation(
                    "Aplicativo conectado ao canal de notificacao (sessao {Sessao})",
                    sessionId?.ToString() ?? "desconhecida");

                // O estado vai primeiro, antes de qualquer evento: sem ele o
                // aplicativo recém-aberto não teria como preencher os cartões,
                // porque quem carrega política agora é o serviço.
                if (_hub.GetRecordedStatus() is { } status
                    && !await TryWriteAsync(writer, status, connection.Token).ConfigureAwait(false))
                {
                    return;
                }

                await foreach (var notification in subscription.Reader.ReadAllAsync(connection.Token).ConfigureAwait(false))
                {
                    if (!await TryWriteAsync(writer, notification, connection.Token).ConfigureAwait(false))
                    {
                        return;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Serviço parando, ou o cliente desconectou.
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Conexao encerrada");
        }
        finally
        {
            connection.Cancel();
            try { await watcher.ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogDebug(ex, "Monitor de desconexao encerrado"); }
            _logger.LogInformation("Aplicativo desconectado do canal de notificacao");
        }
    }

    /// <summary>
    /// Ends the connection when the client disconnects, breaks the pipe or writes
    /// anything: every completion of the single pending read cancels it.
    /// </summary>
    private static async Task WatchClientAsync(PipeStream pipe, CancellationTokenSource connection)
    {
        var buffer = new byte[1];
        try
        {
            _ = await pipe.ReadAsync(buffer, connection.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // Broken pipe, disposal or shutdown: the connection ends either way.
        }
        finally
        {
            try { connection.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }

    /// <summary>
    /// Escreve uma mensagem com prazo.
    /// </summary>
    /// <returns>
    /// Falso quando a conexão deve ser derrubada — cliente desconectado, canal
    /// quebrado ou escrita que passou do prazo. Derrubar é a resposta certa em
    /// todos os três casos: manter a conexão de um cliente que não lê só faz a
    /// fila atrás dele crescer.
    /// </returns>
    private async Task<bool> TryWriteAsync(
        StreamWriter writer,
        AgentNotification notification,
        CancellationToken stoppingToken)
    {
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            deadline.CancelAfter(WriteTimeout);

            await writer.WriteAsync(
                NotificationProtocol.Serialize(notification).AsMemory(),
                deadline.Token).ConfigureAwait(false);

            await writer.FlushAsync(deadline.Token).ConfigureAwait(false);

            return true;
        }
        catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
        {
            _logger.LogWarning("Cliente nao consumiu a notificacao no prazo; conexao derrubada");
            return false;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            return false;
        }
    }
}
