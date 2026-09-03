using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Entrega as notificações aos aplicativos de bandeja conectados, por named
/// pipe.
///
/// O canal é de mão única: o servidor escreve, o cliente lê, e não existe
/// caminho de volta. Não é economia de código — é a garantia de que nada que o
/// usuário faça na interface pode alterar um veredito. Um canal bidirecional
/// exigiria confiar no que o cliente manda; sem ele, não há o que validar.
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

    /// <summary>Compõe o servidor.</summary>
    public NotificationPipeServer(NotificationHub hub, ILogger<NotificationPipeServer> logger)
    {
        _hub = hub ?? throw new ArgumentNullException(nameof(hub));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Canal de notificacao em \\\\.\\pipe\\{Pipe}", NotificationProtocol.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var pipe = CreatePipe();

                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);

                // Cada cliente é atendido em sua própria tarefa. O laço volta
                // imediatamente a aceitar: se ele esperasse o cliente terminar,
                // o segundo aplicativo a abrir ficaria sem conexão até o
                // primeiro fechar.
                _ = ServeAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
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
    private static NamedPipeServerStream CreatePipe()
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
            NotificationProtocol.PipeName,
            PipeDirection.Out,
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
        var sessionId = SessionResolver.TryGetClientSessionId(pipe.SafePipeHandle);

        using var subscription = _hub.Subscribe(sessionId);

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
                if (_hub.CurrentStatus is { } status
                    && !await TryWriteAsync(writer, status, stoppingToken).ConfigureAwait(false))
                {
                    return;
                }

                await foreach (var notification in subscription.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
                {
                    if (!await TryWriteAsync(writer, notification, stoppingToken).ConfigureAwait(false))
                    {
                        return;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Serviço parando.
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Conexao encerrada");
        }
        finally
        {
            _logger.LogInformation("Aplicativo desconectado do canal de notificacao");
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
