using System.Threading.Channels;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Records each emission durably before retaining or delivering it. Subscriber
/// queues are bounded and never wait for a slow client; durable recording is
/// synchronous and may wait for disk. A failed record suppresses delivery.
/// </summary>
public sealed class NotificationHub
{
    /// <summary>
    /// Quantas mensagens cabem na fila de um assinante antes de as antigas
    /// começarem a cair. Uma cópia de pasta grande produz dezenas de eventos em
    /// segundos; o limite absorve a rajada sem virar memória sem fim.
    /// </summary>
    private const int SubscriberQueueCapacity = 256;

    /// <summary>
    /// Por quanto tempo um evento fica guardado para quem ainda não conectou.
    ///
    /// Cobre a janela em que o usuário fecha o aplicativo, um arquivo é
    /// bloqueado, e ele reabre a interface: sem isso, o bloqueio teria
    /// acontecido sem deixar rastro na tela. Não é histórico — histórico é o
    /// <c>queue.jsonl</c>, que guarda tudo e é lido pela tela de histórico.
    /// </summary>
    public static readonly TimeSpan ReplayWindow = TimeSpan.FromSeconds(60);

    /// <summary>Teto de eventos guardados, para a janela não virar memória.</summary>
    private const int MaxReplayEntries = 64;

    private readonly List<Subscription> _subscriptions = [];
    private readonly List<Buffered> _replay = [];
    private readonly Lock _gate = new();
    private readonly TimeProvider _clock;
    private readonly INotificationRecord _record;
    private readonly ILogger<NotificationHub> _logger;

    private StatusNotification? _currentStatus;

    public NotificationHub(INotificationRecord record, ILogger<NotificationHub> logger)
        : this(record, logger, TimeProvider.System) { }

    internal NotificationHub(INotificationRecord record, ILogger<NotificationHub> logger, TimeProvider clock)
    {
        _record = record ?? throw new ArgumentNullException(nameof(record));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    /// <summary>
    /// O último estado publicado, entregue a todo aplicativo que conectar.
    ///
    /// Sem isto, um aplicativo aberto depois do serviço ficaria sem saber a
    /// versão da política até a próxima mudança — que pode não vir nunca.
    /// </summary>
    public StatusNotification? CurrentStatus
    {
        get
        {
            lock (_gate)
            {
                return _currentStatus;
            }
        }
    }

    /// <summary>
    /// Registra um assinante e devolve a fila de onde ele deve ler.
    /// </summary>
    /// <param name="sessionId">
    /// Sessão do Windows do aplicativo que conectou, quando conhecida. Serve
    /// para não entregar a uma sessão o bloqueio ocorrido em outra.
    /// </param>
    /// <returns>
    /// Um descarte que remove a assinatura. Quem conecta é responsável por
    /// chamá-lo ao perder a conexão, senão o hub acumula filas de aplicativos
    /// que já morreram.
    /// </returns>
    public NotificationSubscription Subscribe(uint? sessionId = null)
    {
        // DropOldest e não Wait: escrever nunca pode bloquear quem publica.
        var channel = Channel.CreateBounded<AgentNotification>(
            new BoundedChannelOptions(SubscriberQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });

        var subscription = new Subscription(channel, sessionId);

        lock (_gate)
        {
            _subscriptions.Add(subscription);

            // O que aconteceu enquanto ninguém ouvia vai primeiro, na ordem
            // original, antes de qualquer evento novo.
            PruneReplay();

            foreach (var buffered in _replay)
            {
                if (Targets(subscription, buffered.TargetSessionId) && TryRecord(buffered.Notification, buffered.TargetSessionId))
                {
                    channel.Writer.TryWrite(buffered.Notification);
                }
            }
        }

        return new NotificationSubscription(channel.Reader, () => Remove(subscription));
    }

    /// <summary>
    /// Flushes the emission record, then publishes. Recording failure is logged and suppresses delivery.
    /// </summary>
    /// <param name="notification">A mensagem.</param>
    /// <param name="targetSessionId">
    /// Sessão de destino. Nulo significa difusão para todos os aplicativos
    /// conectados — que é o caminho percorrido hoje, porque a origem de uma
    /// operação detectada por <c>FileSystemWatcher</c> não é determinável.
    /// </param>
    public void Publish(AgentNotification notification, uint? targetSessionId = null)
    {
        ArgumentNullException.ThrowIfNull(notification);

        lock (_gate)
        {
            if (!TryRecord(notification, targetSessionId)) return;

            if (notification is StatusNotification status)
            {
                _currentStatus = status;
            }
            else
            {
                // Só evento entra na janela de reprodução. Estado não precisa:
                // quem conecta já recebe o estado corrente.
                _replay.Add(new Buffered(notification, targetSessionId, _clock.GetUtcNow()));
                PruneReplay();
            }

            foreach (var subscription in _subscriptions)
            {
                if (Targets(subscription, targetSessionId))
                {
                    // TryWrite devolve falso apenas se o canal estiver fechado;
                    // com DropOldest ele nunca recusa por lotação.
                    subscription.Channel.Writer.TryWrite(notification);
                }
            }
        }
    }

    /// <summary>Record the retained status again before the pipe sends it to a new client.</summary>
    public StatusNotification? GetRecordedStatus()
    {
        lock (_gate)
        {
            return _currentStatus is { } status && TryRecord(status, null) ? status : null;
        }
    }

    private bool TryRecord(AgentNotification notification, uint? targetSessionId)
    {
        try { _record.Append(notification, targetSessionId); return true; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Notification recording failed; {Kind} was not delivered", notification.GetType().Name);
            return false;
        }
    }

    /// <summary>
    /// Uma mensagem sem sessão de destino vai para todos; com sessão, só para
    /// quem está nela. Um assinante de sessão desconhecida recebe tudo — é o
    /// caso do aplicativo cuja sessão o sistema não soube informar, e deixá-lo
    /// sem notificação nenhuma seria pior do que mostrar demais.
    /// </summary>
    private static bool Targets(Subscription subscription, uint? targetSessionId) =>
        targetSessionId is null
        || subscription.SessionId is null
        || subscription.SessionId == targetSessionId;

    private void PruneReplay()
    {
        var cutoff = _clock.GetUtcNow() - ReplayWindow;

        _replay.RemoveAll(entry => entry.At <= cutoff);

        if (_replay.Count > MaxReplayEntries)
        {
            _replay.RemoveRange(0, _replay.Count - MaxReplayEntries);
        }
    }

    private void Remove(Subscription subscription)
    {
        lock (_gate)
        {
            _subscriptions.Remove(subscription);
        }

        subscription.Channel.Writer.TryComplete();
    }

    private sealed record Subscription(Channel<AgentNotification> Channel, uint? SessionId);

    private sealed record Buffered(AgentNotification Notification, uint? TargetSessionId, DateTimeOffset At);
}

/// <summary>
/// A assinatura de um aplicativo conectado: de onde ler e como se desligar.
/// </summary>
public sealed class NotificationSubscription : IDisposable
{
    private readonly Action _unsubscribe;
    private bool _disposed;

    internal NotificationSubscription(ChannelReader<AgentNotification> reader, Action unsubscribe)
    {
        Reader = reader;
        _unsubscribe = unsubscribe;
    }

    /// <summary>Fila de mensagens destinadas a este assinante.</summary>
    public ChannelReader<AgentNotification> Reader { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _unsubscribe();
    }
}
