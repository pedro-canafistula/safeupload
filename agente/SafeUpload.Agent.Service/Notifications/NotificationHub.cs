using System.Threading.Channels;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// O ponto de encontro entre quem decide e quem mostra.
///
/// O interceptador publica aqui e segue em frente; quem entrega as mensagens
/// aos aplicativos conectados é outro serviço. A separação existe por uma razão
/// só: <b>publicar não pode bloquear</b>. O veredito já foi dado e o arquivo já
/// foi movido quando a notificação sai — se a entrega ficasse no caminho da
/// decisão, um aplicativo lento, minimizado ou morto seguraria a inspeção do
/// próximo arquivo.
///
/// Cada assinante tem sua própria fila limitada. Fila cheia significa
/// aplicativo que parou de ler: a mensagem mais antiga é descartada em vez de
/// esperar. Perder notificação de tela é aceitável — a trilha de auditoria em
/// disco é a fonte da verdade, e ela não passa por aqui.
/// </summary>
public sealed class NotificationHub
{
    /// <summary>
    /// Quantas mensagens cabem na fila de um assinante antes de as antigas
    /// começarem a cair. Uma cópia de pasta grande produz dezenas de eventos em
    /// segundos; o limite absorve a rajada sem virar memória sem fim.
    /// </summary>
    private const int SubscriberQueueCapacity = 256;

    private readonly List<Subscription> _subscriptions = [];
    private readonly Lock _gate = new();

    private StatusNotification? _currentStatus;

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
    /// <returns>
    /// Um descarte que remove a assinatura. Quem conecta é responsável por
    /// chamá-lo ao perder a conexão, senão o hub acumula filas de aplicativos
    /// que já morreram.
    /// </returns>
    public NotificationSubscription Subscribe()
    {
        // DropOldest e não Wait: escrever nunca pode bloquear quem publica.
        var channel = Channel.CreateBounded<AgentNotification>(
            new BoundedChannelOptions(SubscriberQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });

        var subscription = new Subscription(channel);

        lock (_gate)
        {
            _subscriptions.Add(subscription);
        }

        return new NotificationSubscription(channel.Reader, () => Remove(subscription));
    }

    /// <summary>
    /// Publica uma mensagem para todos os assinantes. Não bloqueia e não lança.
    /// </summary>
    public void Publish(AgentNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);

        if (notification is StatusNotification status)
        {
            lock (_gate)
            {
                _currentStatus = status;
            }
        }

        lock (_gate)
        {
            foreach (var subscription in _subscriptions)
            {
                // TryWrite devolve falso apenas se o canal estiver fechado; com
                // DropOldest ele nunca recusa por lotação.
                subscription.Channel.Writer.TryWrite(notification);
            }
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

    private sealed record Subscription(Channel<AgentNotification> Channel);
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
