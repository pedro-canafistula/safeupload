using System.IO;
using System.IO.Pipes;
using SafeUpload.Agent.Core.Contracts;

namespace SafeUpload.Agent.App.Notifications;

/// <summary>
/// A ponta do aplicativo no canal de notificação.
///
/// Conecta ao pipe do serviço, lê linha a linha e levanta um evento por
/// mensagem. Só lê: não existe método para enviar nada, e é assim que a regra
/// "o serviço decide, o aplicativo mostra" deixa de depender de disciplina e
/// passa a ser uma propriedade do código.
///
/// O aplicativo pode subir antes do serviço, o serviço pode ser reiniciado, e
/// o usuário pode fechar e reabrir a interface a qualquer momento. Por isso o
/// cliente vive num laço: tenta conectar, consome enquanto der, e volta a
/// tentar quando cair. Desconexão é o estado normal, não a exceção.
/// </summary>
public sealed class PipeClient : IAsyncDisposable
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan MinRetryDelay = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Teto da espera entre tentativas. O serviço pode estar parado por muito
    /// tempo; sem teto, o intervalo cresceria até o aplicativo levar minutos
    /// para perceber que ele voltou.
    /// </summary>
    private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(15);

    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    /// <summary>Uma mensagem chegou do serviço.</summary>
    public event EventHandler<AgentNotification>? NotificationReceived;

    /// <summary>
    /// A conexão com o serviço mudou de estado.
    ///
    /// O aplicativo precisa saber disto para não mentir: sem serviço, o cartão
    /// de status não pode continuar dizendo "Protegido".
    /// </summary>
    public event EventHandler<bool>? ConnectionChanged;

    /// <summary>Inicia o laço de conexão em segundo plano.</summary>
    public void Start() => _loop ??= Task.Run(RunAsync);

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);

        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Encerramento normal.
            }
        }

        _stopping.Dispose();
    }

    private async Task RunAsync()
    {
        var delay = MinRetryDelay;

        while (!_stopping.IsCancellationRequested)
        {
            try
            {
                await ConsumeAsync().ConfigureAwait(false);

                // Chegou até aqui: houve conexão de verdade, então a próxima
                // queda recomeça a espera do início em vez de herdar o recuo
                // acumulado de antes.
                delay = MinRetryDelay;
            }
            catch (OperationCanceledException) when (_stopping.IsCancellationRequested)
            {
                // O prazo de ConnectAsync também cancela e lança esta exceção.
                // Só o token vitalício do aplicativo encerra o laço; um prazo
                // vencido significa apenas que o serviço segue indisponível.
                break;
            }
            catch (Exception)
            {
                // Serviço parado, pipe ocupado, acesso negado. Nenhum desses
                // casos merece tratamento diferente: espera e tenta de novo.
            }

            ConnectionChanged?.Invoke(this, false);

            try
            {
                await Task.Delay(delay, _stopping.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            // Recuo exponencial com teto: reconectar imediatamente num laço
            // apertado gastaria CPU enquanto o serviço estiver fora do ar.
            delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, MaxRetryDelay.TotalMilliseconds));
        }
    }

    private async Task ConsumeAsync()
    {
        using var pipe = new NamedPipeClientStream(
            ".",
            NotificationProtocol.PipeName,
            PipeDirection.In,
            PipeOptions.Asynchronous);

        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(_stopping.Token);
        connectTimeout.CancelAfter(ConnectTimeout);

        await pipe.ConnectAsync(connectTimeout.Token).ConfigureAwait(false);

        ConnectionChanged?.Invoke(this, true);

        using var reader = new StreamReader(pipe, NotificationProtocol.Encoding);

        while (!_stopping.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(_stopping.Token).ConfigureAwait(false);

            if (line is null)
            {
                // Fim do fluxo: o serviço encerrou ou derrubou a conexão.
                break;
            }

            // Linha malformada devolve nulo e é descartada. Perder uma
            // mensagem é aceitável; derrubar a conexão e ficar sem todas as
            // seguintes não é.
            if (NotificationProtocol.Deserialize(line) is { } notification)
            {
                NotificationReceived?.Invoke(this, notification);
            }
        }
    }
}
