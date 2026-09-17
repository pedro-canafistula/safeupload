using System.Collections.Concurrent;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Concessões esperando para chegar ao driver.
///
/// Existe por uma restrição do transporte, e não por gosto: a porta do
/// minifiltro aceita um cliente por vez, e quem a segura é a thread do laço
/// de mensagens do <c>MinifilterInterceptor</c>. O canal de justificativas
/// roda noutra thread e não pode falar com o driver; ele deposita aqui, e o
/// laço drena entre uma requisição e outra.
///
/// A fila é pequena e sem prazo próprio: a concessão já nasce com validade
/// curta do lado do driver, e uma que fique aqui por muito tempo é uma que
/// o laço parou de drenar — o que é um problema maior que a concessão.
/// </summary>
public sealed class OverrideGrantQueue
{
    /// <param name="ProcessId">Processo que levou a recusa.</param>
    /// <param name="NtPath">Destino em forma de dispositivo.</param>
    /// <param name="Duration">Prazo pedido; o driver limita.</param>
    public readonly record struct Grant(uint ProcessId, string NtPath, TimeSpan Duration);

    private readonly ConcurrentQueue<Grant> _queue = new();

    /// <summary>Deposita uma concessão.</summary>
    public void Enqueue(uint processId, string ntPath, TimeSpan duration)
    {
        ArgumentException.ThrowIfNullOrEmpty(ntPath);

        _queue.Enqueue(new Grant(processId, ntPath, duration));
    }

    /// <summary>Retira a próxima concessão, se houver.</summary>
    public bool TryDequeue(out Grant grant) => _queue.TryDequeue(out grant);
}
