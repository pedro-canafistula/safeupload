using System.Collections.Concurrent;

namespace SafeUpload.Agent.Service.Notifications;

/// <summary>
/// Bloqueios que ainda podem receber uma justificativa.
///
/// É o que separa "a interface submete uma justificativa" de "a interface
/// libera o que quiser". Uma entrada aqui só nasce quando o serviço bloqueia
/// de fato, e some quando é usada ou quando vence — então um cliente que
/// invente um identificador não encontra nada, e um que repita um antigo
/// encontra um bloqueio já consumido.
/// </summary>
public sealed class PendingOverrides
{
    /// <summary>
    /// Quanto tempo um bloqueio aceita justificativa.
    ///
    /// Curto de propósito. A justificativa é uma reação ao que acabou de
    /// acontecer na tela; meia hora depois já não é a mesma operação, e
    /// manter o bloqueio elegível esse tempo todo é manter uma porta aberta
    /// para quando o usuário sair da máquina.
    /// </summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(3);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>Um bloqueio elegível.</summary>
    /// <param name="ProcessId">Processo que levou a recusa.</param>
    /// <param name="NtPath">Destino, em forma de dispositivo, como o driver o conhece.</param>
    /// <param name="FileName">Nome do arquivo, para a auditoria.</param>
    /// <param name="SessionId">
    /// Sessão a que a notificação foi entregue, ou <c>null</c> quando foi
    /// difusão. Uma justificativa vinda de outra sessão não vale: quem não viu
    /// o bloqueio não tem o que justificar.
    /// </param>
    /// <param name="ExpiresAt">Quando deixa de aceitar justificativa.</param>
    public sealed record Entry(
        uint ProcessId,
        string NtPath,
        string FileName,
        uint? SessionId,
        DateTimeOffset ExpiresAt);

    /// <summary>Registra um bloqueio como elegível.</summary>
    public void Remember(string eventId, Entry entry)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventId);
        ArgumentNullException.ThrowIfNull(entry);

        Prune();

        _entries[eventId] = entry;
    }

    /// <summary>
    /// Retira o bloqueio da lista e devolve, se ele existir, ainda estiver no
    /// prazo e tiver sido entregue à sessão informada.
    ///
    /// Retirar é parte da validação, e não limpeza: uma justificativa vale
    /// para uma operação. Duas tentativas com o mesmo identificador só podem
    /// dar certo na primeira.
    /// </summary>
    public Entry? Consume(string eventId, uint? sessionId)
    {
        if (string.IsNullOrEmpty(eventId) || !_entries.TryRemove(eventId, out Entry? entry))
        {
            return null;
        }

        if (entry.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return null;
        }

        // Difusão (SessionId nulo) aceita de qualquer sessão, porque não se
        // soube a quem entregar. Entrega dirigida só aceita de quem recebeu.
        if (entry.SessionId is { } target && sessionId != target)
        {
            return null;
        }

        return entry;
    }

    private void Prune()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        foreach (KeyValuePair<string, Entry> pair in _entries)
        {
            if (pair.Value.ExpiresAt <= now)
            {
                _entries.TryRemove(pair.Key, out _);
            }
        }
    }
}
