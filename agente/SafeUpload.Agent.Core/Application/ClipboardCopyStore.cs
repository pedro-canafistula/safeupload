using System.Collections.Concurrent;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// A cópia em vigor: o que o serviço precisa lembrar para decidir uma colagem.
///
/// <b>Não há texto aqui, e não é descuido.</b> O clipboard sujo carrega um dado
/// sensível; guardar uma segunda cópia dele no serviço, que roda como
/// LocalSystem, só criaria mais um lugar de onde ele pudesse vazar (RN-006).
/// </summary>
/// <param name="CopyId">Identificador devolvido ao aplicativo na classificação.</param>
/// <param name="Dirty">O clipboard ficou sujo.</param>
/// <param name="SourceProcess">Quem copiou, se conhecido.</param>
public sealed record ClipboardCopy(string CopyId, bool Dirty, string? SourceProcess,
    IReadOnlyList<Category>? Categories = null, long SizeBytes = 0, int PolicyVersion = 1);

/// <summary>
/// Guarda a última cópia de cada sessão do Windows.
///
/// <para>Uma por sessão, porque o clipboard é por sessão: a cópia de um usuário
/// não pode responder à pergunta de colagem de outro. Isso também limita a
/// memória ao número de sessões, sem fila nem limpeza a lembrar.</para>
///
/// <para>Uma cópia nova substitui a anterior. É o que faz "copiar texto limpo
/// volta a limpo": o identificador antigo deixa de valer, e uma colagem que o
/// traga é tratada como cópia desconhecida, ou seja, liberada (RN-013).</para>
/// </summary>
public sealed class ClipboardCopyStore
{
    /// <summary>Sessão desconhecida: todas caem no mesmo balde, que é o mais conservador de errar.</summary>
    private const uint UnknownSession = uint.MaxValue;

    private readonly ConcurrentDictionary<uint, Slot> _latest = new();

    private sealed class Slot
    {
        internal long Revision;
        internal ClipboardCopy? Copy;
    }

    // Reserve before awaiting policy. Completion order must not make an older
    // classification replace the newest request from this same Windows session.
    internal long BeginClassification(uint? sessionId)
    {
        var slot = _latest.GetOrAdd(sessionId ?? UnknownSession, _ => new Slot());
        lock (slot) return ++slot.Revision;
    }

    /// <summary>Registra uma classificação imediata da sessão.</summary>
    public ClipboardCopy Register(uint? sessionId, bool dirty, string? sourceProcess,
        IReadOnlyList<Category>? categories = null, long sizeBytes = 0, int policyVersion = 1)
        => CompleteClassification(sessionId, BeginClassification(sessionId), dirty, sourceProcess,
            categories, sizeBytes, policyVersion);

    internal ClipboardCopy CompleteClassification(uint? sessionId, long revision, bool dirty, string? sourceProcess,
        IReadOnlyList<Category>? categories, long sizeBytes, int policyVersion)
    {
        var copy = new ClipboardCopy(Guid.NewGuid().ToString("N"), dirty, sourceProcess,
            categories?.ToArray(), sizeBytes, policyVersion);
        var slot = _latest[sessionId ?? UnknownSession];
        lock (slot)
        {
            if (slot.Revision == revision) slot.Copy = copy;
        }
        return copy;
    }

    /// <summary>
    /// A cópia em vigor da sessão, se o identificador ainda for o dela.
    /// </summary>
    public ClipboardCopy? TryGet(uint? sessionId, string copyId)
    {
        if (!_latest.TryGetValue(sessionId ?? UnknownSession, out var slot)) return null;
        lock (slot)
            return slot.Copy is { } copy && string.Equals(copy.CopyId, copyId, StringComparison.Ordinal) ? copy : null;
    }
}
