using System.Collections.Concurrent;

namespace SafeUpload.Agent.Service.Clipboard;

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
public sealed record ClipboardCopy(string CopyId, bool Dirty, string? SourceProcess);

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

    private readonly ConcurrentDictionary<uint, ClipboardCopy> _latest = new();

    /// <summary>Registra a cópia nova da sessão e devolve o que ficou guardado.</summary>
    public ClipboardCopy Register(uint? sessionId, bool dirty, string? sourceProcess)
    {
        var copy = new ClipboardCopy(Guid.NewGuid().ToString("N"), dirty, sourceProcess);
        _latest[sessionId ?? UnknownSession] = copy;
        return copy;
    }

    /// <summary>
    /// A cópia em vigor da sessão, se o identificador ainda for o dela.
    /// </summary>
    public ClipboardCopy? TryGet(uint? sessionId, string copyId) =>
        _latest.TryGetValue(sessionId ?? UnknownSession, out var copy) &&
        string.Equals(copy.CopyId, copyId, StringComparison.Ordinal)
            ? copy
            : null;
}
