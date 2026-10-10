namespace SafeUpload.Agent.Network.Bypass;

/// <summary>
/// Detecção automática de pinning (Fase 4 do plano).
///
/// Um programa com pinning só aceita o certificado que ele já conhece do
/// servidor. Diante do certificado emitido pela CA local ele aborta o
/// handshake, e interceptado nunca vai funcionar. Não há lista que preveja
/// todos, então o proxy aprende: quando o mesmo programa recusa o certificado
/// do mesmo host <see cref="Threshold"/> vezes seguidas, as próximas conexões
/// desse par seguem por túnel.
///
/// A recusa aparece de dois jeitos, e o proxy conta os dois:
///
/// - o programa valida o certificado <b>durante</b> o handshake e o aborta
///   (navegadores, SChannel);
/// - o programa conclui o handshake, valida <b>depois</b> e fecha a conexão sem
///   mandar nada (OkHttp, .NET). Para o proxy é um handshake que deu certo
///   seguido de um fechamento imediato, antes de qualquer requisição. O
///   "imediato" (<see cref="AbandonWindow"/>) separa isso da conexão que o
///   navegador abre por antecipação e larga sem usar, que fica aberta por
///   vários segundos.
///
/// Três cuidados:
///
/// - A chave é <b>programa + host</b>, não só o host. Se fosse só o host,
///   qualquer programa que recusasse o certificado de propósito tiraria aquele
///   site da inspeção para a máquina inteira, navegador incluído.
/// - Uma requisição que chega zera a contagem. Aba fechada no meio da conexão
///   também derruba um handshake; só a recusa repetida, sem nenhum uso no
///   meio, indica pinning.
/// - O que foi aprendido expira (<see cref="Lifetime"/>). Depois disso o par
///   volta a ser interceptado e, se o pinning for real, é aprendido de novo.
///
/// O estado fica só em memória: reiniciar o serviço esquece tudo.
/// </summary>
public sealed class PinningDetector
{
    private const int MaxEntries = 4096;

    private readonly Dictionary<string, Rejections> _rejections = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _learned = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();
    private readonly TimeProvider _clock;

    /// <summary>Cria o detector com o relógio do sistema.</summary>
    public PinningDetector() : this(TimeProvider.System)
    {
    }

    /// <summary>Cria o detector com um relógio explícito. Serve aos testes.</summary>
    public PinningDetector(TimeProvider clock) =>
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    /// <summary>Recusas seguidas que fazem o par ir para o túnel.</summary>
    public int Threshold { get; init; } = 2;

    /// <summary>Intervalo em que as recusas precisam acontecer para contar juntas.</summary>
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Até quanto tempo depois do handshake um fechamento sem nenhuma
    /// requisição conta como recusa do certificado.
    /// </summary>
    public TimeSpan AbandonWindow { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Por quanto tempo o par aprendido segue por túnel.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromHours(24);

    /// <summary>Se as conexões deste programa a este host devem seguir por túnel.</summary>
    public bool IsPinned(string? application, string host)
    {
        if (string.IsNullOrEmpty(application))
        {
            return false;
        }

        string key = Key(application, host);

        lock (_gate)
        {
            if (!_learned.TryGetValue(key, out DateTimeOffset expiresAt))
            {
                return false;
            }

            if (expiresAt > _clock.GetUtcNow())
            {
                return true;
            }

            _learned.Remove(key);
            return false;
        }
    }

    /// <summary>
    /// Registra que o programa recusou o certificado emitido pela CA local
    /// (handshake abortado, ou conexão largada logo depois dele). Devolve verdadeiro quando esta recusa completou o
    /// limite e o par acabou de ser aprendido.
    /// </summary>
    public bool RecordRejection(string? application, string host)
    {
        // Sem saber o programa não há a quem atribuir a recusa, e aprender
        // "para qualquer programa" é o atalho que a chave composta evita.
        if (string.IsNullOrEmpty(application))
        {
            return false;
        }

        string key = Key(application, host);
        DateTimeOffset now = _clock.GetUtcNow();

        lock (_gate)
        {
            int count = _rejections.TryGetValue(key, out Rejections previous) && now - previous.First <= Window
                ? previous.Count + 1
                : 1;

            if (count < Threshold)
            {
                if (_rejections.Count >= MaxEntries)
                {
                    _rejections.Clear();
                }

                _rejections[key] = new Rejections(count, count == 1 ? now : previous.First);
                return false;
            }

            _rejections.Remove(key);

            if (_learned.Count >= MaxEntries)
            {
                _learned.Clear();
            }

            _learned[key] = now + Lifetime;
            return true;
        }
    }

    /// <summary>Registra uma conexão usada: o programa aceita o certificado.</summary>
    public void RecordSuccess(string? application, string host)
    {
        if (string.IsNullOrEmpty(application))
        {
            return;
        }

        lock (_gate)
        {
            _rejections.Remove(Key(application, host));
        }
    }

    private static string Key(string application, string host) => $"{application}|{host.TrimEnd('.')}";

    private readonly record struct Rejections(int Count, DateTimeOffset First);
}
