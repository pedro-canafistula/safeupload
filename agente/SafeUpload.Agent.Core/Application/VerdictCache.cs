using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Application;

/// <summary>
/// Guarda por pouco tempo o veredito de uma operação já julgada.
///
/// O ganho não é teórico: copiar uma pasta faz o mesmo arquivo ser oferecido ao
/// agente várias vezes em poucos segundos, e reextrair e revarrer a cada vez
/// gastaria segundos onde o cache responde em menos de um milissegundo. É o
/// que sustenta o requisito de desempenho de acerto de cache abaixo de 10 ms.
///
/// A chave é caminho + tamanho + data de modificação + processo. Tamanho e
/// data juntos são o que impede o erro perigoso: se o usuário editar o arquivo
/// para incluir um CPF e tentar de novo, a chave muda e o veredito antigo de
/// aprovado não é reaproveitado. O processo entra na chave porque a mesma
/// origem pode ter escopo diferente conforme quem a executa.
/// </summary>
public sealed class VerdictCache
{
    /// <summary>Validade padrão de uma entrada.</summary>
    public static readonly TimeSpan DefaultTimeToLive = TimeSpan.FromSeconds(60);

    private const int MaxEntries = 512;

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();
    private readonly TimeSpan _timeToLive;
    private readonly TimeProvider _clock;

    /// <summary>Cria o cache com validade e relógio padrão.</summary>
    public VerdictCache() : this(DefaultTimeToLive, TimeProvider.System)
    {
    }

    /// <summary>Cria o cache com validade e relógio explícitos. Serve aos testes.</summary>
    public VerdictCache(TimeSpan timeToLive, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);

        if (timeToLive <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeToLive), "A validade precisa ser positiva.");
        }

        _timeToLive = timeToLive;
        _clock = clock;
    }

    /// <summary>
    /// Procura um veredito ainda válido para a operação.
    /// </summary>
    /// <param name="operation">Operação sendo julgada.</param>
    /// <param name="policyVersion">
    /// Versão da política em vigor agora. Entrada gravada sob outra versão é
    /// tratada como ausente: quando o administrador muda a política, o efeito
    /// tem de ser imediato, e não daqui a um minuto. Sem isto, ligar uma
    /// categoria nova deixaria arquivos recém-aprovados passarem enquanto o
    /// cache não expirasse.
    /// </param>
    /// <param name="result">Veredito encontrado, se houver.</param>
    public bool TryGet(FileOperation operation, int policyVersion, out InspectionResult? result)
    {
        ArgumentNullException.ThrowIfNull(operation);

        var key = BuildKey(operation);
        var now = _clock.GetUtcNow();

        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var entry))
            {
                if (entry.ExpiresAt > now && entry.Result.PolicyVersion == policyVersion)
                {
                    result = entry.Result;
                    return true;
                }

                _entries.Remove(key);
            }
        }

        result = null;
        return false;
    }

    /// <summary>Guarda o veredito da operação.</summary>
    public void Set(FileOperation operation, InspectionResult result)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(result);

        var key = BuildKey(operation);
        var now = _clock.GetUtcNow();

        lock (_gate)
        {
            if (_entries.Count >= MaxEntries)
            {
                PruneExpired(now);

                // Se ainda estiver cheio depois da limpeza, o cache é
                // esvaziado. Perder entradas custa uma reinspeção; manter um
                // cache que cresce sem limite num processo que fica dias aberto
                // custa memória para sempre.
                if (_entries.Count >= MaxEntries)
                {
                    _entries.Clear();
                }
            }

            _entries[key] = new Entry(result, now + _timeToLive);
        }
    }

    /// <summary>
    /// Esvazia o cache. Usado quando a política é recarregada e pelo simulador,
    /// que precisa forçar uma inspeção nova para demonstrar o caminho do
    /// timeout num arquivo já julgado.
    /// </summary>
    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
        }
    }

    private void PruneExpired(DateTimeOffset now)
    {
        var expired = new List<string>();

        foreach (var (key, entry) in _entries)
        {
            if (entry.ExpiresAt <= now)
            {
                expired.Add(key);
            }
        }

        foreach (var key in expired)
        {
            _entries.Remove(key);
        }
    }

    private static string BuildKey(FileOperation operation) => string.Join(
        '|',
        operation.FilePath,
        operation.SizeBytes.ToString(),
        operation.LastWriteUtc.UtcTicks.ToString(),
        operation.ProcessName);

    private readonly record struct Entry(InspectionResult Result, DateTimeOffset ExpiresAt);
}
