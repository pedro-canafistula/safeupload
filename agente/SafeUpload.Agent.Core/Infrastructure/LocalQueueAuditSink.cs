using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Core.Infrastructure;

/// <summary>
/// Fila de auditoria em disco: uma linha JSON por evento em
/// %ProgramData%\SafeUpload\queue.jsonl.
///
/// O formato JSON Lines foi escolhido por ser append-only. Registrar um evento
/// é acrescentar uma linha, sem reescrever nem reserializar o que já está lá,
/// o que significa que uma queda de energia no meio da gravação corrompe no
/// máximo a última linha, e a leitura simplesmente a descarta. Um array JSON
/// único exigiria reescrever o arquivo inteiro a cada evento e poderia perder
/// a trilha toda.
///
/// Todo evento nasce com dispatched igual a falso. Quem virá a marcar
/// verdadeiro é o despachante da HU-10, que ainda não existe.
/// </summary>
public sealed class LocalQueueAuditSink : IAuditSink
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter() }
    };

    // Serializa as gravações dentro do processo. Não substitui um lock entre
    // processos, mas o agente é instância única por sessão.
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly string _queueFile;

    /// <summary>Usa o caminho padrão do agente.</summary>
    public LocalQueueAuditSink() : this(AgentPaths.QueueFile)
    {
    }

    /// <summary>Usa um caminho específico. Serve aos testes.</summary>
    public LocalQueueAuditSink(string queueFile)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(queueFile);
        _queueFile = queueFile;
    }

    /// <summary>Caminho do arquivo de fila, para exibição na interface.</summary>
    public string QueueFilePath => _queueFile;

    /// <inheritdoc />
    public async Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        var line = JsonSerializer.Serialize(auditEvent, Options);

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_queueFile);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.AppendAllTextAsync(_queueFile, line + Environment.NewLine, Encoding.UTF8, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(
        int maxEvents,
        CancellationToken cancellationToken)
    {
        var all = await ReadAllAsync(cancellationToken).ConfigureAwait(false);

        // Do mais recente para o mais antigo, que é a ordem em que a grade do
        // simulador mostra a fila.
        all.Reverse();
        return maxEvents > 0 && all.Count > maxEvents ? all.GetRange(0, maxEvents) : all;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(
        int maxEvents,
        CancellationToken cancellationToken)
    {
        var all = await ReadAllAsync(cancellationToken).ConfigureAwait(false);
        var pending = all.FindAll(static e => !e.Dispatched);

        return maxEvents > 0 && pending.Count > maxEvents ? pending.GetRange(0, maxEvents) : pending;
    }

    /// <summary>
    /// Reescreve a fila marcando como entregues os eventos informados.
    ///
    /// Esta é a única operação que não é append-only, e por isso grava num
    /// arquivo temporário na mesma pasta e o move por cima do original: se
    /// falhar no meio, a fila antiga continua íntegra. Ela só será chamada
    /// pelo despachante da HU-10.
    /// </summary>
    public async Task MarkDispatchedAsync(
        IReadOnlyCollection<Guid> eventIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(eventIds);

        if (eventIds.Count == 0)
        {
            return;
        }

        var ids = eventIds.ToHashSet();

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_queueFile))
            {
                return;
            }

            var events = await ReadAllUnsynchronizedAsync(cancellationToken).ConfigureAwait(false);
            var builder = new StringBuilder();

            foreach (var current in events)
            {
                var updated = ids.Contains(current.EventId)
                    ? current with { Dispatched = true }
                    : current;

                builder.Append(JsonSerializer.Serialize(updated, Options)).Append(Environment.NewLine);
            }

            var temporary = _queueFile + ".tmp";
            await File.WriteAllTextAsync(temporary, builder.ToString(), Encoding.UTF8, cancellationToken)
                .ConfigureAwait(false);
            File.Move(temporary, _queueFile, overwrite: true);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task<List<AuditEvent>> ReadAllAsync(CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadAllUnsynchronizedAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task<List<AuditEvent>> ReadAllUnsynchronizedAsync(CancellationToken cancellationToken)
    {
        var events = new List<AuditEvent>();

        if (!File.Exists(_queueFile))
        {
            return events;
        }

        var lines = await File.ReadAllLinesAsync(_queueFile, Encoding.UTF8, cancellationToken)
            .ConfigureAwait(false);

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                var parsed = JsonSerializer.Deserialize<AuditEvent>(line, Options);
                if (parsed is not null)
                {
                    events.Add(parsed);
                }
            }
            catch (JsonException)
            {
                // Linha truncada por queda no meio da gravação. É a razão de ser
                // do formato: descartamos a linha e mantemos toda a trilha
                // anterior, em vez de perder o arquivo inteiro.
            }
        }

        return events;
    }
}
