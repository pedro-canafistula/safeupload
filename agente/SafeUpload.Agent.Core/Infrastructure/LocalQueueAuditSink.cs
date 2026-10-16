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

    /// <summary>
    /// UTF-8 <b>sem</b> BOM. Encoding.UTF8 escreve a marca EF BB BF ao criar o
    /// arquivo, e ela ficaria colada no início da primeira linha JSON. O leitor
    /// daqui a tolera, mas um consumidor estrito não: json.loads do Python
    /// recusa, jq recusa, e o despachante da HU-10 mandaria a primeira linha
    /// corrompida para o servidor. Num formato de uma linha por evento a marca
    /// não tem função nenhuma.
    /// </summary>
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

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

            await File.AppendAllTextAsync(_queueFile, line + Environment.NewLine, Utf8NoBom, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task RecordOverrideAsync(
        string eventId,
        string justification,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventId);
        ArgumentException.ThrowIfNullOrWhiteSpace(justification);

        // Linha própria na mesma fila, com um tipo que a distingue. Vai no
        // mesmo arquivo de propósito: a ordem entre o bloqueio e a
        // justificativa é a informação que uma investigação procura, e
        // separar em dois arquivos obrigaria a reconstruí-la por horário.
        var record = new
        {
            type = "override",
            eventId,
            justification,
            occurredAtUtc = DateTimeOffset.UtcNow,
            userName = Environment.UserName,
            endpointId = Environment.MachineName,
        };

        var line = JsonSerializer.Serialize(record, Options);

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_queueFile);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.AppendAllTextAsync(_queueFile, line + Environment.NewLine, Utf8NoBom, cancellationToken)
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
        if (maxEvents <= 0)
        {
            var all = await ReadAllAsync(cancellationToken).ConfigureAwait(false);
            all.Reverse();
            return all;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await ReadRecentUnsynchronizedAsync(maxEvents, cancellationToken).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    // Public-file observation can enter legacy inspection after staged publication.
    // Announce asks for five recent events there, under the same lock used by the
    // publisher's outcome append. Do not parse the entire retained audit history
    // on that path. Keep history untouched and read complete UTF-8 lines backwards
    // from this handle's captured end, with bounded block storage. A long record
    // still costs its own size; invalid/empty lines retain the existing skip rule.
    private async Task<List<AuditEvent>> ReadRecentUnsynchronizedAsync(int maxEvents, CancellationToken token)
    {
        var events = new List<AuditEvent>();
        if (!File.Exists(_queueFile)) return events;
        await using var stream = new FileStream(_queueFile, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 4096, FileOptions.Asynchronous | FileOptions.RandomAccess);
        long end = stream.Length;
        byte[] block = new byte[8192];
        int prefix = (int)Math.Min(4, end);
        await stream.ReadExactlyAsync(block.AsMemory(0, prefix), token).ConfigureAwait(false);
        // StreamReader historically accepted UTF-16/32 BOMs as well. These are
        // not the queue writer's format; preserve that compatibility explicitly.
        if (prefix >= 2 && (block[0] == 0xff && block[1] == 0xfe || block[0] == 0xfe && block[1] == 0xff) ||
            prefix == 4 && block[0] == 0 && block[1] == 0 && block[2] == 0xfe && block[3] == 0xff)
        {
            var all = await ReadAllUnsynchronizedAsync(token).ConfigureAwait(false);
            all.Reverse();
            return all.Count > maxEvents ? all.GetRange(0, maxEvents) : all;
        }
        long lineEnd = end;
        while (end > 0 && events.Count < maxEvents)
        {
            token.ThrowIfCancellationRequested();
            long start = Math.Max(0, end - block.Length);
            int count = checked((int)(end - start));
            stream.Position = start;
            await stream.ReadExactlyAsync(block.AsMemory(0, count), token).ConfigureAwait(false);
            for (int i = count - 1; i >= 0 && events.Count < maxEvents; i--)
            {
                if (block[i] is not (10 or 13)) continue;
                await ReadLineAsync(start + i + 1, lineEnd).ConfigureAwait(false);
                lineEnd = start + i;
            }
            end = start;
        }
        if (events.Count < maxEvents) await ReadLineAsync(0, lineEnd).ConfigureAwait(false);
        return events;

        async Task ReadLineAsync(long start, long stop)
        {
            token.ThrowIfCancellationRequested();
            if (stop <= start) return;
            byte[] bytes = new byte[checked((int)(stop - start))];
            stream.Position = start;
            await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
            string line = Encoding.UTF8.GetString(bytes);
            if (start == 0 && line.StartsWith('\uFEFF')) line = line[1..];
            if (string.IsNullOrWhiteSpace(line)) return;
            try
            {
                if (JsonSerializer.Deserialize<AuditEvent>(line, Options) is { } entry) events.Add(entry);
            }
            catch (JsonException) { } // Same truncated/malformed-line rule as the full reader.
        }
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
            await File.WriteAllTextAsync(temporary, builder.ToString(), Utf8NoBom, cancellationToken)
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

        // FileShare.ReadWrite, e nao a partilha padrao de File.ReadAllLines.
        // Desde a separacao em dois processos, quem escreve nesta fila e o
        // servico e quem le e o aplicativo de bandeja, ao mesmo tempo. Sem
        // permitir escrita concorrente, um dos dois lados falha: ou a leitura
        // do painel, ou — pior — a gravacao do evento de auditoria.
        await using var stream = new FileStream(
            _queueFile,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite);

        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
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
