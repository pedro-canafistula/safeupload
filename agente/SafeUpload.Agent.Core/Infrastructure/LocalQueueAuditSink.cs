using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
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
/// Todo evento nasce com dispatched igual a falso. O despachante marca
/// verdadeiro depois da confirmação do servidor, preservando a trilha local.
/// </summary>
public sealed class LocalQueueAuditSink : IAuditSink, IOverrideQueue
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
    private readonly Action<FileStream> _flushToDisk;
    private readonly IAuditWriteFailureObserver? _failureObserver;

    /// <summary>Usa o caminho padrão do agente.</summary>
    public LocalQueueAuditSink() : this(AgentPaths.QueueFile)
    {
    }

    /// <summary>Usa um caminho específico. Serve aos testes.</summary>
    public LocalQueueAuditSink(string queueFile)
        : this(queueFile, static stream => stream.Flush(flushToDisk: true))
    {
    }

    // The fault seam is internal and never selected by configuration or IPC.
    public LocalQueueAuditSink(string queueFile, IAuditWriteFailureObserver failureObserver)
        : this(queueFile, static stream => stream.Flush(flushToDisk: true),
            failureObserver ?? throw new ArgumentNullException(nameof(failureObserver)))
    {
    }

    internal LocalQueueAuditSink(string queueFile, Action<FileStream> flushToDisk,
        IAuditWriteFailureObserver? failureObserver = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(queueFile);
        ArgumentNullException.ThrowIfNull(flushToDisk);
        _queueFile = queueFile;
        _flushToDisk = flushToDisk;
        _failureObserver = failureObserver;
    }

    /// <summary>Caminho do arquivo de fila, para exibição na interface.</summary>
    public string QueueFilePath => _queueFile;

    /// <inheritdoc />
    public async Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        var line = JsonSerializer.Serialize(auditEvent, Options);
        await AppendRecordAsync(line, AuditWriteKind.Event, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task RecordOverrideAsync(
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
        return RecordOverrideAsync(new AuditOverride(Guid.Parse(eventId), justification,
            DateTimeOffset.UtcNow, Environment.UserName, Environment.MachineName), cancellationToken);
    }

    public async Task RecordOverrideAsync(AuditOverride auditOverride, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(auditOverride);
        if (auditOverride.EventId == Guid.Empty) throw new ArgumentException("Identificador de evento vazio.", nameof(auditOverride));
        ArgumentException.ThrowIfNullOrWhiteSpace(auditOverride.Justification);
        ArgumentException.ThrowIfNullOrWhiteSpace(auditOverride.UserName);
        ArgumentException.ThrowIfNullOrWhiteSpace(auditOverride.EndpointId);
        var record = new
        {
            type = "override",
            eventId = auditOverride.EventId,
            justification = auditOverride.Justification,
            occurredAtUtc = auditOverride.OccurredAtUtc,
            userName = auditOverride.UserName,
            endpointId = auditOverride.EndpointId,
        };

        var line = JsonSerializer.Serialize(record, Options);
        await AppendRecordAsync(line, AuditWriteKind.Override, cancellationToken).ConfigureAwait(false);
    }

    private async Task AppendRecordAsync(string line, AuditWriteKind kind, CancellationToken cancellationToken)
    {
        try
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var directory = Path.GetDirectoryName(_queueFile);
                if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
                await AppendLineAsync(line, cancellationToken).ConfigureAwait(false);
            }
            finally { _writeLock.Release(); }
        }
        catch (Exception error) when (!cancellationToken.IsCancellationRequested)
        {
            // Observe only after releasing the queue lock. A diagnostic failure
            // must never replace the original persistence error or retry a write.
            try { _failureObserver?.OnWriteFailure(kind, error); }
            catch (Exception) { }
            throw;
        }
    }

    // Uma queda pode deixar a última linha sem terminador. Se anexássemos o
    // próximo evento diretamente, ele se perderia junto com a linha truncada.
    private async Task AppendLineAsync(string line, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(_queueFile, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough);
        if (stream.Length > 0)
        {
            stream.Seek(-1, SeekOrigin.End);
            var last = stream.ReadByte();
            stream.Seek(0, SeekOrigin.End);
            if (last != '\n')
                await stream.WriteAsync(Utf8NoBom.GetBytes(Environment.NewLine), cancellationToken).ConfigureAwait(false);
        }
        await stream.WriteAsync(Utf8NoBom.GetBytes(line + Environment.NewLine), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        // FlushAsync alone does not request that intermediate OS buffers reach
        // disk. A failure here must reach the caller, never acknowledge storage.
        _flushToDisk(stream);
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
                using var json = JsonDocument.Parse(line);
                if (json.RootElement.ValueKind != JsonValueKind.Object ||
                    json.RootElement.TryGetProperty("type", out _) ||
                    !json.RootElement.TryGetProperty("eventId", out _))
                    return;
                if (JsonSerializer.Deserialize<AuditEvent>(line, Options) is { } entry && entry.EventId != Guid.Empty)
                    events.Add(entry);
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
    public Task MarkDispatchedAsync(
        IReadOnlyCollection<Guid> eventIds,
        CancellationToken cancellationToken)
        => RewriteDispatchedAsync(eventIds, [], cancellationToken);

    public Task MarkOverridesDispatchedAsync(IReadOnlyCollection<AuditOverride> records,
        CancellationToken cancellationToken)
        => RewriteDispatchedAsync([], records, cancellationToken);

    private async Task RewriteDispatchedAsync(IReadOnlyCollection<Guid> eventIds,
        IReadOnlyCollection<AuditOverride> overrides, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(eventIds);

        if (eventIds.Count == 0 && overrides.Count == 0)
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

            // Preserva os registros de justificativa e linhas desconhecidas: a
            // confirmação de um lote de eventos não pode descartar outros tipos.
            var builder = new StringBuilder();
            await using (var stream = new FileStream(_queueFile, FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var reader = new StreamReader(stream, Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true))
            {
                while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        builder.AppendLine(line);
                        continue;
                    }
                    try
                    {
                        using var json = JsonDocument.Parse(line);
                        if (json.RootElement.ValueKind != JsonValueKind.Object)
                        {
                            builder.AppendLine(line);
                            continue;
                        }
                        bool selected;
                        if (json.RootElement.TryGetProperty("type", out var type))
                        {
                            selected = type.ValueKind == JsonValueKind.String && type.GetString() == "override"
                                && JsonSerializer.Deserialize<AuditOverride>(line, Options) is { } record
                                && overrides.Contains(record);
                        }
                        else
                        {
                            selected = json.RootElement.TryGetProperty("eventId", out var id)
                                && id.ValueKind == JsonValueKind.String && id.TryGetGuid(out var guid)
                                && ids.Contains(guid);
                        }
                        if (!selected)
                        {
                            builder.AppendLine(line);
                            continue;
                        }
                        var updated = JsonNode.Parse(line)!.AsObject();
                        updated["dispatched"] = true;
                        builder.Append(updated.ToJsonString(Options)).Append(Environment.NewLine);
                    }
                    catch (JsonException)
                    {
                        // Não converter nem apagar um registro que não entendemos.
                        builder.AppendLine(line);
                    }
                }
            }

            var temporary = _queueFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                await using (var output = new FileStream(temporary, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await output.WriteAsync(Utf8NoBom.GetBytes(builder.ToString()), cancellationToken).ConfigureAwait(false);
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    _flushToDisk(output);
                }
                cancellationToken.ThrowIfCancellationRequested();
                File.Move(temporary, _queueFile, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<AuditOverride>> ReadPendingOverridesAsync(int maxEvents,
        CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var records = new List<AuditOverride>();
            if (!File.Exists(_queueFile)) return records;
            await using var stream = new FileStream(_queueFile, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8, true);
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                try
                {
                    using var json = JsonDocument.Parse(line);
                    var root = json.RootElement;
                    if (root.ValueKind != JsonValueKind.Object ||
                        !root.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.String ||
                        type.GetString() != "override" ||
                        (root.TryGetProperty("dispatched", out var sent) && sent.ValueKind == JsonValueKind.True))
                        continue;
                    var record = JsonSerializer.Deserialize<AuditOverride>(line, Options);
                    if (record is null || record.EventId == Guid.Empty ||
                        string.IsNullOrWhiteSpace(record.Justification) ||
                        string.IsNullOrWhiteSpace(record.UserName) || string.IsNullOrWhiteSpace(record.EndpointId) ||
                        record.OccurredAtUtc == default) continue;
                    records.Add(record);
                    if (maxEvents > 0 && records.Count >= maxEvents) break;
                }
                catch (JsonException) { /* Preserva linhas que não pode despachar. */ }
            }
            return records;
        }
        finally { _writeLock.Release(); }
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
            FileShare.ReadWrite | FileShare.Delete);

        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                using var json = JsonDocument.Parse(line);
                if (json.RootElement.ValueKind != JsonValueKind.Object ||
                    json.RootElement.TryGetProperty("type", out _) ||
                    !json.RootElement.TryGetProperty("eventId", out _))
                {
                    continue;
                }
                var parsed = JsonSerializer.Deserialize<AuditEvent>(line, Options);
                if (parsed is not null && parsed.EventId != Guid.Empty)
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
