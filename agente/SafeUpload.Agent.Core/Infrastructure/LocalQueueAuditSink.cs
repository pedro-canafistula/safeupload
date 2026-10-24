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
/// permitindo continuar após uma linha inválida. Uma escrita interrompida
/// pode deixar a última linha truncada; ela permanece no arquivo e pode ser
/// diagnosticada por InspectIntegrityAsync. Um array JSON
/// único exigiria reescrever o arquivo inteiro a cada evento e poderia perder
/// a trilha toda.
///
/// Todo evento nasce com dispatched igual a falso. O despachante marca
/// verdadeiro depois da confirmação do servidor, preservando a trilha local.
/// </summary>
public sealed partial class LocalQueueAuditSink : IAuditSink, IOverrideQueue
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

            await AppendLineAsync(line, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
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

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_queueFile);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await AppendLineAsync(line, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // Uma queda pode deixar a última linha sem terminador. Se anexássemos o
    // próximo evento diretamente, ele se perderia junto com a linha truncada.
    private async Task AppendLineAsync(string line, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(_queueFile, FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.Asynchronous);
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
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(
        int maxEvents,
        CancellationToken cancellationToken)
    {
        var all = await ReadEventsAsync(maxEvents, pendingOnly: false, cancellationToken).ConfigureAwait(false);

        // Do mais recente para o mais antigo, que é a ordem em que a grade do
        // simulador mostra a fila.
        all.Reverse();
        return all;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(
        int maxEvents,
        CancellationToken cancellationToken)
    {
        return await ReadEventsAsync(maxEvents, pendingOnly: true, cancellationToken).ConfigureAwait(false);
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
        if (eventIds.Count == 0 && overrides.Count == 0) return;

        var ids = eventIds.ToHashSet();
        var selectedOverrides = overrides.ToHashSet();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_queueFile)) return;
            var temporary = _queueFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var created = false;
            try
            {
                // A cópia é produzida linha a linha: memória proporcional ao lote
                // e à maior linha, sem reter o texto completo da fila. A leitura e
                // a escrita ainda percorrem o arquivo inteiro; não é compactação.
                await using (var output = new FileStream(temporary, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
                {
                    created = true;
                    await using var writer = new StreamWriter(output, Utf8NoBom, bufferSize: 65536);
                    await using var stream = new FileStream(_queueFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var reader = new StreamReader(stream, Encoding.UTF8,
                        detectEncodingFromByteOrderMarks: true);
                    while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
                    {
                        var updated = MarkSelectedLine(line, ids, selectedOverrides);
                        await writer.WriteLineAsync(updated.AsMemory(), cancellationToken).ConfigureAwait(false);
                    }
                    await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                // Não publicar antes de fechar todos os streams nem após cancelar.
                cancellationToken.ThrowIfCancellationRequested();
                File.Move(temporary, _queueFile, overwrite: true);
            }
            finally
            {
                if (created && File.Exists(temporary)) File.Delete(temporary);
            }
        }
        finally { _writeLock.Release(); }
    }

    private static string MarkSelectedLine(string line, HashSet<Guid> ids,
        HashSet<AuditOverride> overrides)
    {
        if (string.IsNullOrWhiteSpace(line)) return line;
        try
        {
            using var json = JsonDocument.Parse(line);
            if (json.RootElement.ValueKind != JsonValueKind.Object) return line;
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
            if (!selected) return line;
            var updated = JsonNode.Parse(line)!.AsObject();
            updated["dispatched"] = true;
            return updated.ToJsonString(Options);
        }
        catch (JsonException)
        {
            // Não converter nem apagar um registro que não entendemos.
            return line;
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

    private async Task<List<AuditEvent>> ReadEventsAsync(
        int maxEvents, bool pendingOnly, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadEventsUnsynchronizedAsync(maxEvents, pendingOnly, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task<List<AuditEvent>> ReadEventsUnsynchronizedAsync(
        int maxEvents, bool pendingOnly, CancellationToken cancellationToken)
    {
        var events = new List<AuditEvent>();
        // Histórico limitado retém somente os últimos N registros na ordem do
        // arquivo. Não ordenar por horário nem deduplicar: isso muda o contrato.
        // Limites não positivos preservam a consulta completa legada.
        Queue<AuditEvent>? recent = !pendingOnly && maxEvents > 0 ? new() : null;

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
                if (parsed is not null && parsed.EventId != Guid.Empty &&
                    (!pendingOnly || !parsed.Dispatched))
                {
                    if (recent is not null)
                    {
                        if (recent.Count == maxEvents) recent.Dequeue();
                        recent.Enqueue(parsed);
                    }
                    else
                    {
                        events.Add(parsed);
                        // O lote pendente é um prefixo dos eventos elegíveis.
                        // Não é necessário ler o restante para enviá-lo.
                        if (pendingOnly && maxEvents > 0 && events.Count >= maxEvents) break;
                    }
                }
            }
            catch (JsonException)
            {
                // A projeção continua sem este registro, mas os bytes permanecem
                // no arquivo. InspectIntegrityAsync permite localizar a linha
                // incompatível sem expor seu conteúdo ou tentar repará-la.
            }
        }

        return recent is null ? events : recent.ToList();
    }
}
