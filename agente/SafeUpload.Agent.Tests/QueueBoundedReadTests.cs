using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class QueueBoundedReadTests
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(7, false)]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(int.MaxValue, false)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    [InlineData(7, true)]
    [InlineData(0, true)]
    [InlineData(-1, true)]
    [InlineData(int.MaxValue, true)]
    public async Task Limites_preservam_ordem_metadados_duplicatas_e_bytes_em_fila_mista(int limit, bool bom)
    {
        using var workspace = new TestWorkspace();
        var first = Event(0);
        AuditEvent[] expected = [first, Event(1) with { Dispatched = true }, Event(2),
            first, Event(3) with { Dispatched = true }, Event(4)];
        var lines = new List<string> { "", "  ", "[]", "null", "{}" };
        foreach (var item in expected)
        {
            lines.Add(JsonSerializer.Serialize(item, Options));
            lines.Add("{\"type\":\"future\",\"eventId\":\"" + item.EventId + "\"}");
            lines.Add("{\"type\":\"override\",\"eventId\":\"" + item.EventId +
                "\",\"justification\":\"sintética\",\"userName\":\"teste\",\"endpointId\":\"PC\",\"occurredAtUtc\":\"2026-10-23T12:00:00Z\"}");
            lines.Add("{\"eventId\":\"bad-guid\"}");
        }
        lines.Add("{\"eventId\":\"00000000-0000-0000-0000-000000000000\"}");
        lines.Add("{linha-final-truncada");
        // Mixed terminators, BOM compatibility and an unterminated final line.
        var text = string.Join(bom ? "\r\n" : "\n", lines);
        await File.WriteAllTextAsync(workspace.QueueFile, text, new UTF8Encoding(bom));
        var before = SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);

        var recent = await sink.ReadRecentAsync(limit, CancellationToken.None);
        var pending = await sink.ReadPendingAsync(limit, CancellationToken.None);
        var cap = limit > 0 ? limit : int.MaxValue;
        Assert.Equal(expected.Reverse().Take(cap).Select(Serialize), recent.Select(Serialize));
        Assert.Equal(expected.Where(e => !e.Dispatched).Take(cap).Select(Serialize), pending.Select(Serialize));
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile)));
        // A new sink sees exactly the same projection; no cursor/checkpoint was persisted.
        Assert.Equal(recent.Select(Serialize),
            (await new LocalQueueAuditSink(workspace.QueueFile).ReadRecentAsync(limit, CancellationToken.None)).Select(Serialize));
    }

    [Fact]
    public async Task Historico_limitado_mantem_ultimos_registros_apos_varias_voltas_sem_ordenar_por_horario()
    {
        using var workspace = new TestWorkspace();
        var expected = Enumerable.Range(0, 1027).Select(Event).ToArray();
        await File.WriteAllLinesAsync(workspace.QueueFile, expected.Select(Serialize));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(expected.Reverse().Take(500).Select(Serialize),
            (await sink.ReadRecentAsync(500, CancellationToken.None)).Select(Serialize));
        Assert.Equal(expected.Take(100).Select(Serialize),
            (await sink.ReadPendingAsync(100, CancellationToken.None)).Select(Serialize));
    }

    [Fact]
    public async Task Leitura_limitada_nao_cria_arquivo_ausente_e_aceita_fila_sem_eventos()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Empty(await sink.ReadRecentAsync(500, CancellationToken.None));
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.False(File.Exists(workspace.QueueFile));
        await sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "Sintética", CancellationToken.None);
        Assert.Empty(await sink.ReadRecentAsync(500, CancellationToken.None));
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
    }

    [Fact]
    public async Task Cancelamento_e_arquivo_ocupado_liberam_lock_para_proxima_gravacao()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.WriteAsync(Event(0), CancellationToken.None);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.ReadRecentAsync(500, canceled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.ReadPendingAsync(100, canceled.Token));
        using (var locked = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            await Assert.ThrowsAsync<IOException>(() => sink.ReadRecentAsync(500, CancellationToken.None));
            await Assert.ThrowsAsync<IOException>(() => sink.ReadPendingAsync(100, CancellationToken.None));
        }
        await sink.WriteAsync(Event(1), CancellationToken.None);
        Assert.Equal(2, (await sink.ReadRecentAsync(500, CancellationToken.None)).Count);
    }

    private static string Serialize(AuditEvent item) => JsonSerializer.Serialize(item, Options);

    private static AuditEvent Event(int index) => new(Guid.NewGuid(),
        // Deliberately decreasing timestamps: order is the append order, not the clock.
        new DateTimeOffset(2026, 10, 23, 12, 0, 0, TimeSpan.Zero).AddSeconds(-index),
        "PC-SINTETICO", "usuario-sintetico", $"relatório-{index}.txt", ".txt", 42,
        Verdict.Blocked, [Category.Cpf], ["•••••••••25"], "processo-sintetico", 123,
        @"C:\DestinoSintetico", null, 1, 10, false, "HASH-SINTETICO", AuditChannel.File);
}
