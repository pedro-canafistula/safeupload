using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueueRetentionPreviewTests
{
    private static readonly DateTimeOffset Cutoff = DateTimeOffset.Parse("2020-01-01T00:00:00Z");

    [Fact]
    public async Task Corte_exclusivo_conta_confirmados_por_ocorrencia_e_preserva_pendentes_duplicatas_e_incompativeis()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var old = Event(Cutoff.AddTicks(-1), true);
        await sink.WriteAsync(old, CancellationToken.None);
        await sink.WriteAsync(old, CancellationToken.None);
        await sink.WriteAsync(Event(Cutoff, true), CancellationToken.None);
        await sink.WriteAsync(Event(Cutoff.AddDays(1), true), CancellationToken.None);
        await sink.WriteAsync(Event(Cutoff.AddYears(-1), false), CancellationToken.None);
        await sink.WriteAsync(Event(default, true), CancellationToken.None);
        // An old confirmed event can still be referenced by an unconfirmed justification.
        var pending = new AuditOverride(old.EventId, "JUSTIFICATIVA_ç", Cutoff.AddDays(-2), "user", "host");
        var confirmed = pending with { EventId = Guid.NewGuid() };
        await sink.RecordOverrideAsync(pending, CancellationToken.None);
        await sink.RecordOverrideAsync(confirmed, CancellationToken.None);
        await sink.MarkOverridesDispatchedAsync(new[] { confirmed }, CancellationToken.None);
        await File.AppendAllTextAsync(workspace.QueueFile, "{INVALIDO\n{\"type\":\"future\",\"dispatched\":true}\n \n");
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var preview = await sink.PreviewRetentionAsync(Cutoff.ToOffset(TimeSpan.FromHours(3)), CancellationToken.None);
        Assert.Equal(Cutoff, preview.OccurredBeforeUtc); Assert.Equal(TimeSpan.Zero, preview.OccurredBeforeUtc.Offset);
        Assert.Equal(2, preview.ConfirmedEventsBeforeCutoff); Assert.Equal(1, preview.ConfirmedOverridesBeforeCutoff);
        Assert.Equal(1, preview.ConfirmedWithoutTimestamp);
        Assert.Equal(1, preview.Integrity.PendingEvents); Assert.Equal(1, preview.Integrity.PendingOverrides);
        Assert.Equal(6, preview.Integrity.ValidEvents); Assert.Equal(2, preview.Integrity.ValidOverrides);
        Assert.Equal(1, preview.Integrity.UnknownRecords); Assert.Equal(1, preview.Integrity.InvalidLines);
        Assert.True(preview.Integrity.RequiresAttention); Assert.True(preview.PreviewOnly); Assert.False(preview.DeletionSupported);
        Assert.Equal("record-occurrence-time", preview.TimestampBasis);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        var json = JsonSerializer.Serialize(preview);
        Assert.DoesNotContain("JUSTIFICATIVA", json); Assert.DoesNotContain(workspace.Root, json);
        Assert.DoesNotContain("ConfirmedEventsBeforeCutoff", JsonSerializer.Serialize(preview.Integrity));
    }

    [Fact]
    public async Task Fila_ausente_e_vazia_nao_e_criada_nem_aplicada_e_data_padrao_e_recusada()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => sink.PreviewRetentionAsync(default, CancellationToken.None));
        var missing = await sink.PreviewRetentionAsync(Cutoff, CancellationToken.None);
        Assert.False(missing.Integrity.FileExists); Assert.Equal(0, missing.ConfirmedEventsBeforeCutoff);
        Assert.False(File.Exists(workspace.QueueFile));
        await File.WriteAllTextAsync(workspace.QueueFile, "", new UTF8Encoding(true));
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        Assert.Equal(0, (await sink.PreviewRetentionAsync(Cutoff, CancellationToken.None)).Integrity.LinesScanned);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
    }

    [Fact]
    public async Task Cancelamento_e_arquivo_ocupado_nao_publicam_resultado_parcial_e_liberam_proxima_operacao()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.WriteAsync(Event(Cutoff.AddDays(-1), true), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.PreviewRetentionAsync(Cutoff, cancel.Token));
        using (var file = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None))
            await Assert.ThrowsAsync<IOException>(() => sink.PreviewRetentionAsync(Cutoff, CancellationToken.None));
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        await sink.WriteAsync(Event(Cutoff, false), CancellationToken.None);
        Assert.Equal(1, (await sink.PreviewRetentionAsync(Cutoff, CancellationToken.None)).ConfirmedEventsBeforeCutoff);
    }

    [Theory]
    [InlineData("")]
    [InlineData(",\"occurredBeforeUtc\":null")]
    [InlineData(",\"occurredBeforeUtc\":12")]
    [InlineData(",\"occurredBeforeUtc\":\"2020-01-01T00:00:00\"")]
    [InlineData(",\"occurredBeforeUtc\":\"2020-01-01T00:00:00-03:00\"")]
    [InlineData(",\"occurredBeforeUtc\":\"SENSIVEL\"")]
    [InlineData(",\"occurredBeforeUtc\":\"0001-01-01T00:00:00Z\"")]
    public async Task Pipe_exige_corte_UTC_explicito_sem_ecoar_valor_invalido(string field)
    {
        using var workspace = new TestWorkspace();
        var response = await Query(workspace.QueueFile, "{\"query\":\"audit-retention-preview\"" + field + "}");
        Assert.False(response.GetProperty("ok").GetBoolean());
        Assert.Contains("occurredBeforeUtc", response.GetProperty("error").GetString());
        Assert.DoesNotContain("SENSIVEL", response.GetRawText());
        Assert.False(File.Exists(workspace.QueueFile));
    }

    [Theory]
    [InlineData("2020-01-01T00:00:00Z", false)]
    [InlineData("2020-01-01T00:00:00.0000000+00:00", false)]
    [InlineData("2020-01-01T00:00:00.0000000Z", false)]
    [InlineData("2020-01-01T00:00:00Z", true)]
    public async Task Pipe_real_sem_driver_retorna_simulacao_somente_leitura_ou_erro_sanitizado(string cutoff, bool locked)
    {
        using var workspace = new TestWorkspace();
        await new LocalQueueAuditSink(workspace.QueueFile).WriteAsync(Event(Cutoff.AddDays(-1), true), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        using (var file = locked ? new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None) : null)
        {
            var response = await Query(workspace.QueueFile,
                JsonSerializer.Serialize(new { query = "audit-retention-preview", occurredBeforeUtc = cutoff }));
            Assert.Equal(!locked, response.GetProperty("ok").GetBoolean());
            Assert.DoesNotContain(workspace.Root, response.GetRawText());
            if (locked) Assert.Contains("io_error", response.GetProperty("error").GetString());
            else
            {
                var data = response.GetProperty("data");
                Assert.True(data.GetProperty("previewOnly").GetBoolean()); Assert.False(data.GetProperty("deletionSupported").GetBoolean());
                Assert.Equal(1, data.GetProperty("confirmedEventsBeforeCutoff").GetInt64());
                Assert.Equal(before.Length, data.GetProperty("integrity").GetProperty("queueBytes").GetInt64());
            }
        }
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
    }

    private static async Task<JsonElement> Query(string path, string request)
    {
        var name = "SafeUpload.Retention.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(),
            NullLogger<DiagnosticsPipeServer>.Instance, name, auditQueue: new LocalQueueAuditSink(path));
        await server.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes(request + "\n"), timeout.Token);
            using var reader = new StreamReader(pipe);
            using var json = JsonDocument.Parse((await reader.ReadLineAsync(timeout.Token))!);
            return json.RootElement.Clone();
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }

    private static AuditEvent Event(DateTimeOffset time, bool dispatched) => new(Guid.NewGuid(), time,
        "PC-SINTETICO", "usuario-sintetico", "arquivo.txt", ".txt", 12, Verdict.Approved, [], [], "teste", 1,
        "destino-sintetico", null, 1, 1, dispatched);
}
