using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueueIntegrityTests
{
    [Fact]
    public async Task Inventario_conta_linhas_e_bytes_sem_descartar_duplicatas_ou_conteudo_desconhecido()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var older = Event() with { OccurredAtUtc = DateTimeOffset.Parse("2020-01-01T12:00:00+03:00") };
        var confirmed = Event() with { Dispatched = true, OccurredAtUtc = older.OccurredAtUtc.AddDays(-2) };
        await sink.WriteAsync(older, CancellationToken.None);
        await sink.WriteAsync(older, CancellationToken.None);
        await sink.WriteAsync(confirmed, CancellationToken.None);
        await sink.WriteAsync(Event() with { OccurredAtUtc = default }, CancellationToken.None);
        await sink.RecordOverrideAsync(older.EventId.ToString(), "JUSTIFICATIVA_ç", CancellationToken.None);
        await File.AppendAllTextAsync(workspace.QueueFile, "{\"type\":\"future\"}\n{INVALIDO\n  \n");
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var scan = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(before.LongLength, scan.QueueBytes);
        Assert.Equal(3, scan.PendingEvents); Assert.Equal(1, scan.DispatchedEvents);
        Assert.Equal(1, scan.PendingOverrides); Assert.Equal(0, scan.DispatchedOverrides);
        Assert.Equal(older.OccurredAtUtc.ToUniversalTime(), scan.OldestPendingUtc);
        Assert.Equal(TimeSpan.Zero, scan.OldestPendingUtc!.Value.Offset);
        Assert.Equal(1, scan.PendingWithoutTimestamp);
        Assert.Equal(1, scan.UnknownRecords); Assert.Equal(1, scan.InvalidLines); Assert.Equal(1, scan.BlankLines);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.DoesNotContain("JUSTIFICATIVA", JsonSerializer.Serialize(scan));

        var pendingOverrides = await sink.ReadPendingOverridesAsync(100, CancellationToken.None);
        await sink.MarkOverridesDispatchedAsync(pendingOverrides, CancellationToken.None);
        await sink.MarkDispatchedAsync(new[] { older.EventId }, CancellationToken.None);
        var after = await new LocalQueueAuditSink(workspace.QueueFile).InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(1, after.PendingEvents); Assert.Equal(3, after.DispatchedEvents);
        Assert.Equal(0, after.PendingOverrides); Assert.Equal(1, after.DispatchedOverrides);
        Assert.Null(after.OldestPendingUtc); Assert.Equal(1, after.PendingWithoutTimestamp);
        Assert.Equal(4, after.ValidEvents); Assert.Equal(1, after.ValidOverrides);
    }

    [Fact]
    public async Task Inventario_ausente_vazio_e_confirmado_nao_inventa_pendente_ou_data()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var missing = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.False(missing.FileExists); Assert.Equal(0, missing.QueueBytes); Assert.Null(missing.OldestPendingUtc);
        Assert.False(File.Exists(workspace.QueueFile));
        await File.WriteAllTextAsync(workspace.QueueFile, "", new UTF8Encoding(false));
        var empty = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.True(empty.FileExists); Assert.Equal(0, empty.QueueBytes); Assert.Equal(0, empty.PendingEvents);
        await sink.WriteAsync(Event() with { Dispatched = true }, CancellationToken.None);
        var confirmed = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(0, confirmed.PendingEvents); Assert.Equal(1, confirmed.DispatchedEvents);
        Assert.Null(confirmed.OldestPendingUtc); Assert.Equal(0, confirmed.PendingWithoutTimestamp);
    }

    [Fact]
    public async Task Data_mais_antiga_inclui_justificativa_pendente_e_ignora_a_confirmada()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var old = new AuditOverride(Guid.NewGuid(), "sintetica", DateTimeOffset.Parse("2019-01-01T10:00:00-03:00"), "user", "endpoint");
        await sink.RecordOverrideAsync(old, CancellationToken.None);
        var recent = Event() with { OccurredAtUtc = old.OccurredAtUtc.AddDays(10) };
        await sink.WriteAsync(recent, CancellationToken.None);
        var before = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(old.OccurredAtUtc.ToUniversalTime(), before.OldestPendingUtc);
        await sink.MarkOverridesDispatchedAsync(new[] { old }, CancellationToken.None);
        var after = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(recent.OccurredAtUtc.ToUniversalTime(), after.OldestPendingUtc);
        Assert.Equal(0, after.PendingOverrides); Assert.Equal(1, after.DispatchedOverrides);
    }

    [Fact]
    public async Task Diagnostico_preserva_bytes_e_eventos_validos_antes_e_depois_da_linha_invalida()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "JUSTIFICATIVA_SENSIVEL", CancellationToken.None);
        var first = Event(); await sink.WriteAsync(first, CancellationToken.None);
        await File.AppendAllTextAsync(workspace.QueueFile, "{CONTEUDO_SENSIVEL\n");
        var second = Event(); await sink.WriteAsync(second, CancellationToken.None);
        var before = SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile));
        var scan = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(4, scan.LinesScanned);
        Assert.Equal(2, scan.ValidEvents); Assert.Equal(1, scan.ValidOverrides);
        Assert.Equal(1, scan.InvalidLines); Assert.True(scan.RequiresAttention);
        Assert.Equal(new AuditQueueLineIssue(3, "invalid_json_or_fields"), Assert.Single(scan.Issues));
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile)));
        Assert.Equal(new[] { first.EventId, second.EventId },
            (await sink.ReadPendingAsync(100, CancellationToken.None)).Select(e => e.EventId));
        Assert.Single(await sink.ReadPendingOverridesAsync(100, CancellationToken.None));
        Assert.DoesNotContain("SENSIVEL", JsonSerializer.Serialize(scan));
        Assert.DoesNotContain(workspace.Root, JsonSerializer.Serialize(scan));
    }

    [Theory]
    [InlineData("null", "non_object")]
    [InlineData("[]", "non_object")]
    [InlineData("{}", "missing_event_id")]
    [InlineData("{\"eventId\":\"00000000-0000-0000-0000-000000000000\"}", "invalid_event")]
    [InlineData("{\"eventId\":\"bad-guid\"}", "invalid_json_or_fields")]
    [InlineData("{\"type\":null}", "invalid_record_type")]
    [InlineData("{\"type\":1}", "invalid_record_type")]
    [InlineData("{\"type\":\"override\"}", "invalid_override")]
    [InlineData("{\"eventId\":", "invalid_json_or_fields")]
    public async Task Classifica_linhas_incompativeis_sem_expor_o_conteudo(string content, string reason)
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllTextAsync(workspace.QueueFile, content);
        var scan = await new LocalQueueAuditSink(workspace.QueueFile).InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(1, scan.InvalidLines); Assert.Equal(0, scan.UnknownRecords);
        Assert.Equal(new AuditQueueLineIssue(1, reason), Assert.Single(scan.Issues));
    }

    [Fact]
    public async Task Tipo_futuro_nao_e_rotulado_como_corrupcao_e_amostra_e_limitada_sem_limitar_contagem()
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllLinesAsync(workspace.QueueFile,
            Enumerable.Repeat("{\"type\":\"future\",\"payload\":\"SENSIVEL\"}", 30));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var scan = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.Equal(30, scan.UnknownRecords); Assert.Equal(0, scan.InvalidLines);
        Assert.True(scan.RequiresAttention); Assert.True(scan.IssuesTruncated);
        Assert.Equal(20, scan.Issues.Count); Assert.Equal(20, scan.Issues[^1].LineNumber);
        Assert.DoesNotContain("SENSIVEL", JsonSerializer.Serialize(scan));
        Assert.Equal(scan.UnknownRecords, (await sink.InspectIntegrityAsync(CancellationToken.None)).UnknownRecords);
    }

    [Fact]
    public async Task Arquivo_ausente_nao_e_criado_e_linhas_em_branco_nao_sao_corrupcao()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.False((await sink.InspectIntegrityAsync(CancellationToken.None)).FileExists);
        Assert.False(File.Exists(workspace.QueueFile));
        await File.WriteAllTextAsync(workspace.QueueFile, "\r\n  \r\n", new UTF8Encoding(true));
        var scan = await sink.InspectIntegrityAsync(CancellationToken.None);
        Assert.True(scan.FileExists); Assert.Equal(2, scan.BlankLines);
        Assert.False(scan.RequiresAttention); Assert.Empty(scan.Issues);
    }

    [Fact]
    public async Task Cancelamento_e_falha_de_leitura_nao_produzem_recibo_saudavel_nem_bloqueiam_proxima_operacao()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.WriteAsync(Event(), CancellationToken.None);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.InspectIntegrityAsync(cancel.Token));
        using (var file = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None))
            await Assert.ThrowsAsync<IOException>(() => sink.InspectIntegrityAsync(CancellationToken.None));
        await sink.WriteAsync(Event(), CancellationToken.None);
        Assert.Equal(2, (await sink.InspectIntegrityAsync(CancellationToken.None)).ValidEvents);
    }

    [Fact]
    public async Task Confirmacao_preserva_linha_truncada_e_diagnostico_nao_conta_releituras_como_novos_erros()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var item = Event(); await sink.WriteAsync(item, CancellationToken.None);
        await File.AppendAllTextAsync(workspace.QueueFile, "{TRUNCADO");
        await sink.MarkDispatchedAsync([item.EventId], CancellationToken.None);
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(1, (await reopened.InspectIntegrityAsync(CancellationToken.None)).InvalidLines);
        Assert.Equal(1, (await reopened.InspectIntegrityAsync(CancellationToken.None)).InvalidLines);
        Assert.Empty(await reopened.ReadPendingAsync(100, CancellationToken.None));
        await reopened.WriteAsync(Event(), CancellationToken.None);
        Assert.Single(await reopened.ReadPendingAsync(100, CancellationToken.None));
        Assert.Equal(1, (await reopened.InspectIntegrityAsync(CancellationToken.None)).InvalidLines);
        Assert.Contains("{TRUNCADO", await File.ReadAllTextAsync(workspace.QueueFile));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pipe_real_sem_driver_retorna_diagnostico_ou_erro_sanitizado(bool locked)
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllTextAsync(workspace.QueueFile, "{SENSIVEL\n");
        using var file = locked ? new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None) : null;
        var name = "SafeUpload.Integrity.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(),
            NullLogger<DiagnosticsPipeServer>.Instance, name, auditQueue: new LocalQueueAuditSink(workspace.QueueFile));
        await server.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"audit-integrity\"}\n"), timeout.Token);
            using var reader = new StreamReader(pipe);
            var response = await reader.ReadLineAsync(timeout.Token);
            Assert.NotNull(response); Assert.DoesNotContain("SENSIVEL", response);
            Assert.DoesNotContain(workspace.Root, response);
            using var json = JsonDocument.Parse(response);
            Assert.Equal(!locked, json.RootElement.GetProperty("ok").GetBoolean());
            if (!locked)
            {
                var data = json.RootElement.GetProperty("data");
                Assert.Equal(1, data.GetProperty("invalidLines").GetInt64());
                Assert.Equal(new FileInfo(workspace.QueueFile).Length, data.GetProperty("queueBytes").GetInt64());
                Assert.Equal(0, data.GetProperty("pendingEvents").GetInt64());
                Assert.Equal(JsonValueKind.Null, data.GetProperty("oldestPendingUtc").ValueKind);
            }
            else Assert.Contains("io_error", json.RootElement.GetProperty("error").GetString());
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }

    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SINTETICO",
        "usuario-sintetico", "arquivo.txt", ".txt", 12, Verdict.Approved, [], [], "teste", 1,
        "destino-sintetico", null, 1, 1, false);
}
