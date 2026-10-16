using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueueOverrideTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();

    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Proxima_gravacao_sobrevive_a_ultima_linha_truncada()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        Directory.CreateDirectory(Path.GetDirectoryName(_workspace.QueueFile)!);
        await File.WriteAllTextAsync(_workspace.QueueFile, "{ultima-linha-truncada");
        await sink.RecordOverrideAsync(Guid.NewGuid().ToString(), "depois da queda", CancellationToken.None);
        var records = await sink.ReadPendingOverridesAsync(100, CancellationToken.None);
        Assert.Equal("depois da queda", Assert.Single(records).Justification);
    }

    [Fact]
    public async Task Confirmacao_preserva_json_desconhecido_e_override_adicionado_depois_do_lote()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var id = Guid.NewGuid();
        await sink.RecordOverrideAsync(id.ToString(), "primeira", CancellationToken.None);
        var batch = await sink.ReadPendingOverridesAsync(100, CancellationToken.None);
        await sink.RecordOverrideAsync(id.ToString(), "segunda", CancellationToken.None);
        var unknown = new[] { "null", "[]", "123", "{truncado", "{\"type\":\"future\",\"x\":1}" };
        await File.AppendAllLinesAsync(_workspace.QueueFile, unknown);
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));
        await sink.MarkDispatchedAsync([id], CancellationToken.None);
        await sink.MarkOverridesDispatchedAsync(batch, CancellationToken.None);
        var pending = await new LocalQueueAuditSink(_workspace.QueueFile)
            .ReadPendingOverridesAsync(100, CancellationToken.None);
        Assert.Equal("segunda", Assert.Single(pending).Justification);
        var lines = await File.ReadAllLinesAsync(_workspace.QueueFile);
        Assert.Equal(unknown, lines.Skip(2).ToArray());
    }

    [Fact]
    public async Task Justificativa_nao_vira_evento_falso_nem_desaparece_ao_confirmar_lote()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var audit = new AuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow,
            "PC-TESTE", "usuario.teste", "documento.txt", ".txt", 100,
            Verdict.Blocked, [Category.Cpf], ["•••••••••25"],
            "explorer.exe", 123, @"E:\destino", null, 1, 20, false);

        await sink.WriteAsync(audit, CancellationToken.None);
        await sink.RecordOverrideAsync(audit.EventId.ToString(),
            "Justificativa de teste", CancellationToken.None);

        var pending = await sink.ReadPendingAsync(100, CancellationToken.None);
        Assert.Single(pending);
        Assert.Equal(audit.EventId, pending[0].EventId);

        await sink.MarkDispatchedAsync([audit.EventId], CancellationToken.None);
        Assert.Empty(await sink.ReadPendingAsync(100, CancellationToken.None));

        var lines = await File.ReadAllLinesAsync(_workspace.QueueFile);
        Assert.Equal(2, lines.Length);
        using var confirmation = JsonDocument.Parse(lines[0]);
        Assert.True(confirmation.RootElement.GetProperty("dispatched").GetBoolean());
        using var justification = JsonDocument.Parse(lines[1]);
        Assert.Equal("override", justification.RootElement.GetProperty("type").GetString());
        Assert.Equal("Justificativa de teste", justification.RootElement.GetProperty("justification").GetString());
    }
}
