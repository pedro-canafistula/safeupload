using System.Text;
using System.Text.Json;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class QueueStreamingConfirmationTests
{
    [Fact]
    public async Task Cancelamento_preserva_bytes_e_libera_fila_para_confirmacao_posterior()
    {
        using var workspace = new TestWorkspace();
        var id = Guid.NewGuid();
        var line = $"{{\"eventId\":\"{id}\",\"dispatched\":false}}";
        await File.WriteAllTextAsync(workspace.QueueFile, line, new UTF8Encoding(false));
        var bytes = await File.ReadAllBytesAsync(workspace.QueueFile);
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.MarkDispatchedAsync([id], cancelled.Token));
        Assert.Equal(bytes, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
        await sink.MarkDispatchedAsync([id], CancellationToken.None);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(workspace.QueueFile));
        Assert.True(json.RootElement.GetProperty("dispatched").GetBoolean());
    }

    [Theory]
    [InlineData(false, "\n")]
    [InlineData(true, "\r\n")]
    [InlineData(true, "\r")]
    public async Task Confirmacao_preserva_linhas_metadados_duplicatas_e_contrato_de_codificacao(bool bom, string newline)
    {
        using var workspace = new TestWorkspace();
        var id = Guid.NewGuid();
        var other = Guid.NewGuid();
        string[] lines = [
            $"  {{\"eventId\":\"{id}\",\"future\":{{\"k\":7}},\"dispatched\":false}}  ",
            $"{{\"eventId\":\"{id}\",\"future\":{{\"k\":8}}}}",
            $" {{\"eventId\":\"{other}\",\"fileName\":\"ação-漢字.txt\"}} ",
            "", " \t ", "null", "[]", "123", "{cauda-truncada",
            $"{{\"type\":\"future\",\"eventId\":\"{id}\",\"x\":1}}",
            "{\"type\":\"override\",\"eventId\":null}",
            "{\"eventId\":false}"
        ];
        await File.WriteAllTextAsync(workspace.QueueFile, string.Join(newline, lines), new UTF8Encoding(bom));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.MarkDispatchedAsync([id, id], CancellationToken.None);
        var actual = await File.ReadAllLinesAsync(workspace.QueueFile);
        Assert.Equal(lines.Length, actual.Length);
        Assert.Equal($"{{\"eventId\":\"{id}\",\"future\":{{\"k\":7}},\"dispatched\":true}}", actual[0]);
        Assert.Equal($"{{\"eventId\":\"{id}\",\"future\":{{\"k\":8}},\"dispatched\":true}}", actual[1]);
        Assert.Equal(lines.Skip(2), actual.Skip(2));
        var bytes = await File.ReadAllBytesAsync(workspace.QueueFile);
        Assert.Equal(Encoding.UTF8.GetBytes(string.Join(Environment.NewLine, actual) + Environment.NewLine), bytes);
        // Repeated acknowledgement remains content-idempotent, including unknown rows.
        await new LocalQueueAuditSink(workspace.QueueFile).MarkDispatchedAsync([id], CancellationToken.None);
        Assert.Equal(bytes, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
    }

    [Fact]
    public async Task Justificativas_com_mesmo_id_confirmam_apenas_conteudo_enviado_incluindo_duplicatas()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var first = new AuditOverride(Guid.NewGuid(), "ação autorizada 漢字", DateTimeOffset.UtcNow,
            "usuario-sintetico", "PC-SINTETICO");
        var next = first with { Justification = "outro conteúdo" };
        await sink.RecordOverrideAsync(first, CancellationToken.None);
        await sink.RecordOverrideAsync(next, CancellationToken.None);
        await sink.RecordOverrideAsync(first, CancellationToken.None);
        var before = await File.ReadAllLinesAsync(workspace.QueueFile);
        await sink.MarkOverridesDispatchedAsync([first, first], CancellationToken.None);
        var lines = await File.ReadAllLinesAsync(workspace.QueueFile);
        Assert.Equal(before[1], lines[1]);
        foreach (var index in new[] { 0, 2 })
        {
            using var json = JsonDocument.Parse(lines[index]);
            Assert.True(json.RootElement.GetProperty("dispatched").GetBoolean());
            Assert.Equal(first.Justification, json.RootElement.GetProperty("justification").GetString());
        }
        Assert.Equal(next, Assert.Single(await new LocalQueueAuditSink(workspace.QueueFile)
            .ReadPendingOverridesAsync(0, CancellationToken.None)));
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
    }

    [Fact]
    public async Task Linha_maior_que_buffer_permanece_inteira_e_confirmacao_sem_correspondencia_nao_remove_dados()
    {
        using var workspace = new TestWorkspace();
        var id = Guid.NewGuid();
        var large = "{\"type\":\"future\",\"data\":\"" + new string('x', 131_073) + "漢字\"}";
        var selected = $"{{\"eventId\":\"{id}\",\"dispatched\":false}}";
        await File.WriteAllTextAsync(workspace.QueueFile, large + "\n" + selected, new UTF8Encoding(false));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.MarkDispatchedAsync([Guid.NewGuid()], CancellationToken.None);
        Assert.Equal(new[] { large, selected }, await File.ReadAllLinesAsync(workspace.QueueFile));
        await sink.MarkDispatchedAsync([id], CancellationToken.None);
        var reopened = await File.ReadAllLinesAsync(workspace.QueueFile);
        Assert.Equal(large, reopened[0]);
        Assert.Equal($"{{\"eventId\":\"{id}\",\"dispatched\":true}}", reopened[1]);
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
    }
}
