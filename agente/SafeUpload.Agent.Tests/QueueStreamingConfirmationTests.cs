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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Falha_ou_cancelamento_apos_escrita_real_no_temporario_preserva_original_e_permite_retomada(bool cancel)
    {
        using var workspace = new TestWorkspace();
        using var cancellation = new CancellationTokenSource();
        var id = Guid.NewGuid();
        var large = "{\"type\":\"future\",\"data\":\"" + new string('x', 262_145) + "\"}";
        var selected = $"{{\"eventId\":\"{id}\",\"dispatched\":false}}";
        await File.WriteAllTextAsync(workspace.QueueFile, large + "\n" + selected, new UTF8Encoding(false));
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        InterruptedCopyStream? copy = null;
        var sink = new LocalQueueAuditSink(workspace.QueueFile, temporary =>
        {
            if (copy is not null)
                return new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
            return copy = new InterruptedCopyStream(temporary, () =>
            {
                if (cancel) cancellation.Cancel();
                else throw new IOException("Synthetic interruption after a native file write.");
            });
        });

        if (cancel)
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.MarkDispatchedAsync([id], cancellation.Token));
        else
            await Assert.ThrowsAnyAsync<IOException>(() => sink.MarkDispatchedAsync([id], cancellation.Token));
        Assert.NotNull(copy);
        Assert.True(copy.BytesWrittenBeforeInterruption > 0);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
        // The same instance must have released its lock and can complete a retry.
        await sink.MarkDispatchedAsync([id], CancellationToken.None);
        var lines = await File.ReadAllLinesAsync(workspace.QueueFile);
        Assert.Equal(large, lines[0]);
        using var confirmed = JsonDocument.Parse(lines[1]);
        Assert.True(confirmed.RootElement.GetProperty("dispatched").GetBoolean());
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
    }

    [Fact]
    public async Task Falha_ao_substituir_original_preserva_bytes_remove_apenas_temporario_proprio_e_permite_retomada()
    {
        using var workspace = new TestWorkspace();
        var id = Guid.NewGuid();
        var line = $"{{\"eventId\":\"{id}\",\"dispatched\":false}}";
        await File.WriteAllTextAsync(workspace.QueueFile, line, new UTF8Encoding(false));
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var unrelated = Path.Combine(workspace.Root, "preservar.tmp");
        await File.WriteAllTextAsync(unrelated, "unrelated synthetic evidence");
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        // A real Windows handle allows reading/copying, but prevents replacing this file.
        using (var blocker = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            var error = await Record.ExceptionAsync(() => sink.MarkDispatchedAsync([id], CancellationToken.None));
            Assert.NotNull(error);
            Assert.True(error is IOException or UnauthorizedAccessException, error.ToString());
        }
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Equal(new[] { unrelated }, Directory.GetFiles(workspace.Root, "*.tmp"));
        Assert.Equal("unrelated synthetic evidence", await File.ReadAllTextAsync(unrelated));
        await sink.MarkDispatchedAsync([id], CancellationToken.None);
        using var confirmed = JsonDocument.Parse(await File.ReadAllTextAsync(workspace.QueueFile));
        Assert.True(confirmed.RootElement.GetProperty("dispatched").GetBoolean());
        Assert.Equal(new[] { unrelated }, Directory.GetFiles(workspace.Root, "*.tmp"));
    }

    [Fact]
    public async Task Lote_vazio_ou_fila_ausente_nao_criam_fila_ou_temporario()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await sink.MarkDispatchedAsync([], CancellationToken.None);
        await sink.MarkOverridesDispatchedAsync([], CancellationToken.None);
        await sink.MarkDispatchedAsync([Guid.NewGuid()], CancellationToken.None);
        Assert.False(File.Exists(workspace.QueueFile));
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
    }

    private sealed class InterruptedCopyStream(string path, Action interrupt)
        : FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous)
    {
        public long BytesWrittenBeforeInterruption { get; private set; }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await base.WriteAsync(buffer, cancellationToken);
            if (BytesWrittenBeforeInterruption != 0) return;
            BytesWrittenBeforeInterruption = buffer.Length;
            interrupt();
        }
    }
}
