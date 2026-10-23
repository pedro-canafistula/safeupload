using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueueTemporaryTests
{
    [Fact]
    public async Task Inventario_conta_somente_nomes_exatos_sem_ler_conteudo_ou_alterar_bytes()
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllTextAsync(workspace.QueueFile, "FILA_PRIVADA");
        var first = workspace.QueueFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var second = workspace.QueueFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await File.WriteAllBytesAsync(first, [1, 2, 3]);
        await File.WriteAllBytesAsync(second, []);
        await File.WriteAllTextAsync(workspace.QueueFile + ".bad.tmp", "IGNORADO");
        await File.WriteAllTextAsync(workspace.QueueFile + "." + Guid.NewGuid().ToString("D") + ".tmp", "IGNORADO");
        await File.WriteAllTextAsync(first + ".bak", "IGNORADO");
        await File.WriteAllTextAsync(Path.Combine(workspace.Root, "other." + Guid.NewGuid().ToString("N") + ".tmp"), "IGNORADO");
        var subdirectory = Path.Combine(workspace.Root, "sub"); Directory.CreateDirectory(subdirectory);
        await File.WriteAllTextAsync(Path.Combine(subdirectory, Path.GetFileName(first)), "IGNORADO");
        Directory.CreateDirectory(workspace.QueueFile + "." + Guid.NewGuid().ToString("N") + ".tmp");
        var before = SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile));
        var temporaryBefore = SHA256.HashData(await File.ReadAllBytesAsync(first));
        AuditQueueTemporarySnapshot scan;
        // Metadata can be queried even when content access is denied by a sharing lock.
        using (var locked = new FileStream(first, FileMode.Open, FileAccess.Read, FileShare.None))
            scan = await new LocalQueueAuditSink(workspace.QueueFile).InspectTemporaryFilesAsync(CancellationToken.None);
        Assert.True(scan.DirectoryExists); Assert.True(scan.Complete); Assert.True(scan.RequiresAttention);
        Assert.Equal(2, scan.CandidateFiles); Assert.Equal(3, scan.TotalBytes);
        Assert.Equal(0, scan.UnreadableCandidates); Assert.Equal(0, scan.SkippedReparsePoints);
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile)));
        Assert.Equal(temporaryBefore, SHA256.HashData(await File.ReadAllBytesAsync(first)));
        Assert.DoesNotContain(workspace.Root, JsonSerializer.Serialize(scan));
        Assert.DoesNotContain("PRIVADA", JsonSerializer.Serialize(scan));
        Assert.DoesNotContain(Path.GetFileName(first), JsonSerializer.Serialize(scan));
        Assert.Equal(scan, await new LocalQueueAuditSink(workspace.QueueFile).InspectTemporaryFilesAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Diretorio_ausente_nao_e_criado_e_fila_ausente_nao_impede_contar_temporario()
    {
        using var workspace = new TestWorkspace();
        var missing = Path.Combine(workspace.Root, "ausente", "queue.jsonl");
        var scan = await new LocalQueueAuditSink(missing).InspectTemporaryFilesAsync(CancellationToken.None);
        Assert.False(scan.DirectoryExists); Assert.True(scan.Complete); Assert.False(scan.RequiresAttention);
        Assert.False(Directory.Exists(Path.GetDirectoryName(missing)));
        await File.WriteAllBytesAsync(workspace.QueueFile + "." + Guid.NewGuid().ToString("N") + ".tmp", [42]);
        scan = await new LocalQueueAuditSink(workspace.QueueFile).InspectTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(1, scan.CandidateFiles); Assert.Equal(1, scan.TotalBytes); Assert.False(File.Exists(workspace.QueueFile));
    }

    [Fact]
    public async Task Limite_de_entradas_informa_resultado_incompleto_sem_rotular_como_saudavel()
    {
        using var workspace = new TestWorkspace();
        for (var i = 0; i < 10_001; i++) File.WriteAllBytes(Path.Combine(workspace.Root, i.ToString()), []);
        var scan = await new LocalQueueAuditSink(workspace.QueueFile).InspectTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(10_000, scan.EntriesExamined); Assert.True(scan.ScanLimitReached);
        Assert.False(scan.Complete); Assert.True(scan.RequiresAttention);
    }

    [Fact]
    public async Task Cancelamento_nao_bloqueia_consulta_seguinte()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.InspectTemporaryFilesAsync(cancel.Token));
        var scan = await sink.InspectTemporaryFilesAsync(CancellationToken.None);
        Assert.True(scan.Complete); Assert.False(scan.RequiresAttention);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pipe_real_sem_driver_retorna_contagens_ou_erro_sanitizado(bool invalidDirectory)
    {
        using var workspace = new TestWorkspace();
        var queue = workspace.QueueFile;
        if (invalidDirectory)
        {
            await File.WriteAllTextAsync(queue, "CONTEUDO_PRIVADO");
            queue = Path.Combine(queue, "queue.jsonl");
        }
        else await File.WriteAllBytesAsync(queue + "." + Guid.NewGuid().ToString("N") + ".tmp", [1, 2]);
        var name = "SafeUpload.Temporaries.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(),
            NullLogger<DiagnosticsPipeServer>.Instance, name, auditQueue: new LocalQueueAuditSink(queue));
        await server.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"audit-temporaries\"}\n"), timeout.Token);
            using var reader = new StreamReader(pipe);
            var response = await reader.ReadLineAsync(timeout.Token);
            Assert.NotNull(response); Assert.DoesNotContain(workspace.Root, response);
            Assert.DoesNotContain("CONTEUDO_PRIVADO", response);
            using var json = JsonDocument.Parse(response);
            Assert.Equal(!invalidDirectory, json.RootElement.GetProperty("ok").GetBoolean());
            if (invalidDirectory) Assert.Contains("io_error", json.RootElement.GetProperty("error").GetString());
            else Assert.Equal(1, json.RootElement.GetProperty("data").GetProperty("candidateFiles").GetInt64());
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }
}
