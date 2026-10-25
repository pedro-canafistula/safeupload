using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class QueueTemporaryClassificationTests
{
    [Fact]
    public async Task Classifica_sem_promover_copia_completa_nem_alterar_bytes_ids_ou_metadados()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var events = Enumerable.Range(0, 8).Select(_ => Event()).ToArray();
        foreach (var item in events) await sink.WriteAsync(item, CancellationToken.None);
        var reason = new AuditOverride(events[0].EventId, "RAZAO_PRIVADA", events[0].OccurredAtUtc, events[0].UserName, events[0].EndpointId);
        await sink.RecordOverrideAsync(reason, CancellationToken.None);
        var full = Candidate(workspace);
        File.Copy(workspace.QueueFile, full);
        // A complete candidate has conflicting delivery state; it must never win.
        await new LocalQueueAuditSink(full).MarkDispatchedAsync(events.Select(e => e.EventId).ToArray(), CancellationToken.None);
        var partial = Candidate(workspace); await File.WriteAllTextAsync(partial, "{\"eventId\":\"CAUDA_PRIVADA");
        var future = Candidate(workspace); await File.WriteAllTextAsync(future, "{\"type\":\"future\",\"content\":\"CONTEUDO_PRIVADO\"}\n");
        var empty = Candidate(workspace); await File.WriteAllBytesAsync(empty, []);
        var inUse = Candidate(workspace); File.Copy(full, inUse);
        string[] paths = [workspace.QueueFile, full, partial, future, empty, inUse];
        var hashes = await Hashes(paths);
        AuditQueueTemporaryClassification result;
        using (var writer = new FileStream(inUse, FileMode.Open, FileAccess.Write, FileShare.None))
            result = await sink.ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(5, result.CandidateEntries);
        Assert.Equal(1, result.StructurallyCompleteCandidates); Assert.Equal(1, result.UnterminatedCandidates);
        Assert.Equal(2, result.SuspiciousCandidates); Assert.Equal(1, result.InUseCandidates);
        Assert.Equal(0, result.UnavailableCandidates); Assert.Equal(0, result.UnsafeCandidates);
        Assert.True(result.Complete); Assert.True(result.RequiresAttention);
        Assert.False(result.RecoveryEligible); Assert.False(result.PromotionSupported);
        Assert.False(result.DeletionSupported); Assert.False(result.OwnershipVerified);
        Assert.Equal(hashes, await Hashes(paths));
        var serialized = JsonSerializer.Serialize(result);
        foreach (var secret in new[] { workspace.Root, "PRIVADA", "PRIVADO", events[0].EventId.ToString(), Path.GetFileName(full) })
            Assert.DoesNotContain(secret, serialized);
        // Reopen public sink and keep using published queue, never candidate state.
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var before = await reopened.ReadPendingAsync(0, CancellationToken.None);
        Assert.Equal(events.Select(e => JsonSerializer.Serialize(e)), before.Select(e => JsonSerializer.Serialize(e)));
        Assert.Contains(reason, await reopened.ReadPendingOverridesAsync(0, CancellationToken.None));
        var next = Event(); await reopened.WriteAsync(next, CancellationToken.None);
        await reopened.MarkDispatchedAsync([next.EventId], CancellationToken.None);
        var after = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(8, (await after.ReadPendingAsync(0, CancellationToken.None)).Count);
        Assert.Equal(9, (await after.ReadRecentAsync(0, CancellationToken.None)).Count);
        Assert.Equal(hashes.Skip(1), (await Hashes(paths)).Skip(1));
    }

    [Theory]
    [InlineData("{unfinished")]
    [InlineData("{\"eventId\":\"00000000-0000-0000-0000-000000000001\"}")]
    public async Task Ausencia_de_LF_e_indicio_de_cauda_sem_provar_causa(string text)
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllTextAsync(Candidate(workspace), text);
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(1, result.UnterminatedCandidates); Assert.Equal(0, result.StructurallyCompleteCandidates);
        Assert.False(File.Exists(workspace.QueueFile));
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("[]\n")]
    [InlineData("{broken}\n")]
    [InlineData("{\"type\":\"future\"}\n")]
    [InlineData("{\"eventId\":\"not-guid\"}\n")]
    [InlineData("{\"eventId\":\"00000000-0000-0000-0000-000000000001\",\"eventId\":\"00000000-0000-0000-0000-000000000002\"}\n")]
    public async Task Conteudo_suspeito_ou_nao_suportado_nao_e_candidato_a_recuperacao(string text)
    {
        using var workspace = new TestWorkspace();
        var candidate = Candidate(workspace); await File.WriteAllTextAsync(candidate, text);
        var before = await File.ReadAllBytesAsync(candidate);
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(1, result.SuspiciousCandidates); Assert.Equal(0, result.StructurallyCompleteCandidates);
        Assert.Equal(before, await File.ReadAllBytesAsync(candidate));
    }

    [Fact]
    public async Task UTF8_invalido_e_recusado_sem_incluir_conteudo_na_resposta()
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllBytesAsync(Candidate(workspace), [123, 34, 120, 34, 58, 34, 0xff, 34, 125, 10]);
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(1, result.SuspiciousCandidates);
    }

    [Theory]
    [InlineData(AuditChannel.File)]
    [InlineData(AuditChannel.Clipboard)]
    [InlineData(AuditChannel.Web)]
    public async Task Eventos_de_canais_suportados_incluindo_nome_vazio_continuam_legiveis(AuditChannel channel)
    {
        using var workspace = new TestWorkspace();
        var candidate = Candidate(workspace);
        var item = Event() with { Channel = channel, FileName = channel == AuditChannel.File ? "sintetico.txt" : "", MaskedSnippets = ["ação 漢字"] };
        await new LocalQueueAuditSink(candidate).WriteAsync(item, CancellationToken.None);
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(1, result.StructurallyCompleteCandidates); Assert.False(result.RecoveryEligible);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reparse_no_candidato_ou_ancestral_nao_segue_o_destino(bool ancestor)
    {
        using var workspace = new TestWorkspace();
        using var outside = new TestWorkspace();
        await new LocalQueueAuditSink(outside.QueueFile).WriteAsync(Event(), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(outside.QueueFile);
        var link = ancestor ? Path.Combine(workspace.Root, "link") : Candidate(workspace);
        if (ancestor) Directory.CreateSymbolicLink(link, outside.Root); else File.CreateSymbolicLink(link, outside.QueueFile);
        try
        {
            var sink = new LocalQueueAuditSink(ancestor ? Path.Combine(link, "queue.jsonl") : workspace.QueueFile);
            var result = await sink.ClassifyTemporaryFilesAsync(CancellationToken.None);
            Assert.Equal(0, result.BytesRead); Assert.False(result.Complete);
            if (ancestor) Assert.True(result.DirectoryTraversalBlocked); else Assert.Equal(1, result.UnsafeCandidates);
            Assert.Equal(before, await File.ReadAllBytesAsync(outside.QueueFile));
        }
        finally { if (ancestor) Directory.Delete(link); else File.Delete(link); }
    }

    [Fact]
    public async Task Linha_longa_e_arquivo_grande_ficam_indeterminados_sem_resultado_completo()
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllTextAsync(Candidate(workspace), new string('x', 65537));
        using (var file = File.Create(Candidate(workspace))) file.SetLength(4 * 1024 * 1024 + 1);
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(2, result.IndeterminateCandidates); Assert.False(result.Complete);
        Assert.True(result.BytesRead <= 65537);
    }

    [Fact]
    public async Task Orcamento_total_limita_leitura_sem_confundir_limite_com_sucesso()
    {
        using var workspace = new TestWorkspace();
        var one = Path.Combine(workspace.Root, "one.jsonl");
        await new LocalQueueAuditSink(one).WriteAsync(Event(), CancellationToken.None);
        var record = (await File.ReadAllTextAsync(one)).TrimEnd('\r', '\n');
        var line = Encoding.UTF8.GetBytes(record.PadRight(65535) + "\n");
        Assert.Equal(65536, line.Length);
        for (var file = 0; file < 6; file++)
        {
            await using var output = File.Create(Candidate(workspace));
            for (var i = 0; i < 64; i++) await output.WriteAsync(line);
        }
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(4, result.StructurallyCompleteCandidates); Assert.Equal(2, result.IndeterminateCandidates);
        Assert.Equal(16 * 1024 * 1024, result.BytesRead); Assert.False(result.Complete);
    }

    [Fact]
    public async Task Limite_de_candidatos_nao_varre_todo_o_diretorio()
    {
        using var workspace = new TestWorkspace();
        for (var i = 0; i < 17; i++) await File.WriteAllTextAsync(Candidate(workspace), "{");
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(16, result.CandidateEntries); Assert.True(result.ScanLimitReached); Assert.False(result.Complete);
    }

    [Fact]
    public async Task Diretorio_ausente_nao_e_criado_cancelamento_libera_lock_e_nomes_fora_do_padrao_sao_ignorados()
    {
        using var workspace = new TestWorkspace();
        var missing = Path.Combine(workspace.Root, "missing", "queue.jsonl");
        var sink = new LocalQueueAuditSink(missing);
        var result = await sink.ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.False(result.DirectoryExists); Assert.True(result.Complete); Assert.False(Directory.Exists(Path.GetDirectoryName(missing)));
        using var cancel = new CancellationTokenSource(); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.ClassifyTemporaryFilesAsync(cancel.Token));
        await File.WriteAllTextAsync(workspace.QueueFile + ".bad.tmp", "IGNORADO");
        await File.WriteAllTextAsync(Candidate(workspace) + ".bak", "IGNORADO");
        result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(0, result.CandidateEntries); Assert.True(result.Complete);
    }

    [Fact]
    public async Task Hardlink_e_diretorio_com_nome_de_candidato_sao_recusados_sem_ler_fila()
    {
        using var workspace = new TestWorkspace();
        await new LocalQueueAuditSink(workspace.QueueFile).WriteAsync(Event(), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(workspace.QueueFile);
        Assert.True(CreateHardLinkW(Candidate(workspace), workspace.QueueFile, IntPtr.Zero), "Hardlink fixture failed.");
        Directory.CreateDirectory(Candidate(workspace));
        var result = await new LocalQueueAuditSink(workspace.QueueFile).ClassifyTemporaryFilesAsync(CancellationToken.None);
        Assert.Equal(2, result.UnsafeCandidates); Assert.Equal(0, result.BytesRead); Assert.False(result.Complete);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pipe_real_sem_driver_publica_diagnostico_ou_erro_sanitizado(bool invalidDirectory)
    {
        using var workspace = new TestWorkspace();
        var queue = workspace.QueueFile;
        if (invalidDirectory) { await File.WriteAllTextAsync(queue, "SEGREDO_PRIVADO"); queue = Path.Combine(queue, "queue.jsonl"); }
        else await File.WriteAllTextAsync(Candidate(workspace), "{partial");
        var name = "SafeUpload.TemporaryClassification.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(), NullLogger<DiagnosticsPipeServer>.Instance,
            name, auditQueue: new LocalQueueAuditSink(queue));
        await server.StartAsync(CancellationToken.None);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(timeout.Token);
            await pipe.WriteAsync(Encoding.UTF8.GetBytes("{\"query\":\"audit-temporary-classification\"}\n"), timeout.Token);
            using var reader = new StreamReader(pipe);
            var response = await reader.ReadLineAsync(timeout.Token);
            Assert.NotNull(response); Assert.DoesNotContain(workspace.Root, response); Assert.DoesNotContain("SEGREDO", response);
            using var document = JsonDocument.Parse(response);
            Assert.Equal(!invalidDirectory, document.RootElement.GetProperty("ok").GetBoolean());
            if (!invalidDirectory)
            {
                var data = document.RootElement.GetProperty("data");
                Assert.Equal(1, data.GetProperty("unterminatedCandidates").GetInt64());
                Assert.False(data.GetProperty("recoveryEligible").GetBoolean());
                Assert.False(data.GetProperty("promotionSupported").GetBoolean());
            }
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }

    private static string Candidate(TestWorkspace workspace) => workspace.QueueFile + "." + Guid.NewGuid().ToString("N") + ".tmp";
    private static async Task<string[]> Hashes(string[] paths)
    {
        var hashes = new List<string>();
        foreach (var path in paths) hashes.Add(Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(path))));
        return hashes.ToArray();
    }
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC-SINTETICO", "usuario-sintetico",
        "ARQUIVO_PRIVADO.txt", ".txt", 1, Verdict.Blocked, [Category.Cpf], ["TRECHO_PRIVADO"],
        "processo-sintetico", 123, "DESTINO_PRIVADO", null, 1, 10, false);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool CreateHardLinkW(string link, string target, IntPtr reserved);
}
