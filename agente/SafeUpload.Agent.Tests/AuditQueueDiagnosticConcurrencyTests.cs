using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;

namespace SafeUpload.Agent.Tests;

public sealed class AuditQueueDiagnosticConcurrencyTests
{
    [Fact]
    public async Task Leitura_capturada_libera_gravacao_e_confirmacao_e_nao_inclui_append_posterior()
    {
        using var workspace = new TestWorkspace();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var first = Event(0);
        await sink.WriteAsync(first, deadline.Token);
        var original = await File.ReadAllTextAsync(workspace.QueueFile, deadline.Token);
        await using var window = await sink.OpenIntegritySnapshotAsync(deadline.Token);
        Assert.NotNull(window);
        // Both operations complete while the original read handle remains open.
        await sink.WriteAsync(Event(1), deadline.Token);
        await sink.MarkDispatchedAsync([first.EventId], deadline.Token);
        using var reader = new StreamReader(window, leaveOpen: true);
        Assert.Equal(original, reader.ReadToEnd());
        Assert.Equal(Encoding.UTF8.GetByteCount(original), window.CapturedLength);
        var current = await sink.InspectIntegrityAsync(deadline.Token);
        Assert.Equal(2, current.ValidEvents);
        Assert.Equal(1, current.PendingEvents);
        Assert.Equal(1, current.DispatchedEvents);
    }

    [Fact]
    public async Task Truncamento_externo_nao_e_apresentado_como_leitura_completa()
    {
        using var workspace = new TestWorkspace();
        await File.WriteAllTextAsync(workspace.QueueFile, new string('x', 8192));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        await using var window = await sink.OpenIntegritySnapshotAsync(CancellationToken.None);
        Assert.NotNull(window);
        using (var external = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Write,
            FileShare.ReadWrite | FileShare.Delete)) external.SetLength(2);
        var buffer = new byte[16];
        Assert.Equal(2, await window.ReadAsync(buffer.AsMemory(), CancellationToken.None));
        await Assert.ThrowsAsync<IOException>(async () => { await window.ReadAsync(buffer.AsMemory(), CancellationToken.None); });
    }

    [Fact]
    public async Task Consultas_com_gravacao_e_confirmacao_preservam_conjuntos_apos_reabertura()
    {
        using var workspace = new TestWorkspace();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var token = deadline.Token;
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var initial = Enumerable.Range(0, 200).Select(Event).ToArray();
        var added = Enumerable.Range(200, 100).Select(Event).ToArray();
        foreach (var item in initial) await sink.WriteAsync(item, token);
        var firstWrite = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstScan = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var confirmed = new HashSet<Guid>();

        var writer = Task.Run(async () =>
        {
            await sink.WriteAsync(added[0], token);
            firstWrite.SetResult();
            // Require a real scan before completing the producer workload.
            await firstScan.Task.WaitAsync(token);
            foreach (var item in added.Skip(1)) await sink.WriteAsync(item, token);
        }, token);
        var acknowledger = Task.Run(async () =>
        {
            await firstWrite.Task.WaitAsync(token);
            for (var iteration = 0; iteration < 12; iteration++)
            {
                var batch = await sink.ReadPendingAsync(15, token);
                await sink.MarkDispatchedAsync(batch.Select(e => e.EventId).ToArray(), token);
                foreach (var item in batch) confirmed.Add(item.EventId);
            }
        }, token);
        var scanner = Task.Run(async () =>
        {
            await firstWrite.Task.WaitAsync(token);
            for (var iteration = 0; iteration < 20; iteration++)
            {
                var integrity = await sink.InspectIntegrityAsync(token);
                CheckSnapshot(integrity);
                firstScan.TrySetResult();
            }
        }, token);
        await Task.WhenAll(writer, acknowledger, scanner);
        Assert.Equal(180, confirmed.Count);

        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        var expected = initial.Concat(added).Select(e => e.EventId).ToHashSet();
        var history = await reopened.ReadRecentAsync(0, token);
        Assert.Equal(expected.Count, history.Count);
        Assert.True(expected.SetEquals(history.Select(e => e.EventId)));
        Assert.True(confirmed.SetEquals(history.Where(e => e.Dispatched).Select(e => e.EventId)));
        var pending = await reopened.ReadPendingAsync(0, token);
        Assert.True(expected.Except(confirmed).ToHashSet().SetEquals(pending.Select(e => e.EventId)));
        var before = await File.ReadAllBytesAsync(workspace.QueueFile, token);
        var final = await reopened.InspectIntegrityAsync(token);
        Assert.Equal(confirmed.Count, final.DispatchedEvents);
        Assert.Equal(expected.Count - confirmed.Count, final.PendingEvents);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile, token));
    }

    [Fact]
    public async Task Prazo_real_do_pipe_cancela_espera_do_lock_sem_sucesso_parcial_e_permite_retomada()
    {
        const string query = "audit-integrity";
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var initial = Event(0);
        var added = Event(1);
        await sink.WriteAsync(initial, CancellationToken.None);
        var original = await File.ReadAllBytesAsync(workspace.QueueFile);
        // Test-only control of contention, not a production hook or a slow-scan claim.
        var field = typeof(LocalQueueAuditSink).GetField("_writeLock", BindingFlags.Instance | BindingFlags.NonPublic);
        var gate = Assert.IsType<SemaphoreSlim>(field!.GetValue(sink));
        await gate.WaitAsync();
        var held = true;
        var name = "SafeUpload.Deadline.Test." + Guid.NewGuid().ToString("N");
        using var server = new DiagnosticsPipeServer(new DriverDiagnosticsSource(),
            NullLogger<DiagnosticsPipeServer>.Instance, name, auditQueue: sink);
        using var harnessDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var token = harnessDeadline.Token;
        Task? write = null;
        try
        {
            await server.StartAsync(token);
            await using (var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                await pipe.ConnectAsync(token);
                var request = JsonSerializer.Serialize(new { query });
                var elapsed = Stopwatch.StartNew();
                await pipe.WriteAsync(Encoding.UTF8.GetBytes(request + "\n"), token);
                using var reader = new StreamReader(pipe, leaveOpen: true);
                string? response = null;
                try { response = await reader.ReadLineAsync(token); }
                catch (IOException) { /* A canceled server request may close as a broken pipe. */ }
                Assert.Null(response); // No successful or partial inventory is published.
                Assert.True(elapsed.Elapsed >= TimeSpan.FromSeconds(4), "Request ended before the five-second budget.");
            }
            Assert.Equal(original, await File.ReadAllBytesAsync(workspace.QueueFile, token));
            write = sink.WriteAsync(added, token);
            Assert.False(write.IsCompleted);
            gate.Release(); held = false;
            await write;

            // The same server and sink must serve a fresh request after deadline expiry.
            await using var next = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await next.ConnectAsync(token);
            var nextRequest = JsonSerializer.Serialize(new { query });
            await next.WriteAsync(Encoding.UTF8.GetBytes(nextRequest + "\n"), token);
            using var nextReader = new StreamReader(next, leaveOpen: true);
            using var json = JsonDocument.Parse((await nextReader.ReadLineAsync(token))!);
            Assert.True(json.RootElement.GetProperty("ok").GetBoolean());
            var data = json.RootElement.GetProperty("data");
            Assert.Equal(2, data.GetProperty("pendingEvents").GetInt64());
            var events = await new LocalQueueAuditSink(workspace.QueueFile).ReadPendingAsync(0, token);
            Assert.Equal(2, events.Count);
            Assert.Equal(2, events.Select(e => e.EventId).Distinct().Count());
            Assert.True(new[] { initial.EventId, added.EventId }.ToHashSet().SetEquals(events.Select(e => e.EventId)));
        }
        finally
        {
            if (held) gate.Release();
            if (write is not null) await write;
            await server.StopAsync(CancellationToken.None);
        }
    }

    private static void CheckSnapshot(AuditQueueIntegritySnapshot snapshot)
    {
        Assert.InRange(snapshot.ValidEvents, 201, 300);
        Assert.Equal(snapshot.ValidEvents, snapshot.PendingEvents + snapshot.DispatchedEvents);
        Assert.Equal(snapshot.ValidEvents, snapshot.LinesScanned);
        Assert.Equal(0, snapshot.InvalidLines);
        Assert.Equal(0, snapshot.UnknownRecords);
        Assert.False(snapshot.RequiresAttention);
        Assert.Equal(0, snapshot.PendingWithoutTimestamp);
        Assert.True(snapshot.QueueBytes > 0);
    }

    private static AuditEvent Event(int index) => new(Guid.NewGuid(),
        new DateTimeOffset(2026, 10, 24, 12, 0, 0, TimeSpan.Zero).AddSeconds(index),
        "PC-SINTETICO", "usuario-sintetico", $"sintetico-{index}.txt", ".txt", 42,
        Verdict.Approved, [], [], "processo-sintetico", 1, "destino-sintetico", null, 1, 1, false);
}
