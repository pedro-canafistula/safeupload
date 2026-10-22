using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Dispatch;

namespace SafeUpload.Agent.Tests;

public sealed class QueueLongevityTests
{
    [Fact]
    public async Task Backlog_em_varios_lotes_sobrevive_a_resposta_perdida_503_e_reabertura_sem_trocar_ids()
    {
        using var workspace = new TestWorkspace();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        var token = timeout.Token;
        var expected = Enumerable.Range(0, 1201).Select(Event).ToArray();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        foreach (var item in expected) await sink.WriteAsync(item, token);
        var overrides = expected.Where((_, i) => i % 100 == 0)
            .Select(e => new AuditOverride(e.EventId, "Justificativa sintética", e.OccurredAtUtc,
                e.UserName, e.EndpointId)).ToArray();
        foreach (var item in overrides) await sink.RecordOverrideAsync(item, token);

        var accepted = new Dictionary<Guid, string>();
        var acceptedOverrides = new HashSet<Guid>();
        var attempts = 0;
        var duplicates = 0;
        await using var api = new LoopbackHttpFixture(request =>
        {
            Assert.Equal("/agent/events", request.Target);
            Assert.DoesNotContain("LOCAL_ONLY_SYNTHETIC", request.Body);
            using var payload = JsonDocument.Parse(request.Body);
            var events = payload.RootElement.GetProperty("events");
            var reasons = payload.RootElement.GetProperty("overrides");
            Assert.InRange(events.GetArrayLength(), 0, 100);
            Assert.InRange(reasons.GetArrayLength(), 0, 100);
            attempts++;
            if (attempts == 4) return new(503, "{}");
            foreach (var item in events.EnumerateArray())
            {
                var id = item.GetProperty("eventId").GetGuid();
                if (accepted.TryGetValue(id, out var previous))
                {
                    Assert.Equal(previous, item.GetRawText());
                    duplicates++;
                }
                else accepted.Add(id, item.GetRawText());
            }
            foreach (var item in reasons.EnumerateArray())
                acceptedOverrides.Add(item.GetProperty("eventId").GetGuid());
            // The synthetic server stored the first request but its receipt was lost.
            if (attempts == 1) return null;
            return new(200, JsonSerializer.Serialize(new
            {
                acceptedEvents = events.GetArrayLength(), acceptedOverrides = reasons.GetArrayLength()
            }));
        });
        using var client = api.CreateClient();
        for (var cycle = 0; cycle < 20; cycle++)
        {
            // New queue/dispatcher objects model reopening durable state, not a process crash.
            sink = new LocalQueueAuditSink(workspace.QueueFile);
            if ((await sink.ReadPendingAsync(1, token)).Count == 0 &&
                (await sink.ReadPendingOverridesAsync(1, token)).Count == 0) break;
            using var dispatcher = new HttpAgentDispatcher(sink, new Policies(), client, "PC-SINTETICO",
                TimeSpan.FromSeconds(30), NullLogger<HttpAgentDispatcher>.Instance);
            if (cycle == 0)
            {
                await Assert.ThrowsAsync<HttpRequestException>(() => dispatcher.DispatchPendingAsync(token));
                Assert.Equal(1201, (await sink.ReadPendingAsync(0, token)).Count);
                Assert.Equal(overrides.Length, (await sink.ReadPendingOverridesAsync(0, token)).Count);
            }
            else await dispatcher.DispatchPendingAsync(token);
        }
        sink = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Empty(await sink.ReadPendingAsync(1, token));
        Assert.Empty(await sink.ReadPendingOverridesAsync(1, token));
        Assert.Equal(expected.Select(e => e.EventId).Order(), accepted.Keys.Order());
        Assert.Equal(overrides.Select(e => e.EventId).Order(), acceptedOverrides.Order());
        Assert.Equal(100, duplicates); // At-least-once transport; the server must deduplicate.
        Assert.Equal(15, attempts); // 13 accepted batches, one lost receipt, one 503.
        var history = await sink.ReadRecentAsync(0, token);
        Assert.Equal(1201, history.Count);
        Assert.All(history, e => Assert.True(e.Dispatched));
        Assert.Equal(expected.OrderBy(e => e.EventId).Select(e => JsonSerializer.Serialize(e)),
            history.Select(e => e with { Dispatched = false }).OrderBy(e => e.EventId).Select(e => JsonSerializer.Serialize(e)));
        Assert.Equal(1201 + overrides.Length, (await File.ReadAllLinesAsync(workspace.QueueFile, token)).Length);
    }

    [Fact]
    public async Task Falha_de_gravacao_por_arquivo_ocupado_e_observavel_preserva_fila_e_permite_retomada()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var first = Event(0);
        var next = Event(1);
        await sink.WriteAsync(first, CancellationToken.None);
        var before = SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile));
        using (var locked = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.None))
            await Assert.ThrowsAsync<IOException>(() => sink.WriteAsync(next, CancellationToken.None));
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile)));
        await sink.WriteAsync(next, CancellationToken.None);
        var pending = await new LocalQueueAuditSink(workspace.QueueFile).ReadPendingAsync(0, CancellationToken.None);
        Assert.Equal(new[] { first.EventId, next.EventId }, pending.Select(e => e.EventId));
    }

    [Fact]
    public async Task Falha_na_substituicao_atomica_preserva_pendentes_e_limpa_temporario_sem_apagar_linhas_desconhecidas()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var first = Event(0);
        await sink.WriteAsync(first, CancellationToken.None);
        const string unknown = "{\"type\":\"future\",\"synthetic\":true}";
        const string corrupt = "{linha-sintetica-truncada";
        await File.AppendAllLinesAsync(workspace.QueueFile, [unknown, corrupt]);
        var before = SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile));
        // Allow reading but deny replacement of the destination on Windows.
        using (var locked = new FileStream(workspace.QueueFile, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var failure = await Record.ExceptionAsync(() => sink.MarkDispatchedAsync([first.EventId], CancellationToken.None));
            Assert.True(failure is IOException or UnauthorizedAccessException,
                $"Expected a filesystem refusal, received: {failure?.GetType().Name ?? "no exception"}");
        }
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(workspace.QueueFile)));
        Assert.Empty(Directory.GetFiles(workspace.Root, "*.tmp"));
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(first.EventId, Assert.Single(await reopened.ReadPendingAsync(1, CancellationToken.None)).EventId);
        await reopened.MarkDispatchedAsync([first.EventId], CancellationToken.None);
        Assert.Empty(await reopened.ReadPendingAsync(1, CancellationToken.None));
        Assert.Equal(new[] { unknown, corrupt }, (await File.ReadAllLinesAsync(workspace.QueueFile)).Skip(1));
    }

    private static AuditEvent Event(int index) => new(Guid.NewGuid(),
        new DateTimeOffset(2026, 10, 22, 12, 0, 0, TimeSpan.Zero).AddSeconds(index),
        "PC-SINTETICO", "usuario-sintetico", $"sintetico-{index}.txt", ".txt", 42,
        Verdict.Blocked, [Category.Cpf], ["LOCAL_ONLY_SYNTHETIC"], "processo-sintetico", 123,
        @"C:\DestinoSintetico", null, 1, 10, false);

    private sealed class Policies : IPolicyStore
    {
        public Task<Policy> LoadAsync(CancellationToken token) => Task.FromResult(LocalPolicyStore.CreateDefault());
    }
}
