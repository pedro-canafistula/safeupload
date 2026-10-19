using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class PendingAuditBatchTests
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };
    private static AuditEvent Event(bool sent = false) => new(Guid.NewGuid(), DateTimeOffset.UtcNow,
        "PC-TESTE", "usuario", "synthetic.txt", ".txt", 10, Verdict.Blocked, [Category.Cpf], [],
        "teste", 1, @"E:\destino", null, 1, 1, sent);
    private static string Line(AuditEvent entry) => JsonSerializer.Serialize(entry, Options);

    [Fact]
    public async Task Batch_stops_at_the_last_selected_record_without_reading_the_tail()
    {
        var first = Event();
        var second = Event();
        using var reader = new LimitedReader([
            Line(Event(true)), "not-json", "[]", "{\"type\":\"override\"}", Line(first),
            "", Line(Event(true)), Line(second)]);
        var result = await LocalQueueAuditSink.ReadEventsAsync(reader, true, 2, default);
        Assert.Equal(new[] { first.EventId, second.EventId }, result.Select(e => e.EventId));
        Assert.Equal(8, reader.Reads);
        // A further read throws. Completing this request proves no EOF probe
        // or parsing of the retained history after the selected batch.
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Nonpositive_limit_retains_existing_unlimited_pending_semantics(int limit)
    {
        var first = Event();
        var second = Event();
        using var reader = new StringReader(string.Join("\n", Line(first), Line(Event(true)), Line(second)));
        var result = await LocalQueueAuditSink.ReadEventsAsync(reader, true, limit, default);
        Assert.Equal(new[] { first.EventId, second.EventId }, result.Select(e => e.EventId));
    }

    [Theory]
    [InlineData("utf8")]
    [InlineData("utf16")]
    [InlineData("utf32")]
    public async Task Real_queue_preserves_encoding_order_history_unknown_lines_and_reopen_retry(string encodingName)
    {
        using var workspace = new TestWorkspace();
        var history = Event(true);
        var first = Event();
        var second = Event();
        Encoding encoding = encodingName switch
        {
            "utf16" => Encoding.Unicode, "utf32" => Encoding.UTF32, _ => new UTF8Encoding(true)
        };
        string[] lines = [Line(history), "", "not-json", "[]", "{\"type\":\"future\",\"opaque\":73}",
            Line(first), Line(Event() with { EventId = Guid.Empty }), Line(second)];
        await File.WriteAllTextAsync(workspace.QueueFile, string.Join("\n", lines), encoding);
        byte[] before = await File.ReadAllBytesAsync(workspace.QueueFile);
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(first.EventId, Assert.Single(await sink.ReadPendingAsync(1, default)).EventId);
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Equal(new[] { first.EventId, second.EventId },
            (await sink.ReadPendingAsync(100, default)).Select(e => e.EventId));
        Assert.Equal(3, (await sink.ReadRecentAsync(0, default)).Count);
        await sink.MarkDispatchedAsync([first.EventId], default);
        var reopened = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(second.EventId, Assert.Single(await reopened.ReadPendingAsync(1, default)).EventId);
        string persisted = await File.ReadAllTextAsync(workspace.QueueFile);
        Assert.Contains("not-json", persisted);
        Assert.Contains("\"opaque\":73", persisted);
        Assert.Equal(3, (await reopened.ReadRecentAsync(0, default)).Count);
    }

    [Fact]
    public async Task Cancelled_pending_read_does_not_mutate_queue_or_prevent_the_next_read()
    {
        using var workspace = new TestWorkspace();
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        var entry = Event();
        await sink.WriteAsync(entry, default);
        byte[] before = await File.ReadAllBytesAsync(workspace.QueueFile);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.ReadPendingAsync(1, cancelled.Token));
        Assert.Equal(before, await File.ReadAllBytesAsync(workspace.QueueFile));
        Assert.Equal(entry.EventId, Assert.Single(await sink.ReadPendingAsync(1, default)).EventId);
    }

    [Fact]
    public async Task Dispatched_history_is_not_deserialized_into_the_pending_batch()
    {
        // The historical entry has a schema field that cannot deserialize.
        // It is already sent; neither it nor unknown/truncated rows fill a batch.
        using var workspace = new TestWorkspace();
        var pending = Event();
        await File.WriteAllTextAsync(workspace.QueueFile,
            "{\"eventId\":\""+Guid.NewGuid()+"\",\"dispatched\":true,\"verdict\":{}}\n"+Line(pending));
        var sink = new LocalQueueAuditSink(workspace.QueueFile);
        Assert.Equal(pending.EventId, Assert.Single(await sink.ReadPendingAsync(1, default)).EventId);
    }

    private sealed class LimitedReader(string[] lines) : TextReader
    {
        public int Reads { get; private set; }
        public override ValueTask<string?> ReadLineAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (Reads == lines.Length) throw new InvalidOperationException("Batch read past its selected tail.");
            return ValueTask.FromResult<string?>(lines[Reads++]);
        }
    }
}
