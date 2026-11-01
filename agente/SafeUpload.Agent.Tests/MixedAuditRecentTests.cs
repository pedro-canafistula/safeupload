using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;

namespace SafeUpload.Agent.Tests;

public sealed class MixedAuditRecentTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() }
    };
    private static AuditEvent Event(int index) => new(Guid.NewGuid(), DateTimeOffset.UtcNow,
        "SYNTHETIC-ENDPOINT", "synthetic-user", "relatório-" + new string('界', index == 7 ? 6000 : 20) + index + ".txt",
        ".txt", 1, Verdict.Blocked, [Category.Cpf], [], "test", 1, @"C:\Synthetic", null, 7, 1, false);

    [Theory]
    [InlineData("utf8", "\n")]
    [InlineData("utf8-bom", "\r\n")]
    [InlineData("utf8", "\r")]
    [InlineData("utf16", "\n")]
    [InlineData("utf32", "\n")]
    public async Task Recent_tail_and_full_reader_select_only_events_in_a_mixed_history(string format, string newline)
    {
        var events = Enumerable.Range(0, 12).Select(Event).ToArray();
        var lines = new List<string>();
        foreach (var entry in events)
        {
            lines.Add(JsonSerializer.Serialize(entry, Options));
            lines.Add(JsonSerializer.Serialize(new { type = "override", eventId = entry.EventId,
                justification = "finalidade de teste", occurredAtUtc = DateTimeOffset.UtcNow,
                userName = "S-1-5-21-123-456-789-1001", endpointId = "SYNTHETIC-ENDPOINT" }, Options));
            lines.Add(JsonSerializer.Serialize(new { type = "future", eventId = entry.EventId, future = true }, Options));
            lines.Add("null"); lines.Add("[]"); lines.Add("{}"); lines.Add("{truncated");
        }
        Encoding encoding = format switch
        {
            "utf8-bom" => new UTF8Encoding(true), "utf16" => Encoding.Unicode,
            "utf32" => new UTF32Encoding(false, true), _ => new UTF8Encoding(false)
        };
        await File.WriteAllTextAsync(_workspace.QueueFile, string.Join(newline, lines), encoding);
        byte[] before = SHA256.HashData(await File.ReadAllBytesAsync(_workspace.QueueFile));
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var all = await sink.ReadRecentAsync(0, default);
        Assert.Equal(events.Reverse().Select(e => e.EventId), all.Select(e => e.EventId));
        foreach (int count in new[] { 1, 5, 12, 20 })
            Assert.Equal(all.Take(count).Select(e => JsonSerializer.Serialize(e, Options)),
                (await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(count, default))
                    .Select(e => JsonSerializer.Serialize(e, Options)));
        Assert.Equal(12, (await sink.ReadPendingOverridesAsync(100, default)).Count);
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(_workspace.QueueFile)));
    }

    [Fact]
    public async Task Event_and_override_acknowledgements_preserve_tail_selection_and_typed_unknown_lines()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var events = Enumerable.Range(0, 6).Select(Event).ToArray();
        foreach (var entry in events)
        {
            await sink.WriteAsync(entry, default);
            await sink.RecordOverrideAsync(new AuditOverride(entry.EventId, "purpose", DateTimeOffset.UtcNow,
                "S-1-5-21-123-456-789-1001", "SYNTHETIC-ENDPOINT"), default);
        }
        const string unknown = "{\"type\":\"future\",\"eventId\":\"00000000-0000-0000-0000-000000000001\",\"x\":42}";
        await File.AppendAllTextAsync(_workspace.QueueFile, unknown + Environment.NewLine);
        var batch = await sink.ReadPendingOverridesAsync(3, default);
        await sink.MarkDispatchedAsync(events.Take(3).Select(e => e.EventId).ToArray(), default);
        await sink.MarkOverridesDispatchedAsync(batch, default);
        var reopened = new LocalQueueAuditSink(_workspace.QueueFile);
        var all = await reopened.ReadRecentAsync(0, default);
        Assert.Equal(events.Reverse().Select(e => e.EventId), all.Select(e => e.EventId));
        Assert.Equal(all.Take(5).Select(e => JsonSerializer.Serialize(e, Options)),
            (await reopened.ReadRecentAsync(5, default)).Select(e => JsonSerializer.Serialize(e, Options)));
        Assert.Equal(3, (await reopened.ReadPendingAsync(100, default)).Count);
        Assert.Equal(3, (await reopened.ReadPendingOverridesAsync(100, default)).Count);
        Assert.Contains(unknown, await File.ReadAllLinesAsync(_workspace.QueueFile));
    }
}
