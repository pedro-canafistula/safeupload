using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using Xunit.Abstractions;

namespace SafeUpload.Agent.Tests;

[Collection("Journal scaling")]
public sealed class AuditRecentScalingTests(ITestOutputHelper output) : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    public void Dispose() => _workspace.Dispose();
    private static AuditEvent Event(int cycle) => new(Guid.NewGuid(), DateTimeOffset.UtcNow,
        "fixture", "observer", $"destination-{cycle % 8}.txt", ".txt", 5, Verdict.Approved,
        [], [], "powershell", 2345, $@"C:\Protected\t4\destination-{cycle % 8}.txt", null, 1, 1, false);

    private static string Serialize(AuditEvent entry) => System.Text.Json.JsonSerializer.Serialize(entry,
        new System.Text.Json.JsonSerializerOptions {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });

    [Fact]
    public async Task Ten_thousand_repeated_saves_to_eight_names_keep_recent_outcome_work_bounded()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        AuditEvent[] expected = new AuditEvent[10_000];
        for (int i = 0; i < expected.Length; i++)
        {
            expected[i] = Event(i);
            await sink.WriteAsync(expected[i], default);
        }
        // Recreate the sink: no per-process cache may stand in for the retained
        // on-disk audit history used by Announce after public-file observation.
        sink = new LocalQueueAuditSink(_workspace.QueueFile);
        byte[] before = SHA256.HashData(await File.ReadAllBytesAsync(_workspace.QueueFile));
        await sink.ReadRecentAsync(5, default); // JIT/serializer warmup
        long allocated = GC.GetTotalAllocatedBytes(true);
        var timer = Stopwatch.StartNew();
        for (int save = 0; save < 8; save++)
        {
            var recent = await sink.ReadRecentAsync(5, default);
            Assert.Equal(expected.TakeLast(5).Reverse().Select(e => e.EventId), recent.Select(e => e.EventId));
        }
        double ms = timer.Elapsed.TotalMilliseconds;
        long bytes = GC.GetTotalAllocatedBytes(true) - allocated;
        output.WriteLine($"10k / eight names: recent outcome reads(8)={ms:F3}ms/{bytes}B; per-save={ms / 8:F3}ms");
        Assert.InRange(bytes, 0, 2 * 1024 * 1024);
        Assert.InRange(ms, 0, 1000);
        Assert.Equal(before, SHA256.HashData(await File.ReadAllBytesAsync(_workspace.QueueFile)));
        Assert.Equal(expected.Length, (await sink.ReadRecentAsync(0, default)).Count);
    }

    [Theory]
    [InlineData("\n", false)]
    [InlineData("\r\n", false)]
    [InlineData("\r", false)]
    [InlineData("\n", true)]
    public async Task Recent_tail_matches_full_history_across_unicode_block_edges_and_damaged_lines(string newline, bool bom)
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        for (int i = 0; i < 40; i++)
        {
            var entry = Event(i) with { FileName = "relatório-" + new string('界', i == 35 ? 20_000 : 1000) + i };
            await File.AppendAllTextAsync(_workspace.QueueFile, Serialize(entry) + "\n{broken\n\nnull\n");
        }
        string text = (await File.ReadAllTextAsync(_workspace.QueueFile)).Replace("\r\n", "\n").Replace("\n", newline);
        // Also accept a valid final record without a newline, as StreamReader did.
        text += Serialize(Event(40));
        await File.WriteAllTextAsync(_workspace.QueueFile, text, new UTF8Encoding(bom));
        var all = await sink.ReadRecentAsync(0, default);
        Assert.Equal(41, all.Count);
        foreach (int count in new[] { 1, 5, 17, 100 })
            Assert.Equal(all.Take(count).Select(e => (e.EventId, e.FileName)),
                (await new LocalQueueAuditSink(_workspace.QueueFile).ReadRecentAsync(count, default))
                    .Select(e => (e.EventId, e.FileName)));
    }

    [Theory]
    [InlineData("utf16-le")]
    [InlineData("utf16-be")]
    [InlineData("utf32-le")]
    [InlineData("utf32-be")]
    public async Task Missing_empty_legacy_encoding_append_and_dispatch_keep_recent_read_semantics(string legacyEncoding)
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        Assert.Empty(await sink.ReadRecentAsync(5, default));
        await File.WriteAllTextAsync(_workspace.QueueFile, "");
        Assert.Empty(await sink.ReadRecentAsync(5, default));
        var first = Event(1); var second = Event(2);
        string line = Serialize(first);
        Encoding encoding = legacyEncoding switch {
            "utf16-le" => Encoding.Unicode,
            "utf16-be" => Encoding.BigEndianUnicode,
            "utf32-le" => new UTF32Encoding(false, true),
            "utf32-be" => new UTF32Encoding(true, true),
            _ => throw new ArgumentException(nameof(legacyEncoding))
        };
        await File.WriteAllTextAsync(_workspace.QueueFile, line + "\n", encoding);
        Assert.Equal(first.EventId, Assert.Single(await sink.ReadRecentAsync(1, default)).EventId);
        await File.WriteAllTextAsync(_workspace.QueueFile, line + "\n", new UTF8Encoding(true));
        Assert.Equal(first.EventId, Assert.Single(await sink.ReadRecentAsync(1, default)).EventId);
        await sink.WriteAsync(second, default);
        await sink.MarkDispatchedAsync([first.EventId], default);
        Assert.Equal(new[] { second.EventId, first.EventId },
            (await sink.ReadRecentAsync(5, default)).Select(e => e.EventId));
        Assert.True((await sink.ReadRecentAsync(5, default))[1].Dispatched);
        Assert.Equal(2, (await sink.ReadRecentAsync(-1, default)).Count);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sink.ReadRecentAsync(5, cancelled.Token));
    }
}
