using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;

namespace SafeUpload.Agent.Tests;

public sealed class PublicationAuditQueueTests
{
    private static AuditEvent Event() => new(Guid.NewGuid(), DateTimeOffset.UtcNow, "synthetic-pc", "synthetic-user",
        "file.txt", ".txt", 10, Verdict.Approved, [Category.Cpf], ["masked"], "explorer", 123,
        @"C:\Synthetic\file.txt", null, 7, 1, false) { OwnerSid = "S-1-5-21-111-222-333-1001" };

    [Fact]
    public async Task Concurrent_replays_append_one_event_and_keep_dispatched_state_on_later_replay()
    {
        using var work = new TestWorkspace();
        var sink = new LocalQueueAuditSink(work.QueueFile);
        var item = Event();
        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => sink.WritePublicationAsync(item, true, default)));
        Assert.Single(await sink.ReadRecentAsync(0, default));
        await sink.MarkDispatchedAsync([item.EventId], default);
        byte[] before = File.ReadAllBytes(work.QueueFile);
        await new LocalQueueAuditSink(work.QueueFile).WritePublicationAsync(item, true, default);
        Assert.Equal(before, File.ReadAllBytes(work.QueueFile));
        Assert.Empty(await sink.ReadPendingAsync(10, default));
    }

    [Theory]
    [InlineData("reason")]
    [InlineData("categories")]
    [InlineData("timestamp")]
    [InlineData("owner")]
    [InlineData("hash")]
    [InlineData("size")]
    public async Task Conflicting_payload_for_the_same_id_never_acknowledges_or_overwrites_history(string field)
    {
        using var work = new TestWorkspace();
        var sink = new LocalQueueAuditSink(work.QueueFile);
        var item = Event();
        var conflict = field switch
        {
            "reason" => item with { NotInspectedReason = "changed" },
            "categories" => item with { Categories = [Category.Cnpj] },
            "timestamp" => item with { OccurredAtUtc = item.OccurredAtUtc.AddSeconds(1) },
            "owner" => item with { OwnerSid = "another-owner" },
            "hash" => item with { PublishedSha256Hex = new string('F', 64) },
            _ => item with { SizeBytes = 11 }
        };
        await sink.WriteAsync(conflict, default);
        byte[] before = File.ReadAllBytes(work.QueueFile);
        await Assert.ThrowsAsync<IOException>(() => sink.WritePublicationAsync(item, true, default));
        Assert.Equal(before, File.ReadAllBytes(work.QueueFile));
    }

    [Fact]
    public async Task Override_and_unrelated_malformed_lines_do_not_acknowledge_an_event()
    {
        using var work = new TestWorkspace();
        var sink = new LocalQueueAuditSink(work.QueueFile);
        var item = Event();
        File.WriteAllText(work.QueueFile, "{\"eventId\":17}\nmalformed\n");
        await sink.RecordOverrideAsync(item.EventId.ToString(), "Synthetic reason", default);
        await File.AppendAllTextAsync(work.QueueFile, "{\"unfinished\":");
        await sink.WritePublicationAsync(item, true, default);
        Assert.Single(await sink.ReadRecentAsync(0, default));
        Assert.Single(await sink.ReadPendingOverridesAsync(10, default));
        Assert.Contains("{\"unfinished\":", File.ReadAllText(work.QueueFile));
    }

    [Fact]
    public async Task Duplicate_properties_on_the_requested_id_are_not_silently_accepted()
    {
        using var work = new TestWorkspace();
        var sink = new LocalQueueAuditSink(work.QueueFile);
        var item = Event();
        await sink.WriteAsync(item, default);
        string original = File.ReadAllText(work.QueueFile);
        string ambiguous = original.Replace("\"sizeBytes\":10", "\"sizeBytes\":11,\"sizeBytes\":10");
        Assert.NotEqual(original, ambiguous);
        File.WriteAllText(work.QueueFile, ambiguous);
        await Assert.ThrowsAsync<IOException>(() => sink.WritePublicationAsync(item, true, default));
        Assert.Equal(ambiguous, File.ReadAllText(work.QueueFile));
    }

    [Fact]
    public async Task Monitored_durable_write_reports_failure_and_recovery_without_swallowing_the_error()
    {
        using var work = new TestWorkspace();
        var inner = new LocalQueueAuditSink(work.QueueFile);
        var health = new AuditQueueHealth();
        var sink = new MonitoredAuditSink(inner, health, NullLogger<MonitoredAuditSink>.Instance);
        var item = Event();
        Directory.CreateDirectory(work.QueueFile);
        var error = await Record.ExceptionAsync(() => sink.WritePublicationAsync(item, false, default));
        Assert.True(error is IOException or UnauthorizedAccessException);
        Assert.True(health.Read().Degraded);
        Directory.Delete(work.QueueFile);
        await sink.WritePublicationAsync(item, true, default);
        Assert.False(health.Read().Degraded);
        Assert.Single(await inner.ReadRecentAsync(0, default));
    }
}
