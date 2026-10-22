using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class AuditHistoryTests : IDisposable
{
    private readonly TestWorkspace _workspace = new();
    private static AuditEvent Event(string user = "LAB\\alice") => new(Guid.NewGuid(),
        DateTimeOffset.UtcNow.AddMinutes(-5), Environment.MachineName, user, "synthetic.txt", ".txt", 29,
        Verdict.Blocked, [Category.Cpf], ["•••••••••25"], "desconhecido", 0,
        @"C:\SafeUpload\Escopo Monitorado", null, 1, 28, false);
    public void Dispose() => _workspace.Dispose();

    [Fact]
    public async Task Persisted_history_survives_reader_restart_without_exposing_other_accounts()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var own = Event();
        var shared = Event(Environment.MachineName + "$");
        foreach (var item in new[] { own, Event("LAB\\bob"), shared,
            shared with { EventId = Guid.NewGuid(), Channel = AuditChannel.Clipboard },
            shared with { EventId = Guid.NewGuid(), Channel = AuditChannel.Web },
            shared with { EventId = Guid.NewGuid(), ProcessId = 42 },
            own with { EventId = Guid.NewGuid(), EndpointId = "OTHER-PC" }, Event("alice") })
            await sink.WriteAsync(item, CancellationToken.None);

        var reader = new AuditHistoryReader(new LocalQueueAuditSink(_workspace.QueueFile));
        var history = await reader.ReadAsync("lab\\ALICE", CancellationToken.None);
        Assert.True(history.Available);
        Assert.Equal(new[] { shared.EventId, own.EventId }, history.Events.Select(e => e.EventId));
        Assert.All(history.Events, e => Assert.DoesNotContain("52998224725", string.Join("", e.MaskedSnippets)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("alice")]
    public async Task Missing_or_unqualified_identity_receives_no_history(string? account)
    {
        var history = await new AuditHistoryReader(new LocalQueueAuditSink(_workspace.QueueFile))
            .ReadAsync(account, CancellationToken.None);
        Assert.False(history.Available);
        Assert.Empty(history.Events);
    }

    [Fact]
    public void Snapshot_roundtrip_and_replay_do_not_duplicate_rows()
    {
        var item = Event();
        var serialized = NotificationProtocol.Serialize(new HistoryNotification([item, item]));
        var history = Assert.IsType<HistoryNotification>(NotificationProtocol.Deserialize(serialized.TrimEnd('\n')));
        var model = new AgentViewModel(new StatusViewModel(), new HistoryViewModel());
        model.ApplyHistory(history);
        model.ApplyHistory(history); // Reconnect replaces, rather than appending.
        Assert.False(model.History.Prepend(item)); // False suppresses an old block popup.
        model.Status.PrependActivity(item);
        Assert.Single(model.History.Events);
        Assert.Single(model.Status.RecentActivity);
        Assert.Equal(item.EventId, model.History.Events[0].EventId);
    }

    [Fact]
    public void History_and_activity_have_limits_and_unavailable_is_distinct_from_empty()
    {
        var items = Enumerable.Range(0, 510).Select(_ => Event()).ToArray();
        var model = new AgentViewModel(new StatusViewModel(), new HistoryViewModel());
        Assert.Contains("Aguardando", model.History.EmptyMessage);
        model.ApplyHistory(new HistoryNotification(items));
        Assert.Equal(500, model.History.Events.Count);
        Assert.Equal(8, model.Status.RecentActivity.Count);
        Assert.True(model.History.Prepend(Event()));
        Assert.Equal(500, model.History.Events.Count);
        model.ApplyHistory(new HistoryNotification([], Available: false));
        Assert.True(model.History.IsEmpty);
        Assert.Contains("indisponível", model.History.EmptyMessage);
        model.ApplyHistory(new HistoryNotification([]));
        Assert.Contains("Nenhuma operação", model.History.EmptyMessage);
    }

    [Fact]
    public async Task Real_pipe_sends_persisted_history_before_live_events_and_restores_it_on_reconnect()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var own = Event(identity.Name);
        var shared = Event(Environment.MachineName + "$");
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        foreach (var item in new[] { own, shared, Event("OTHER\\person") })
            await sink.WriteAsync(item, CancellationToken.None);
        string name = "SafeUpload.Test.History." + Guid.NewGuid().ToString("N");
        var hub = NotificationTestHub.Create();
        hub.Publish(new StatusNotification(1, 5, true, AuditOnly: true));
        using var server = new NotificationPipeServer(hub, NullLogger<NotificationPipeServer>.Instance,
            new AuditHistoryReader(sink), name);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await server.StartAsync(timeout.Token);
        try
        {
            for (int connection = 0; connection < 2; connection++)
            {
                using var pipe = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(timeout.Token);
                using var reader = new StreamReader(pipe, NotificationProtocol.Encoding);
                Assert.IsType<StatusNotification>(NotificationProtocol.Deserialize((await reader.ReadLineAsync(timeout.Token))!));
                var history = Assert.IsType<HistoryNotification>(NotificationProtocol.Deserialize((await reader.ReadLineAsync(timeout.Token))!));
                Assert.True(history.Available);
                Assert.Equal(new[] { shared.EventId, own.EventId }, history.Events.Select(e => e.EventId));
                if (connection == 0)
                {
                    hub.Publish(new EventNotification(Event(), []));
                    Assert.IsType<EventNotification>(NotificationProtocol.Deserialize((await reader.ReadLineAsync(timeout.Token))!));
                }
            }
        }
        finally { await server.StopAsync(CancellationToken.None); }
    }
}
