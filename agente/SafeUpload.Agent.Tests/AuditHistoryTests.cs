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
    [Theory]
    [InlineData(false, 229, true)]
    [InlineData(false, 0, false)]
    [InlineData(false, 5, false)]
    [InlineData(false, 6, false)]
    [InlineData(false, 233, false)]
    [InlineData(true, 0, false)]
    [InlineData(true, 229, false)]
    public void Identidade_de_processo_local_exige_transporte_local_confirmado(bool hasRemoteName, int error, bool expected) =>
        Assert.Equal(expected, SessionResolver.IsConfirmedLocalPipe(hasRemoteName, error));

    [Fact]
    public async Task Sid_e_autoritativo_sem_fallback_para_nome_igual_ou_evento_compartilhado()
    {
        const string mine = "S-1-5-21-1-2-3-1001", other = "S-1-5-21-1-2-3-1002";
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var own = Event("OLD-DOMAIN\\old-name") with { OwnerSid = mine, Channel = AuditChannel.Web };
        var sameNameOtherSid = Event("CURRENT\\alice") with { OwnerSid = other };
        var sharedOtherSid = Event(Environment.MachineName + "$") with { OwnerSid = other };
        foreach (var item in new[] { own, sameNameOtherSid, sharedOtherSid }) await sink.WriteAsync(item, CancellationToken.None);
        var reader = new AuditHistoryReader(new LocalQueueAuditSink(_workspace.QueueFile));
        var history = await reader.ReadAsync("CURRENT\\alice", CancellationToken.None, mine);
        Assert.Equal(own.EventId, Assert.Single(history.Events).EventId);
        // A failed account-name lookup still permits only the authenticated SID's events.
        history = await reader.ReadAsync(null, CancellationToken.None, mine);
        Assert.True(history.Available);
        Assert.Equal(own.EventId, Assert.Single(history.Events).EventId);
        var invalid = await reader.ReadAsync("CURRENT\\alice", CancellationToken.None, "invalid-sid");
        Assert.False(invalid.Available); Assert.Empty(invalid.Events);
        var namesOnly = await reader.ReadAsync("CURRENT\\alice", CancellationToken.None);
        Assert.Empty(namesOnly.Events);
    }

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
        Assert.Equal(500, model.History.Events.Count);
        Assert.Contains("indisponível", model.History.AvailabilityMessage);
        model.ApplyHistory(new HistoryNotification([]));
        Assert.Contains("Nenhuma operação", model.History.EmptyMessage);
    }

    [Fact]
    public async Task Filtro_de_conta_ocorre_antes_do_limite_e_o_arquivo_permanece_inalterado()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var own = Event();
        await sink.WriteAsync(own, CancellationToken.None);
        for (int i = 0; i < 520; i++) await sink.WriteAsync(Event("LAB\\bob"), CancellationToken.None);
        var before = await File.ReadAllBytesAsync(_workspace.QueueFile);
        var history = await new AuditHistoryReader(sink).ReadAsync("LAB\\alice", CancellationToken.None);
        Assert.Equal(own.EventId, Assert.Single(history.Events).EventId);
        Assert.Equal(before, await File.ReadAllBytesAsync(_workspace.QueueFile));
    }

    [Fact]
    public async Task Tamanho_da_mensagem_e_limitado_sem_enviar_linha_grande_ou_conta_alheia()
    {
        var sink = new LocalQueueAuditSink(_workspace.QueueFile);
        var own = Event();
        await sink.WriteAsync(own, CancellationToken.None);
        await sink.WriteAsync(Event() with { MaskedSnippets = [new string('x', HistoryNotification.MaximumPayloadBytes)] }, CancellationToken.None);
        var history = await new AuditHistoryReader(sink).ReadAsync("LAB\\alice", CancellationToken.None);
        Assert.True(history.Truncated);
        Assert.Equal(own.EventId, Assert.Single(history.Events).EventId);
        Assert.True(NotificationProtocol.Encoding.GetByteCount(NotificationProtocol.Serialize(history)) <= HistoryNotification.MaximumPayloadBytes);
    }

    [Theory]
    [InlineData("{\"type\":\"history\"}")]
    [InlineData("{\"type\":\"history\",\"events\":[null]}")]
    [InlineData("{\"type\":\"history\",\"events\":[{}]}")]
    public void Historico_malformado_nao_chega_a_interface(string json) => Assert.Null(NotificationProtocol.Deserialize(json));

    [Fact]
    public void Historico_nao_pode_ser_publicado_ou_reproduzido_para_outros_assinantes()
    {
        var hub = NotificationTestHub.Create();
        using var subscriber = hub.Subscribe(1, "S-TEST-1");
        var history = new HistoryNotification([Event()]);
        Assert.Throws<InvalidOperationException>(() => hub.Publish(history));
        Assert.True(hub.RecordHistory(history, 1));
        Assert.False(subscriber.Reader.TryRead(out _));
        using var other = hub.Subscribe(2, "S-TEST-2");
        Assert.False(other.Reader.TryRead(out _));
    }

    [Fact]
    public void Registro_de_emissao_de_historico_e_reaberto_sem_conter_os_eventos()
    {
        var directory = Path.Combine(_workspace.Root, "notifications");
        var item = Event() with { FileName = "PRIVATE-HISTORY-FILE" };
        using (var record = new NotificationRecord(directory, NullLogger<NotificationRecord>.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true))
            record.Append(new HistoryNotification([item]), 1);
        string text = File.ReadAllText(Path.Combine(directory, "emissions.jsonl"));
        Assert.Contains("History", text);
        Assert.DoesNotContain("PRIVATE-HISTORY-FILE", text);
        Assert.DoesNotContain(item.EventId.ToString(), text);
        using var reopened = new NotificationRecord(directory, NullLogger<NotificationRecord>.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true);
    }

    [Fact]
    public async Task Real_pipe_sends_persisted_history_before_live_events_and_restores_it_on_reconnect()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var own = Event(identity.Name) with { OwnerSid = identity.User!.Value };
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
