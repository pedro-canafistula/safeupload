using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Audit;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class AuditWriteTrayTests
{
    private static AuditWriteFailureDiagnostics Diagnostics() => new(NullLogger<AuditWriteFailureDiagnostics>.Instance);
    private static NotificationHub Hub(Record record) => new(record, NullLogger<NotificationHub>.Instance);
    private static AuditWriteStatusPublisher Publisher(AuditWriteFailureDiagnostics diagnostic, NotificationHub hub) =>
        new(diagnostic, hub, NullLogger<AuditWriteStatusPublisher>.Instance);

    [Fact]
    public void Legacy_wire_omits_optional_diagnostic_and_new_wire_remains_readable_by_old_clients()
    {
        var original = new StatusNotification(1, 2, false);
        string legacy = NotificationProtocol.Serialize(original);
        Assert.DoesNotContain("auditWrites", legacy);
        Assert.Equal(original, NotificationProtocol.Deserialize(legacy));
        var current = original with { AuditWrites = new(1, "event", "io") };
        string wire = NotificationProtocol.Serialize(current);
        Assert.Equal(current, NotificationProtocol.Deserialize(wire));
        Assert.Equal(new LegacyStatus(1, 2, false),
            JsonSerializer.Deserialize<LegacyStatus>(wire, NotificationProtocol.JsonOptions));
    }

    [Fact]
    public void Projection_only_contains_fixed_diagnostic_metadata()
    {
        var diagnostic = Diagnostics();
        Assert.Equal(new AuditWriteStatus(0, null, null), diagnostic.ForNotification());
        diagnostic.OnWriteFailure(AuditWriteKind.Override, new IOException("secret-file CPF justification"));
        Assert.Equal(new AuditWriteStatus(1, "override", "io"), diagnostic.ForNotification());
        string wire = NotificationProtocol.Serialize(new StatusNotification(1, 2, false)
        { AuditWrites = diagnostic.ForNotification() });
        Assert.DoesNotContain("secret", wire);
        Assert.DoesNotContain("CPF", wire);
        diagnostic.OnWriteFailure((AuditWriteKind)99, new Exception("secret"));
        Assert.Equal(new AuditWriteStatus(2, "event", "unexpected"), diagnostic.ForNotification());
    }

    [Fact]
    public void Summary_waits_for_real_status_and_survives_alternating_policy_and_interceptor_updates()
    {
        var record = new Record();
        var hub = Hub(record);
        var audit = new AuditWriteStatus(1, "event", "io");
        Assert.True(hub.PublishAuditWrites(audit));
        Assert.Null(hub.CurrentStatus);
        Assert.Empty(record.Messages);
        var actual = new StatusNotification(7, 3, true, true, AdmissionCoverageStatus.Degraded, "held", 19);
        Assert.True(hub.Publish(actual));
        var policy = new PolicyIntegrationStatus(8, "remote", 8, 7, true, false, false, false);
        Assert.True(hub.PublishPolicyIntegration(policy));
        Assert.True(hub.PublishAuditWrites(audit with { FailureCount = 2 }));
        Assert.True(hub.Publish(actual with { ActiveCategories = 4 }));
        var current = hub.CurrentStatus!;
        Assert.Equal(actual with { ActiveCategories = 4 }, current with { AuditWrites = null, PolicyIntegration = null });
        Assert.Equal(policy, current.PolicyIntegration);
        Assert.Equal(2, current.AuditWrites!.FailureCount);
        int before = record.Messages.Count;
        for (int index = 0; index < 100; index++) Assert.True(hub.PublishAuditWrites(current.AuditWrites));
        Assert.Equal(before, record.Messages.Count);
    }

    [Fact]
    public async Task Failed_record_suppresses_delivery_preserves_status_and_retries_the_same_summary()
    {
        var diagnostic = Diagnostics();
        var record = new Record();
        var hub = Hub(record);
        hub.Publish(new StatusNotification(1, 2, false));
        using var publisher = Publisher(diagnostic, hub);
        Assert.True(publisher.PublishOnce());
        var before = hub.CurrentStatus;
        using var subscription = hub.Subscribe();
        diagnostic.OnWriteFailure(AuditWriteKind.Event, new UnauthorizedAccessException("private"));
        record.Fail = true;
        Assert.False(publisher.PublishOnce());
        Assert.Equal(before, hub.CurrentStatus);
        Assert.False(subscription.Reader.TryRead(out _));
        Assert.Null(hub.GetRecordedStatus());
        record.Fail = false;
        Assert.True(publisher.PublishOnce());
        var notice = Assert.IsType<StatusNotification>(await subscription.Reader.ReadAsync());
        Assert.Equal(new AuditWriteStatus(1, "event", "access_denied"), notice.AuditWrites);
        Assert.False(notice.ProtectionActive);
    }

    [Theory]
    [InlineData("event", "io", "evento", "entrada e saída")]
    [InlineData("override", "access_denied", "justificativa", "acesso negado")]
    [InlineData("event", "interrupted", "evento", "gravação interrompida")]
    [InlineData("private-kind", "private-error", "registro", "falha não especificada")]
    public void Failure_display_uses_safe_labels_and_preserves_history(string kind, string error, string label, string message)
    {
        var display = AuditWritePresentation.From(new(3, kind, error));
        Assert.Contains("3", display.Summary);
        Assert.Contains(label, display.Detail);
        Assert.Contains(message, display.Detail);
        Assert.Contains("não recuperam", display.Message);
        Assert.DoesNotContain("private", display.ToString());
    }

    [Fact]
    public void Zero_unknown_disconnect_and_large_counts_do_not_claim_complete_audit_or_recovery()
    {
        Assert.Equal(AuditWritePresentation.Unavailable, AuditWritePresentation.From(null));
        Assert.Equal(AuditWritePresentation.Unavailable, AuditWritePresentation.From(new(-1, null, null)));
        var zero = AuditWritePresentation.From(new(0, null, null));
        Assert.Equal("Nenhuma falha relatada pelo serviço", zero.Summary);
        Assert.Contains("não confirma", zero.Message);
        Assert.Contains("Sem comunicação", AuditWritePresentation.Disconnected.Summary);
        Assert.Contains("9223372036854775807", AuditWritePresentation.From(new(long.MaxValue, null, null)).Summary);
    }

    [Fact]
    public async Task Private_pipe_delivers_latest_diagnostic_on_reconnect_without_changing_protection()
    {
        string name = "SafeUpload.Agent.AuditTest." + Guid.NewGuid().ToString("N");
        var hub = Hub(new Record());
        hub.Publish(new StatusNotification(2, 3, false));
        hub.PublishAuditWrites(new(1, "override", "io"));
        using var server = new NotificationPipeServer(hub, NullLogger<NotificationPipeServer>.Instance, name);
        await server.StartAsync(default);
        try
        {
            for (int index = 0; index < 2; index++)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var client = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous);
                await client.ConnectAsync(deadline.Token);
                using var reader = new StreamReader(client, NotificationProtocol.Encoding);
                var notice = Assert.IsType<StatusNotification>(
                    NotificationProtocol.Deserialize((await reader.ReadLineAsync(deadline.Token))!));
                Assert.Equal(new AuditWriteStatus(1, "override", "io"), notice.AuditWrites);
                Assert.False(notice.ProtectionActive);
            }
        }
        finally { await server.StopAsync(default); }
    }

    [Fact]
    public async Task Background_publisher_sends_history_and_stops_on_cancellation()
    {
        var diagnostic = Diagnostics();
        diagnostic.OnWriteFailure(AuditWriteKind.Event, new IOException("private"));
        var hub = Hub(new Record());
        hub.Publish(new StatusNotification(1, 2, false));
        using var subscription = hub.Subscribe();
        using var publisher = Publisher(diagnostic, hub);
        await publisher.StartAsync(default);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var notice = Assert.IsType<StatusNotification>(await subscription.Reader.ReadAsync(deadline.Token));
            Assert.Equal(1, notice.AuditWrites!.FailureCount);
            Assert.False(notice.ProtectionActive);
        }
        finally { await publisher.StopAsync(default).WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    private sealed record LegacyStatus(int PolicyVersion, int ActiveCategories, bool ProtectionActive);
    private sealed class Record : INotificationRecord
    {
        public bool Fail { get; set; }
        public List<AgentNotification> Messages { get; } = [];
        public void Append(AgentNotification notification, uint? session)
        {
            if (Fail) throw new IOException("synthetic record failure");
            Messages.Add(notification);
        }
    }
}
