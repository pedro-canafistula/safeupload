using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Service.Notifications;
using SafeUpload.Agent.Service.Policies;

namespace SafeUpload.Agent.Tests;

public sealed class PolicyIntegrationTrayTests
{
    private static Policy Policy(int version) => LocalPolicyStore.CreateDefault() with { Version = version };
    private static PolicyIntegrationDiagnostics Diagnostics() => new(NullLogger<PolicyIntegrationDiagnostics>.Instance);
    private static NotificationHub Hub(Record record) => new(record, NullLogger<NotificationHub>.Instance);
    private static PolicyIntegrationStatus Summary(int version = 2) => new(version, "remote", version, 1, true, false, false, false);
    private static PolicyIntegrationStatusPublisher Publisher(PolicyIntegrationDiagnostics diagnostics, NotificationHub hub) =>
        new(diagnostics, hub, NullLogger<PolicyIntegrationStatusPublisher>.Instance);

    [Fact]
    public void Legacy_status_remains_readable_and_does_not_announce_a_diagnostic()
    {
        var original = new StatusNotification(1, 2, false);
        string wire = NotificationProtocol.Serialize(original);
        Assert.DoesNotContain("policyIntegration", wire);
        Assert.Equal(original, NotificationProtocol.Deserialize(wire));
        Assert.Equal(PolicyIntegrationPresentation.Unavailable, PolicyIntegrationPresentation.From(null));
    }

    [Fact]
    public void Optional_summary_roundtrips_and_is_ignored_by_the_legacy_status_shape()
    {
        var original = new StatusNotification(1, 2, false, AdmissionCoverage: AdmissionCoverageStatus.Degraded,
            AdmissionCoverageReason: "held", NativePolicyGeneration: 17) { PolicyIntegration = Summary() };
        string wire = NotificationProtocol.Serialize(original);
        Assert.Equal(original, NotificationProtocol.Deserialize(wire));
        var legacy = JsonSerializer.Deserialize<LegacyStatus>(wire, NotificationProtocol.JsonOptions)!;
        Assert.False(legacy.ProtectionActive);
        Assert.Equal(1, legacy.PolicyVersion);
        Assert.Equal(AdmissionCoverageStatus.Degraded, legacy.AdmissionCoverage);
        Assert.Equal((uint)17, legacy.NativePolicyGeneration);
    }

    [Fact]
    public void Projection_contains_no_hash_policy_body_or_exception_details()
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordSnapshot(Policy(2), "unrecognized private source");
        diagnostic.RecordStrictRead(Policy(2));
        diagnostic.RecordDriverScopeAccepted(Policy(1));
        diagnostic.RecordStrictFailure(new IOException("private file path and server URL"));
        var summary = diagnostic.ForNotification();
        string wire = JsonSerializer.Serialize(summary, NotificationProtocol.JsonOptions);
        Assert.Equal("unknown", summary.SnapshotSource);
        Assert.True(summary.CurrentReadFailed);
        Assert.Null(summary.CurrentContentMatchesAccepted);
        Assert.DoesNotContain(diagnostic.Read().StrictFingerprint!, wire);
        Assert.DoesNotContain("private", wire);
        Assert.DoesNotContain("IOException", wire);
        Assert.Equal(8, JsonDocument.Parse(wire).RootElement.EnumerateObject().Count());
    }

    [Fact]
    public void Publisher_does_not_synthesize_protection_before_the_interceptor_announces_status()
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordStrictRead(Policy(2));
        var record = new Record();
        var hub = Hub(record);
        Assert.True(Publisher(diagnostic, hub).PublishOnce());
        Assert.Null(hub.CurrentStatus);
        Assert.Empty(record.Messages);
        hub.Publish(new StatusNotification(0, 0, false));
        Assert.Equal(2, hub.CurrentStatus!.PolicyIntegration!.StrictVersion);
        Assert.False(hub.CurrentStatus.ProtectionActive);
    }

    [Fact]
    public void Refresh_preserves_readiness_generation_and_real_status_while_reporting_a_different_policy()
    {
        var diagnostic = Diagnostics();
        var accepted = Policy(7);
        diagnostic.RecordDriverScopeAccepted(accepted);
        diagnostic.RecordStrictRead(accepted with { ActiveCategories = new HashSet<Category> { Category.Secret } });
        var hub = Hub(new Record());
        var original = new StatusNotification(7, 5, true, AuditOnly: true,
            AdmissionCoverage: AdmissionCoverageStatus.Pending, AdmissionCoverageReason: "original gate", NativePolicyGeneration: 19);
        hub.Publish(original);
        Publisher(diagnostic, hub).PublishOnce();
        var current = hub.CurrentStatus!;
        Assert.Equal(original, current with { PolicyIntegration = null });
        Assert.False(current.PolicyIntegration!.CurrentContentMatchesAccepted);
        Assert.Contains("difere", PolicyIntegrationPresentation.From(current.PolicyIntegration).Message);
    }

    [Fact]
    public void Identical_polls_do_not_repeat_durable_records_and_normal_status_keeps_the_summary()
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordSnapshot(Policy(2), "disk");
        var record = new Record();
        var hub = Hub(record);
        hub.Publish(new StatusNotification(1, 1, false));
        var publisher = Publisher(diagnostic, hub);
        Assert.True(publisher.PublishOnce());
        int before = record.Messages.Count;
        for (int index = 0; index < 100; index++) Assert.True(publisher.PublishOnce());
        Assert.Equal(before, record.Messages.Count);
        hub.Publish(new StatusNotification(1, 2, true));
        Assert.Equal(2, hub.CurrentStatus!.ActiveCategories);
        Assert.Equal(2, hub.CurrentStatus.PolicyIntegration!.SnapshotVersion);
    }

    [Fact]
    public void Failed_durable_record_suppresses_the_new_summary_and_retries_without_losing_real_status()
    {
        var diagnostic = Diagnostics();
        var record = new Record();
        var hub = Hub(record);
        var original = new StatusNotification(1, 2, false);
        hub.Publish(original);
        var publisher = Publisher(diagnostic, hub);
        Assert.True(publisher.PublishOnce());
        var before = hub.CurrentStatus;
        diagnostic.RecordSnapshot(Policy(2), "remote");
        record.Fail = true;
        Assert.False(publisher.PublishOnce());
        Assert.Equal(before, hub.CurrentStatus);
        record.Fail = false;
        Assert.True(publisher.PublishOnce());
        Assert.Equal(2, hub.CurrentStatus!.PolicyIntegration!.SnapshotVersion);
        Assert.Equal(original, hub.CurrentStatus with { PolicyIntegration = null });
    }

    [Fact]
    public void Scope_disconnect_preserves_history_and_removes_the_comparison()
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordStrictRead(Policy(2));
        diagnostic.RecordDriverScopeAccepted(Policy(2));
        Assert.True(diagnostic.ForNotification().CurrentContentMatchesAccepted);
        diagnostic.RecordDriverDisconnected();
        var summary = diagnostic.ForNotification();
        Assert.False(summary.DriverScopeRecorded);
        Assert.Null(summary.CurrentContentMatchesAccepted);
        Assert.Contains("histórico", PolicyIntegrationPresentation.From(summary).Accepted);
    }

    [Theory]
    [InlineData("remote", "servidor")]
    [InlineData("disk", "cache em disco")]
    [InlineData("memory", "memória")]
    [InlineData("default", "padrão local")]
    public void Presentation_identifies_the_snapshot_origin_without_claiming_protection(string source, string label)
    {
        var display = PolicyIntegrationPresentation.From(Summary() with { SnapshotSource = source });
        Assert.Contains(label, display.Available);
        Assert.DoesNotContain("Protegido", display.Message);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Failure_presentation_distinguishes_application_failure_from_a_historical_read(bool apply)
    {
        var summary = Summary() with { DriverApplyFailed = apply, CurrentReadFailed = !apply, DriverScopeRecorded = !apply };
        var display = PolicyIntegrationPresentation.From(summary);
        Assert.Contains(apply ? "Falha ao aplicar" : "consulta da política atual falhou", display.Message);
        if (apply) Assert.Contains("histórico", display.Accepted);
    }

    [Fact]
    public async Task Real_private_notification_pipe_delivers_the_latest_summary_on_reconnect()
    {
        string name = "SafeUpload.Agent.PolicyTest." + Guid.NewGuid().ToString("N");
        var hub = Hub(new Record());
        hub.Publish(new StatusNotification(1, 2, false));
        Assert.True(hub.PublishPolicyIntegration(Summary()));
        using var server = new NotificationPipeServer(hub, NullLogger<NotificationPipeServer>.Instance, name);
        await server.StartAsync(default);
        try
        {
            for (int index = 0; index < 2; index++)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var client = new NamedPipeClientStream(".", name, PipeDirection.In, PipeOptions.Asynchronous);
                await client.ConnectAsync(timeout.Token);
                using var reader = new StreamReader(client, NotificationProtocol.Encoding);
                string? line = await reader.ReadLineAsync(timeout.Token);
                var notice = Assert.IsType<StatusNotification>(NotificationProtocol.Deserialize(line!));
                Assert.Equal(Summary(), notice.PolicyIntegration);
                Assert.False(notice.ProtectionActive);
                Assert.Contains("difere", PolicyIntegrationPresentation.From(notice.PolicyIntegration).Message);
            }
        }
        finally { await server.StopAsync(default); }
    }

    [Fact]
    public async Task Background_publisher_delivers_the_summary_and_stops_on_cancellation()
    {
        var diagnostic = Diagnostics();
        diagnostic.RecordSnapshot(Policy(3), "remote");
        var hub = Hub(new Record());
        hub.Publish(new StatusNotification(1, 2, false));
        using var subscription = hub.Subscribe();
        using var publisher = Publisher(diagnostic, hub);
        await publisher.StartAsync(default);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var notice = Assert.IsType<StatusNotification>(await subscription.Reader.ReadAsync(deadline.Token));
            Assert.Equal(3, notice.PolicyIntegration!.SnapshotVersion);
            Assert.False(notice.ProtectionActive);
        }
        finally { await publisher.StopAsync(default).WaitAsync(TimeSpan.FromSeconds(5)); }
    }

    private sealed record LegacyStatus(int PolicyVersion, int ActiveCategories, bool ProtectionActive,
        bool AuditOnly, AdmissionCoverageStatus AdmissionCoverage, string? AdmissionCoverageReason, uint? NativePolicyGeneration);

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
