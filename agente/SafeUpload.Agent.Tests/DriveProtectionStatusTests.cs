using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class DriveProtectionStatusTests
{
    [Theory]
    [InlineData(GateApplyResult.Unavailable, false)]
    [InlineData(GateApplyResult.Unavailable, true)]
    [InlineData(GateApplyResult.Rejected, false)]
    [InlineData(GateApplyResult.Rejected, true)]
    public void Mounted_drives_without_accepted_gate_scope_are_incomplete_including_audit_mode(GateApplyResult gate, bool audit)
    {
        var status = DriveProtectionSnapshot.Create(Policy() with { AuditOnly = audit }, gate, ["first"], ["first"]);
        Assert.False(status.ProtectionActive);
        var model = Present(status);
        Assert.True(model.Connected);
        Assert.False(model.MonitoringActive);
        Assert.Equal("Proteção incompleta", model.SecurityState);
        Assert.Equal(gate == GateApplyResult.Rejected ? DriveProtectionIssue.GateRejected : DriveProtectionIssue.GateUnavailable,
            status.DriveProtection!.Issue);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Missing_or_wrong_mounts_are_not_hidden_by_equal_counts(bool wrongSet)
    {
        var status = DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Applied,
            ["first", "second"], wrongSet ? ["wrong", "other"] : ["first"]);
        Assert.False(status.ProtectionActive);
        Assert.Equal(DriveProtectionIssue.MountsIncomplete, status.DriveProtection!.Issue);
        Assert.Equal(wrongSet ? 0 : 1, status.DriveProtection.MountedDrives);
        Assert.False(Present(status).MonitoringActive);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Complete_scope_and_available_mounts_enable_monitoring_and_roundtrip(bool audit)
    {
        var status = DriveProtectionSnapshot.Create(Policy() with { AuditOnly = audit }, GateApplyResult.Applied,
            ["first", "second", "FIRST"], ["SECOND", "FIRST"]);
        Assert.True(status.ProtectionActive);
        Assert.Equal(2, status.DriveProtection!.MountedDrives);
        Assert.Equal(status, NotificationProtocol.Deserialize(NotificationProtocol.Serialize(status)));
        var model = Present(status);
        Assert.True(model.MonitoringActive);
        Assert.Equal(audit ? "Em auditoria" : "Proteção confirmada", model.SecurityState);
        model.SetDisconnected();
        Assert.False(model.MonitoringActive);
        Assert.False(model.Connected);
    }

    [Fact]
    public void No_destinations_does_not_claim_active_protection()
    {
        var status = DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Applied, [], []);
        Assert.False(status.ProtectionActive);
        Assert.Equal(DriveProtectionIssue.NoDestinations, status.DriveProtection!.Issue);
        Assert.Equal("Sem destinos disponíveis", Present(status).SecurityState);
    }

    [Fact]
    public void Connected_legacy_service_does_not_turn_the_monitoring_indicator_green_without_protection()
    {
        var status = Assert.IsType<StatusNotification>(NotificationProtocol.Deserialize(
            "{\"type\":\"status\",\"policyVersion\":1,\"activeCategories\":1,\"protectionActive\":false}"));
        Assert.Null(status.DriveProtection);
        var model = Present(status);
        Assert.True(model.Connected);
        Assert.False(model.MonitoringActive);
        model.ApplyStatus(status with { ProtectionActive = true });
        Assert.True(model.MonitoringActive);
    }

    [Fact]
    public void Degradation_updates_the_indicator_while_the_service_connection_stays_open()
    {
        var model = Present(DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Applied, ["first"], ["first"]));
        var changed = new List<string?>();
        model.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        model.ApplyStatus(DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Unavailable, ["first"], ["first"]));
        Assert.True(model.Connected);
        Assert.False(model.MonitoringActive);
        Assert.Contains(nameof(model.MonitoringActive), changed);
        Assert.DoesNotContain(nameof(model.Connected), changed);
    }

    [Fact]
    public async Task Policy_read_failure_replaces_old_ready_status_and_recovery_announces_current_scope()
    {
        var policy = new Policies { Failure = new InvalidPolicyException("Synthetic unreadable policy") };
        var hub = NotificationTestHub.Create();
        hub.Publish(DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Applied, ["old"], ["old"]));
        using var gate = GateClientStateTests.Client(new GateClientStateTests.Connection());
        using var service = Service(policy, hub, gate);
        await Assert.ThrowsAsync<InvalidPolicyException>(() => service.SyncAsync(CancellationToken.None));
        var failed = hub.CurrentStatus!;
        Assert.False(failed.ProtectionActive);
        Assert.Equal(DriveProtectionIssue.PolicyUnavailable, failed.DriveProtection!.Issue);
        Assert.Equal("—", Present(failed).PolicyVersion);
        policy.Failure = null;
        await service.SyncAsync(CancellationToken.None);
        Assert.Equal(DriveProtectionIssue.NoDestinations, hub.CurrentStatus!.DriveProtection!.Issue);
        Assert.Equal(7, hub.CurrentStatus.PolicyVersion);
        await service.StopAsync(CancellationToken.None);
        Assert.Equal(DriveProtectionIssue.Stopped, hub.CurrentStatus.DriveProtection.Issue);
        Assert.False(hub.CurrentStatus.ProtectionActive);
    }

    [Fact]
    public async Task Invalid_scope_clears_old_ready_status_before_any_native_or_mount_operation()
    {
        var policy = new Policies();
        policy.Current = policy.Current with { MonitoredScopes = policy.Current.MonitoredScopes with
            { DestinationPaths = Enumerable.Range(0, 17).Select(i => @"C:\Synthetic\" + i).ToArray() } };
        var hub = NotificationTestHub.Create();
        hub.Publish(DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Applied, ["old"], ["old"]));
        var wire = new GateClientStateTests.Connection();
        using var gate = GateClientStateTests.Client(wire);
        using var service = Service(policy, hub, gate);
        await Assert.ThrowsAsync<InvalidPolicyException>(() => service.SyncAsync(CancellationToken.None));
        Assert.Empty(wire.Commands);
        Assert.Equal(0, wire.ConnectCalls);
        Assert.False(hub.CurrentStatus!.ProtectionActive);
        Assert.Equal(DriveProtectionIssue.ScopeInvalid, hub.CurrentStatus.DriveProtection!.Issue);
        Assert.DoesNotContain("Synthetic", NotificationProtocol.Serialize(hub.CurrentStatus));
    }

    [Fact]
    public async Task Failed_status_record_is_retried_even_when_the_observation_did_not_change()
    {
        var record = new Record();
        var hub = new NotificationHub(record, NullLogger<NotificationHub>.Instance);
        hub.Publish(DriveProtectionSnapshot.Create(Policy(), GateApplyResult.Applied, ["old"], ["old"]));
        using var gate = GateClientStateTests.Client(new GateClientStateTests.Connection());
        using var service = Service(new Policies(), hub, gate);
        record.Fail = true;
        await service.SyncAsync(CancellationToken.None);
        Assert.True(hub.CurrentStatus!.ProtectionActive); // The hub retains only successfully recorded status.
        record.Fail = false;
        await service.SyncAsync(CancellationToken.None);
        Assert.False(hub.CurrentStatus!.ProtectionActive);
        Assert.Equal(DriveProtectionIssue.NoDestinations, hub.CurrentStatus.DriveProtection!.Issue);
    }

    [Fact]
    public async Task Synchronization_checks_the_connection_again_before_status_and_recovers_by_resending_scope()
    {
        var wire = new GateClientStateTests.Connection { ProbeResult = -1 };
        var hub = NotificationTestHub.Create();
        using var gate = GateClientStateTests.Client(wire);
        using var service = Service(new Policies(), hub, gate);
        await service.SyncAsync(CancellationToken.None);
        Assert.Equal(new uint[] { 1, 2 }, wire.Commands);
        Assert.False(hub.CurrentStatus!.DriveProtection!.GatePolicyApplied);
        wire.ProbeResult = 0;
        await service.SyncAsync(CancellationToken.None);
        Assert.Equal(new uint[] { 1, 2, 1, 2 }, wire.Commands);
        Assert.True(hub.CurrentStatus!.DriveProtection!.GatePolicyApplied);
        Assert.False(hub.CurrentStatus.ProtectionActive); // Still no destination to monitor.
    }

    private static StatusViewModel Present(StatusNotification status)
    {
        var model = new StatusViewModel();
        model.ApplyStatus(status);
        return model;
    }

    private static Policy Policy() => LocalPolicyStore.CreateDefault() with { Version = 7,
        MonitoredScopes = new MonitoredScopes(new HashSet<string> { ".txt" }, [], false, false) };

    private static DriveService Service(IPolicyStore policies, NotificationHub hub, GateClient gate) => new(policies,
        new InspectionService(policies, new Audit(), ExtractorRegistry.CreateDefault(), new VerdictCache()), hub,
        new DriveJustifications(), gate, new ConfigurationBuilder().Build(), NullLogger<DriveService>.Instance);

    private sealed class Policies : IPolicyStore
    {
        public Policy Current = Policy();
        public Exception? Failure;
        public Task<Policy> LoadAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return Failure is { } error ? Task.FromException<Policy>(error) : Task.FromResult(Current);
        }
    }

    private sealed class Record : INotificationRecord
    {
        public bool Fail;
        public void Append(AgentNotification notification, uint? targetSessionId)
        { if (Fail) throw new IOException("Synthetic status record failure"); }
    }

    private sealed class Audit : IAuditSink
    {
        public Task WriteAsync(AuditEvent auditEvent, CancellationToken token) => Task.CompletedTask;
        public Task RecordOverrideAsync(string eventId, string justification, CancellationToken token) => Task.CompletedTask;
        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int max, CancellationToken token) => Task.FromResult<IReadOnlyList<AuditEvent>>([]);
        public Task<IReadOnlyList<AuditEvent>> ReadPendingAsync(int max, CancellationToken token) => Task.FromResult<IReadOnlyList<AuditEvent>>([]);
        public Task MarkDispatchedAsync(IReadOnlyCollection<Guid> ids, CancellationToken token) => Task.CompletedTask;
    }
}
