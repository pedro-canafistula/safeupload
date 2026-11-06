using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.App.Notifications;
using SafeUpload.Agent.App.ViewModels;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Core.Infrastructure;
using SafeUpload.Agent.Core.Infrastructure.Extraction;
using SafeUpload.Agent.Drive;
using SafeUpload.Agent.Service.Drive;
using SafeUpload.Agent.Service.Gate;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

// Real files and filesystem callbacks; no mounted WinFsp drive or native gate.
public sealed class DriveOutcomeNotificationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Completed_publication_notifies_only_owner_with_the_immutable_journal_event(bool alert)
    {
        using var f = new DriveRecoveryTests.Fixture();
        f.Policies.Current = f.Policies.Current with { AuditOnly = alert, OverrideAllowed = false };
        var hub = NotificationTestHub.Create();
        using var owner = hub.Subscribe(7, DriveRecoveryTests.Fixture.Sid);
        using var other = hub.Subscribe(8, DriveRecoveryTests.Fixture.Sid);
        using var sameSessionOtherUser = hub.Subscribe(7, "S-1-5-21-111-222-333-9999");
        using var gate = new GateClient(NullLogger<GateClient>.Instance);
        using var service = Service(f, hub, gate);
        var content = f.Write(@"\report.txt", alert ? "CPF: 529.982.247-25" : "Clean bytes");
        Invoke(f.Fs, "InspectOne", content);
        var decision = Assert.Single(f.Observer.Decisions);
        await service.HandleDecisionAsync(decision, f.Policies.Current, kind => f.Fs.Approve(decision.VersionId, kind));
        Assert.False(owner.Reader.TryRead(out _)); // Classification alone is never a completed transfer.
        Invoke(f.Fs, "Reconcile");
        var publication = Assert.Single(f.Observer.Publications);
        await service.HandlePublicationAsync(publication);
        var notice = Assert.IsType<TransferNotification>(await owner.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(TransferPhase.Released, notice.Phase);
        Assert.Equal(decision.VersionId, notice.TransferId);
        Assert.Equal(publication.EventId, notice.Event!.EventId);
        Assert.Equal(publication.Event!.OccurredAtUtc, notice.Event.OccurredAtUtc);
        Assert.Equal(publication.Event.PublishedSha256Hex, notice.PublishedSha256Hex);
        var queue = new LocalQueueAuditSink(f.Work.QueueFile);
        Assert.Equal(notice.Event.EventId, Assert.Single(await queue.ReadPendingAsync(10, default)).EventId);
        Assert.False(other.Reader.TryRead(out _));
        Assert.False(sameSessionOtherUser.Reader.TryRead(out _));
        var decoded = Assert.IsType<TransferNotification>(NotificationProtocol.Deserialize(NotificationProtocol.Serialize(notice)));
        var history = new HistoryViewModel();
        Assert.True(history.Prepend(decoded.Event!));
        Assert.False(history.Prepend(decoded.Event!)); // Replay must not raise another alert.
        var display = StagedPublicationPresentation.Released("report.txt", decoded);
        Assert.Equal(alert, display.Title.Contains("alerta"));
        if (alert) Assert.Contains(Category.Cpf, decoded.Event!.Categories);
        using var record = new NotificationRecord(Path.Combine(f.Work.Root, "notifications"),
            NullLogger<NotificationRecord>.Instance, NotificationRecord.SegmentBytes, "test/boot", testIdentity: true);
        record.Append(decoded, 7); // Real emission validation accepts its hash/phase combination.
    }

    [Fact]
    public async Task Failed_publication_is_retained_then_a_distinct_confirmed_outcome_is_released()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var hub = NotificationTestHub.Create();
        using var owner = hub.Subscribe(7, DriveRecoveryTests.Fixture.Sid);
        using var gate = new GateClient(NullLogger<GateClient>.Instance);
        using var service = Service(f, hub, gate);
        var content = f.Write(@"\report.txt", "Clean bytes");
        Invoke(f.Fs, "InspectOne", content);
        using (var held = new FileStream(f.Target, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.Throws<TargetInvocationException>(() => Invoke(f.Fs, "Reconcile"));
        await service.HandlePublicationAsync(Assert.Single(f.Observer.Publications));
        var retained = Assert.IsType<TransferNotification>(await owner.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(TransferPhase.Retained, retained.Phase);
        Assert.Equal("publication_failed", retained.Event!.NotInspectedReason);
        Assert.Null(retained.PublishedSha256Hex);
        Invoke(f.Fs, "Reconcile");
        await service.HandlePublicationAsync(f.Observer.Publications[1]);
        var released = Assert.IsType<TransferNotification>(await owner.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(TransferPhase.Released, released.Phase);
        Assert.Equal(retained.TransferId, released.TransferId);
        Assert.NotEqual(retained.Event.EventId, released.Event!.EventId);
        Assert.Equal(2, (await new LocalQueueAuditSink(f.Work.QueueFile).ReadPendingAsync(10, default)).Count);
    }

    [Fact]
    public async Task Block_updates_live_history_without_a_second_block_popup_and_unknown_owner_is_not_broadcast()
    {
        using var f = new DriveRecoveryTests.Fixture();
        var hub = NotificationTestHub.Create();
        using var owner = hub.Subscribe(7, DriveRecoveryTests.Fixture.Sid);
        using var gate = new GateClient(NullLogger<GateClient>.Instance);
        using var service = Service(f, hub, gate);
        var content = f.Write(@"\report.txt", "CPF: 529.982.247-25");
        Invoke(f.Fs, "InspectOne", content);
        var decision = Assert.Single(f.Observer.Decisions);
        await service.HandleDecisionAsync(decision, f.Policies.Current, null);
        var blocked = Assert.IsType<TransferNotification>(await owner.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(TransferPhase.Blocked, blocked.Phase);
        Assert.Equal(decision.VersionId, blocked.Event!.EventId);
        Assert.Equal(Verdict.Blocked, blocked.Event.Verdict);
        Assert.False(owner.Reader.TryRead(out _));
        var unknown = decision with { Writer = null, Approved = true };
        var id = Guid.NewGuid();
        await service.HandlePublicationAsync(new DrivePublication(id, unknown, f.Target, true, true,
            blocked.Event with { EventId = id, Verdict = Verdict.Approved, PublishedSha256Hex = new string('a', 64) }));
        Assert.False(owner.Reader.TryRead(out _));
    }

    private static DriveService Service(DriveRecoveryTests.Fixture f, NotificationHub hub, GateClient gate) =>
        new(f.Policies, new InspectionService(f.Policies, new LocalQueueAuditSink(f.Work.QueueFile),
                ExtractorRegistry.CreateDefault(), new VerdictCache()), hub, new DriveJustifications(), gate,
            new ConfigurationBuilder().Build(), NullLogger<DriveService>.Instance);

    private static void Invoke(object target, string method, params object[] args) =>
        target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, args);
}
