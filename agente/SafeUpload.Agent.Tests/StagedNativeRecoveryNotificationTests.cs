using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Interception;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class StagedNativeRecoveryNotificationTests
{
    private const string OwnerSid = "S-1-5-21-100-200-300-1001";
    private const string OtherSid = "S-1-5-21-100-200-300-1002";

    private sealed class Record : INotificationRecord
    {
        internal readonly List<(AgentNotification Notification, uint? Session)> Entries = [];
        public void Append(AgentNotification notification, uint? targetSessionId) => Entries.Add((notification, targetSessionId));
    }

    private sealed class CaptureLogger : ILogger
    {
        internal readonly List<Dictionary<string, object?>> Entries = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add(((IEnumerable<KeyValuePair<string, object?>>)(object)state!).ToDictionary(p => p.Key, p => p.Value));
    }

    private static (StagedDestinationHead Head, StagedPublicDeleteRecord Delete) Intent(uint session = 2)
    {
        var destination = new StagedDestinationIdentity(new(7, 11, 12), new(7, 21, 22), false, "report.txt");
        var binding = new StagedPublicDeleteBinding(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), 17,
            new(7, 91, 92), 1234, 123456, session, OwnerSid, 42);
        var delete = new StagedPublicDeleteRecord(binding, 1, StagedPublicDeleteState.AcceptedUnresolved,
            DateTimeOffset.UtcNow, Guid.NewGuid(), StagedPublicDeleteKind.NativeOnClose, true);
        return (new(destination, @"C:\Protected\report.txt", 1, null, 0, 0, null, 0, null, [delete]), delete);
    }

    [Fact]
    public void Exact_unresolved_intent_records_diagnostics_and_delivers_only_to_its_owner_session_and_sid()
    {
        var record = new Record(); var log = new CaptureLogger();
        var hub = new NotificationHub(record, Microsoft.Extensions.Logging.Abstractions.NullLogger<NotificationHub>.Instance);
        using var owner = hub.Subscribe(2, OwnerSid);
        using var wrongUser = hub.Subscribe(2, OtherSid);
        using var wrongSession = hub.Subscribe(3, OwnerSid);
        using var unscoped = hub.Subscribe();
        var (head, delete) = Intent();
        Assert.True(StagedNativeRecoveryNotifications.Publish(hub, log, head, delete,
            StagedRecoveryAdvice.CollectDiagnostics, "parent_identity_unresolved"));
        Assert.True(owner.Reader.TryRead(out var delivered));
        var notice = Assert.IsType<TransferNotification>(delivered);
        Assert.Equal(head.Locator, notice.FileName);
        Assert.Equal(delete.Binding.TransferId, notice.TransferId);
        Assert.Equal(TransferPhase.Retained, notice.Phase);
        Assert.Equal(StagedRecoveryAdvice.CollectDiagnostics, notice.RecoveryAdvice);
        Assert.False(notice.OverrideAllowed);
        Assert.False(wrongUser.Reader.TryRead(out _));
        Assert.False(wrongSession.Reader.TryRead(out _));
        Assert.False(unscoped.Reader.TryRead(out _));
        var emission = Assert.Single(record.Entries);
        Assert.Equal(notice, emission.Notification); Assert.Equal(2u, emission.Session);
        var diagnostic = Assert.Single(log.Entries);
        Assert.Equal(head.Locator, diagnostic["Destination"]);
        Assert.Equal(delete.Generation, diagnostic["Generation"]);
        Assert.Equal(delete.Binding.PublicIdentity.FileIdHigh, diagnostic["FileIdHigh"]);
        Assert.Equal(delete.Binding.PublicIdentity.FileIdLow, diagnostic["FileIdLow"]);
        Assert.Equal(delete.Binding.ConnectionEpoch, diagnostic["ConnectionEpoch"]);
        Assert.Equal("parent_identity_unresolved", diagnostic["Reason"]);
    }

    [Fact]
    public void Session_zero_recovery_is_recorded_without_delivery_or_override()
    {
        var record = new Record(); var log = new CaptureLogger();
        var hub = new NotificationHub(record, Microsoft.Extensions.Logging.Abstractions.NullLogger<NotificationHub>.Instance);
        using var zero = hub.Subscribe(0, OwnerSid); using var unscoped = hub.Subscribe();
        var (head, delete) = Intent(0);
        Assert.False(StagedNativeRecoveryNotifications.Publish(hub, log, head, delete,
            StagedRecoveryAdvice.RestartService, "service_disconnected"));
        Assert.Single(log.Entries); Assert.Single(record.Entries);
        Assert.False(zero.Reader.TryRead(out _)); Assert.False(unscoped.Reader.TryRead(out _));
        Assert.False(Assert.IsType<TransferNotification>(record.Entries[0].Notification).OverrideAllowed);
    }

    [Fact]
    public void Recovery_emission_uses_the_existing_durable_record_and_survives_its_restart()
    {
        using var workspace = new TestWorkspace();
        string directory = Path.Combine(workspace.Root, "notifications");
        var (head, delete) = Intent();
        NotificationRecordEntry[] Entries() => File.ReadAllLines(Path.Combine(directory, "emissions.jsonl"))
            .Select(line => JsonSerializer.Deserialize<NotificationRecordEntry>(line)!).ToArray();
        using (var record = new NotificationRecord(directory, NullLogger.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true))
        {
            var hub = new NotificationHub(record, NullLogger<NotificationHub>.Instance);
            using var owner = hub.Subscribe(2, OwnerSid);
            Assert.True(StagedNativeRecoveryNotifications.Publish(hub, new CaptureLogger(), head, delete,
                StagedRecoveryAdvice.CollectDiagnostics, "parent_identity_unresolved"));
            var emission = Assert.Single(Entries().Where(entry => entry.Kind == "Transfer"));
            Assert.Equal(delete.Binding.TransferId, emission.TransferId);
            Assert.Equal(TransferPhase.Retained.ToString(), emission.Phase);
            Assert.Equal(2u, emission.TargetSessionId);
            var anchor = JsonSerializer.Deserialize<NotificationRecordHead>(
                File.ReadAllText(Path.Combine(directory, "head.json")))!;
            Assert.Equal(emission.Sequence, anchor.Sequence);
            Assert.True(owner.Reader.TryRead(out _));
        }
        // Reopening verifies the old hash chain; no new persisted recovery schema is needed.
        using var restarted = new NotificationRecord(directory, NullLogger.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true);
        var retained = Assert.Single(Entries().Where(entry => entry.Kind == "Transfer"));
        Assert.Equal(delete.Binding.TransferId, retained.TransferId);
        Assert.Equal(TransferPhase.Retained.ToString(), retained.Phase);
    }

    [Theory]
    [InlineData("session")]
    [InlineData("sid")]
    [InlineData("both")]
    public void Recovery_guidance_without_a_complete_owner_binding_is_never_broadcast(string missing)
    {
        var record = new Record();
        var hub = new NotificationHub(record, Microsoft.Extensions.Logging.Abstractions.NullLogger<NotificationHub>.Instance);
        using var subscriber = hub.Subscribe();
        var notice = new TransferNotification(Guid.NewGuid(), "report.txt", TransferPhase.Retained,
            RecoveryAdvice: StagedRecoveryAdvice.CloseApplication);
        Assert.False(hub.Publish(notice, missing is "session" or "both" ? null : 2,
            missing is "sid" or "both" ? null : OwnerSid));
        Assert.Empty(record.Entries); Assert.False(subscriber.Reader.TryRead(out _));
    }

    [Theory]
    [InlineData(TransferPhase.Analyzing)]
    [InlineData(TransferPhase.Released)]
    [InlineData(TransferPhase.Blocked)]
    public void Recovery_hint_cannot_report_a_release_or_open_a_block_override_flow(TransferPhase phase)
    {
        var record = new Record();
        var hub = new NotificationHub(record, Microsoft.Extensions.Logging.Abstractions.NullLogger<NotificationHub>.Instance);
        Assert.False(hub.Publish(new TransferNotification(Guid.NewGuid(), "report.txt", phase,
            RecoveryAdvice: StagedRecoveryAdvice.CloseApplication), 2, OwnerSid));
        Assert.Empty(record.Entries);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Recovery_guidance_rejects_unknown_advice_and_any_override(bool overrideAllowed)
    {
        var record = new Record();
        var hub = new NotificationHub(record, Microsoft.Extensions.Logging.Abstractions.NullLogger<NotificationHub>.Instance);
        Assert.False(hub.Publish(new TransferNotification(Guid.NewGuid(), "report.txt", TransferPhase.Retained,
            OverrideAllowed: overrideAllowed,
            RecoveryAdvice: overrideAllowed ? StagedRecoveryAdvice.CloseApplication : (StagedRecoveryAdvice)999), 2, OwnerSid));
        Assert.Empty(record.Entries);
    }

    [Theory]
    [InlineData("ordinary")]
    [InlineData("resolved")]
    [InlineData("not-in-head")]
    public void Guidance_requires_the_exact_durable_unresolved_native_record(string invalid)
    {
        var record = new Record(); var log = new CaptureLogger();
        var hub = new NotificationHub(record, Microsoft.Extensions.Logging.Abstractions.NullLogger<NotificationHub>.Instance);
        var (head, delete) = Intent();
        if (invalid == "ordinary") delete = delete with { Kind = StagedPublicDeleteKind.Ordinary };
        if (invalid == "resolved") delete = delete with { State = StagedPublicDeleteState.Admitted };
        if (invalid == "not-in-head") head = head with { Deletes = [] };
        Assert.Throws<InvalidOperationException>(() => StagedNativeRecoveryNotifications.Publish(hub, log, head, delete,
            StagedRecoveryAdvice.CollectDiagnostics, "unknown"));
        Assert.Empty(record.Entries); Assert.Empty(log.Entries);
    }

    [Theory]
    [InlineData(StagedRecoveryAdvice.CloseApplication)]
    [InlineData(StagedRecoveryAdvice.RestartService)]
    [InlineData(StagedRecoveryAdvice.CollectDiagnostics)]
    public void Guidance_crosses_the_existing_notification_pipe_without_new_transfer_states(StagedRecoveryAdvice advice)
    {
        var notice = new TransferNotification(Guid.NewGuid(), @"C:\Protected\report.txt", TransferPhase.Retained,
            RecoveryAdvice: advice);
        var roundTrip = Assert.IsType<TransferNotification>(NotificationProtocol.Deserialize(
            NotificationProtocol.Serialize(notice).TrimEnd('\n')));
        Assert.Equal(notice, roundTrip);
        Assert.False(roundTrip.OverrideAllowed); Assert.Null(roundTrip.Findings); Assert.Null(roundTrip.PublishedSha256Hex);
    }
}
