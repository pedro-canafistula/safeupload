using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Diagnostics;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

// Real file admission in a private test-identity tree, not production SYSTEM ACL/SCM acceptance.
public sealed class NotificationAdmissionRecoveryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "notification-admission-" + Guid.NewGuid());
    private string DirectoryPath => Path.Combine(_root, "notifications");
    private string Active => Path.Combine(DirectoryPath, "emissions.jsonl");
    private NotificationRecord Open() => new(DirectoryPath, NullLogger.Instance,
        NotificationRecord.SegmentBytes, "test/boot", testIdentity: true, recoverCorruption: true);
    private static NotificationHub Hub(INotificationRecord record) => new(record, NullLogger<NotificationHub>.Instance);
    private static HistoryNotification History() => new([], false);
    private readonly Clock _clock = new();
    private sealed class Clock : TimeProvider
    {
        public long Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Ticks;
        public void Advance() => Ticks += TimeSpan.TicksPerSecond * 5;
    }

    [Fact]
    public void Released_writer_lease_recovers_latest_status_on_periodic_sample_before_delivery()
    {
        Directory.CreateDirectory(_root);
        var owner = Open();
        using var recovering = new RecoveringNotificationRecord(Open, NullLogger.Instance, _clock);
        var hub = Hub(recovering);
        using var subscription = hub.Subscribe();
        var publisher = new CommunicationStatusPublisher(new CommunicationHealth(false), hub);
        publisher.PublishSnapshot();
        var original = File.ReadAllBytes(Active);
        hub.Publish(new StatusNotification(1, 2, true));
        hub.Publish(new StatusNotification(3, 4, false));
        Assert.False(hub.RecordHistory(History(), 1));
        Assert.Null(hub.CurrentStatus);
        Assert.Null(hub.GetRecordedStatus());
        Assert.False(subscription.Reader.TryRead(out _));
        Assert.Equal(original, File.ReadAllBytes(Active));
        owner.Dispose();
        _clock.Advance();
        // Communication has not changed. A pending, un-emitted status must still be retried.
        publisher.PublishSnapshot();
        Assert.True(subscription.Reader.TryRead(out var delivered));
        var status = Assert.IsType<StatusNotification>(delivered);
        Assert.Equal(3, status.PolicyVersion);
        Assert.False(status.ProtectionActive);
        Assert.Equal(status, hub.CurrentStatus);
        var entries = File.ReadAllLines(Active).Select(line => JsonSerializer.Deserialize<NotificationRecordEntry>(line)!).ToArray();
        Assert.Equal("Status", entries[^1].Kind);
        Assert.Single(entries, entry => entry.Kind == "Status");
        Assert.True(hub.RecordHistory(History(), 1));
        Assert.NotNull(hub.GetRecordedStatus());
    }

    [Fact]
    public void New_client_recovers_pending_status_before_returning_it()
    {
        Directory.CreateDirectory(_root);
        var owner = Open();
        using var recovering = new RecoveringNotificationRecord(Open, NullLogger.Instance, _clock);
        var hub = Hub(recovering);
        hub.Publish(new StatusNotification(7, 2, false));
        Assert.Null(hub.GetRecordedStatus());
        owner.Dispose();
        _clock.Advance();
        var status = Assert.IsType<StatusNotification>(hub.GetRecordedStatus());
        Assert.Equal(7, status.PolicyVersion);
        Assert.False(status.ProtectionActive);
        Assert.Equal("Status", JsonSerializer.Deserialize<NotificationRecordEntry>(File.ReadAllLines(Active)[^1])!.Kind);
    }

    [Fact]
    public void Persistent_failure_is_rate_limited_and_never_delivers_or_replays()
    {
        int attempts = 0;
        using var record = new RecoveringNotificationRecord(() =>
        {
            attempts++;
            throw new IOException("Still locked");
        }, NullLogger.Instance, _clock);
        var hub = Hub(record);
        using var subscription = hub.Subscribe();
        hub.Publish(new StatusNotification(1, 2, true));
        for (int i = 0; i < 10; i++) Assert.False(hub.RecordHistory(History(), 1));
        Assert.Equal(1, attempts);
        _clock.Advance();
        new CommunicationStatusPublisher(new CommunicationHealth(false), hub).PublishSnapshot();
        Assert.Equal(2, attempts);
        Assert.Null(hub.CurrentStatus);
        Assert.Null(hub.GetRecordedStatus());
        Assert.False(subscription.Reader.TryRead(out _));
        using var replay = hub.Subscribe();
        Assert.False(replay.Reader.TryRead(out _));
    }

    [Fact]
    public void Unsafe_acl_is_still_refused_on_every_admission_without_repair()
    {
        if (!OperatingSystem.IsWindows()) return;
        Directory.CreateDirectory(_root);
        using (var original = Open()) { }
        var security = new DirectoryInfo(DirectoryPath).GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).SetAccessControl(security);
        var descriptor = new DirectoryInfo(DirectoryPath).GetAccessControl().GetSecurityDescriptorBinaryForm();
        var bytes = File.ReadAllBytes(Active);
        using var recovering = new RecoveringNotificationRecord(Open, NullLogger.Instance, _clock);
        for (int i = 0; i < 2; i++)
        {
            var error = Assert.Throws<IOException>(() => recovering.Append(new StatusNotification(1, 2, true), null));
            Assert.IsType<UnauthorizedAccessException>(error.InnerException);
            _clock.Advance();
        }
        Assert.Equal(descriptor, new DirectoryInfo(DirectoryPath).GetAccessControl().GetSecurityDescriptorBinaryForm());
        Assert.Equal(bytes, File.ReadAllBytes(Active));
    }

    [Fact]
    public void Linked_record_remains_refused_and_outside_bytes_are_untouched()
    {
        Directory.CreateDirectory(_root);
        using (var original = Open()) { }
        string outside = Path.Combine(_root, "outside");
        File.Copy(Active, outside);
        byte[] bytes = File.ReadAllBytes(outside);
        File.Delete(Active);
        Assert.True(CreateHardLink(Active, outside, IntPtr.Zero));
        using var recovering = new RecoveringNotificationRecord(Open, NullLogger.Instance, _clock);
        for (int i = 0; i < 2; i++)
        {
            Assert.Throws<IOException>(() => recovering.Append(new StatusNotification(1, 2, true), null));
            _clock.Advance();
        }
        Assert.Equal(bytes, File.ReadAllBytes(outside));
        Assert.True(File.Exists(Active));
        Assert.Empty(Directory.GetDirectories(_root, "notifications.corrupt-*"));
    }

    [Fact]
    public void Write_failure_does_not_replace_an_admitted_recorder_or_expose_stale_status()
    {
        int opens = 0;
        var admitted = new FailingRecord();
        using var recovering = new RecoveringNotificationRecord(() => { opens++; return admitted; }, NullLogger.Instance, _clock);
        var hub = Hub(recovering);
        hub.Publish(new StatusNotification(1, 2, true));
        admitted.Fail = true;
        using var subscription = hub.Subscribe();
        hub.Publish(new StatusNotification(2, 2, false));
        Assert.True(hub.CurrentStatus!.ProtectionActive);
        Assert.False(hub.HasRecordedStatus(new StatusNotification(1, 2, true)));
        _clock.Advance();
        Assert.Null(hub.GetRecordedStatus());
        Assert.False(hub.RecordHistory(History(), 1));
        Assert.False(subscription.Reader.TryRead(out _));
        Assert.Equal(1, opens);
        admitted.Fail = false;
        // A producer returning to the previous emitted state must supersede
        // the failed intermediate state rather than deduplicate against it.
        hub.Publish(new StatusNotification(1, 2, true));
        Assert.True(subscription.Reader.TryRead(out var delivered));
        Assert.True(Assert.IsType<StatusNotification>(delivered).ProtectionActive);
    }

    [Fact]
    public void Disposing_wrapper_releases_admitted_lease_and_never_reopens_it()
    {
        Directory.CreateDirectory(_root);
        var recovering = new RecoveringNotificationRecord(Open, NullLogger.Instance, _clock);
        recovering.Append(new StatusNotification(1, 2, true), null);
        recovering.Dispose();
        recovering.Dispose();
        Assert.Throws<ObjectDisposedException>(() => recovering.Append(new StatusNotification(1, 2, true), null));
        using var reopened = Open();
        reopened.Append(new StatusNotification(2, 2, true), null);
    }

    private sealed class FailingRecord : INotificationRecord
    {
        public bool Fail;
        public void Append(AgentNotification notification, uint? targetSessionId)
        {
            if (Fail) throw new IOException("Uncertain write; strict recovery required");
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true); }
}
