using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class NotificationRecordTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "su-notify-" + Guid.NewGuid().ToString("N"));
    private string DirectoryPath => Path.Combine(_root, "notifications");
    private string Active => Path.Combine(DirectoryPath, "emissions.jsonl");
    public NotificationRecordTests() => Directory.CreateDirectory(_root);
    private NotificationRecord Record(int limit = NotificationRecord.SegmentBytes) => new(
        DirectoryPath, NullLogger<NotificationRecord>.Instance, limit, "test/boot", testIdentity: true);
    private static NotificationHub Hub(INotificationRecord record, ILogger<NotificationHub>? logger = null) => new(
        record, logger ?? NullLogger<NotificationHub>.Instance);
    private static TransferNotification Transfer() => new(Guid.NewGuid(), "fixture.txt",
        TransferPhase.Released, PublishedSha256Hex: new string('A', 64));
    private List<NotificationRecordEntry> Entries() => new[] { "previous.jsonl", "emissions.jsonl" }
        .SelectMany(name => File.Exists(Path.Combine(DirectoryPath, name))
            ? File.ReadAllLines(Path.Combine(DirectoryPath, name)).Select(s => JsonSerializer.Deserialize<NotificationRecordEntry>(s)!)
            : []).ToList();

    [Fact]
    public void Record_is_flushed_before_queue_and_retained_state_are_changed()
    {
        using var record = Record();
        NotificationHub? hub = null;
        NotificationSubscription? subscription = null;
        var ordering = new List<bool>();
        hub = Hub(new InspectRecord(record, notification =>
        {
            ordering.Add(!subscription!.Reader.TryRead(out _) && hub!.CurrentStatus is null);
            Assert.Equal(notification is TransferNotification ? "Transfer" : "Status", Entries()[^1].Kind);
            var head = JsonSerializer.Deserialize<NotificationRecordHead>(File.ReadAllText(Path.Combine(DirectoryPath, "head.json")))!;
            Assert.Equal(Entries()[^1].Sequence, head.Sequence);
        }));
        subscription = hub.Subscribe();
        using var subscriptionLifetime = subscription;
        var transfer = Transfer();
        hub.Publish(transfer, 4);
        Assert.True(subscription.Reader.TryRead(out var delivered));
        Assert.Equal(transfer, delivered);
        Assert.Equal(transfer.TransferId, Entries()[^1].TransferId);
        Assert.Equal((uint)4, Entries()[^1].TargetSessionId);
        hub.Publish(new StatusNotification(1, 2, true));
        Assert.NotNull(hub.CurrentStatus);
        Assert.Equal(2, ordering.Count);
        Assert.All(ordering, beforeDelivery => Assert.True(beforeDelivery));
    }

    [Fact]
    public void Released_transfer_requires_its_published_digest()
    {
        using var record = Record();
        Assert.Throws<InvalidDataException>(() => record.Append(
            new TransferNotification(Guid.NewGuid(), "fixture.txt", TransferPhase.Released), null));
    }

    [Fact]
    public void Replayed_events_and_connection_status_are_recorded_again_before_send()
    {
        using var record = Record();
        var hub = Hub(record);
        var transfer = Transfer();
        hub.Publish(transfer);
        hub.Publish(new StatusNotification(1, 2, true));
        long previous = Entries()[^1].Sequence;
        using var replay = hub.Subscribe();
        Assert.Equal(previous + 1, Entries()[^1].Sequence);
        Assert.Equal("Transfer", Entries()[^1].Kind);
        Assert.True(replay.Reader.TryRead(out var delivered));
        Assert.Equal(transfer, delivered);
        Assert.NotNull(hub.GetRecordedStatus());
        Assert.Equal(previous + 2, Entries()[^1].Sequence);
        Assert.Equal("Status", Entries()[^1].Kind);
        Directory.CreateDirectory(Path.Combine(DirectoryPath, "head.tmp"));
        using var refusedReplay = hub.Subscribe();
        Assert.False(refusedReplay.Reader.TryRead(out _));
        Assert.Null(hub.GetRecordedStatus());
    }

    [Fact]
    public void Chain_hashes_exact_utf8_line_without_lf_and_restart_keeps_sequence()
    {
        using (var record = Record())
        {
            record.Append(Transfer(), null);
            record.Heartbeat();
        }
        long previous = Entries()[^1].Sequence;
        using var restarted = Record();
        Assert.Equal(previous + 1, Entries()[^1].Sequence);
        var lines = File.ReadAllLines(Active);
        string hash = NotificationRecord.ZeroHash;
        for (int i = 0; i < lines.Length; i++)
        {
            var entry = JsonSerializer.Deserialize<NotificationRecordEntry>(lines[i])!;
            Assert.Equal(i + 1, entry.Sequence);
            Assert.Equal(hash, entry.PreviousSha256);
            hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(lines[i])));
        }
        Assert.Equal(hash, JsonSerializer.Deserialize<NotificationRecordHead>(File.ReadAllText(Path.Combine(DirectoryPath, "head.json")))!.Sha256);
        Assert.NotEqual(Entries()[0].InstanceId, Entries()[^1].InstanceId);
        Assert.All(Entries(), e => Assert.Equal("test/boot", e.BootId));
    }

    [Theory]
    [InlineData("edit")]
    [InlineData("tail")]
    [InlineData("partial")]
    [InlineData("sequence")]
    [InlineData("head")]
    public void Corruption_is_refused_without_repair(string corruption)
    {
        using (var record = Record()) record.Append(Transfer(), null);
        var lines = File.ReadAllLines(Active).ToList();
        if (corruption == "edit") lines[0] = lines[0].Replace("test/boot", "fake/boot");
        if (corruption == "tail") lines.RemoveAt(lines.Count - 1);
        if (corruption == "sequence") lines[1] = lines[1].Replace("\"Sequence\":2", "\"Sequence\":9");
        File.WriteAllText(Active, string.Join('\n', lines) + (corruption == "partial" ? "" : "\n"), new UTF8Encoding(false));
        if (corruption == "head") File.WriteAllText(Path.Combine(DirectoryPath, "head.json"), "{\"Version\":1,\"Sequence\":1,\"Sha256\":\"bad\"}");
        var before = File.ReadAllBytes(Active);
        Assert.Throws<InvalidDataException>(() => Record());
        Assert.Equal(before, File.ReadAllBytes(Active));
    }

    [Fact]
    public void Complete_history_removal_cannot_silently_reset_an_existing_writer_lease()
    {
        using (var record = Record()) record.Append(Transfer(), null);
        File.Delete(Active);
        File.Delete(Path.Combine(DirectoryPath, "head.json"));
        Assert.Throws<InvalidDataException>(() => Record());
    }

    [Fact]
    public void Rotation_announces_loss_and_keeps_bounded_contiguous_history()
    {
        const int limit = NotificationRecord.MaximumLineBytes * 2;
        using (var record = Record(limit))
            for (int i = 0; i < 30; i++) record.Append(Transfer(), null);
        var entries = Entries();
        Assert.Contains(entries, e => e.Kind == "Rotation" && e.DroppedThroughSequence > 0);
        Assert.Equal(entries[^1].DroppedThroughSequence + 1, entries[0].Sequence);
        Assert.All(new[] { Active, Path.Combine(DirectoryPath, "previous.jsonl") }, p => Assert.InRange(new FileInfo(p).Length, 1, limit));
        for (int i = 1; i < entries.Count; i++) Assert.Equal(entries[i - 1].Sequence + 1, entries[i].Sequence);
        long last = entries[^1].Sequence;
        using var restarted = Record(limit);
        Assert.True(Entries()[^1].Sequence > last);
        Assert.Equal("Start", Entries()[^1].Kind);
    }

    [Fact]
    public void A_second_writer_is_refused_until_the_first_closes()
    {
        using (var record = Record())
        {
            Assert.Throws<IOException>(() => Record());
            record.Append(Transfer(), null);
        }
        using var reopened = Record();
        reopened.Append(Transfer(), null);
    }

    [Fact]
    public void Write_failure_suppresses_delivery_replay_and_status_and_is_logged()
    {
        using var record = Record();
        var logger = new CaptureLogger();
        var hub = Hub(record, logger);
        using var subscription = hub.Subscribe();
        // Same failure path as an IO/share/ACL error: checkpoint cannot be created.
        Directory.CreateDirectory(Path.Combine(DirectoryPath, "head.tmp"));
        hub.Publish(Transfer());
        hub.Publish(new StatusNotification(1, 2, true));
        Assert.False(subscription.Reader.TryRead(out _));
        using var replay = hub.Subscribe();
        Assert.False(replay.Reader.TryRead(out _));
        Assert.Null(hub.CurrentStatus);
        Assert.Equal(2, logger.Errors);
        Assert.Throws<IOException>(() => record.Heartbeat());
    }

    [Fact]
    public async Task Concurrent_emitters_have_one_durable_total_order_matching_delivery()
    {
        using var record = Record();
        var hub = Hub(record);
        using var subscription = hub.Subscribe();
        await Task.WhenAll(Enumerable.Range(0, 128).Select(_ => Task.Run(() => hub.Publish(Transfer()))));
        var delivered = new List<Guid>();
        while (subscription.Reader.TryRead(out var item)) delivered.Add(((TransferNotification)item).TransferId);
        var entries = Entries();
        Assert.Equal(128, delivered.Count);
        Assert.Equal(entries.Where(e => e.Kind == "Transfer").Select(e => e.TransferId!.Value), delivered);
        Assert.Equal(Enumerable.Range(1, entries.Count).Select(i => (long)i), entries.Select(e => e.Sequence));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Unsafe_acl_is_refused_on_open_without_repair(bool directory)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var record = Record();
        string path = directory ? DirectoryPath : Active;
        FileSystemSecurity acl = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Read, AccessControlType.Allow));
        if (directory) new DirectoryInfo(path).SetAccessControl((DirectorySecurity)acl);
        else new FileInfo(path).SetAccessControl((FileSecurity)acl);
        string before = (directory ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl()).GetSecurityDescriptorSddlForm(AccessControlSections.All);
        Assert.Throws<UnauthorizedAccessException>(() => record.Append(Transfer(), null));
        record.Dispose(); // Release the exclusive writer before testing recovery admission.
        Assert.Throws<UnauthorizedAccessException>(() => Record());
        Assert.Equal(before, (directory ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl()).GetSecurityDescriptorSddlForm(AccessControlSections.All));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Reparse_and_hard_link_files_are_refused(bool hardLink)
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var record = Record()) record.Append(Transfer(), null);
        string outside = Path.Combine(_root, "outside.jsonl");
        File.Move(Active, outside);
        var prior = File.ReadAllBytes(outside);
        if (hardLink) Assert.True(CreateHardLink(Active, outside, IntPtr.Zero));
        else File.CreateSymbolicLink(Active, outside);
        try { Assert.Throws<IOException>(() => Record()); Assert.Equal(prior, File.ReadAllBytes(outside)); }
        finally { File.Delete(Active); }
    }

    [Fact]
    public void Reparse_directory_is_refused()
    {
        string outside = Path.Combine(_root, "outside");
        Directory.CreateDirectory(outside);
        Directory.CreateSymbolicLink(DirectoryPath, outside);
        try { Assert.Throws<IOException>(() => Record()); Assert.Empty(Directory.EnumerateFileSystemEntries(outside)); }
        finally { Directory.Delete(DirectoryPath); }
    }

    public void Dispose() { if (Directory.Exists(_root)) Directory.Delete(_root, true); }
    private sealed class InspectRecord(INotificationRecord inner, Action<AgentNotification> inspect) : INotificationRecord
    {
        public void Append(AgentNotification n, uint? session) { inner.Append(n, session); inspect(n); }
    }
    private sealed class CaptureLogger : ILogger<NotificationHub>
    {
        public int Errors;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        { if (level == LogLevel.Error) Errors++; }
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);
}
