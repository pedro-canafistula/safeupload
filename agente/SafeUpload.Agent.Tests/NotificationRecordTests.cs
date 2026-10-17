using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Tests;

public sealed class NotificationRecordTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "su-notify-" + Guid.NewGuid().ToString("N"));
    private string DirectoryPath => Path.Combine(_root, "notifications");
    private string Active => Path.Combine(DirectoryPath, "emissions.jsonl");
    public NotificationRecordTests() => Directory.CreateDirectory(_root);
    // Existing corruption controls still exercise strict validation unchanged.
    // Production uses recovery; the controls below also prove its fresh chain.
    private NotificationRecord Record(int limit = NotificationRecord.SegmentBytes) => new(
        DirectoryPath, NullLogger<NotificationRecord>.Instance, limit, "test/boot", testIdentity: true, recoverCorruption: false);
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
    public void Retired_empty_private_reason_is_reserved_and_cannot_be_emitted()
    {
        Assert.Equal(0, (int)StagedBlockReason.ReservedEmptySavePrivate);
        using var record = Record();
        var notice = new TransferNotification(Guid.NewGuid(), "empty.txt", TransferPhase.Blocked,
            BlockReason: StagedBlockReason.ReservedEmptySavePrivate);
        Assert.Throws<InvalidDataException>(() => record.Append(notice, 7));
        Assert.DoesNotContain(Entries(), entry => entry.Kind == "Transfer");
    }

    [Fact]
    public void Seed_export_restriction_is_recorded_and_survives_restart_without_export_authority()
    {
        var notice = new TransferNotification(Guid.NewGuid(), "write-only.txt", TransferPhase.Blocked,
            HandbackVerified: false, SnapshotSha256Hex: new string('B', 64),
            BlockReason: StagedBlockReason.SeedExportRestricted);
        using (var record = Record())
        {
            record.Append(notice, 7);
            var entry = Entries()[^1];
            Assert.Equal(notice.TransferId, entry.TransferId);
            Assert.Equal(StagedBlockReason.SeedExportRestricted, entry.BlockReason);
            Assert.Equal("Blocked", entry.Phase);
            Assert.Equal((uint)7, entry.TargetSessionId);
            Assert.Equal(notice.SnapshotSha256Hex, entry.Sha256Hex);
            Assert.Null(entry.HandBackPath);
        }
        using var restarted = Record();
        var next = Transfer();
        restarted.Append(next, 7);
        Assert.Equal(next.TransferId, Entries()[^1].TransferId);
        Assert.Single(Entries().Where(entry => entry.TransferId == notice.TransferId));
    }

    [Theory]
    [InlineData("analyzing")]
    [InlineData("released")]
    [InlineData("retained")]
    [InlineData("override")]
    [InlineData("handback")]
    [InlineData("unknown")]
    public void Seed_export_restriction_rejects_inconsistent_authority_without_closing_record(string mutation)
    {
        using var record = Record();
        var notice = new TransferNotification(Guid.NewGuid(), "write-only.txt", TransferPhase.Blocked,
            HandbackVerified: false, SnapshotSha256Hex: new string('B', 64),
            BlockReason: StagedBlockReason.SeedExportRestricted);
        notice = mutation switch
        {
            "analyzing" => notice with { Phase = TransferPhase.Analyzing },
            "released" => notice with { Phase = TransferPhase.Released },
            "retained" => notice with { Phase = TransferPhase.Retained },
            "override" => notice with { OverrideAllowed = true },
            "handback" => notice with { HandbackVerified = true, HandbackPath = "returned.txt" },
            "unknown" => notice with { BlockReason = (StagedBlockReason)999 },
            _ => throw new ArgumentOutOfRangeException(nameof(mutation))
        };
        Assert.Throws<InvalidDataException>(() => record.Append(notice, 7));
        Assert.DoesNotContain(Entries(), entry => entry.TransferId == notice.TransferId);
        var next = Transfer();
        record.Append(next, 7);
        Assert.Equal(next.TransferId, Entries()[^1].TransferId);
    }

    [Theory]
    [InlineData(TransferPhase.Analyzing)]
    [InlineData(TransferPhase.Retained)]
    [InlineData(TransferPhase.Released)]
    [InlineData(TransferPhase.Blocked)]
    public void Inspection_failure_metadata_is_refused_for_unknown_kind_or_nonblocked_phase(TransferPhase phase)
    {
        using var record = Record();
        var notification = new TransferNotification(Guid.NewGuid(), "fixture.txt", phase,
            PublishedSha256Hex: phase == TransferPhase.Released ? new string('A', 64) : null,
            SnapshotSha256Hex: phase == TransferPhase.Blocked ? new string('B', 64) : null,
            HandbackVerified: phase == TransferPhase.Blocked ? false : null,
            InspectionFailure: phase == TransferPhase.Blocked ? (InspectionFailureKind)999 : InspectionFailureKind.Timeout);
        Assert.Throws<InvalidDataException>(() => record.Append(notification, null));
        Assert.DoesNotContain(Entries(), entry => entry.Kind == "Transfer");
    }

    [Fact]
    public void Staging_space_alert_and_invalid_input_do_not_close_later_notifications()
    {
        using var record = Record();
        var alert = new TransferNotification(Guid.NewGuid(), "large.txt", TransferPhase.Retained,
            InspectionFailure: InspectionFailureKind.NotEnoughStagingSpace);
        record.Append(alert, 1);
        Assert.Equal("Retained", Entries()[^1].Phase);
        Assert.Null(Entries()[^1].Sha256Hex);
        Assert.Throws<InvalidDataException>(() => record.Append(alert with { TransferId = Guid.Empty }, 1));
        Assert.Throws<InvalidDataException>(() => record.Append(alert with { PublishedSha256Hex = new string('A', 64) }, 1));
        Assert.Throws<InvalidDataException>(() => record.Append(alert with { OverrideAllowed = true }, 1));
        var next = Transfer(); record.Append(next, 1); record.Heartbeat();
        Assert.Equal(next.TransferId, Entries()[^2].TransferId);
        Assert.Equal("Heartbeat", Entries()[^1].Kind);
    }

    [Fact]
    public void Transient_storage_failure_recovers_in_process_preserves_damage_and_never_delivers_failed_emission()
    {
        using var record = new NotificationRecord(DirectoryPath, NullLogger.Instance, NotificationRecord.SegmentBytes,
            "test/boot", testIdentity: true, recoverCorruption: true);
        long now = System.Diagnostics.Stopwatch.GetTimestamp(); record.RecoveryClock = () => now;
        string previousInstance = Entries()[^1].InstanceId;
        var hub = Hub(record); using var subscription = hub.Subscribe();
        string temporary = Path.Combine(DirectoryPath, "head.tmp");
        Directory.CreateDirectory(temporary);
        var failed = Transfer(); hub.Publish(failed);
        Assert.False(subscription.Reader.TryRead(out _));
        Assert.Throws<IOException>(() => record.Heartbeat());
        now += System.Diagnostics.Stopwatch.Frequency * 2;
        Assert.Throws<IOException>(() => record.Heartbeat()); // Unsafe child is never normalized.
        Assert.True(Directory.Exists(temporary));
        Directory.Delete(temporary);
        byte[] damaged = File.ReadAllBytes(Active);
        now += System.Diagnostics.Stopwatch.Frequency * 2;
        var next = Transfer(); hub.Publish(next);
        Assert.True(subscription.Reader.TryRead(out var delivered)); Assert.Equal(next, delivered);
        Assert.False(subscription.Reader.TryRead(out _));
        string archive = Assert.Single(Directory.GetDirectories(_root, "notifications.corrupt-*"));
        Assert.Equal(damaged, File.ReadAllBytes(Path.Combine(archive, "emissions.jsonl")));
        Assert.NotEqual(previousInstance, Entries()[0].InstanceId);
        Assert.Equal("Start", Entries()[0].Kind); Assert.Equal(1, Entries()[0].Sequence);
        Assert.DoesNotContain(Entries(), entry => entry.TransferId == failed.TransferId);
        Assert.Equal(next.TransferId, Entries()[^1].TransferId);
        record.Dispose();
        now += System.Diagnostics.Stopwatch.Frequency * 2;
        Assert.Throws<ObjectDisposedException>(() => record.Append(Transfer(), 1));
    }

    [Fact]
    public void Online_empty_history_recovery_starts_a_new_instance_even_for_an_initially_fresh_writer()
    {
        using var record = new NotificationRecord(DirectoryPath, NullLogger.Instance, NotificationRecord.SegmentBytes,
            "test/boot", testIdentity: true, recoverCorruption: true);
        long now = System.Diagnostics.Stopwatch.GetTimestamp(); record.RecoveryClock = () => now;
        record.Append(Transfer(), 1);
        string original = Entries()[^1].InstanceId;
        string temporary = Path.Combine(DirectoryPath, "head.tmp"); Directory.CreateDirectory(temporary);
        Assert.Throws<IOException>(() => record.Append(Transfer(), 1));
        Directory.Delete(temporary);
        File.Delete(Active); File.Delete(Path.Combine(DirectoryPath, "head.json"));
        now += System.Diagnostics.Stopwatch.Frequency * 2;
        record.Append(Transfer(), 1);
        Assert.NotEqual(original, Entries()[0].InstanceId);
        Assert.Equal(1, Entries()[0].Sequence); Assert.Equal(NotificationRecord.ZeroHash, Entries()[0].PreviousSha256);
        Assert.Equal("Start", Entries()[0].Kind);
        record.Dispose(); using var strict = Record(); // Recovered anchor/chain validates independently.
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

    [Theory]
    [InlineData("tail")]
    [InlineData("partial")]
    [InlineData("json")]
    [InlineData("head")]
    [InlineData("missing-head")]
    [InlineData("temporary-head")]
    [InlineData("missing-history")]
    public void Startup_preserves_damaged_history_warns_and_delivers_on_a_fresh_chain(string damage)
    {
        string head = Path.Combine(DirectoryPath, "head.json");
        using (var record = Record()) record.Append(Transfer(), null);
        var oldInstance = Entries()[0].InstanceId;
        if (damage == "tail") File.WriteAllLines(Active, File.ReadAllLines(Active)[..^1], new UTF8Encoding(false));
        if (damage == "partial") File.AppendAllText(Active, "{\"Version\":");
        if (damage == "json") File.WriteAllText(Active, "{broken}\n");
        if (damage == "head") File.WriteAllText(head, "{\"Version\":1,\"Sequence\":1,\"Sha256\":\"bad\"}");
        if (damage == "missing-head") File.Delete(head);
        if (damage == "temporary-head") File.Copy(head, Path.Combine(DirectoryPath, "head.tmp"));
        if (damage == "missing-history") { File.Delete(Active); File.Delete(head); }
        var original = Directory.GetFiles(DirectoryPath).Where(p => Path.GetFileName(p) != "writer.lock")
            .ToDictionary(p => Path.GetFileName(p)!, File.ReadAllBytes);
        var logger = new RecoveryLogger();
        using (var recovered = new NotificationRecord(DirectoryPath, logger, NotificationRecord.SegmentBytes,
            "test/boot", testIdentity: true))
        {
            string archive = Assert.Single(Directory.GetDirectories(_root, "notifications.corrupt-*"));
            Assert.Equal(original.Keys.Order(), Directory.GetFiles(archive).Select(Path.GetFileName).Order());
            foreach (var (name, bytes) in original) Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(archive, name!)));
            Assert.Equal(1, logger.Warnings);
            Assert.Contains(archive, logger.Message);
            var start = Assert.Single(Entries());
            Assert.Equal("Start", start.Kind);
            Assert.Equal(1, start.Sequence);
            Assert.Equal(NotificationRecord.ZeroHash, start.PreviousSha256);
            Assert.NotEqual(oldInstance, start.InstanceId);
            if (OperatingSystem.IsWindows()) Assert.Throws<IOException>(() => Record());
            var hub = Hub(recovered);
            using var subscriber = hub.Subscribe();
            var transfer = Transfer();
            hub.Publish(transfer, 4);
            Assert.True(subscriber.Reader.TryRead(out var delivered));
            Assert.Equal(transfer, delivered);
            Assert.Equal(transfer.TransferId, Entries()[^1].TransferId);
        }
        long last = Entries()[^1].Sequence;
        using var restarted = Record(); // Fresh history satisfies the original strict validator.
        Assert.Equal(last + 1, Entries()[^1].Sequence);
        Assert.Single(Directory.GetDirectories(_root, "notifications.corrupt-*"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Startup_archives_a_temporary_head_without_trusting_or_reading_its_dacl(bool denyRead)
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var record = Record()) record.Append(Transfer(), null);
        string temporary = Path.Combine(DirectoryPath, "head.tmp");
        File.Copy(Path.Combine(DirectoryPath, "head.json"), temporary);
        byte[] bytes = File.ReadAllBytes(temporary);
        var originalAcl = new FileInfo(temporary).GetAccessControl();
        var damagedAcl = new FileInfo(temporary).GetAccessControl();
        damagedAcl.SetAccessRuleProtection(true, true);
        damagedAcl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(denyRead ? WellKnownSidType.WorldSid : WellKnownSidType.BuiltinUsersSid, null),
            denyRead ? FileSystemRights.ReadData : FileSystemRights.Read, denyRead ? AccessControlType.Deny : AccessControlType.Allow));
        new FileInfo(temporary).SetAccessControl(damagedAcl);
        var descriptor = new FileInfo(temporary).GetAccessControl().GetSecurityDescriptorBinaryForm();
        if (denyRead) Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllBytes(temporary));
        var logger = new RecoveryLogger();
        using var recovered = new NotificationRecord(DirectoryPath, logger, NotificationRecord.SegmentBytes,
            "test/boot", testIdentity: true);
        string archive = Assert.Single(Directory.GetDirectories(_root, "notifications.corrupt-*"));
        string preserved = Path.Combine(archive, "head.tmp");
        Assert.False(File.Exists(temporary));
        Assert.Equal(descriptor, new FileInfo(preserved).GetAccessControl().GetSecurityDescriptorBinaryForm());
        // Only the test restores read access to inspect the preserved bytes.
        originalAcl.SetSecurityDescriptorBinaryForm(originalAcl.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
        new FileInfo(preserved).SetAccessControl(originalAcl);
        Assert.Equal(bytes, File.ReadAllBytes(preserved));
        Assert.Equal(1, logger.Warnings);
        var start = Assert.Single(Entries());
        Assert.Equal("Start", start.Kind);
        Assert.Equal(1, start.Sequence);
        Assert.Equal(NotificationRecord.ZeroHash, start.PreviousSha256);
        var hub = Hub(recovered);
        using var subscriber = hub.Subscribe();
        var transfer = Transfer();
        hub.Publish(transfer, 4);
        Assert.True(subscriber.Reader.TryRead(out var delivered));
        Assert.Equal(transfer, delivered);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Recovery_refuses_a_linked_temporary_head_before_moving_any_evidence(bool hardLink)
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var record = Record()) record.Append(Transfer(), null);
        byte[] original = File.ReadAllBytes(Active);
        string outside = Path.Combine(_root, "outside-head.json");
        File.Copy(Path.Combine(DirectoryPath, "head.json"), outside);
        byte[] outsideBytes = File.ReadAllBytes(outside);
        string temporary = Path.Combine(DirectoryPath, "head.tmp");
        if (hardLink) Assert.True(CreateHardLink(temporary, outside, IntPtr.Zero));
        else File.CreateSymbolicLink(temporary, outside);
        try
        {
            Assert.Throws<IOException>(() => new NotificationRecord(DirectoryPath, NullLogger.Instance,
                NotificationRecord.SegmentBytes, "test/boot", testIdentity: true));
            Assert.Equal(original, File.ReadAllBytes(Active));
            Assert.Equal(outsideBytes, File.ReadAllBytes(outside));
            Assert.Empty(Directory.GetDirectories(_root, "notifications.corrupt-*"));
        }
        finally { File.Delete(temporary); }
    }

    [Fact]
    public void Recovery_does_not_move_unexpected_children_or_follow_links()
    {
        using (var record = Record()) record.Append(Transfer(), null);
        string outside = Path.Combine(_root, "outside");
        File.WriteAllText(outside, "outside evidence");
        File.Delete(Active);
        File.CreateSymbolicLink(Active, outside);
        Assert.Throws<IOException>(() => new NotificationRecord(DirectoryPath, NullLogger.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true));
        Assert.Equal("outside evidence", File.ReadAllText(outside));
        Assert.Empty(Directory.GetDirectories(_root, "notifications.corrupt-*"));
        File.Delete(Active);
        Directory.CreateDirectory(Path.Combine(DirectoryPath, "unexpected"));
        Assert.Throws<IOException>(() => new NotificationRecord(DirectoryPath, NullLogger.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true));
        Assert.Empty(Directory.GetDirectories(_root, "notifications.corrupt-*"));
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
    public void Two_hours_of_heartbeats_keep_a_small_hash_chained_window_across_restart()
    {
        using (var record = Record(NotificationRecord.RetainedSegmentBytes))
            for (int i = 0; i < 7200; i++) record.Heartbeat();
        AssertRetainedWindow();
        long last = Entries()[^1].Sequence;
        using (var restarted = Record(NotificationRecord.RetainedSegmentBytes))
            restarted.Heartbeat();
        Assert.True(Entries()[^1].Sequence > last);
        AssertRetainedWindow();
    }

    [Fact]
    public void Smaller_window_accepts_legacy_segments_and_ages_them_out_without_chain_reset()
    {
        using (var record = Record())
            for (int i = 0; i < 700; i++) record.Heartbeat();
        Assert.True(new FileInfo(Active).Length > NotificationRecord.RetainedSegmentBytes);
        long last = Entries()[^1].Sequence;
        using (var record = Record(NotificationRecord.RetainedSegmentBytes))
        {
            Assert.Equal(last + 2, Entries()[^1].Sequence); // Rotation, Start
            for (int i = 0; i < 700; i++) record.Heartbeat();
        }
        AssertRetainedWindow();
        Assert.Empty(Directory.GetDirectories(_root, "notifications.corrupt-*"));
    }

    private void AssertRetainedWindow()
    {
        Assert.All(new[] { Active, Path.Combine(DirectoryPath, "previous.jsonl") },
            path => Assert.InRange(new FileInfo(path).Length, 1, NotificationRecord.RetainedSegmentBytes));
        var lines = new[] { "previous.jsonl", "emissions.jsonl" }
            .SelectMany(name => File.ReadAllLines(Path.Combine(DirectoryPath, name))).ToArray();
        var entries = Entries();
        Assert.True(entries[0].Sequence > 1);
        Assert.Equal(entries[^1].DroppedThroughSequence + 1, entries[0].Sequence);
        for (int i = 1; i < entries.Count; i++)
        {
            Assert.Equal(entries[i - 1].Sequence + 1, entries[i].Sequence);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(lines[i - 1]))),
                entries[i].PreviousSha256);
        }
        var head = JsonSerializer.Deserialize<NotificationRecordHead>(File.ReadAllText(Path.Combine(DirectoryPath, "head.json")))!;
        Assert.Equal(entries[^1].Sequence, head.Sequence);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(lines[^1]))), head.Sha256);
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
        Assert.Throws<UnauthorizedAccessException>(() => new NotificationRecord(DirectoryPath, NullLogger.Instance,
            NotificationRecord.SegmentBytes, "test/boot", testIdentity: true));
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
    private sealed class RecoveryLogger : ILogger
    {
        public int Warnings;
        public string Message = "";
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        { if (level == LogLevel.Warning) { Warnings++; Message = formatter(state, exception); } }
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(string link, string existing, IntPtr reserved);
}
