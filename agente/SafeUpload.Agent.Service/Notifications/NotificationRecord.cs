using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Service.Notifications;

public interface INotificationRecord
{
    void Append(AgentNotification notification, uint? targetSessionId);
}

/// <summary>
/// Emissions, not delivery receipts. One serialized writer; durable head anchors
/// the tail. Any uncertain write poisons this instance until administrative
/// recovery, so a damaged timeline can never authorize subsequent delivery.
/// Privileged local actors are in the trust boundary (as with the journal).
/// </summary>
public sealed class NotificationRecord : INotificationRecord, IDisposable
{
    public const int SegmentBytes = 4 * 1024 * 1024;
    public const int MaximumLineBytes = 16 * 1024;
    public const string ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private readonly string _directory;
    private readonly int _limit;
    private readonly string _boot;
    private readonly string _instance = Guid.NewGuid().ToString("D");
    private readonly SecurityIdentifier? _testOwner;
    private readonly Lock _gate = new();
    private readonly ILogger _logger;
    private Timer? _timer;
    private readonly FileStream _lease;
    private readonly bool _fresh;
    private long _sequence;
    private string _hash = ZeroHash;
    private long _dropped;
    private bool _failed, _disposed;

    public NotificationRecord(string directory, ILogger<NotificationRecord> logger)
        : this(directory, logger, SegmentBytes, BootIdentity(), false, true) { }

    // Tests use a private temporary tree and the invoking identity. Production
    // never permits this exception and never repairs an existing descriptor.
    internal NotificationRecord(string directory, ILogger logger, int segmentBytes,
        string bootId, bool testIdentity, bool heartbeat = false)
    {
        _directory = Path.GetFullPath(directory);
        _limit = segmentBytes;
        if (_limit < MaximumLineBytes * 2) throw new ArgumentOutOfRangeException(nameof(segmentBytes));
        _boot = bootId;
        _logger = logger;
        if (OperatingSystem.IsWindows() && testIdentity)
        {
            using var identity = WindowsIdentity.GetCurrent();
            _testOwner = identity.User;
        }
        RequirePath();
        // The hub can be constructed before the policy store first loads.
        // Create a missing SafeUpload parent with the same private descriptor;
        // never normalize an existing parent or its children.
        if (OperatingSystem.IsWindows() && !testIdentity)
        {
            string parent = Path.GetDirectoryName(_directory)
                ?? throw new IOException("Notification record needs a private parent.");
            if (!Directory.Exists(parent)) new DirectoryInfo(parent).Create(DirectoryAcl());
            RequirePath();
            RequireParent();
        }
        if (!Directory.Exists(_directory))
        {
            if (OperatingSystem.IsWindows())
            {
                if (!testIdentity) RequireParent();
                new DirectoryInfo(_directory).Create(DirectoryAcl());
            }
            else Directory.CreateDirectory(_directory);
        }
        RequireDirectory();
        _fresh = !File.Exists(Lease);
        _lease = _fresh ? Create(Lease) : Open(Lease, writable: true);
        try
        {
            if (_lease.Length != 0) throw new InvalidDataException("Invalid notification writer lease.");
            Recover();
            Write("Start", null, null, null, null);
            if (heartbeat) _timer = new Timer(_ => Tick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        }
        catch { _lease.Dispose(); throw; }
    }

    private string Lease => Path.Combine(_directory, "writer.lock");
    private string Active => Path.Combine(_directory, "emissions.jsonl");
    private string Previous => Path.Combine(_directory, "previous.jsonl");
    private string Head => Path.Combine(_directory, "head.json");

    public void Append(AgentNotification notification, uint? targetSessionId)
    {
        lock (_gate)
        {
            RequireHealthy();
            try
            {
                if (notification is TransferNotification candidate &&
                    (candidate.TransferId == Guid.Empty || !Enum.IsDefined(candidate.Phase)))
                    throw new InvalidDataException("Invalid transfer notification identity/phase.");
                if (notification is TransferNotification transfer &&
                    ((transfer.PublishedSha256Hex is { } digest &&
                      (digest.Length != 64 || !digest.All(Uri.IsHexDigit))) ||
                     (transfer.SnapshotSha256Hex is { } snapshotDigest &&
                      (snapshotDigest.Length != 64 || !snapshotDigest.All(Uri.IsHexDigit))) ||
                     (transfer.Phase == TransferPhase.Released &&
                      transfer.PublishedSha256Hex is null) ||
                     (transfer.Phase == TransferPhase.Blocked &&
                      (transfer.PublishedSha256Hex is not null || transfer.SnapshotSha256Hex is null)) ||
                     (transfer.Phase != TransferPhase.Blocked && transfer.SnapshotSha256Hex is not null) ||
                     (transfer.Phase == TransferPhase.Blocked &&
                      (transfer.HandbackVerified is null ||
                       (transfer.HandbackVerified == true && string.IsNullOrWhiteSpace(transfer.HandbackPath)) ||
                       (transfer.HandbackVerified == false && transfer.HandbackPath is not null))) ||
                     (transfer.Phase != TransferPhase.Blocked &&
                      (transfer.HandbackPath is not null || transfer.HandbackVerified is not null))))
                    throw new InvalidDataException("Invalid staged hand-back notification evidence.");
                if (notification is EventNotification audit && audit.Event.EventId == Guid.Empty)
                    throw new InvalidDataException("Invalid audit notification identity.");
                var (kind, transferId, eventId, phase) = notification switch
                {
                    TransferNotification t => ("Transfer", (Guid?)t.TransferId, (Guid?)null, t.Phase.ToString()),
                    EventNotification e => ("Event", (Guid?)null, (Guid?)e.Event.EventId, e.Event.Verdict.ToString()),
                    StatusNotification => ("Status", (Guid?)null, (Guid?)null, (string?)null),
                    _ => throw new InvalidDataException("Unknown notification kind.")
                };
                Write(kind, transferId, eventId, phase, targetSessionId);
            }
            catch { _failed = true; throw; }
        }
    }

    internal void Heartbeat()
    {
        lock (_gate)
        {
            RequireHealthy();
            try { Write("Heartbeat", null, null, null, null); }
            catch { _failed = true; throw; }
        }
    }

    private void Tick()
    {
        try
        {
            lock (_gate)
            {
                if (_failed || _disposed) return;
                Heartbeat();
            }
        }
        catch (Exception ex) { _logger.LogError(ex, "Notification record coverage failed; notifications suppressed until recovery"); }
    }

    private void RequireHealthy()
    {
        if (_failed || _disposed) throw new IOException("Notification record is closed after a failure or shutdown.");
    }

    private void Write(string kind, Guid? transfer, Guid? eventId, string? phase, uint? session)
    {
        RequireDirectory();
        if (File.Exists(Active))
        {
            using var current = Open(Active);
            if (current.Length + MaximumLineBytes * 2 > _limit)
            {
                current.Dispose();
                long dropped = _dropped;
                if (File.Exists(Previous))
                {
                    using var prior = Open(Previous);
                    dropped = ReadLines(prior).Last().Entry.Sequence;
                }
                // Durable announcement BEFORE discarding a retained segment.
                WriteLine("Rotation", null, null, null, null, dropped);
                if (File.Exists(Previous)) File.Delete(Previous);
                File.Move(Active, Previous);
                _dropped = dropped;
            }
        }
        WriteLine(kind, transfer, eventId, phase, session, _dropped);
    }

    private void WriteLine(string kind, Guid? transfer, Guid? eventId, string? phase, uint? session, long dropped)
    {
        if (!File.Exists(Active)) { using var created = Create(Active); }
        using var file = Open(Active, writable: true);
        var entry = new NotificationRecordEntry(1, checked(_sequence + 1), _boot, _instance,
            DateTimeOffset.UtcNow, Stopwatch.GetTimestamp(), Stopwatch.Frequency,
            kind, transfer, eventId, phase, session, _hash, dropped);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(entry);
        if (bytes.Length + 1 > MaximumLineBytes || file.Length + bytes.Length + 1 > _limit)
            throw new InvalidDataException("Notification record size bound exceeded.");
        file.Position = file.Length;
        file.Write(bytes);
        file.WriteByte(10);
        file.Flush(flushToDisk: true);
        string hash = Convert.ToHexString(SHA256.HashData(bytes));
        // Flush head before any subscriber can see this notification. An
        // interrupted append/head replacement is rejected rather than repaired.
        if (File.Exists(Head)) { using var old = Open(Head); }
        string temporary = Path.Combine(_directory, "head.tmp");
        using (var checkpoint = Create(temporary))
        {
            checkpoint.Write(JsonSerializer.SerializeToUtf8Bytes(new NotificationRecordHead(1, entry.Sequence, hash)));
            checkpoint.Flush(flushToDisk: true);
        }
        File.Move(temporary, Head, overwrite: true);
        _sequence = entry.Sequence;
        _hash = hash;
    }

    private void Recover()
    {
        var names = Directory.EnumerateFileSystemEntries(_directory).Select(Path.GetFileName).Where(n => n != "writer.lock").ToArray();
        if (names.Any(n => n is not ("emissions.jsonl" or "previous.jsonl" or "head.json")))
            throw new InvalidDataException("Unexpected notification record child; recovery requires investigation.");
        var lines = new List<(NotificationRecordEntry Entry, string Hash)>();
        foreach (string path in new[] { Previous, Active })
            if (File.Exists(path)) { using var file = Open(path); lines.AddRange(ReadLines(file)); }
        if (lines.Count == 0)
        {
            if (!_fresh || names.Length != 0) throw new InvalidDataException("Empty/truncated notification record.");
            return;
        }
        var first = lines[0].Entry;
        if (first.Sequence != lines[^1].Entry.DroppedThroughSequence + 1 ||
            (first.Sequence == 1 && first.PreviousSha256 != ZeroHash))
            throw new InvalidDataException("Unannounced notification history loss.");
        for (int i = 1; i < lines.Count; i++)
            if (lines[i].Entry.Sequence != lines[i - 1].Entry.Sequence + 1 ||
                lines[i].Entry.PreviousSha256 != lines[i - 1].Hash)
                throw new InvalidDataException("Notification sequence/hash chain broken.");
        using var head = Open(Head);
        var anchor = JsonSerializer.Deserialize<NotificationRecordHead>(head)
            ?? throw new InvalidDataException("Missing notification head.");
        if (anchor.Version != 1 || anchor.Sequence != lines[^1].Entry.Sequence || anchor.Sha256 != lines[^1].Hash)
            throw new InvalidDataException("Notification tail differs from durable head.");
        _sequence = anchor.Sequence;
        _hash = anchor.Sha256;
        _dropped = lines[^1].Entry.DroppedThroughSequence;
    }

    internal static List<(NotificationRecordEntry Entry, string Hash)> ReadLines(FileStream file)
    {
        using var memory = new MemoryStream();
        file.CopyTo(memory);
        byte[] bytes = memory.ToArray();
        if (bytes.Length == 0 || bytes[^1] != 10) throw new InvalidDataException("Incomplete notification line.");
        var result = new List<(NotificationRecordEntry, string)>();
        int start = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] != 10) continue;
            var line = bytes.AsSpan(start, i - start);
            if (line.Length == 0 || line.Length >= MaximumLineBytes) throw new InvalidDataException("Invalid notification line size.");
            var entry = JsonSerializer.Deserialize<NotificationRecordEntry>(line)
                ?? throw new InvalidDataException("Invalid notification JSON.");
            if (entry.Version != 1 || entry.Sequence <= 0 || entry.DroppedThroughSequence < 0 ||
                entry.DroppedThroughSequence >= entry.Sequence || string.IsNullOrWhiteSpace(entry.BootId) ||
                !Guid.TryParse(entry.InstanceId, out var instance) || instance == Guid.Empty || entry.Utc == default || entry.Utc.Offset != TimeSpan.Zero || entry.Qpc < 0 || entry.QpcFrequency <= 0 ||
                entry.PreviousSha256.Length != 64 || !entry.PreviousSha256.All(Uri.IsHexDigit) ||
                entry.Kind is not ("Start" or "Heartbeat" or "Stop" or "Rotation" or "Transfer" or "Event" or "Status"))
                throw new InvalidDataException("Invalid notification record fields.");
            if ((entry.Kind == "Transfer" && (entry.TransferId is null || entry.TransferId == Guid.Empty ||
                    entry.Phase is not ("Analyzing" or "Released" or "Blocked" or "Retained"))) ||
                (entry.Kind == "Event" && (entry.EventId is null || entry.EventId == Guid.Empty ||
                    entry.Phase is not ("Approved" or "Blocked" or "AllowedWithoutInspection" or "Retained"))))
                throw new InvalidDataException("Invalid notification payload identity/phase.");
            result.Add((entry, Convert.ToHexString(SHA256.HashData(line))));
            start = i + 1;
        }
        return result;
    }

    private FileStream Open(string path, bool writable = false)
    {
        RequireDirectory();
        var stream = StagedJournalFile.Open(path, writable: writable, maximumBytes: _limit);
        try { if (OperatingSystem.IsWindows()) RequireAcl(stream.GetAccessControl(), false); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private FileStream Create(string path)
    {
        var stream = OperatingSystem.IsWindows()
            ? new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.Read,
                4096, FileOptions.WriteThrough, FileAcl())
            : new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.WriteThrough);
        try { if (OperatingSystem.IsWindows()) RequireAcl(stream.GetAccessControl(), false); return stream; }
        catch { stream.Dispose(); throw; }
    }

    private void RequirePath()
    {
        for (string? path = _directory; path is not null; path = Path.GetDirectoryName(path))
            if ((Directory.Exists(path) || File.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Notification record path contains a reparse point.");
    }

    private void RequireDirectory()
    {
        RequirePath();
        if (OperatingSystem.IsWindows())
        {
            if (_testOwner is null) RequireParent();
            RequireAcl(new DirectoryInfo(_directory).GetAccessControl(), true);
        }
    }

    private void RequireParent()
    {
        StagedTransferJournal.RequireProtectedParent(_directory);
        RequireAcl(new DirectoryInfo(Path.GetDirectoryName(_directory)!).GetAccessControl(), true);
    }

    private IEnumerable<SecurityIdentifier> Trustees() => new[]
    {
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
    }.Concat(_testOwner is null ? [] : new[] { _testOwner }).Distinct();

    private void ConfigureAcl(FileSystemSecurity acl, bool directory)
    {
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(_testOwner ?? new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        foreach (var sid in Trustees()) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
            directory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
            PropagationFlags.None, AccessControlType.Allow));
    }
    private DirectorySecurity DirectoryAcl() { var acl = new DirectorySecurity(); ConfigureAcl(acl, true); return acl; }
    private FileSecurity FileAcl() { var acl = new FileSecurity(); ConfigureAcl(acl, false); return acl; }

    private void RequireAcl(FileSystemSecurity acl, bool directory)
    {
        var allowed = Trustees().Select(s => s.Value).ToHashSet();
        var owner = acl.GetOwner(typeof(SecurityIdentifier))?.Value;
        if (owner is null || !acl.AreAccessRulesProtected || (owner != "S-1-5-18" && owner != "S-1-5-32-544" && owner != _testOwner?.Value))
            throw new UnauthorizedAccessException("Notification record owner/DACL is untrusted.");
        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
        if (rules.Length != allowed.Count || rules.Any(r => r.IsInherited || r.AccessControlType != AccessControlType.Allow ||
            !allowed.Remove(r.IdentityReference.Value) || r.FileSystemRights != FileSystemRights.FullControl ||
            r.PropagationFlags != PropagationFlags.None || r.InheritanceFlags != (directory
                ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None)) || allowed.Count != 0)
            throw new UnauthorizedAccessException("Notification record requires an exact private DACL.");
    }

    public void Dispose()
    {
        _timer?.Dispose();
        lock (_gate)
        {
            if (_disposed) return;
            try { if (!_failed) Write("Stop", null, null, null, null); }
            catch (Exception ex) { _logger.LogError(ex, "Notification record shutdown failed"); }
            _disposed = true;
            _lease.Dispose();
        }
    }

    private static string BootIdentity()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Notification record production requires Windows.");
        int status = NtQuerySystemInformation(3, out var times, Marshal.SizeOf<TimeOfDay>(), out _);
        if (status != 0) throw new IOException($"Cannot identify Windows boot: NTSTATUS {status:X8}");
        return Environment.MachineName + "/" + new DateTime(DateTime.FromFileTimeUtc(times.BootTime).Ticks / 10 * 10, DateTimeKind.Utc).ToString("o");
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TimeOfDay { public long BootTime, CurrentTime, TimeZoneBias; public uint TimeZoneId, Reserved; public ulong BootTimeBias, SleepTimeBias; }
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, out TimeOfDay information, int length, out int returned);
}

public sealed record NotificationRecordEntry(int Version, long Sequence, string BootId, string InstanceId,
    DateTimeOffset Utc, long Qpc, long QpcFrequency, string Kind, Guid? TransferId, Guid? EventId,
    string? Phase, uint? TargetSessionId, string PreviousSha256, long DroppedThroughSequence);
public sealed record NotificationRecordHead(int Version, long Sequence, string Sha256);

internal sealed class UnavailableNotificationRecord(Exception error) : INotificationRecord
{
    public void Append(AgentNotification notification, uint? targetSessionId) =>
        throw new IOException("Notification record unavailable; delivery refused.", error);
}
