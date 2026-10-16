using System.Buffers.Binary;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>Private storage reservations. Values are physical bytes, including overlapping copies.</summary>
public sealed record StagedSpaceOptions(bool Enabled, long TotalBytes, long PerUserBytes, long FreeSpaceFloorBytes)
{
    public TimeSpan SeedTimeout { get; init; } = TimeSpan.FromSeconds(120);
    internal const long GiB = 1024L * 1024 * 1024;
    public static StagedSpaceOptions Defaults(long available, long volumeSize) => new(true,
        Math.Min(32 * GiB, available / 10), Math.Min(8 * GiB, available / 40),
        Math.Max(GiB, volumeSize / 20));
    public static StagedSpaceOptions Proposed(long available, long volumeSize) => Defaults(available, volumeSize) with { Enabled = false };
}

/// <summary>A resource refusal never grants inspection/publication authority.</summary>
public sealed class StagedSpaceException(string message) : IOException(message)
{
    public const string Reason = "not_enough_staging_space";
}

/// <summary>
/// Persist capacity BEFORE output creation. A full capacity lease deliberately overcharges small
/// saves; there is no on-demand kernel RPC, wait, or disk write under a kernel accounting lock.
/// </summary>
public sealed partial class StagedSpaceBudget
{
    internal const long MetadataBytes = 1024 * 1024;
    internal const long MinimumCapacity = StagedTransferAllocator.MaximumSeedBytes;
    internal const long CopyCount = 4;
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly StagedSpaceOptions _options;
    private readonly FileSecurity? _fileSecurity;
    private readonly SecurityIdentifier? _owner;
    private readonly long _stageGranularity = 64 * 1024;
    private readonly long _metadataGranularity = 4096;
    private readonly long _metadataBytes = MetadataBytes;
    internal TimeSpan SeedTimeout => _options.SeedTimeout;
    private readonly Func<long> _available;
    private readonly Dictionary<Guid, Reservation> _reservations = new();
    private readonly HashSet<Guid> _liveSnapshots = new();
    private bool _faulted;
    private Dictionary<string, long>? _archiveAllocations;
    private long _archiveAllocationBytes;
    private long _hotAllocationBytes;
    private string? _archiveDirectory;
    private sealed record Snapshot(string Path, StagedStageIdentity Identity);
    private sealed record Reservation(Guid Id, string Sid, long Capacity, string? StagePath,
        StagedStageIdentity? StageIdentity, Snapshot? Snapshot, int Version, bool ContentReleased = false, bool GrantIssued = false,
        bool LegacyGuard = false);

    public StagedSpaceBudget(string stagingRoot, StagedSpaceOptions options, Func<long>? availableBytes = null,
        StagedTransferJournal? legacyJournal = null)
    {
        if (!options.Enabled || options.TotalBytes < 0 || options.PerUserBytes < 0 ||
            options.PerUserBytes > options.TotalBytes || options.FreeSpaceFloorBytes < 0 ||
            options.SeedTimeout <= TimeSpan.Zero || options.SeedTimeout > TimeSpan.FromMinutes(10))
            throw new ArgumentException("Invalid staging space configuration.", nameof(options));
        _options = options;
        _directory = Path.Combine(Path.GetFullPath(stagingRoot), ".space-reservations");
        _available = availableBytes ?? (() => new DriveInfo(Path.GetPathRoot(_directory)!).AvailableFreeSpace);
        RequireExistingSecurity(stagingRoot);
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User ?? throw new UnauthorizedAccessException("Missing budget owner.");
            _owner = owner;
            _metadataGranularity = ReadAllocationGranularity(stagingRoot, content: false);
            _stageGranularity = Math.Max(64 * 1024, _metadataGranularity);
            _metadataBytes = Math.Max(MetadataBytes, checked(_metadataGranularity * 16));
            var directorySecurity = new DirectorySecurity();
            directorySecurity.SetAccessRuleProtection(true, false); directorySecurity.SetOwner(owner);
            _fileSecurity = new FileSecurity(); _fileSecurity.SetAccessRuleProtection(true, false); _fileSecurity.SetOwner(owner);
            foreach (var sid in new[] { owner, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                         new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
            {
                directorySecurity.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                _fileSecurity.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            }
            var directory = new DirectoryInfo(_directory);
            if (!directory.Exists) directory.Create(directorySecurity);
        }
        else Directory.CreateDirectory(_directory);
        if ((File.GetAttributes(_directory) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("The reservation directory is a reparse point.");
        foreach (string path in Directory.EnumerateFiles(_directory))
        {
            // A failed write stays evidence, not an uncharged scratch file.
            if (!path.EndsWith(".json", StringComparison.Ordinal) || new FileInfo(path).Length > 64 * 1024 ||
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Unresolved staging reservation record: " + Path.GetFileName(path));
            using var input = StagedJournalFile.Open(path, maximumBytes: 64 * 1024);
            if (_owner is not null) RequireRecordSecurity(input, path, _owner);
            var record = JsonSerializer.Deserialize<Reservation>(input) ?? throw new IOException("Missing staging reservation.");
            if (record.Version != 1 || record.Id == Guid.Empty || Path.GetFileName(path) != record.Id.ToString("N") + ".json" ||
                string.IsNullOrWhiteSpace(record.Sid) || record.Capacity < MinimumCapacity ||
                record.Capacity > (long.MaxValue - _metadataBytes) / CopyCount || (record.Capacity & 65535) != 0 ||
                record.StageIdentity is not null && record.StagePath is null ||
                record.GrantIssued && record.StageIdentity is null ||
                record.LegacyGuard && (record.Capacity != MinimumCapacity || record.GrantIssued) ||
                !_reservations.TryAdd(record.Id, record))
                throw new IOException("Invalid staging reservation.");
        }
        // Validate all persisted locators before any exact-object cleanup can use them.
        if (legacyJournal is not null) UpgradeLegacyJournal(legacyJournal);
        VerifyInventory(stagingRoot);
    }

    // Call before any allocator ACL recovery can alter inherited evidence.
    internal static void RequireExistingSecurity(string stagingRoot)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new UnauthorizedAccessException("Missing budget owner.");
        bool system = owner.IsWellKnown(WellKnownSidType.LocalSystemSid);
        string root = Path.GetFullPath(stagingRoot);
        if (Directory.Exists(root))
        {
            var rootSecurity = StagedPrivateSecurity.ReadDirectory(root);
            if (system) StagedTransferJournal.RequireTrustedOwner(rootSecurity, "staging root");
            StagedTransferJournal.RequireNoUntrustedWriters(rootSecurity, owner);
            foreach (string path in Directory.EnumerateFiles(root))
            {
                var fileSecurity = StagedPrivateSecurity.ReadFile(path);
                if (system) StagedTransferJournal.RequireTrustedOwner(fileSecurity, "private staging file");
                StagedTransferJournal.RequireNoUntrustedWriters(fileSecurity, owner);
            }
        }
        string directory = Path.Combine(root, ".space-reservations");
        if (!Directory.Exists(directory)) return;
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("A reservation directory is a reparse point.");
        var security = StagedPrivateSecurity.ReadDirectory(directory);
        if (system) StagedTransferJournal.RequireTrustedOwner(security, "staging reservations");
        StagedTransferJournal.RequireNoUntrustedWriters(security, owner);
        if (!security.AreAccessRulesProtected) throw new UnauthorizedAccessException("The reservation directory DACL is not protected.");
        foreach (string path in Directory.EnumerateFiles(directory))
        {
            using var stream = StagedJournalFile.Open(path, maximumBytes: 64 * 1024);
            RequireRecordSecurity(stream, path, owner);
        }
    }

    private static void RequireRecordSecurity(FileStream stream, string path, SecurityIdentifier owner)
    {
        var security = StagedJournalFile.ReadSecurity(stream, path);
        if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
            StagedTransferJournal.RequireTrustedOwner(security, "staging reservation");
        StagedTransferJournal.RequireNoUntrustedWriters(security, owner);
        if (!security.AreAccessRulesProtected) throw new UnauthorizedAccessException("A reservation DACL is not protected.");
    }

    private static long ReadAllocationGranularity(string path, bool content = true)
    {
        if (!GetDiskFreeSpaceW(Path.GetPathRoot(Path.GetFullPath(path))!, out uint sectors, out uint bytes, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        long unit = checked((long)sectors * bytes);
        if (unit <= 0 || (unit & (unit - 1)) != 0) throw new IOException("Invalid staging allocation unit.");
        return content ? Math.Max(64 * 1024, unit) : unit;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpaceW(string root, out uint sectorsPerCluster, out uint bytesPerSector,
        out uint freeClusters, out uint totalClusters);

    internal void VerifyInventory(string stagingRoot)
    {
        string root = Path.GetFullPath(stagingRoot);
        lock (_gate)
        {
            var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var record in _reservations.Values)
            {
                if (record.StagePath is { } stage)
                {
                    RequireChild(stage); paths.Add(stage); paths.Add(stage + ".space");
                }
                if (record.Snapshot is { } snapshot) { RequireChild(snapshot.Path); paths.Add(snapshot.Path); }
            }
            foreach (string path in Directory.EnumerateFiles(root))
                if (!paths.Contains(path) && !IsNegativeReceiptPath(path))
                    throw new IOException("Unreserved private staging object: " + Path.GetFileName(path));
            RefreshNegativeReceiptStorage(root);
            void RequireChild(string path)
            {
                if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), root, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("A reservation locator escaped the private staging root.");
            }
        }
    }

    public long Reserve(Guid id, string sid, string? stagePath = null, string? destinationPath = null)
    {
        if (id == Guid.Empty || string.IsNullOrWhiteSpace(sid)) throw new ArgumentException("A staging budget requires a bound user.");
        lock (_gate)
        {
            RequireHealthy();
            bool reuse = _reservations.TryGetValue(id, out var prior);
            if (reuse)
            {
                if (prior!.LegacyGuard) throw new IOException("A legacy guarded version cannot be reused for new capacity.");
                if (prior!.Sid != sid || prior.StagePath != stagePath) throw new IOException("The staging reservation owner changed.");
                if (!prior.ContentReleased) return prior.Capacity;
                if (prior.GrantIssued) throw new IOException("A completed allocation reservation cannot be reused.");
                // The exact failed seed is gone and no reply was ever issued.
                // Retry this stable allocation intent, retaining its metadata debit.
            }
            long total = checked(_metadataBytes + _legacyJournalAllowance + _legacyNegativeAllowance), user = 0;
            foreach (var record in _reservations.Values)
            {
                long charge = checked((record.ContentReleased ? 0 : record.Capacity * CopyCount) + _metadataBytes);
                total = checked(total + charge);
                if (record.Sid == sid) user = checked(user + charge);
            }
            long remaining = Math.Min(_options.TotalBytes - total, _options.PerUserBytes - user);
            // Available space is an additional live guard. Outstanding reservations may not yet
            // occupy any disk, so subtract ALL of them rather than counting free space twice.
            long available = Math.Max(0, _available());
            long afterFloor = available <= _options.FreeSpaceFloorBytes ? 0 : available - _options.FreeSpaceFloorBytes;
            long unreserved = afterFloor <= total ? 0 : afterFloor - total;
            remaining = Math.Min(remaining, unreserved);
            long metadataNeeded = reuse ? 0 : _metadataBytes;
            long capacity = remaining <= metadataNeeded ? 0 : (remaining - metadataNeeded) / CopyCount;
            long alignment = _stageGranularity;
            if (OperatingSystem.IsWindows() && destinationPath is not null)
                alignment = Math.Max(alignment, ReadAllocationGranularity(destinationPath));
            capacity = capacity / alignment * alignment;
            if (capacity < MinimumCapacity) throw new StagedSpaceException("Not enough staging space for this user. Finish or recover earlier saves and try again.");
            var reservation = new Reservation(id, sid, capacity, stagePath, null, null, 1);
            Persist(reservation, create: !reuse);
            _reservations[id] = reservation;
            return capacity;
        }
    }

    // Compatibility only: no new negative receipts are created. Even partial
    // legacy data is debited as storage, not interpreted as allocation authority.
    internal static bool IsNegativeReceiptPath(string path)
    {
        string leaf = Path.GetFileName(path);
        if (leaf.Length < 32 || !Guid.TryParseExact(leaf[..32], "N", out var id) || id == Guid.Empty) return false;
        string suffix = leaf[32..];
        const string refused = ".allocation-refused";
        return suffix == refused || suffix.Length == refused.Length + 1 + 32 + 4 &&
            suffix.StartsWith(refused + ".", StringComparison.Ordinal) && suffix.EndsWith(".tmp", StringComparison.Ordinal) &&
            Guid.TryParseExact(suffix.AsSpan(refused.Length + 1, 32), "N", out _);
    }

    internal void RefreshNegativeReceiptStorage(string stagingRoot)
    {
        lock (_gate)
        {
            RequireHealthy(); long bytes = 0;
            foreach (string path in Directory.EnumerateFiles(stagingRoot, "*.allocation-refused*"))
            {
                if (!IsNegativeReceiptPath(path)) throw new IOException("Unrecognized legacy refusal metadata.");
                // A regular held file supplies the size. Malformed bytes stay
                // held for this nonce, never become a global admission veto.
                var metadata = StagedStageFile.ReadAttachedMetadata(path);
                bytes = checked(bytes + NegativeStorageCharge(metadata.Length));
            }
            _legacyNegativeAllowance = bytes;
        }
    }

    private long NegativeStorageCharge(long length) =>
        checked(Math.Max(_metadataGranularity, RoundMetadata(length)) + _metadataGranularity);

    internal void RetiredNegativeReceipt(long length)
    {
        lock (_gate)
        {
            // No new refusals are persisted. Startup inventories their rounded
            // bytes once; exact confirmed deletion is the only refund event.
            _legacyNegativeAllowance = Math.Max(0, _legacyNegativeAllowance - NegativeStorageCharge(length));
        }
    }

    internal void VerifyJournalInventory(string directory, StagedTransferJournal? journal = null)
    {
        lock (_gate)
        {
            foreach (string path in Directory.EnumerateFiles(directory))
            {
                string leaf = Path.GetFileName(path);
                if (leaf.Length >= 32 && Guid.TryParseExact(leaf[..32], "N", out Guid id) &&
                    !_reservations.ContainsKey(id) && !_legacyCompleted.Contains(id) && !LegacySecurityMetadataPath(path))
                    throw new IOException("Unreserved historical transfer metadata prevents large-mode admission.");
            }
        }
        // Journal -> budget is the normal admission lock order. Never wait
        // for the journal while holding the reservation gate.
        journal?.RequireArchivedReservationsAsync(id =>
        {
            lock (_gate) return _reservations.ContainsKey(id) || _legacyCompleted.Contains(id);
        }, CancellationToken.None).GetAwaiter().GetResult();
        RequireArchiveAdmission(Path.Combine(directory, "completed", "segments.state"), 0);
    }

    internal void RequireArchiveAdmission(string path, long maximumLength)
    {
        lock (_gate)
        {
            RequireHealthy();
            string completed = Path.GetDirectoryName(Path.GetFullPath(path))!;
            if (Path.GetFileName(completed) != "completed" || maximumLength < 0 ||
                maximumLength > StagedTransferJournal.MaximumArchiveSegmentBytes)
                throw new IOException("Invalid archive storage admission.");
            string journalRoot = Path.GetDirectoryName(completed)!;
            RequireJournalGrowthAdmission(journalRoot, path, maximumLength);
        }
    }

    private void RequireJournalGrowthAdmission(string journalRoot, string path, long maximumLength)
    {
        string completed = Path.Combine(journalRoot, "completed");
        if (_archiveAllocations is null) RefreshArchiveStorage(completed);
        if (!string.Equals(_archiveDirectory, completed, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The archive accounting directory changed.");
        // Hot admission stays O(active). Cold bytes are reconstructed once,
        // debited before growth and refreshed only by archive maintenance.
        _hotAllocationBytes = 0;
        foreach (var file in MetadataFiles(journalRoot)) _hotAllocationBytes = checked(_hotAllocationBytes + file.Value);
        long current = checked(_archiveAllocationBytes + _hotAllocationBytes);
        bool archive = string.Equals(Path.GetDirectoryName(path), completed, StringComparison.OrdinalIgnoreCase);
        long existing = archive ? _archiveAllocations!.GetValueOrDefault(path) :
            File.Exists(path) ? RoundMetadata(new FileInfo(path).Length) : 0;
        long growth = Math.Max(0, RoundMetadata(maximumLength) - existing);
        long allowance = checked(_reservations.Count * (_metadataBytes / 2) + _metadataBytes / 4 + _legacyJournalAllowance);
        if (current > allowance - growth)
            throw new StagedSpaceException("Staging archive cleanup must finish before another metadata write.");
        if (!archive) _hotAllocationBytes = checked(_hotAllocationBytes + growth);
        if (archive)
        {
            _archiveAllocations![path] = checked(existing + growth);
            _archiveAllocationBytes = checked(_archiveAllocationBytes + growth);
        }
    }

    private long RoundMetadata(long bytes) => checked((bytes + _metadataGranularity - 1) / _metadataGranularity * _metadataGranularity);

    private IEnumerable<KeyValuePair<string, long>> MetadataFiles(string directory)
    {
        if (!Directory.Exists(directory)) yield break;
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("A journal accounting directory is a reparse point.");
        foreach (string file in Directory.EnumerateFiles(directory))
        {
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Unresolved journal object prevents storage admission.");
            yield return new(file, RoundMetadata(new FileInfo(file).Length));
        }
    }

    internal void RefreshArchiveStorage(string completed)
    {
        lock (_gate)
        {
            RequireHealthy();
            try
            {
                completed = Path.GetFullPath(completed);
                if (_archiveDirectory is not null && !string.Equals(_archiveDirectory, completed, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The archive accounting directory changed.");
                var files = MetadataFiles(completed).ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
                _archiveAllocationBytes = files.Values.Sum();
                _archiveAllocations = files;
                _archiveDirectory = completed;
            }
            catch { _faulted = true; throw; }
        }
    }

    internal bool ContentReservationPending(Guid id)
    {
        lock (_gate)
        {
            RequireHealthy();
            return _reservations.TryGetValue(id, out var record) && !record.ContentReleased;
        }
    }

    internal void RequireMetadataAdmission(string temporary)
    {
        lock (_gate)
        {
            RequireHealthy();
            string leaf = Path.GetFileName(temporary);
            bool transfer = leaf.Length >= 32 && Guid.TryParseExact(leaf[..32], "N", out _);
            string prefix = transfer ? leaf[..32] : "";
            if (transfer && !_reservations.ContainsKey(Guid.ParseExact(prefix, "N")) &&
                !_legacyCompleted.Contains(Guid.ParseExact(prefix, "N")) && !LegacySecurityMetadataPath(temporary))
                throw new StagedSpaceException("The transfer has no metadata reservation.");
            long current = 0;
            foreach (string path in Directory.EnumerateFiles(Path.GetDirectoryName(temporary)!))
            {
                string existing = Path.GetFileName(path);
                bool hasId = existing.Length >= 32 && Guid.TryParseExact(existing[..32], "N", out _);
                if (transfer ? !existing.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) : hasId) continue;
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Unresolved metadata object prevents storage admission.");
                long length = new FileInfo(path).Length;
                current = checked(current + ((length + _metadataGranularity - 1) / _metadataGranularity * _metadataGranularity));
            }
            // Half of each 1 MiB charge is for journal files, including failed
            // replacement residue; the rest covers ledger overlap, grant/MFT/index overhead.
            long allowance = LegacySecurityMetadataPath(temporary) ? _legacyJournalAllowance :
                transfer ? _metadataBytes / 2 : _metadataBytes / 4;
            long maximum = LegacySecurityMetadataPath(temporary) ? StagedAllocationSecuritySnapshot.MaximumBytes : StagedJournalFile.MaximumManifestBytes;
            long nextAllocation = (maximum + _metadataGranularity - 1) / _metadataGranularity * _metadataGranularity;
            if (current > allowance - nextAllocation)
                throw new StagedSpaceException("Staging metadata cleanup must finish before another update.");
            RequireJournalGrowthAdmission(Path.GetDirectoryName(temporary)!, temporary, maximum);
        }
    }

    internal void RecordStage(Guid id, string path, StagedStageIdentity identity)
    {
        lock (_gate)
        {
            RequireHealthy(); var record = _reservations[id];
            if (record.StagePath != path || record.StageIdentity is not null && record.StageIdentity != identity || record.GrantIssued)
                throw new IOException("The seed object does not match its private reservation.");
            var next = record with { StageIdentity = identity };
            Persist(next); _reservations[id] = next;
        }
    }

    internal void RetireFailedAllocation(Guid id)
    {
        lock (_gate)
        {
            RequireHealthy();
            if (!_reservations.TryGetValue(id, out var record) || record.LegacyGuard || record.GrantIssued ||
                record.Snapshot is not null || _liveSnapshots.Contains(id) || record.StagePath is null) return;
            bool absent = record.StageIdentity is { } exact
                ? StagedStageFile.TryDeleteExactAndConfirmAbsent(record.StagePath, exact, out _)
                : StagedStageFile.TryConfirmAbsent(record.StagePath, out _); // No grant/reply issued; access errors do not imply absence.
            if (!absent || !StagedStageFile.TryConfirmAbsent(record.StagePath + ".space", out _)) return;
            DeleteReservationMetadata(record);
        }
    }

    internal void RequireFailedAllocationAbsent(Guid id, string stagePath)
    {
        lock (_gate)
        {
            RequireHealthy();
            if (_reservations.TryGetValue(id, out var record))
            {
                if (record.LegacyGuard || record.StagePath != stagePath || record.GrantIssued || record.Snapshot is not null)
                    throw new IOException("The failed allocation cannot be released from its recorded custody.");
                // This helper deletes only a previously recorded exact identity. A crash
                // between CREATE and RecordStage leaves an unknown present object held.
                RetireFailedAllocation(id);
                if (_reservations.ContainsKey(id))
                    throw new IOException("Failed allocation cleanup is unresolved; no terminal refusal is authorized.");
            }
            if (!StagedStageFile.TryConfirmAbsent(stagePath, out var failure))
                throw new IOException("An unknown private object remains; no terminal refusal is authorized.", failure);
        }
    }

    // Caller holds allocator serialization and has established manifest absence.
    // Never erase issued authority, unknown custody, readers, or replacement data.
    internal bool RetireUnissuedMetadata(Guid id)
    {
        lock (_gate)
        {
            RetireFailedAllocation(id);
            return !_reservations.ContainsKey(id);
        }
    }

    private void DeleteReservationMetadata(Reservation record)
    {
        string path = RecordPath(record.Id);
        StagedStageIdentity identity;
        using (var held = StagedStageFile.Open(path))
        {
            if (held.Stream.Length > 64 * 1024 || JsonSerializer.Deserialize<Reservation>(held.Stream) != record)
                throw new IOException("Reservation metadata changed; retain its charge.");
            identity = held.Identity;
        }
        if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(path, identity, out var failure))
            throw new IOException("Exact reservation metadata retirement is unresolved.", failure);
        // A crash before this removal only overcharges; restart reconstructs
        // absence after the durable metadata deletion. Repeated cleanup is a no-op.
        _reservations.Remove(record.Id);
    }

    internal void Bind(TransferJournalEntry entry)
    {
        lock (_gate)
        {
            RequireHealthy();
            var record = _reservations[entry.Transfer.TransferId];
            if (record.LegacyGuard)
            {
                if (record.ContentReleased || record.StagePath != entry.Transfer.StagePath ||
                    record.StageIdentity is null || record.StageIdentity != entry.StageIdentity)
                    throw new IOException("The legacy allocation remains held without exact custody evidence.");
                return; // Finish this version under its original 16 MiB kernel guard; never issue a larger grant.
            }
            if (record.ContentReleased || entry.StageIdentity is null || record.StagePath != entry.Transfer.StagePath ||
                record.Sid != entry.Transfer.RequestorSid ||
                record.StageIdentity is not null && record.StageIdentity != entry.StageIdentity)
                throw new IOException("The capacity grant does not match the allocated object.");
            var bound = record with { StagePath = entry.Transfer.StagePath, StageIdentity = entry.StageIdentity, GrantIssued = true };
            Persist(bound); _reservations[record.Id] = bound;
            WriteGrant(bound);
        }
    }

    internal IDisposable BeginSnapshot(Guid id, string path, FileStream stream, long expectedLength)
    {
        lock (_gate)
        {
            RequireHealthy();
            var record = _reservations[id];
            if (record.ContentReleased || expectedLength < 0 || expectedLength > record.Capacity)
                throw new StagedSpaceException("The snapshot exceeds its reserved staging space.");
            if (record.Snapshot is { } previous && !_liveSnapshots.Contains(id) &&
                StagedStageFile.TryDeleteExactAndConfirmAbsent(previous.Path, previous.Identity, out _))
            {
                record = record with { Snapshot = null };
                Persist(record); _reservations[id] = record;
            }
            if (record.Snapshot is not null || !_liveSnapshots.Add(id))
                throw new StagedSpaceException("An earlier inspection still owns staging space. Try again after it finishes.");
            try
            {
                var snapshot = new Snapshot(path, StagedDestinationFile.ReadIdentity(stream.SafeFileHandle));
                var next = record with { Snapshot = snapshot };
                Persist(next); _reservations[id] = next;
                return new SnapshotLease(this, id);
            }
            catch { _liveSnapshots.Remove(id); throw; }
        }
    }

    private sealed class SnapshotLease(StagedSpaceBudget owner, Guid id) : IDisposable
    {
        private StagedSpaceBudget? _owner = owner;
        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.EndSnapshot(id);
    }
    private void EndSnapshot(Guid id)
    {
        lock (_gate)
        {
            _liveSnapshots.Remove(id);
            // Keep the exact identity in the receipt. Reconciliation confirms deletion rather
            // than inferring it from the publisher's cancellation or a returned task.
        }
    }

    private int _recoveryCursor;

    internal async Task ReconcileAsync(StagedTransferJournal journal, CancellationToken token,
        int maximumItems = int.MaxValue, Action<Guid, Exception>? held = null)
    {
        Reservation[] records;
        lock (_gate)
        {
            RequireHealthy();
            int start = _reservations.Count == 0 ? 0 : _recoveryCursor % _reservations.Count;
            records = _reservations.Values.Skip(start).Take(maximumItems).ToArray();
            _recoveryCursor = records.Length < maximumItems || start + records.Length >= _reservations.Count ? 0 : start + records.Length;
        }
        foreach (var record in records)
        {
            token.ThrowIfCancellationRequested();
            try
            {
                TransferJournalEntry entry;
                try { entry = await journal.ReadAsync(record.Id, token).ConfigureAwait(false); }
                catch (FileNotFoundException)
                {
                    // No typed reply is possible before GrantIssued is persisted.
                    // Retire only the recorded exact seed; uncertain objects remain charged.
                    RetireUnissuedMetadata(record.Id);
                    continue;
                }
                lock (_gate)
                {
                    if (_liveSnapshots.Contains(record.Id) || !_reservations.TryGetValue(record.Id, out var current) || current != record) continue;
                    if (record.Snapshot is { } snapshot)
                    {
                        if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(snapshot.Path, snapshot.Identity, out _)) continue;
                        var next = record with { Snapshot = null };
                        Persist(next); _reservations[record.Id] = next;
                    }
                    bool disposalComplete = entry.StageDeleted &&
                        (entry.UnboundCancellation is not null || entry.State is
                            (TransferJournalState.Released or TransferJournalState.Discarded or TransferJournalState.Blocked));
                    // Kind-5 (and ordinary private discard) ACK is its own exact
                    // deletion receipt; DiscardPending deliberately has no StageDeleted.
                    bool discardComplete = entry.State == TransferJournalState.DiscardPending &&
                        entry.DiscardAcknowledgedAtUtc is not null && entry.DiscardReservationId is not null &&
                        entry.DiscardKind is (StagedDiscardKind.UnattachedAllocation or StagedDiscardKind.PrivateVersion or
                            StagedDiscardKind.RetireUnexposed or StagedDiscardKind.RetireAttachedPrivate);
                    if (record.ContentReleased)
                    {
                        RetireCompletedMetadata(record, entry, journal);
                        continue;
                    }
                    if (!(disposalComplete || discardComplete) || record.StageIdentity is null ||
                        entry.StageIdentity != record.StageIdentity ||
                        record.StagePath is null || entry.PendingRename is not null ||
                        entry.Transfer.StagePath != record.StagePath || entry.StageCleanupStarted ||
                        entry.HandbackState is StagedHandbackState.Copying) continue;
                    if (discardComplete && !StagedStageFile.TryConfirmAbsent(record.StagePath, out _)) continue;
                    // Require durable exact-object cleanup, plus drained snapshot
                    // leases. Path absence alone never authorizes a content refund.
                    DeleteGrant(record);
                    if (RetireCompletedMetadata(_reservations[record.Id], entry, journal, exactContentRelease: true)) continue;
                    var released = _reservations[record.Id] with { ContentReleased = true };
                    Persist(released); _reservations[record.Id] = released;
                    RetireCompletedMetadata(released, entry, journal);
                }
            }
            catch (Exception error) when (held is not null && error is IOException or UnauthorizedAccessException)
            {
                held(record.Id, error);
            }
        }
    }

    // Finished never-exposed allocations keep exact journal/replay evidence and
    // high-water generations, but do not retain one 1-MiB SID charge per abort.
    private bool RetireCompletedMetadata(Reservation record, TransferJournalEntry entry, StagedTransferJournal journal,
        bool exactContentRelease = false)
    {
        if ((!record.ContentReleased && !exactContentRelease) || record.Snapshot is not null || _liveSnapshots.Contains(record.Id) ||
            entry.DiscardKind is not (StagedDiscardKind.UnattachedAllocation or StagedDiscardKind.RetireUnexposed or
                StagedDiscardKind.RetireAttachedPrivate) || !StagedTransferJournal.StageSpaceUpgradeComplete(entry) ||
            !StagedStageFile.TryConfirmAbsent(entry.Transfer.StagePath, out _) ||
            !StagedStageFile.TryConfirmAbsent(entry.Transfer.StagePath + ".space", out _)) return false;
        // Replace the per-user metadata envelope BEFORE deleting its ledger.
        // Startup independently reconstructs completed inventory and this same
        // shared storage debit from authenticated hot/packed journal records.
        // Admission already maintains these conservative physical frontiers;
        // no hot/cold directory scan per retired item or foreground cleanup.
        long bytes = checked(_hotAllocationBytes + _archiveAllocationBytes);
        _legacyJournalAllowance = Math.Max(_legacyJournalAllowance, checked(bytes * 2 + 16 * MetadataBytes));
        _legacyCompleted.Add(record.Id);
        DeleteReservationMetadata(record);
        return true;
    }

    private static void DeleteGrant(Reservation record)
    {
        string path = record.StagePath! + ".space";
        if (StagedStageFile.TryConfirmAbsent(path, out _)) return;
        StagedStageIdentity identity;
        using (var held = StagedStageFile.Open(path))
        {
            byte[] bytes = new byte[64]; held.Stream.ReadExactly(bytes);
            if (held.Stream.Length != 64 || !bytes.AsSpan().SequenceEqual(GrantBytes(record)))
                throw new IOException("Capacity grant changed; retain this transfer's charge.");
            identity = held.Identity;
        }
        if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(path, identity, out var error, expectedLength: 64))
            throw new IOException("Exact capacity grant deletion remains pending.", error);
    }

    private void RequireHealthy()
    {
        if (_faulted) throw new IOException("Staging accounting persistence is unresolved; restart and recover before admitting saves.");
    }
    private string RecordPath(Guid id) => Path.Combine(_directory, id.ToString("N") + ".json");
    private void Persist(Reservation record, bool create = false)
    {
        string path = RecordPath(record.Id), temporary = path + ".new";
        try
        {
            if (create && File.Exists(path)) throw new IOException("A staging reservation already exists.");
            using var output = OperatingSystem.IsWindows()
                ? new FileInfo(temporary).Create(FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.FullControl,
                    FileShare.None, 4096, FileOptions.WriteThrough, _fileSecurity!)
                : new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            JsonSerializer.Serialize(output, record);
            StagedJournalReplacement.CommitAsync(output, temporary, path, CancellationToken.None).GetAwaiter().GetResult();
        }
        catch { _faulted = true; throw; } // Never refund an ambiguous durable write.
    }
    private static byte[] GrantBytes(Reservation record)
    {
        byte[] bytes = new byte[64];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, 0x3150535553464153UL); // SAFSUSP1
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(8), record.Capacity);
        var identity = record.StageIdentity!;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16), identity.VolumeSerialNumber);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(24), identity.FileIdLow);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(32), identity.FileIdHigh);
        record.Id.TryWriteBytes(bytes.AsSpan(40));
        return bytes;
    }
    private static void WriteGrant(Reservation record)
    {
        byte[] bytes = GrantBytes(record);
        string path = record.StagePath! + ".space";
        if (File.Exists(path))
        {
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> existing = stackalloc byte[64]; input.ReadExactly(existing);
            if (input.Length != 64 || !existing.SequenceEqual(bytes)) throw new IOException("The capacity grant changed.");
            return;
        }
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        output.Write(bytes); output.Flush(true);
    }
}
