using System.Buffers.Binary;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>Opt-in private storage reservations. Values are physical bytes, including overlapping copies.</summary>
public sealed record StagedSpaceOptions(bool Enabled, long TotalBytes, long PerUserBytes, long FreeSpaceFloorBytes)
{
    public TimeSpan SeedTimeout { get; init; } = TimeSpan.FromSeconds(120);
    internal const long GiB = 1024L * 1024 * 1024;
    public static StagedSpaceOptions Proposed(long available, long volumeSize) => new(false,
        Math.Min(32 * GiB, available / 10), Math.Min(8 * GiB, available / 40),
        Math.Max(GiB, volumeSize / 20));
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
public sealed class StagedSpaceBudget
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
    private sealed record Snapshot(string Path, StagedStageIdentity Identity);
    private sealed record Reservation(Guid Id, string Sid, long Capacity, string? StagePath,
        StagedStageIdentity? StageIdentity, Snapshot? Snapshot, int Version, bool ContentReleased = false, bool GrantIssued = false);

    public StagedSpaceBudget(string stagingRoot, StagedSpaceOptions options, Func<long>? availableBytes = null)
    {
        if (!options.Enabled || options.TotalBytes <= MetadataBytes || options.PerUserBytes <= MetadataBytes ||
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
            if (options.PerUserBytes <= _metadataBytes || options.TotalBytes <= _metadataBytes)
                throw new ArgumentException("The configured budget cannot cover the volume's metadata allocation units.");
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
                !_reservations.TryAdd(record.Id, record))
                throw new IOException("Invalid staging reservation.");
        }
        // Validate all persisted locators before any exact-object cleanup can use them.
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
                if (!paths.Contains(path) && !IsNegativeReceipt(path))
                    throw new IOException("Unreserved private staging object: " + Path.GetFileName(path));
            RequireNegativeReceiptSpace(root, creating: false);
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
                if (prior!.Sid != sid || prior.StagePath != stagePath) throw new IOException("The staging reservation owner changed.");
                if (!prior.ContentReleased) return prior.Capacity;
                if (prior.GrantIssued) throw new IOException("A completed allocation reservation cannot be reused.");
                // The exact failed seed is gone and no reply was ever issued.
                // Retry this stable allocation intent, retaining its metadata debit.
            }
            long total = _metadataBytes, user = 0; // Global epoch/recovery metadata reserve.
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

    private static bool IsNegativeReceipt(string path)
    {
        string leaf = Path.GetFileName(path);
        if (!leaf.EndsWith(".allocation-refused", StringComparison.Ordinal) || leaf.Length != 32 + ".allocation-refused".Length ||
            !Guid.TryParseExact(leaf[..32], "N", out _)) return false;
        using var input = StagedJournalFile.Open(path, maximumBytes: SafeUpload.Agent.Minifilter.Contract.RequestSize);
        if (input.Length != SafeUpload.Agent.Minifilter.Contract.RequestSize)
            throw new IOException("Incomplete negative allocation receipt.");
        return true; // Existing allocator validates the complete exact tuple before replay.
    }

    internal void RequireNegativeReceiptSpace(string stagingRoot, bool creating = true)
    {
        lock (_gate)
        {
            RequireHealthy(); long bytes = 0;
            foreach (string path in Directory.EnumerateFiles(stagingRoot, "*.allocation-refused*"))
            {
                if (!IsNegativeReceipt(path)) throw new IOException("Unrecognized negative allocation receipt.");
                long length = new FileInfo(path).Length;
                bytes = checked(bytes + (length + _metadataGranularity - 1) / _metadataGranularity * _metadataGranularity);
            }
            long next = creating ? (SafeUpload.Agent.Minifilter.Contract.RequestSize + _metadataGranularity - 1) /
                _metadataGranularity * _metadataGranularity : 0;
            if (bytes > _metadataBytes / 4 - next)
                throw new StagedSpaceException("Negative allocation receipts require recovery before more metadata can be stored.");
        }
    }

    internal void VerifyJournalInventory(string directory)
    {
        lock (_gate)
        {
            foreach (string path in Directory.EnumerateFiles(directory))
            {
                string leaf = Path.GetFileName(path);
                if (leaf.Length >= 32 && Guid.TryParseExact(leaf[..32], "N", out Guid id) && !_reservations.ContainsKey(id))
                    throw new IOException("Unreserved historical transfer metadata prevents large-mode admission.");
            }
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
            if (transfer && !_reservations.ContainsKey(Guid.ParseExact(prefix, "N")))
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
            long allowance = transfer ? _metadataBytes / 2 : _metadataBytes / 4;
            long nextAllocation = (StagedJournalFile.MaximumManifestBytes + _metadataGranularity - 1) / _metadataGranularity * _metadataGranularity;
            if (current > allowance - nextAllocation)
                throw new StagedSpaceException("Staging metadata cleanup must finish before another update.");
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
            RequireHealthy(); var record = _reservations[id];
            if (record.ContentReleased || record.GrantIssued || record.Snapshot is not null || record.StagePath is null) return;
            bool absent = record.StageIdentity is { } exact
                ? StagedStageFile.TryDeleteExactAndConfirmAbsent(record.StagePath, exact, out _)
                : StagedStageFile.TryConfirmAbsent(record.StagePath, out _); // No grant/reply issued; access errors do not imply absence.
            if (!absent) return;
            var next = record with { ContentReleased = true };
            Persist(next); _reservations[id] = next;
        }
    }

    internal void RequireFailedAllocationAbsent(Guid id, string stagePath)
    {
        lock (_gate)
        {
            RequireHealthy();
            if (_reservations.TryGetValue(id, out var record))
            {
                if (record.StagePath != stagePath || record.GrantIssued || record.Snapshot is not null)
                    throw new IOException("The failed allocation cannot be released from its recorded custody.");
                // This helper deletes only a previously recorded exact identity. A crash
                // between CREATE and RecordStage leaves an unknown present object held.
                RetireFailedAllocation(id);
                if (!_reservations[id].ContentReleased)
                    throw new IOException("Failed allocation cleanup is unresolved; no terminal refusal is authorized.");
            }
            if (!StagedStageFile.TryConfirmAbsent(stagePath, out var failure))
                throw new IOException("An unknown private object remains; no terminal refusal is authorized.", failure);
        }
    }

    internal void Bind(TransferJournalEntry entry)
    {
        lock (_gate)
        {
            RequireHealthy();
            var record = _reservations[entry.Transfer.TransferId];
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

    internal async Task ReconcileAsync(StagedTransferJournal journal, CancellationToken token)
    {
        Reservation[] records;
        lock (_gate) { RequireHealthy(); records = _reservations.Values.ToArray(); }
        foreach (var record in records)
        {
            token.ThrowIfCancellationRequested();
            TransferJournalEntry entry;
            try { entry = await journal.ReadAsync(record.Id, token).ConfigureAwait(false); }
            catch (FileNotFoundException)
            {
                // No typed reply is possible before GrantIssued is persisted.
                // Retire only the recorded exact seed; uncertain objects remain charged.
                RetireFailedAllocation(record.Id);
                continue;
            }
            lock (_gate)
            {
                if (_liveSnapshots.Contains(record.Id) || _reservations[record.Id] != record) continue;
                if (record.Snapshot is { } snapshot)
                {
                    if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(snapshot.Path, snapshot.Identity, out _)) continue;
                    var next = record with { Snapshot = null };
                    Persist(next); _reservations[record.Id] = next;
                }
                if (record.ContentReleased || !entry.StageDeleted || entry.StageIdentity != record.StageIdentity ||
                    record.StagePath is null || entry.PendingRename is not null ||
                    entry.State is not (TransferJournalState.Released or TransferJournalState.Discarded or TransferJournalState.Blocked) ||
                    entry.HandbackState is StagedHandbackState.Copying) continue;
                // StageDeleted is the journal's exclusive exact-object cleanup receipt, not a
                // pathname scan. Active snapshot leases must also be gone before refund.
                string grant = record.StagePath + ".space";
                File.Delete(grant);
                var released = _reservations[record.Id] with { ContentReleased = true };
                Persist(released); _reservations[record.Id] = released;
            }
        }
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
    private static void WriteGrant(Reservation record)
    {
        byte[] bytes = new byte[64];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, 0x3150535553464153UL); // SAFSUSP1
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(8), record.Capacity);
        var identity = record.StageIdentity!;
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16), identity.VolumeSerialNumber);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(24), identity.FileIdLow);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(32), identity.FileIdHigh);
        record.Id.TryWriteBytes(bytes.AsSpan(40));
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
