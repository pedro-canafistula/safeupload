using System.Buffers.Binary;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace SafeUpload.Agent.Service.Interception;

public sealed partial class StagedTransferJournal
{
    // Exact terminal receipts remain durable, but no longer participate in hot
    // directory enumeration. Packed files avoid one retained NTFS file per save.
    internal const int MaximumArchiveSegmentBytes = 4 * 1024 * 1024;
    internal const int ArchiveHeaderBytes = 60; // magic/version, payload length, exact ID, SHA256
    private const uint ArchiveMagic = 0x414A5553; // SUJA
    internal const int ArchiveControlBytes = 4096;
    private const uint ArchiveControlMagic = 0x43415553; // SUAC
    private readonly string _completedDirectory;
    private sealed record ArchiveLocation(string Path, long Offset, int Length, string Digest);
    private sealed record ArchiveMaximum(long Generation, HashSet<Guid> Transfers);
    private readonly Dictionary<Guid, ArchiveLocation> _archived = new();
    private readonly Dictionary<string, ArchiveMaximum> _archivedClaims = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ArchiveMaximum> _archivedEffectiveClaims = new(StringComparer.OrdinalIgnoreCase);
    private bool _archiveLoaded;
    private string? _archiveAppendPath;
    private int _archiveSegmentCount;
    private string ArchiveInventoryPath => Path.Combine(_completedDirectory, "segments.state");
    private sealed record ArchiveInventory(int Version, int SegmentCount);
    private readonly List<Guid> _archiveAuditIds = [];
    private int _archiveAuditCursor;
    internal Action<string>? ArchiveObserver { get; set; }
    internal int ArchivedTransfers => _archived.Count;
    internal bool IntegrityHeld => _gate.IntegrityHeld;

    internal string DirectoryPath => _directory;
    internal static bool StageSpaceUpgradeComplete(TransferJournalEntry entry) => CompletedArchiveShape(entry);

    internal async Task VisitStageSpaceUpgradeAsync(Action<TransferJournalEntry> visit, Action<Guid> securitySnapshot,
        CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureArchiveLoadedCoreAsync(token).ConfigureAwait(false);
            foreach (var file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
            {
                token.ThrowIfCancellationRequested();
                if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                    throw new IOException("Unexpected legacy transfer journal file.");
                visit(await ReadCoreAsync(id, token).ConfigureAwait(false));
            }
            foreach (Guid id in _archived.Keys)
            {
                token.ThrowIfCancellationRequested();
                visit(await ReadArchivedCoreAsync(id, token).ConfigureAwait(false));
            }
            // Existing immutable snapshots may be referenced by bound history or
            // be pre-manifest residue. Validate the held bytes/owner/shape before
            // granting inventory compatibility; references still bind them on read.
            foreach (var file in new DirectoryInfo(_directory).EnumerateFiles("*.security"))
            {
                token.ThrowIfCancellationRequested();
                if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                    throw new IOException("Unexpected legacy security snapshot file.");
                var bytes = await ReadAllocationSecurityBytesCoreAsync(id, token).ConfigureAwait(false);
                if (StagedAllocationSecuritySnapshot.Decode(bytes).SnapshotId != id)
                    throw new IOException("The legacy security snapshot identity changed.");
                securitySnapshot(id);
            }
        }
        finally { _gate.Release(); }
    }

    internal async Task RequireArchivedReservationsAsync(Func<Guid, bool> reserved, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureArchiveLoadedCoreAsync(token).ConfigureAwait(false);
            if (_archived.Keys.Any(id => !reserved(id)))
                throw new IOException("Unreserved archived transfer metadata prevents large-mode admission.");
        }
        finally { _gate.Release(); }
    }

    private static bool CompletedArchiveShape(TransferJournalEntry e) =>
        e.BoundAllocation is null && e.AllocationSecurity is null && e.SeedProvenance is null &&
        e.PendingRename is null && !e.StageCleanupStarted &&
        (e.DiscardRequestedAtUtc is null || e.DiscardAcknowledgedAtUtc is not null) &&
        (e.UnboundCancellation is not null ? e.StageDeleted :
         e.State == TransferJournalState.Released && e.StageDeleted &&
             e.HandbackState == StagedHandbackState.NotAttempted ||
         BlockedCleanupComplete(e) && StagedSeedExport.Failure(e) is null ||
         e.State == TransferJournalState.Discarded ||
         e.State == TransferJournalState.DiscardPending && e.DiscardAcknowledgedAtUtc is not null);

    // Caller has finished its notification/outcome work. This moves metadata
    // only; it grants no cleanup, publication, export or native replay authority.
    internal async Task<bool> ArchiveCompletedAsync(TransferJournalEntry expected, CancellationToken token) =>
        await ArchiveCompletedBatchAsync([expected], token).ConfigureAwait(false) == 1;

    // Startup migrations and worker batches flush a segment once, rather than
    // forcing one disk barrier for every historical completed save. The caller
    // supplies only records whose non-journal obligations have completed.
    internal async Task<int> ArchiveCompletedBatchAsync(IReadOnlyList<TransferJournalEntry> expected, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureArchiveLoadedCoreAsync(token).ConfigureAwait(false);
            var accepted = new List<TransferJournalEntry>();
            var seen = new HashSet<Guid>();
            foreach (var snapshot in expected)
            {
                if (!seen.Add(snapshot.Transfer.TransferId)) throw new ArgumentException("Duplicate completion snapshot.", nameof(expected));
                var current = await ReadCoreAsync(snapshot.Transfer.TransferId, token).ConfigureAwait(false);
                if (current == snapshot && CompletedArchiveShape(current) && StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out _))
                    accepted.Add(current);
            }
            int cursor = 0;
            while (cursor < accepted.Count)
            {
                while (cursor < accepted.Count && _archived.ContainsKey(accepted[cursor].Transfer.TransferId)) cursor++;
                if (cursor == accepted.Count) break;
                var pending = new List<(TransferJournalEntry Entry, ArchiveLocation Location)>();
                PrepareCompletedDirectory();
                if (_archiveAppendPath is null || new FileInfo(_archiveAppendPath).Length + ArchiveHeaderBytes + StagedJournalFile.MaximumManifestBytes > MaximumArchiveSegmentBytes)
                    _archiveAppendPath = Path.Combine(_completedDirectory, checked(_archiveSegmentCount + 1).ToString("X8") + ".pack");
                bool newSegment = !File.Exists(_archiveAppendPath);
                using (var stream = newSegment ? CreatePrivateTemporary(_archiveAppendPath, archive: true) : OpenArchiveFile(_archiveAppendPath, writable: true))
                {
                    if (newSegment)
                    {
                        ArchiveGrowthAdmission?.Invoke(_archiveAppendPath, ArchiveControlBytes);
                        stream.SetLength(ArchiveControlBytes);
                        WriteArchiveFrontier(stream, ArchiveControlBytes);
                    }
                    stream.Position = newSegment ? ArchiveControlBytes : ReadArchiveFrontier(stream);
                    while (cursor < accepted.Count)
                    {
                        var entry = accepted[cursor];
                        Guid id = entry.Transfer.TransferId;
                        if (_archived.ContainsKey(id)) { cursor++; continue; }
                        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(entry);
                        if (payload.Length > StagedJournalFile.MaximumManifestBytes)
                            throw new InvalidDataException("Archived manifest exceeds its bound.");
                        if (stream.Position + ArchiveHeaderBytes + payload.Length > MaximumArchiveSegmentBytes) break;
                        var location = new ArchiveLocation(_archiveAppendPath, stream.Position, payload.Length, Convert.ToHexString(SHA256.HashData(payload)));
                        ArchiveGrowthAdmission?.Invoke(_archiveAppendPath, stream.Position + ArchiveHeaderBytes + payload.Length);
                        ArchiveObserver?.Invoke("before-append");
                        await WriteArchiveFrameAsync(stream, id, payload, token).ConfigureAwait(false);
                        pending.Add((entry, location));
                        cursor++;
                    }
                    ArchiveObserver?.Invoke("before-frontier");
                    WriteArchiveFrontier(stream, stream.Position);
                    ArchiveObserver?.Invoke("before-flush");
                    using (StagedRequestTiming.Measure("journal-flush")) stream.Flush(flushToDisk: true);
                }
                if (newSegment) await WriteArchiveInventoryCoreAsync(checked(_archiveSegmentCount + 1), token).ConfigureAwait(false);
                foreach (var row in pending)
                {
                    Guid id = row.Entry.Transfer.TransferId;
                    _archived.Add(id, row.Location); _archiveAuditIds.Add(id); AddArchivedClaims(row.Entry);
                }
                ArchiveObserver?.Invoke("after-flush");
                if (cursor < accepted.Count) _archiveAppendPath = null;
            }
            foreach (var entry in accepted)
            {
                Guid id = entry.Transfer.TransferId;
                File.Delete(ManifestPath(id)); ForgetScanned(id);
                _unboundCommitted.Remove(id); _unboundPublicationAttempts.Remove(id);
            }
            return accepted.Count;
        }
        catch
        {
            _archiveLoaded = false; _archiveAppendPath = null;
            throw;
        }
        finally
        {
            try { ArchiveStorageChanged?.Invoke(_completedDirectory); }
            finally { _gate.Release(); }
        }
    }

    internal async Task ArchiveDiscardedTransfersAsync(CancellationToken token)
    {
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                throw new InvalidDataException("Unexpected transfer journal file.");
            TransferJournalEntry entry;
            await _gate.WaitAsync(token).ConfigureAwait(false);
            try { entry = await ReadScannedAsync(file, id, token).ConfigureAwait(false); }
            finally { _gate.Release(); }
            if (entry.State == TransferJournalState.Discarded)
                await ArchiveCompletedAsync(entry, token).ConfigureAwait(false);
        }
    }

    internal async Task<IReadOnlyList<TransferJournalEntry>> ReadCompletedCandidatesAsync(CancellationToken token)
    {
        var candidates = new List<TransferJournalEntry>();
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                throw new InvalidDataException("Unexpected transfer journal file.");
            await _gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                var entry = await ReadScannedAsync(file, id, token).ConfigureAwait(false);
                if (CompletedArchiveShape(entry)) candidates.Add(entry);
            }
            finally { _gate.Release(); }
        }
        return candidates;
    }

    private void PrepareCompletedDirectory()
    {
        if (Directory.Exists(_completedDirectory))
        {
            if ((File.GetAttributes(_completedDirectory) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Completed journal directory is a reparse point.");
            if (_owner is not null)
            {
                var security = StagedPrivateSecurity.ReadDirectory(_completedDirectory);
                if (_owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) RequireTrustedOwner(security, "completed journal");
                RequireNoUntrustedWriters(security, _owner);
            }
        }
        else if (_owner is not null)
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            AddPrivateRules(security, _owner, inherit: true);
            new DirectoryInfo(_completedDirectory).Create(security);
        }
        else Directory.CreateDirectory(_completedDirectory);
    }

    private FileStream OpenArchiveFile(string path, bool writable = false)
    {
        var stream = StagedJournalFile.Open(path, writable: writable, maximumBytes: MaximumArchiveSegmentBytes, writeThrough: false);
        try
        {
            if (_owner is not null)
            {
                var security = StagedJournalFile.ReadSecurity(stream, path);
                if (_owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) RequireTrustedOwner(security, "completed journal segment");
                RequireNoUntrustedWriters(security, _owner);
            }
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    private async Task EnsureArchiveLoadedCoreAsync(CancellationToken token)
    {
        if (_archiveLoaded) return;
        try { await LoadArchiveCoreAsync(token).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { _gate.FailClosed(error); throw; }
    }

    private async Task LoadArchiveCoreAsync(CancellationToken token)
    {
        _archived.Clear(); _archivedClaims.Clear(); _archivedEffectiveClaims.Clear(); _archiveAuditIds.Clear();
        _archiveAuditCursor = 0; _archiveAppendPath = null; _archiveSegmentCount = 0;
        if (Directory.Exists(_completedDirectory))
        {
            PrepareCompletedDirectory();
            if (File.Exists(ArchiveInventoryPath))
            {
                using var inventory = OpenArchiveFile(ArchiveInventoryPath);
                ArchiveInventory? head;
                try { head = await JsonSerializer.DeserializeAsync<ArchiveInventory>(inventory, cancellationToken: token).ConfigureAwait(false); }
                catch (JsonException error) { throw new InvalidDataException("Invalid archive inventory JSON.", error); }
                if (head is not { Version: 1, SegmentCount: >= 0 }) throw new InvalidDataException("Invalid archive inventory.");
                _archiveSegmentCount = head.SegmentCount;
            }
            var segments = new SortedDictionary<int, string>();
            foreach (string path in Directory.EnumerateFileSystemEntries(_completedDirectory))
            {
                token.ThrowIfCancellationRequested();
                string name = Path.GetFileName(path);
                if (path == ArchiveInventoryPath) continue;
                if (name.EndsWith(".tmp", StringComparison.Ordinal))
                {
                    using (OpenArchiveFile(path)) { }
                    continue; // unselected atomic-replacement output
                }
                if (name.Length != 13 || !name.EndsWith(".pack", StringComparison.Ordinal) ||
                    !int.TryParse(name.AsSpan(0, 8), System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out int number) || number <= 0 || !segments.TryAdd(number, path))
                    throw new InvalidDataException("Unexpected completed journal file.");
            }
            // The tiny durable frontier detects an entirely missing segment;
            // absence cannot silently reset its generation/receipt index.
            if (_archiveSegmentCount > segments.Count || segments.Count > (long)_archiveSegmentCount + 1)
                throw new InvalidDataException("Completed journal inventory lost a segment.");
            var duplicatedHot = new List<string>();
            int expected = 0;
            foreach (var (number, path) in segments)
            {
                if (number != ++expected) throw new InvalidDataException("Completed journal segment gap.");
                bool needsFlush = number > _archiveSegmentCount;
                foreach (var row in await ReadArchiveSegmentCoreAsync(path, repairTail: true, token).ConfigureAwait(false))
                {
                    Guid id = row.Entry.Transfer.TransferId;
                    if (!_archived.TryAdd(id, row.Location)) throw new InvalidDataException("Duplicate archived transfer receipt.");
                    _archiveAuditIds.Add(id);
                    string hot = ManifestPath(id);
                    if (File.Exists(hot))
                    {
                        if (await ReadHotManifestCoreAsync(id, token).ConfigureAwait(false) != row.Entry)
                            throw new InvalidDataException("Hot and archived transfer receipts disagree.");
                        duplicatedHot.Add(hot);
                        needsFlush = true;
                    }
                    else if (number > _archiveSegmentCount)
                        throw new InvalidDataException("Uncommitted archive segment has no surviving hot receipt.");
                    AddArchivedClaims(row.Entry);
                }
                if (needsFlush)
                {
                    // A full visible frame may precede a failed Flush(true).
                    // Establish durability again before consolidating its hot copy.
                    using var uncommitted = OpenArchiveFile(path, writable: true);
                    if (uncommitted.Length == 0)
                    {
                        ArchiveGrowthAdmission?.Invoke(path, ArchiveControlBytes);
                        uncommitted.SetLength(ArchiveControlBytes);
                        WriteArchiveFrontier(uncommitted, ArchiveControlBytes);
                    }
                    ArchiveObserver?.Invoke("before-recovery-flush");
                    uncommitted.Flush(flushToDisk: true);
                    ArchiveObserver?.Invoke("after-recovery-flush");
                }
            }
            if (segments.Count > _archiveSegmentCount)
                await WriteArchiveInventoryCoreAsync(segments.Count, token).ConfigureAwait(false);
            foreach (string hot in duplicatedHot)
            {
                ArchiveObserver?.Invoke("before-hot-consolidation");
                File.Delete(hot);
            }
            if (segments.Count > 0) _archiveAppendPath = segments.Last().Value;
        }
        _archiveLoaded = true;
        ArchiveStorageChanged?.Invoke(_completedDirectory);
    }

    private async Task WriteArchiveInventoryCoreAsync(int count, CancellationToken token)
    {
        string temporary = ArchiveInventoryPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = CreatePrivateTemporary(temporary, archive: true))
            {
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new ArchiveInventory(1, count));
                ArchiveGrowthAdmission?.Invoke(temporary, payload.Length);
                await stream.WriteAsync(payload, token).ConfigureAwait(false);
                ArchiveObserver?.Invoke("before-inventory-replace");
                await StagedJournalReplacement.CommitAsync(stream, temporary, ArchiveInventoryPath, token).ConfigureAwait(false);
                ArchiveObserver?.Invoke("after-inventory-replace");
            }
            _archiveSegmentCount = count;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private void AddArchivedClaims(TransferJournalEntry entry)
    {
        Add(_archivedClaims, entry.Transfer.DestinationPath, Math.Max(entry.DestinationGeneration, entry.UnboundCancellation?.Generation ?? 0));
        if (!RetiredUnattachedAllocation(entry))
            Add(_archivedEffectiveClaims, entry.Transfer.DestinationPath, Math.Max(entry.DestinationGeneration, entry.UnboundCancellation?.Generation ?? 0));
        for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
        {
            Add(_archivedClaims, name.DestinationPath, name.Generation);
            Add(_archivedEffectiveClaims, name.DestinationPath, name.Generation);
        }
        void Add(Dictionary<string, ArchiveMaximum> claims, string path, long generation)
        {
            Guid id = entry.Transfer.TransferId;
            if (!claims.TryGetValue(path, out var prior) || generation > prior.Generation)
                claims[path] = new(generation, [id]);
            else if (generation == prior.Generation) prior.Transfers.Add(id);
        }
    }

    private static async Task WriteArchiveFrameAsync(Stream stream, Guid id, byte[] payload, CancellationToken token)
    {
        byte[] header = new byte[ArchiveHeaderBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(header, ArchiveMagic);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4), 1);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), payload.Length);
        id.TryWriteBytes(header.AsSpan(12, 16));
        SHA256.HashData(payload, header.AsSpan(28, 32));
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(payload, token).ConfigureAwait(false);
    }

    private sealed record ArchiveRow(TransferJournalEntry Entry, ArchiveLocation Location);
    private static long ReadArchiveFrontier(FileStream stream)
    {
        stream.Position = 0;
        byte[] control = new byte[48];
        stream.ReadExactly(control);
        long end = BinaryPrimitives.ReadInt64LittleEndian(control.AsSpan(8));
        if (BinaryPrimitives.ReadUInt32LittleEndian(control) != ArchiveControlMagic ||
            BinaryPrimitives.ReadInt32LittleEndian(control.AsSpan(4)) != 1 || end < ArchiveControlBytes ||
            end > stream.Length || end > MaximumArchiveSegmentBytes ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(control.AsSpan(0, 16)), control.AsSpan(16, 32)))
            throw new InvalidDataException("Invalid completed journal committed frontier.");
        return end;
    }

    private static void WriteArchiveFrontier(FileStream stream, long end)
    {
        byte[] control = new byte[48];
        BinaryPrimitives.WriteUInt32LittleEndian(control, ArchiveControlMagic);
        BinaryPrimitives.WriteInt32LittleEndian(control.AsSpan(4), 1);
        BinaryPrimitives.WriteInt64LittleEndian(control.AsSpan(8), end);
        SHA256.HashData(control.AsSpan(0, 16), control.AsSpan(16, 32));
        stream.Position = 0;
        stream.Write(control);
    }

    private async Task<List<ArchiveRow>> ReadArchiveSegmentCoreAsync(string path, bool repairTail, CancellationToken token)
    {
        var rows = new List<ArchiveRow>();
        long frontier;
        long actualLength;
        using (var stream = OpenArchiveFile(path))
        {
            // An empty orphan was created before the first frame/frontier.
            // Only the unregistered next segment may be discarded this way.
            bool orphan = Path.GetFileName(path) == checked(_archiveSegmentCount + 1).ToString("X8") + ".pack";
            if (stream.Length == 0 && orphan) return rows;
            frontier = ReadArchiveFrontier(stream);
            actualLength = stream.Length;
            stream.Position = ArchiveControlBytes;
            byte[] header = new byte[ArchiveHeaderBytes];
            while (stream.Position < frontier)
            {
                token.ThrowIfCancellationRequested();
                if (frontier - stream.Position < ArchiveHeaderBytes)
                    throw new InvalidDataException("Incomplete committed archive header.");
                long offset = stream.Position;
                await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
                RequireArchiveHeader(header);
                int length = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8));
                Guid id = new(header.AsSpan(12, 16));
                if (id == Guid.Empty || length <= 0 || length > StagedJournalFile.MaximumManifestBytes || frontier - stream.Position < length)
                    throw new InvalidDataException("Invalid committed archive frame.");
                byte[] payload = new byte[length];
                await stream.ReadExactlyAsync(payload, token).ConfigureAwait(false);
                rows.Add(new(DecodeArchiveFrame(id, header, payload), new(path, offset, length, Convert.ToHexString(header.AsSpan(28, 32)))));
            }
        }
        if (actualLength > frontier && repairTail)
        {
            // The old valid frontier still owns these bytes. A newer append
            // cannot delete a hot manifest until BOTH data and frontier flush.
            using var stream = OpenArchiveFile(path, writable: true);
            stream.SetLength(frontier);
            stream.Flush(flushToDisk: true);
        }
        return rows;
    }

    private static void RequireArchiveHeader(byte[] header)
    {
        if (BinaryPrimitives.ReadUInt32LittleEndian(header) != ArchiveMagic || BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4)) != 1)
            throw new InvalidDataException("Invalid completed journal format/version.");
    }

    private static TransferJournalEntry DecodeArchiveFrame(Guid id, byte[] header, byte[] payload)
    {
        RequireArchiveHeader(header);
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), header.AsSpan(28, 32)))
            throw new InvalidDataException("Completed journal checksum mismatch.");
        TransferJournalEntry? entry;
        try { entry = JsonSerializer.Deserialize<TransferJournalEntry>(payload); }
        catch (JsonException error) { throw new InvalidDataException("Invalid completed journal JSON.", error); }
        ValidateEntry(entry, id);
        if (!CompletedArchiveShape(entry!)) throw new InvalidDataException("Completed journal contains unfinished work.");
        return entry!;
    }

    private async Task<TransferJournalEntry> ReadArchivedCoreAsync(Guid id, CancellationToken token)
    {
        try { return await ReadArchivedCheckedCoreAsync(id, token).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { _gate.FailClosed(error); throw; }
    }

    private async Task<TransferJournalEntry> ReadArchivedCheckedCoreAsync(Guid id, CancellationToken token)
    {
        var location = _archived[id];
        using var stream = OpenArchiveFile(location.Path);
        long frontier = ReadArchiveFrontier(stream);
        if (location.Offset < ArchiveControlBytes || location.Offset + ArchiveHeaderBytes + location.Length > frontier)
            throw new InvalidDataException("Archived receipt escaped its committed frontier.");
        stream.Position = location.Offset;
        byte[] header = new byte[ArchiveHeaderBytes];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        if (BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(8)) != location.Length || new Guid(header.AsSpan(12, 16)) != id ||
            Convert.ToHexString(header.AsSpan(28, 32)) != location.Digest)
            throw new InvalidDataException("Completed journal receipt location changed.");
        byte[] payload = new byte[location.Length];
        await stream.ReadExactlyAsync(payload, token).ConfigureAwait(false);
        return DecodeArchiveFrame(id, header, payload);
    }

    internal async Task ValidateArchivedSliceAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await EnsureArchiveLoadedCoreAsync(token).ConfigureAwait(false);
            int count = Math.Min(16, _archiveAuditIds.Count);
            for (int i = 0; i < count; i++)
            {
                if (_archiveAuditCursor >= _archiveAuditIds.Count) _archiveAuditCursor = 0;
                await ReadArchivedCoreAsync(_archiveAuditIds[_archiveAuditCursor++], token).ConfigureAwait(false);
            }
        }
        finally { _gate.Release(); }
    }

    private async Task CompactArchiveCoreAsync(HashSet<Guid> removed, CancellationToken token)
    {
        try { await RewriteArchiveCoreAsync(removed, token).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { _gate.FailClosed(error); throw; }
    }

    private async Task RewriteArchiveCoreAsync(HashSet<Guid> removed, CancellationToken token)
    {
        foreach (string path in _archived.Where(r => removed.Contains(r.Key)).Select(r => r.Value.Path).Distinct().ToArray())
        {
            var rows = await ReadArchiveSegmentCoreAsync(path, repairTail: false, token).ConfigureAwait(false);
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                long maximumLength = ArchiveControlBytes + rows.Where(r => !removed.Contains(r.Entry.Transfer.TransferId))
                    .Sum(r => (long)ArchiveHeaderBytes + r.Location.Length);
                using (var output = CreatePrivateTemporary(temporary, archive: true))
                {
                    ArchiveGrowthAdmission?.Invoke(temporary, maximumLength);
                    output.SetLength(ArchiveControlBytes);
                    output.Position = ArchiveControlBytes;
                    foreach (var row in rows.Where(r => !removed.Contains(r.Entry.Transfer.TransferId)))
                        await WriteArchiveFrameAsync(output, row.Entry.Transfer.TransferId,
                            JsonSerializer.SerializeToUtf8Bytes(row.Entry), token).ConfigureAwait(false);
                    WriteArchiveFrontier(output, output.Position);
                    ArchiveObserver?.Invoke("before-compaction-replace");
                    await StagedJournalReplacement.CommitAsync(output, temporary, path, token).ConfigureAwait(false);
                    ArchiveObserver?.Invoke("after-compaction-replace");
                }
            }
            finally
            {
                // Even an uncertain replacement invalidates every offset.
                _archiveLoaded = false;
                _archiveAppendPath = null;
                if (File.Exists(temporary)) File.Delete(temporary);
                ArchiveStorageChanged?.Invoke(_completedDirectory);
            }
        }
        await EnsureArchiveLoadedCoreAsync(token).ConfigureAwait(false);
    }
}
