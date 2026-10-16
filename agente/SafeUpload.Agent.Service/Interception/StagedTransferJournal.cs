using System.Text.Json;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using SafeUpload.Agent.Core.Domain;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Durable state for transfers held off the protected destination. Each state
/// change replaces one manifest on the same local volume. A service restart
/// can therefore distinguish an unapproved file from a published one.
/// The journal directory must be writable only by the service account.
/// </summary>
public sealed partial class StagedTransferJournal
{
    private const uint RequiredStageV20Capabilities = 0x1bf;
    internal static readonly string EmptySha256Hex = Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()));
    private readonly string _directory;
    private readonly StagedJournalGate _gate = new();
    private readonly FileSecurity? _fileSecurity;
    private readonly SecurityIdentifier? _owner;
    private readonly string _driverEpochPath;
    private readonly Action<StagedJournalWritePoint, TransferJournalEntry>? _writeObserver;
    internal Action<StagedJournalWritePoint, TransferJournalEntry>? AllocationCommitObserver { get; set; }

    // The publish loop (every 250 ms) and every destination-version scan used to open, ACL-check and JSON-parse EVERY
    // historical manifest, so each stage operation cost O(journal age): latency grew ~3 ms per retained record (C04
    // rename-ex 30 ms -> 340 ms over 100 rounds) and the loop competed with kernel requests for _gate. A manifest is now
    // fully read, ACL-checked and validated once per change; scans reuse the parsed entry while the directory
    // enumeration still reports the same size, timestamps and attributes. Every write through this class drops the
    // entry (Create/Replace), and ReadAsync/ReadCoreAsync, which every state change starts from, always read the disk.
    private readonly record struct ManifestStamp(long Length, long LastWriteTicks, long CreationTicks,
        FileAttributes Attributes);
    private readonly Dictionary<Guid, (ManifestStamp Stamp, TransferJournalEntry Entry, LinkedListNode<Guid> Use)> _scanCache = new();
    private readonly LinkedList<Guid> _scanUses = new();
    private const int MaximumScanCacheEntries = 50_000;
    private readonly int _scanCacheCapacity;
    private long _scanManifestReads;
    private long _manifestReads;
    internal long ManifestReads => Interlocked.Read(ref _manifestReads);
    private long _scanCacheEvictions;
    /// <summary>Manifests a scan had to read, ACL-check and parse (cache misses); test observability.</summary>
    internal long ScanManifestReads => Interlocked.Read(ref _scanManifestReads);
    internal long ScanCacheEvictions => Interlocked.Read(ref _scanCacheEvictions);
    internal int ScanCacheEntries { get { lock (_scanCache) return _scanCache.Count; } }

    /// <summary>
    /// Persists the single accepted driver epoch. A new channel may resume the
    /// same undrained epoch; a different epoch is accepted only after an exact
    /// durable drain receipt. This deliberately does not infer reboot or
    /// abandonment from time, process exit, or a changed GUID.
    /// </summary>
    public async Task<StagedDriverEpochReconcileV20> ReconcileDriverInstanceV20Async(Guid driverInstanceId,
        uint requiredCapabilities, CancellationToken token)
    {
        if (driverInstanceId == Guid.Empty || requiredCapabilities != RequiredStageV20Capabilities)
            return StagedDriverEpochReconcileV20.Rejected;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            DriverEpochRecord? current = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.DriverInstanceId == driverInstanceId)
                    return current.DrainNonce is null
                        ? StagedDriverEpochReconcileV20.Active
                        : StagedDriverEpochReconcileV20.DrainReplayOnly;
                if (current.DrainNonce is null) return StagedDriverEpochReconcileV20.Rejected;
            }
            await WriteDriverEpochCoreAsync(new DriverEpochRecord(driverInstanceId, null,
                null, DateTimeOffset.UtcNow, null), token).ConfigureAwait(false);
            return StagedDriverEpochReconcileV20.Active;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Records epoch drain only after every exact stage owned by that epoch is
    /// terminal and absent/disposed. An active or unknown attachment keeps the
    /// epoch busy and prevents a later driver instance from being admitted.
    /// </summary>
    public async Task<bool> DrainDriverInstanceV20Async(Guid driverInstanceId,
        ulong requestId, ulong drainNonce, CancellationToken token)
    {
        if (driverInstanceId == Guid.Empty || requestId == 0 || drainNonce == 0) return false;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            DriverEpochRecord? epoch = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
            if (epoch is null || epoch.DriverInstanceId != driverInstanceId) return false;
            if (epoch.DrainNonce is { } existingNonce)
                return epoch.DrainRequestId == requestId && existingNonce == drainNonce;

            foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
            {
                token.ThrowIfCancellationRequested();
                if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                    throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
                TransferJournalEntry entry = await ReadCoreAsync(id, token).ConfigureAwait(false);
                if (entry.DriverInstanceId == driverInstanceId &&
                    !IsEpochEntryTerminalAndAbsent(entry)) return false;
            }

            await WriteDriverEpochCoreAsync(epoch with
            {
                DrainRequestId = requestId,
                DrainNonce = drainNonce,
                DrainedAtUtc = DateTimeOffset.UtcNow
            }, token).ConfigureAwait(false);
            return true;
        }
        finally { _gate.Release(); }
    }

    private static bool IsEpochEntryTerminalAndAbsent(TransferJournalEntry entry)
    {
        bool absent = StagedStageFile.TryConfirmAbsent(entry.Transfer.StagePath, out _);
        if (!absent) return false;
        if (entry.State == TransferJournalState.DiscardPending)
            return entry.DiscardAcknowledgedAtUtc is not null;
        if (entry.State == TransferJournalState.Discarded) return true;
        if (entry.State == TransferJournalState.LegacyEmptyHeld)
            return entry.DiscardRequestedAtUtc is not null && entry.DiscardAcknowledgedAtUtc is not null;
        return entry.State is (TransferJournalState.Released or TransferJournalState.Blocked) &&
               entry.StageDeleted;
    }

    private async Task<DriverEpochRecord?> ReadDriverEpochCoreAsync(CancellationToken token)
    {
        using var phaseTiming = StagedRequestTiming.Measure("journal-scan");
        if (!File.Exists(_driverEpochPath)) return null;
        await using FileStream stream = StagedJournalFile.Open(_driverEpochPath,
            maximumBytes: 4096);
        if (_owner is not null)
        {
            var security = stream.GetAccessControl();
            if (_owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                RequireTrustedOwner(security, "driver epoch journal");
            RequireNoUntrustedWriters(security, _owner);
        }
        DriverEpochRecord? record = await JsonSerializer.DeserializeAsync<DriverEpochRecord>(stream,
            cancellationToken: token).ConfigureAwait(false);
        if (record is null || record.DriverInstanceId == Guid.Empty ||
            record.AcceptedAtUtc == default || record.AcceptedAtUtc.Offset != TimeSpan.Zero)
            throw new InvalidDataException("The durable driver epoch record is invalid.");

        bool active = record.DrainRequestId is null && record.DrainNonce is null &&
            record.DrainedAtUtc is null;
        bool drainedRecord = record.DrainRequestId is > 0 && record.DrainNonce is > 0 &&
            record.DrainedAtUtc is { } drainedAt && drainedAt != default &&
            drainedAt.Offset == TimeSpan.Zero && drainedAt >= record.AcceptedAtUtc;
        if (!active && !drainedRecord)
            throw new InvalidDataException("The durable driver epoch record has an unpaired drain receipt.");
        return record;
    }

    private async Task WriteDriverEpochCoreAsync(DriverEpochRecord record, CancellationToken token)
    {
        using var phaseTiming = StagedRequestTiming.Measure("journal-write");
        string temporary = _driverEpochPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using FileStream stream = CreatePrivateTemporary(temporary);
            await JsonSerializer.SerializeAsync(stream, record, cancellationToken: token)
                .ConfigureAwait(false);
            if (stream.Length > 4096)
                throw new InvalidDataException("The driver epoch record exceeds its bound.");
            StagedDestinationFile.Commit(stream, temporary, _driverEpochPath);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private sealed record DriverEpochRecord(Guid DriverInstanceId, ulong? DrainRequestId,
        ulong? DrainNonce, DateTimeOffset AcceptedAtUtc, DateTimeOffset? DrainedAtUtc,
        uint? OsBootSequence = null);

    public StagedTransferJournal(string directory, bool requireProtectedParent = false)
        : this(directory, requireProtectedParent, MaximumScanCacheEntries) { }

    // Small capacities let tests exercise the actual disk-reading scan path at
    // its bound; production always uses the fixed maximum above.
    internal StagedTransferJournal(string directory, bool requireProtectedParent, int scanCacheCapacity,
        Action<StagedJournalWritePoint, TransferJournalEntry>? writeObserver = null)
    {
        if (scanCacheCapacity <= 0 || scanCacheCapacity > MaximumScanCacheEntries)
            throw new ArgumentOutOfRangeException(nameof(scanCacheCapacity));
        _scanCacheCapacity = scanCacheCapacity;
        _writeObserver = writeObserver;
        _directory = Path.GetFullPath(directory);
        _driverEpochPath = Path.Combine(_directory, "driver-epoch.state");
        for (string? path = _directory; path is not null; path = Path.GetDirectoryName(path))
        {
            if (Directory.Exists(path) &&
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("The journal path contains a reparse point.");
            }
        }
        if (OperatingSystem.IsWindows())
        {
            if (requireProtectedParent)
            {
                RequireProtectedParent(_directory);
            }
            // Manifests authorize later publication. A normal user must not
            // edit one to invent an approval, including during driver unload.
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User ?? throw new InvalidOperationException(
                "The journal needs a Windows service identity.");
            _owner = owner;
            var directorySecurity = new DirectorySecurity();
            directorySecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddPrivateRules(directorySecurity, owner, inherit: true);
            var info = new DirectoryInfo(_directory);
            if (!info.Exists)
            {
                info.Create(directorySecurity);
            }
            else
            {
                var existingSecurity = StagedPrivateSecurity.ReadDirectory(_directory);
                if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    RequireTrustedOwner(existingSecurity, "journal directory");
                }
                RequireNoUntrustedWriters(existingSecurity, owner);
                // Setting an inheritable directory DACL can update a child's
                // shared object before its own ACL is visited. Preflight ALL
                // children before allowing that propagation, then reopen and
                // validate each object again for its handle-based ACL update.
                foreach (string path in Directory.EnumerateFileSystemEntries(_directory))
                {
                    using var file = StagedJournalFile.Open(path, maximumBytes: StagedJournalFile.RecoverySizeBound(path));
                    var security = StagedJournalFile.ReadSecurity(file, path);
                    if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                        RequireTrustedOwner(security, "journal manifest");
                    RequireNoUntrustedWriters(security, owner);
                }
                // Reapplying even the same DACL can change NTFS inheritance
                // control bits and propagate to children. Preserve an already
                // private descriptor byte-for-byte on a service restart.
                if (!HasSameProtectedDacl(existingSecurity, directorySecurity))
                    info.SetAccessControl(directorySecurity);
            }

            _fileSecurity = new FileSecurity();
            _fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddPrivateRules(_fileSecurity, owner, inherit: false);
            foreach (string path in Directory.EnumerateFiles(_directory))
            {
                using var file = StagedJournalFile.Open(path, recoverAcl: true,
                    maximumBytes: StagedJournalFile.RecoverySizeBound(path));
                var security = StagedJournalFile.ReadSecurity(file, path);
                if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    RequireTrustedOwner(security, "journal manifest");
                }
                RequireNoUntrustedWriters(security, owner);
                if (!HasSameProtectedDacl(security, _fileSecurity))
                    file.SetAccessControl(_fileSecurity);
            }
        }
        else
        {
            Directory.CreateDirectory(_directory);
        }
    }

    public async Task<TransferJournalEntry> CreateAsync(
        StagedTransfer transfer,
        CancellationToken cancellationToken,
        Guid? tombstoneOwner = null,
        Guid? parentTransferId = null,
        uint? allocationDisposition = null,
        Guid? allocationReferenceId = null,
        uint? allocationReferenceKind = null,
        Guid? driverInstanceId = null,
        StagedStageIdentity? parentDirectoryIdentity = null)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        if (transfer.TransferId == Guid.Empty)
        {
            throw new ArgumentException("A transfer needs a nonempty ID.", nameof(transfer));
        }

        if (parentTransferId == Guid.Empty || allocationDisposition is > 5 ||
            allocationReferenceId == Guid.Empty || allocationReferenceKind is > 2 ||
            driverInstanceId == Guid.Empty ||
            (allocationReferenceKind is null && allocationReferenceId is not null) ||
            (allocationReferenceKind is { } referenceKind &&
                ((referenceKind == 0) != (allocationReferenceId is null))) ||
            ((allocationReferenceKind is null) != (driverInstanceId is null)))
            throw new ArgumentException("The allocation ancestry or disposition is invalid.");
        string path = ManifestPath(transfer.TransferId);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        TransferJournalEntry entry;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var scanTiming = StagedRequestTiming.Measure("journal-scan");
            StagedVersionIdentity? parentIdentity = null;
            TransferJournalEntry? seedParent = null;
            if (parentTransferId is { } priorId)
            {
                TransferJournalEntry parent = await ReadCoreAsync(priorId, cancellationToken)
                    .ConfigureAwait(false);
                RequireFollowupOwner(parent, transfer);
                if (driverInstanceId is { } expectedDriverInstance &&
                    (expectedDriverInstance == Guid.Empty || parent.DriverInstanceId != expectedDriverInstance))
                    throw new IOException("The v20 followup predecessor is not bound to this driver epoch.");
                if (!parent.SealedOnce || parent.StageCleanupStarted || parent.StageDeleted ||
                    parent.StageIdentity is null || parent.DestinationGeneration <= 0 ||
                    parent.State is not (TransferJournalState.Sealed or TransferJournalState.Retained or
                        TransferJournalState.LegacyEmptyHeld))
                    throw new IOException("The followup predecessor has no stable sealed stage identity.");
                await RequireCurrentDestinationAsync(parent, cancellationToken).ConfigureAwait(false);
                parentIdentity = VersionIdentity(parent);
                seedParent = parent;
            }

            var versions = await DestinationVersionsAsync(transfer.DestinationPath, cancellationToken)
                .ConfigureAwait(false);
            if (versions.Any(e => e.Reserved))
                throw new IOException("Publication or rename currently holds this destination.");
            if (tombstoneOwner is not null)
            {
                long head = versions.Select(e => e.Generation).DefaultIfEmpty(0).Max();
                var claims = versions.Where(e => e.Generation == head).ToArray();
                if (claims.Length != 1 || !claims[0].Tombstone ||
                    claims[0].Entry.Transfer.TransferId != tombstoneOwner ||
                    claims[0].Entry.Transfer.ProcessId != transfer.ProcessId ||
                    claims[0].Entry.Transfer.SessionId != transfer.SessionId ||
                    !string.Equals(claims[0].Entry.Transfer.RequestorSid, transfer.RequestorSid,
                        StringComparison.OrdinalIgnoreCase) ||
                    claims[0].Entry.Transfer.RequestorProcessCreationTime !=
                        transfer.RequestorProcessCreationTime)
                    throw new IOException("No current committed tombstone belongs to this writer and session.");
            }
            // Ordinary ALLOCATE is backing-first and one-shot. Capture the
            // stage identity only after the backing exists and immediately
            // before the durable generation/head claim, which is committed
            // before returning the name to the driver. A response lost after
            // this point is a private orphan candidate, never publishable.
            StagedStageIdentity? stageIdentity = null;
            if (File.Exists(transfer.StagePath))
            {
                using StagedStageFile stage = StagedStageFile.Open(transfer.StagePath);
                stageIdentity = stage.Identity;
            }
            DateTimeOffset createdAtUtc = DateTimeOffset.UtcNow;
            entry = new TransferJournalEntry(transfer, TransferJournalState.Allocated, null, createdAtUtc)
            {
                StateHistory = [new TransferJournalStateChange(TransferJournalState.Allocated, createdAtUtc)],
                StageIdentity = stageIdentity,
                DestinationGeneration = checked(versions.Select(e => e.Generation).DefaultIfEmpty(0).Max() + 1),
                ParentVersionIdentity = parentIdentity,
                CreateReservationId = allocationDisposition is null ? null : transfer.TransferId,
                AllocationDisposition = allocationDisposition,
                AllocationReferenceId = allocationReferenceId,
                AllocationReferenceKind = allocationReferenceKind,
                DriverInstanceId = driverInstanceId,
                ParentDirectoryIdentity = parentDirectoryIdentity
            };
            if (allocationDisposition is 1 or 3 && seedParent is not null &&
                (seedParent.SeedProvenance is not null || seedParent.BoundAllocation is not null ||
                 StagedSeedExport.IsFailure(seedParent.HandbackFailureReason)))
                entry = entry with { SeedProvenance = StagedSeedProvenance.Inherit(entry, seedParent) };
            ValidateEntry(entry, transfer.TransferId);
            scanTiming?.Dispose();
            using var writeTiming = StagedRequestTiming.Measure("journal-write");
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                if (stream.Length > StagedJournalFile.MaximumManifestBytes)
                    throw new InvalidDataException("Journal manifest exceeds the qualified size bound.");
                stream.Flush(flushToDisk: true);
            }

            // A complete, flushed manifest becomes visible all at once. A
            // duplicate ID cannot take over an earlier destination.
            bool allocationCommitted = false;
            try
            {
                AllocationCommitObserver?.Invoke(StagedJournalWritePoint.BeforeReplacement, entry);
                File.Move(temporary, path);
                allocationCommitted = true;
                AllocationCommitObserver?.Invoke(StagedJournalWritePoint.AfterReplacement, entry);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                throw new StagedJournalPersistenceException(path, temporary, entry, "create-replace",
                    allocationCommitted, ex);
            }
            ForgetScanned(transfer.TransferId);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
            _gate.Release();
        }

        return entry;
    }

    /// <summary>
    /// Resolves a stable v19 allocation reservation after an RPC reply was
    /// lost. The exact reservation-derived manifest and stage identity are the
    /// only source of the returned tuple; current namespace checks are left to
    /// the driver's post-RPC attach validation so stale replies can be retired
    /// with the same exact identity.
    /// </summary>
    public async Task<TransferJournalEntry> ResolveAllocationV19Async(
        StagedTransfer expectedTransfer, StagedAllocationIntentV19 intent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expectedTransfer);
        ArgumentNullException.ThrowIfNull(intent);
        if (intent.ReservationId == Guid.Empty || expectedTransfer.TransferId != intent.ReservationId ||
            intent.DriverInstanceId == Guid.Empty || intent.Disposition > 5 ||
            intent.ReferenceKind > 2 ||
            (intent.ReferenceKind == 0) != (intent.ParentTransferId == Guid.Empty))
            throw new ArgumentException("The exact v19 allocation replay tuple is invalid.");

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(intent.ReservationId, cancellationToken)
                .ConfigureAwait(false);
            if (current.BoundAllocation is not null || current.AllocationExtensionVersion is not null ||
                current.Transfer != expectedTransfer || current.CreateReservationId != intent.ReservationId ||
                current.AllocationDisposition != intent.Disposition ||
                current.AllocationReferenceId != (intent.ParentTransferId == Guid.Empty
                    ? null : intent.ParentTransferId) ||
                current.AllocationReferenceKind != intent.ReferenceKind ||
                current.DriverInstanceId != intent.DriverInstanceId || current.StageIdentity is null ||
                current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                current.PendingRename is not null)
                throw new IOException("The v19 reservation has no matching replayable allocation intent.");
            if (intent.ReferenceKind == 1)
            {
                if (current.ParentVersionIdentity is not { } parentIdentity ||
                    parentIdentity.TransferId != intent.ParentTransferId)
                    throw new IOException("The v19 allocation's exact predecessor identity changed.");
                TransferJournalEntry parent = await ReadCoreAsync(parentIdentity.TransferId, cancellationToken)
                    .ConfigureAwait(false);
                if (VersionIdentity(parent) != parentIdentity || !SameWriter(parent.Transfer, current.Transfer) ||
                    parent.Transfer.DestinationPath != current.Transfer.DestinationPath ||
                    parent.DriverInstanceId != intent.DriverInstanceId || parent.DriverInstanceId == Guid.Empty)
                    throw new IOException("The v19 allocation's predecessor manifest changed.");
            }
            else if (intent.ReferenceKind == 2)
            {
                TransferJournalEntry owner = await ReadCoreAsync(intent.ParentTransferId, cancellationToken)
                    .ConfigureAwait(false);
                if (current.AllocationDisposition != 2 || owner.Transfer.TransferId != intent.ParentTransferId ||
                    !SameWriter(owner.Transfer, current.Transfer) || owner.Transfer.Destination != current.Transfer.Destination ||
                    !string.Equals(owner.Transfer.DestinationPath, current.Transfer.DestinationPath,
                        StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The v19 tombstone owner no longer matches the allocation request.");
            }
            using StagedStageFile stage = StagedStageFile.Open(current.Transfer.StagePath);
            if (stage.Identity != current.StageIdentity)
                throw new IOException("The v19 allocation stage no longer matches its durable identity.");
            return current;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Captures allocation identity only after the manifest-first transaction
    /// and backing-file creation. This is allocation evidence, never a seal or
    /// a positive-length assertion.
    /// </summary>
    public async Task<TransferJournalEntry> CaptureAllocationIdentityAsync(Guid transferId,
        Guid reservationId, CancellationToken cancellationToken, bool requireCurrentDestination = true)
    {
        if (transferId == Guid.Empty || reservationId == Guid.Empty)
            throw new ArgumentException("Allocation identity needs a stable reservation.");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(transferId, cancellationToken).ConfigureAwait(false);
            if (current.State != TransferJournalState.Allocated || current.SealedOnce ||
                current.SealedLength is not null || current.CreateReservationId != reservationId ||
                current.PendingRename is not null || current.DestinationGeneration <= 0)
                throw new IOException("The allocation intent is no longer eligible for identity capture.");
            using StagedStageFile stage = StagedStageFile.Open(current.Transfer.StagePath);
            if (current.StageIdentity is { } captured && captured != stage.Identity)
                throw new IOException("The allocation stage identity changed before reply or replay.");
            if (requireCurrentDestination)
            {
                if (current.BoundAllocation is null && current.ParentDirectoryIdentity is { } expectedDirectory &&
                    StagedStageFile.ReadDirectoryIdentity(Path.GetDirectoryName(current.Transfer.DestinationPath)!) !=
                        expectedDirectory)
                    throw new IOException("The destination parent directory changed during allocation.");
                if (current.DeleteVersionIdentity is not null && PathExists(current.Transfer.DestinationPath))
                    throw new IOException("The public destination appeared during private allocation.");
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                RequireBoundAllocationSource(current, cancellationToken);
#endif
                await RequireCurrentDestinationAsync(current, cancellationToken).ConfigureAwait(false);
            }
            if (current.DeleteVersionIdentity is { } deleted)
            {
                TransferJournalEntry pendingDelete = await ReadCoreAsync(deleted.TransferId, cancellationToken)
                    .ConfigureAwait(false);
                if (pendingDelete.State != TransferJournalState.DiscardPending ||
                    pendingDelete.DiscardReservationId != deleted.TransferId ||
                    pendingDelete.CreateAfterReservationId != reservationId ||
                    VersionIdentity(pendingDelete) != deleted)
                    throw new IOException("The exact delete predecessor changed during allocation.");
            }

            if (current.StageIdentity is not null) return current;

            var updated = current with { StageIdentity = stage.Identity, UpdatedAtUtc = DateTimeOffset.UtcNow };
            await ReplaceAsync(ManifestPath(transferId), updated, cancellationToken).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Identity/head check before the allocation reply. For V23 this
    /// transfers an empty private candidate to the kernel, not app exposure.</summary>
    public async Task<TransferJournalEntry> ValidateAllocationReplyAsync(
        StagedVersionIdentity expectedVersion, Guid reservationId, CancellationToken cancellationToken,
        bool requireCurrentDestination = true)
    {
        ArgumentNullException.ThrowIfNull(expectedVersion);
        if (reservationId == Guid.Empty) throw new ArgumentException("An allocation reservation is required.");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(expectedVersion.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (current.State != TransferJournalState.Allocated || current.SealedOnce ||
                current.SealedLength is not null || current.CreateReservationId != reservationId ||
                VersionIdentity(current) != expectedVersion || current.PendingRename is not null)
                throw new IOException("The allocation reply no longer matches its durable exact tuple.");
            using (StagedStageFile stage = StagedStageFile.Open(current.Transfer.StagePath))
            {
                if (stage.Identity != expectedVersion.StageIdentity || stage.Stream.Length < 0)
                    throw new IOException("The allocation stage changed before its reply.");
                if (current.BoundAllocation is not null && current.SeedCompletion is null && stage.Stream.Length != 0)
                    throw new IOException("seed_completion_unproved");
            }
            if (requireCurrentDestination && current.BoundAllocation is null &&
                current.ParentDirectoryIdentity is { } expectedDirectory &&
                StagedStageFile.ReadDirectoryIdentity(Path.GetDirectoryName(current.Transfer.DestinationPath)!) !=
                    expectedDirectory)
                throw new IOException("The destination parent directory changed before the allocation reply.");
            if (current.DeleteVersionIdentity is { } deleted)
            {
                if (requireCurrentDestination && PathExists(current.Transfer.DestinationPath))
                    throw new IOException("The public destination appeared before the allocation reply.");
                TransferJournalEntry pendingDelete = await ReadCoreAsync(deleted.TransferId, cancellationToken)
                    .ConfigureAwait(false);
                if (pendingDelete.State != TransferJournalState.DiscardPending ||
                    pendingDelete.DiscardReservationId != deleted.TransferId ||
                    pendingDelete.CreateAfterReservationId != reservationId ||
                    VersionIdentity(pendingDelete) != deleted)
                    throw new IOException("The exact delete predecessor changed before the allocation reply.");
            }
            if (requireCurrentDestination)
            {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                RequireBoundAllocationSource(current, cancellationToken);
#endif
                await RequireCurrentDestinationAsync(current, cancellationToken).ConfigureAwait(false);
            }
            return current;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Commits V2's terminal DiscardPending state before writing the fresh V3
    /// Allocated manifest. Both writes are serialized under _gate. A crash
    /// between them is replayable with the same ReservationId and exact V2
    /// tuple; the requested generation is never supplied by the caller.
    /// </summary>
    public async Task<StagedCreateAfterIntentResult> CreateAfterPrivateDiscardIntentAsync(
        StagedCreateAfterDiscardRequest request, StagedTransfer child,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(child);
        string destination = Path.GetFullPath(request.DestinationPath);
        string parentDirectory = Path.GetDirectoryName(destination) ??
            throw new IOException("The destination has no parent directory.");
        if (request.ReservationId == Guid.Empty || request.DeleteVersion.TransferId == Guid.Empty ||
            request.DeleteVersion.DestinationGeneration <= 0 || request.Disposition != 5 ||
            request.DriverInstanceId == Guid.Empty ||
            request.ProcessId <= 0 ||
            string.IsNullOrWhiteSpace(request.RequestorSid) || request.RequestorSid.Length > 184 ||
            request.RequestorProcessCreationTime <= 0 || child.TransferId != request.ReservationId ||
            child.DestinationPath != destination || child.Destination != request.Destination ||
            child.ProcessId != request.ProcessId || child.SessionId != request.SessionId ||
            !string.Equals(child.RequestorSid, request.RequestorSid, StringComparison.OrdinalIgnoreCase) ||
            child.RequestorProcessCreationTime != request.RequestorProcessCreationTime)
            throw new ArgumentException("The create-after-discard reservation has invalid identity or disposition.");

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        string childPath = ManifestPath(child.TransferId);
        string temporary = childPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            TransferJournalEntry delete = await ReadCoreAsync(request.DeleteVersion.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (VersionIdentity(delete) != request.DeleteVersion ||
                !SameWriter(delete.Transfer, child) ||
                !string.Equals(delete.Transfer.DestinationPath, destination, StringComparison.OrdinalIgnoreCase) ||
                delete.Transfer.Destination != request.Destination || delete.PendingRename is not null ||
                delete.StageIdentity is null || delete.State is TransferJournalState.LegacyEmptyHeld or
                    TransferJournalState.Blocked or TransferJournalState.Approved or
                    TransferJournalState.Publishing or TransferJournalState.Released or
                    TransferJournalState.Discarded)
                throw new IOException("The exact private delete predecessor is not eligible for replacement.");

            // Keep legacy V19 CREATE_AFTER explicit: it remains eligible only
            // when both the request and predecessor have no v20 epoch. A
            // measured predecessor must carry the durable op19 receipt for
            // this exact manifest before V2 can move to DiscardPending.
            // ApplyAttachmentV20Async records that receipt only after checking
            // the active driver epoch and full version tuple.
            if (delete.DriverInstanceId is null)
            {
                if (request.DriverInstanceId is not null)
                    throw new IOException("The legacy private delete belongs to a different driver epoch.");
            }
            else
            {
                if (delete.DriverInstanceId == Guid.Empty || delete.DriverInstanceId != request.DriverInstanceId)
                    throw new IOException("The private delete predecessor is not bound to this driver epoch.");
                if (delete.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved ||
                    delete.CompletionPermitRequestIdV20 is not > 0 ||
                    delete.HandleObservedRequestIdV20 is not > 0 ||
                    delete.CompletionPermitRequestIdV20 == delete.HandleObservedRequestIdV20)
                    throw new IOException("The exact private delete predecessor has no durable op19 handle receipt.");
            }

            // Validate the complete V1/V2 epoch chain before mutating the V2
            // delete intent. A legacy or mismatched V1 must remain untouched;
            // otherwise a retry could leave a durable V2 reservation that can
            // never safely authorize V3 cleanup.
            if (delete.ParentVersionIdentity is not { } parentIdentity)
                throw new IOException("The private delete has no durable exact predecessor ancestry.");
            TransferJournalEntry parent = await ReadCoreAsync(parentIdentity.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (VersionIdentity(parent) != parentIdentity || parent.State != TransferJournalState.LegacyEmptyHeld ||
                parent.SealedLength != 0 || parent.PendingRename is not null ||
                !string.Equals(parent.Transfer.DestinationPath, destination, StringComparison.OrdinalIgnoreCase) ||
                !SameWriter(parent.Transfer, child) || parent.DriverInstanceId != request.DriverInstanceId ||
                parent.DriverInstanceId == Guid.Empty)
                throw new IOException("The exact EmptyHeld predecessor is not bound to this driver epoch.");

            TransferJournalEntry? existingChild = null;
            try { existingChild = await ReadCoreAsync(child.TransferId, cancellationToken).ConfigureAwait(false); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            if (existingChild is not null)
            {
                if (!MatchesCreateAfterRequest(existingChild, child, request) ||
                    existingChild.ParentVersionIdentity != delete.ParentVersionIdentity ||
                    delete.State != TransferJournalState.DiscardPending ||
                    delete.DiscardReservationId != delete.Transfer.TransferId ||
                    delete.CreateAfterReservationId != request.ReservationId)
                    throw new IOException("The create-after reservation was already committed with different inputs.");
                if (existingChild.StageIdentity is { } replayIdentity)
                {
                    using StagedStageFile replayStage = StagedStageFile.Open(existingChild.Transfer.StagePath);
                    if (replayStage.Identity != replayIdentity)
                        throw new IOException("The create-after replay stage identity changed.");
                }
                return new StagedCreateAfterIntentResult(existingChild, IsReplay: true);
            }

            if (StagedStageFile.ReadDirectoryIdentity(parentDirectory) != request.ParentDirectoryIdentity ||
                PathExists(destination))
                throw new IOException("The destination parent changed or the public destination is present.");

            await RequireCurrentDestinationAsync(delete, cancellationToken).ConfigureAwait(false);
            if (delete.State != TransferJournalState.DiscardPending)
            {
                if (delete.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed or
                        TransferJournalState.SealPending or TransferJournalState.Sealed or TransferJournalState.Retained))
                    throw new IOException("The private delete predecessor cannot enter DiscardPending.");
                IReadOnlyList<TransferJournalStateChange> deleteHistory =
                    AppendState(delete, TransferJournalState.DiscardPending);
                delete = delete with
                {
                    State = TransferJournalState.DiscardPending,
                    DiscardReservationId = delete.Transfer.TransferId,
                    DiscardKind = StagedDiscardKind.PrivateVersion,
                    DiscardRequestedAtUtc = DateTimeOffset.UtcNow,
                    DiscardAcknowledgedAtUtc = null,
                    CreateAfterReservationId = request.ReservationId,
                    UpdatedAtUtc = deleteHistory.Count == 0 ? DateTimeOffset.UtcNow : deleteHistory[^1].OccurredAtUtc,
                    StateHistory = deleteHistory
                };
                await ReplaceAsync(ManifestPath(delete.Transfer.TransferId), delete, cancellationToken)
                    .ConfigureAwait(false);
            }
            else if (delete.DiscardReservationId != delete.Transfer.TransferId ||
                delete.DiscardKind != StagedDiscardKind.PrivateVersion ||
                (delete.CreateAfterReservationId is { } priorReservation &&
                    priorReservation != request.ReservationId))
            {
                throw new IOException("A different create-after reservation already owns the private delete.");
            }
            if (delete.CreateAfterReservationId is null)
            {
                delete = delete with { CreateAfterReservationId = request.ReservationId,
                    UpdatedAtUtc = DateTimeOffset.UtcNow };
                await ReplaceAsync(ManifestPath(delete.Transfer.TransferId), delete, cancellationToken)
                    .ConfigureAwait(false);
            }

            var versions = await DestinationVersionsAsync(destination, cancellationToken).ConfigureAwait(false);
            if (versions.Any(e => e.Reserved))
                throw new IOException("Publication or rename currently holds this destination.");
            DateTimeOffset createdAtUtc = DateTimeOffset.UtcNow;
            var allocated = new TransferJournalEntry(child, TransferJournalState.Allocated, null, createdAtUtc)
            {
                StateHistory = [new TransferJournalStateChange(TransferJournalState.Allocated, createdAtUtc)],
                DestinationGeneration = checked(versions.Select(e => e.Generation).DefaultIfEmpty(0).Max() + 1),
                ParentVersionIdentity = parentIdentity,
                DeleteVersionIdentity = request.DeleteVersion,
                CreateReservationId = request.ReservationId,
                ParentDirectoryIdentity = request.ParentDirectoryIdentity,
                AllocationDisposition = request.Disposition,
                AllocationReferenceId = request.DriverInstanceId is null
                    ? null : request.DeleteVersion.TransferId,
                AllocationReferenceKind = request.DriverInstanceId is null ? null : 1u,
                DriverInstanceId = request.DriverInstanceId
            };
            ValidateEntry(allocated, child.TransferId);
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                await JsonSerializer.SerializeAsync(stream, allocated, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                if (stream.Length > StagedJournalFile.MaximumManifestBytes)
                    throw new InvalidDataException("Journal manifest exceeds the qualified size bound.");
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, childPath);
            ForgetScanned(child.TransferId);
            return new StagedCreateAfterIntentResult(allocated, IsReplay: false);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
            _gate.Release();
        }
    }

    /// <summary>
    /// Durably queues an exact identity-qualified cleanup request. This method
    /// never removes the stage; callers on the filter-port thread can return
    /// Pending immediately while the background worker performs deletion.
    /// </summary>
    public async Task<StagedDiscardStatus> BeginOrConfirmDiscardAsync(
        StagedDiscardRequest request, CancellationToken cancellationToken, int? requestorProcessId = null,
        Guid? currentDriverInstanceId = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateDiscardRequest(request);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(request.Version.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (VersionIdentity(current) != request.Version || current.PendingRename is not null)
                throw new IOException("The discard does not identify the exact durable stage version.");
            if (requestorProcessId is > 0 && request.Kind is not
                    (StagedDiscardKind.OwnerExitEmpty or StagedDiscardKind.DriverUnloadEmpty) &&
                requestorProcessId != current.Transfer.ProcessId)
                throw new IOException("The discard requestor is not the exact staged-version owner.");
            if (currentDriverInstanceId is { } activeDriver)
            {
                if (request.Kind == StagedDiscardKind.EmptyHeldPredecessor)
                {
                    TransferJournalEntry child = await ReadCoreAsync(request.ReservationId, cancellationToken)
                        .ConfigureAwait(false);
                    if (current.DriverInstanceId != activeDriver || child.DriverInstanceId != activeDriver ||
                        child.ParentVersionIdentity is null)
                        throw new IOException("The predecessor cleanup is not bound to the active driver epoch.");
                }
                else if (current.DriverInstanceId != activeDriver)
                {
                    throw new IOException("The discard is not bound to the active driver epoch.");
                }
            }
            return await BeginOrValidateDiscardCoreAsync(current, request, cancellationToken)
                .ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Applies one idempotent v20 attachment receipt to the exact allocated
    /// manifest. Operations 16 and 18 persist a pending terminal intent and
    /// return null until the background identity-qualified deletion ACK is
    /// durable; callers must then replay the same request tuple.
    /// </summary>
    public async Task<uint?> ApplyAttachmentV20Async(StagedAttachmentRequestV20 request,
        bool ownerIsLive, bool commitPolicyAllowed, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestId == 0 || request.Operation is not (12 or 13 or 14 or 15 or 16 or 18 or 19) ||
            request.Version.TransferId == Guid.Empty ||
            request.Version.DestinationGeneration <= 0 || request.DriverInstanceId == Guid.Empty ||
            request.Version.StageIdentity is null || request.ParentDirectoryIdentity is null ||
            request.RequestorProcessId <= 0 || string.IsNullOrWhiteSpace(request.DestinationPath))
            throw new ArgumentException("The v20 attachment request lacks exact identity.", nameof(request));

        string destination = Path.GetFullPath(request.DestinationPath);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            DriverEpochRecord? epoch = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
            if (epoch is null || epoch.DriverInstanceId != request.DriverInstanceId || epoch.DrainNonce is not null)
                throw StagedRequestRefusal.Create("The attachment request does not belong to the active v20 epoch.");
            TransferJournalEntry current = await ReadCoreAsync(request.Version.TransferId, token)
                .ConfigureAwait(false);
            if (VersionIdentity(current) != request.Version || current.DriverInstanceId != request.DriverInstanceId ||
                current.ParentDirectoryIdentity != request.ParentDirectoryIdentity ||
                current.Transfer.ProcessId != request.RequestorProcessId ||
                !string.Equals(current.Transfer.DestinationPath, destination, StringComparison.OrdinalIgnoreCase) ||
                current.PendingRename is not null || current.ParentDirectoryIdentity is null ||
                StagedStageFile.ReadDirectoryIdentity(Path.GetDirectoryName(destination)!) !=
                    request.ParentDirectoryIdentity)
                throw StagedRequestRefusal.Create("The v20 attachment tuple does not match the exact allocation manifest.");

            uint? replay = ResolveAttachmentReplay(current, request);
            if (replay.HasValue) return replay.Value;
            if ((request.Operation is 16 or 18) && current.RetireRequestIdV20 == request.RequestId &&
                current.AttachmentStateV20 is (StagedAttachmentStateV20.RetireUnexposedPending or
                    StagedAttachmentStateV20.RetireAttachedPrivatePending))
                return null;
            if (request.Operation == 14 && current.AttachAbortRequestIdV20 == request.RequestId &&
                current.AttachmentStateV20 == StagedAttachmentStateV20.Aborted)
                return StageV20WireResult.AttachAborted;
            if (request.RequestId == current.AttachPrepareRequestIdV20 ||
                request.RequestId == current.AttachCommitRequestIdV20 ||
                request.RequestId == current.AttachAbortRequestIdV20 ||
                request.RequestId == current.CompletionPermitRequestIdV20 ||
                request.RequestId == current.RetireRequestIdV20 ||
                request.RequestId == current.HandleObservedRequestIdV20)
                throw StagedRequestRefusal.Create("A v20 lifecycle RequestId is already bound to another exact phase.");
            if (request.Operation == 14 && current.AttachmentStateV20 is
                    (StagedAttachmentStateV20.Committed or StagedAttachmentStateV20.CompletionPermitted or
                     StagedAttachmentStateV20.HandleObserved or StagedAttachmentStateV20.RetireUnexposedPending or
                     StagedAttachmentStateV20.RetiredUnexposed or
                     StagedAttachmentStateV20.RetireAttachedPrivatePending or
                     StagedAttachmentStateV20.RetiredAttachedPrivate))
                // This is a read-only monotonic result. It never creates an
                // abort receipt, and remains safe if the private stage is gone.
                return StageV20WireResult.AttachAlreadyCommitted;

            // PREPARE, COMMIT, COMPLETION and the CLEANUP receipt run while the
            // driver's writer holds the stage open without sharing: verify them
            // through a metadata-only handle. The other operations keep a data
            // open without write sharing, which still fails if a writer remains.
            bool writerAttached = request.Operation is 12 or 13 or 15 or 19;
            StagedStageIdentity? attachedIdentity = null;
            long attachedLength = 0;
            if (writerAttached)
                (attachedIdentity, attachedLength) = StagedStageFile.ReadAttachedMetadata(current.Transfer.StagePath);
            using (StagedStageFile? stage = writerAttached ? null
                       : StagedStageFile.Open(current.Transfer.StagePath, allowWriters: false))
            {
                StagedStageIdentity stageIdentity = stage?.Identity ?? attachedIdentity
                    ?? throw StagedRequestRefusal.Create("The v20 attachment stage identity is unavailable.");
                long StageLength() => stage?.Stream.Length ?? attachedLength;
                if (stageIdentity != request.Version.StageIdentity)
                    throw StagedRequestRefusal.Create("The v20 attachment stage identity changed.");
                if (current.DeleteVersionIdentity is not null && PathExists(destination))
                    throw StagedRequestRefusal.Create("The public destination reappeared during private attachment.");

                switch (request.Operation)
                {
                    case 12: // Prepare
                        if (current.AttachPrepareRequestIdV20 == request.RequestId)
                            return StageV20WireResult.AttachPrepared;
                        if (current.AttachmentStateV20 != StagedAttachmentStateV20.None || !ownerIsLive ||
                            current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                            current.SealedOnce || current.SealedLength is not null ||
                            current.DiscardRequestedAtUtc is not null || current.StageCleanupStarted || current.StageDeleted)
                            throw StagedRequestRefusal.Create("The exact stage is not eligible for attachment prepare.");
                        await ReplaceAsync(ManifestPath(request.Version.TransferId), current with
                        {
                            AttachmentStateV20 = StagedAttachmentStateV20.Prepared,
                            AttachPrepareRequestIdV20 = request.RequestId,
                            UpdatedAtUtc = DateTimeOffset.UtcNow
                        }, token).ConfigureAwait(false);
                        return StageV20WireResult.AttachPrepared;

                    case 13: // Commit
                        if (current.AttachCommitRequestIdV20 == request.RequestId)
                            return current.AttachmentStateV20 switch
                            {
                                StagedAttachmentStateV20.Committed or StagedAttachmentStateV20.CompletionPermitted or
                                    StagedAttachmentStateV20.HandleObserved or
                                    StagedAttachmentStateV20.RetireAttachedPrivatePending or
                                    StagedAttachmentStateV20.RetiredAttachedPrivate =>
                                        current.AttachCommitResultV20 ?? StageV20WireResult.AttachCommitted,
                                StagedAttachmentStateV20.CommitDenied => StageV20WireResult.AttachCommitDenied,
                                _ => throw StagedRequestRefusal.Create("The saved commit request has no exact result.")
                            };
                        if (current.AttachmentStateV20 != StagedAttachmentStateV20.Prepared || !ownerIsLive ||
                            current.AttachCommitRequestIdV20 is not null || current.AttachAbortRequestIdV20 is not null)
                            throw StagedRequestRefusal.Create("The exact stage is not eligible for attachment commit.");
                        StagedAttachmentStateV20 committedState = commitPolicyAllowed
                            ? StagedAttachmentStateV20.Committed : StagedAttachmentStateV20.CommitDenied;
                        await ReplaceAsync(ManifestPath(request.Version.TransferId), current with
                        {
                            AttachmentStateV20 = committedState,
                            AttachCommitRequestIdV20 = request.RequestId,
                            AttachCommitResultV20 = commitPolicyAllowed
                                ? StageV20WireResult.AttachCommitted : StageV20WireResult.AttachCommitDenied,
                            UpdatedAtUtc = DateTimeOffset.UtcNow
                        }, token).ConfigureAwait(false);
                        return commitPolicyAllowed ? StageV20WireResult.AttachCommitted :
                            StageV20WireResult.AttachCommitDenied;

                    case 14: // Abort prepared, unexposed attachment
                        if (current.AttachAbortRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 == StagedAttachmentStateV20.Aborted)
                            return StageV20WireResult.AttachAborted;
                        if (current.AttachmentStateV20 is not (StagedAttachmentStateV20.Prepared or
                                StagedAttachmentStateV20.CommitDenied) || current.AttachAbortRequestIdV20 is not null ||
                            current.CompletionPermitRequestIdV20 is not null ||
                            current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                            current.DiscardRequestedAtUtc is not null)
                            throw StagedRequestRefusal.Create("The exact attachment cannot be aborted after commit/expose ambiguity.");
                        IReadOnlyList<TransferJournalStateChange> abortHistory =
                            AppendState(current, TransferJournalState.DiscardPending);
                        await ReplaceAsync(ManifestPath(request.Version.TransferId), current with
                        {
                            State = TransferJournalState.DiscardPending,
                            StateHistory = abortHistory,
                            AttachmentStateV20 = StagedAttachmentStateV20.Aborted,
                            AttachAbortRequestIdV20 = request.RequestId,
                            DiscardReservationId = current.Transfer.TransferId,
                            DiscardKind = StagedDiscardKind.UnattachedAllocation,
                            DiscardRequestedAtUtc = DateTimeOffset.UtcNow,
                            DiscardAcknowledgedAtUtc = null,
                            UpdatedAtUtc = abortHistory[^1].OccurredAtUtc
                        }, token).ConfigureAwait(false);
                        return StageV20WireResult.AttachAborted;

                    case 15: // CompletionPermitted; never means app handle delivery
                        StagedSeedCompletion.Require(current);
                        if (current.CompletionPermitRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 is (StagedAttachmentStateV20.CompletionPermitted or
                                StagedAttachmentStateV20.HandleObserved or
                                StagedAttachmentStateV20.RetireAttachedPrivatePending or
                                StagedAttachmentStateV20.RetiredAttachedPrivate))
                            return StageV20WireResult.CompletionPermitted;
                        if (current.AttachmentStateV20 != StagedAttachmentStateV20.Committed || !ownerIsLive ||
                            current.CompletionPermitRequestIdV20 is not null ||
                            current.DiscardRequestedAtUtc is not null)
                            throw StagedRequestRefusal.Create("The exact attachment has no completion permission.");
                        await ReplaceAsync(ManifestPath(request.Version.TransferId), current with
                        {
                            AttachmentStateV20 = StagedAttachmentStateV20.CompletionPermitted,
                            CompletionPermitRequestIdV20 = request.RequestId,
                            UpdatedAtUtc = DateTimeOffset.UtcNow
                        }, token).ConfigureAwait(false);
                        return StageV20WireResult.CompletionPermitted;

                    case 16: // RetireUnexposed, only if op 15 is provably absent
                        if (current.RetireRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 == StagedAttachmentStateV20.RetiredUnexposed &&
                            current.DiscardAcknowledgedAtUtc is not null)
                            return StageV20WireResult.AttachRetiredUnexposed;
                        if (current.RetireRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 == StagedAttachmentStateV20.RetireUnexposedPending)
                            return null;
                        if (current.AttachmentStateV20 != StagedAttachmentStateV20.Committed ||
                            current.CompletionPermitRequestIdV20 is not null || current.RetireRequestIdV20 is not null ||
                            current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                            current.SealedOnce || current.SealedLength is not null || current.DiscardRequestedAtUtc is not null)
                            throw StagedRequestRefusal.Create("RetireUnexposed requires committed attachment with no op15 send.");
                        await BeginAttachmentRetirementCoreAsync(current, request,
                            StagedDiscardKind.RetireUnexposed,
                            StagedAttachmentStateV20.RetireUnexposedPending, token).ConfigureAwait(false);
                        return null;

                    case 18: // RetireAttachedPrivate, op18 native callsite remains disabled
                        if (current.RetireRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 == StagedAttachmentStateV20.RetiredAttachedPrivate &&
                            current.DiscardAcknowledgedAtUtc is not null)
                            return StageV20WireResult.AttachRetiredPrivate;
                        if (current.RetireRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 == StagedAttachmentStateV20.RetireAttachedPrivatePending)
                            return null;
                        if (current.AttachmentStateV20 != StagedAttachmentStateV20.CompletionPermitted ||
                            current.HandleObservedRequestIdV20 is not null || current.RetireRequestIdV20 is not null ||
                            current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                            current.SealedOnce || current.SealedLength is not null || current.DiscardRequestedAtUtc is not null ||
                            StageLength() != 0)
                            throw StagedRequestRefusal.Create("RetireAttachedPrivate requires an exact zero-byte attached stage with no use receipt.");
                        await BeginAttachmentRetirementCoreAsync(current, request,
                            StagedDiscardKind.RetireAttachedPrivate,
                            StagedAttachmentStateV20.RetireAttachedPrivatePending, token).ConfigureAwait(false);
                        return null;

                    case 19: // Sticky positive file-object CLEANUP receipt
                        if (current.HandleObservedRequestIdV20 == request.RequestId &&
                            current.AttachmentStateV20 == StagedAttachmentStateV20.HandleObserved)
                            return StageV20WireResult.HandleLifetimeObserved;
                        if (current.AttachmentStateV20 != StagedAttachmentStateV20.CompletionPermitted ||
                            current.HandleObservedRequestIdV20 is not null || current.DiscardRequestedAtUtc is not null ||
                            current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed))
                            throw StagedRequestRefusal.Create("The exact attached version cannot accept a late handle receipt.");
                        await ReplaceAsync(ManifestPath(request.Version.TransferId), current with
                        {
                            AttachmentStateV20 = StagedAttachmentStateV20.HandleObserved,
                            HandleObservedRequestIdV20 = request.RequestId,
                            UpdatedAtUtc = DateTimeOffset.UtcNow
                        }, token).ConfigureAwait(false);
                        return StageV20WireResult.HandleLifetimeObserved;

                    default:
                        throw StagedRequestRefusal.Create("Unknown v20 attachment operation.");
                }
            }
        }
        finally { _gate.Release(); }
    }

    private async Task BeginAttachmentRetirementCoreAsync(TransferJournalEntry current,
        StagedAttachmentRequestV20 request, StagedDiscardKind discardKind,
        StagedAttachmentStateV20 pendingState, CancellationToken token)
    {
        IReadOnlyList<TransferJournalStateChange> history = AppendState(current, TransferJournalState.DiscardPending);
        await ReplaceAsync(ManifestPath(request.Version.TransferId), current with
        {
            State = TransferJournalState.DiscardPending,
            StateHistory = history,
            AttachmentStateV20 = pendingState,
            RetireRequestIdV20 = request.RequestId,
            DiscardReservationId = current.Transfer.TransferId,
            DiscardKind = discardKind,
            DiscardRequestedAtUtc = DateTimeOffset.UtcNow,
            DiscardAcknowledgedAtUtc = null,
            UpdatedAtUtc = history[^1].OccurredAtUtc
        }, token).ConfigureAwait(false);
    }

    private static uint? ResolveAttachmentReplay(TransferJournalEntry entry,
        StagedAttachmentRequestV20 request)
    {
        if (request.Operation == 12 && entry.AttachPrepareRequestIdV20 == request.RequestId)
            return StageV20WireResult.AttachPrepared;
        if (request.Operation == 13 && entry.AttachCommitRequestIdV20 == request.RequestId)
            return entry.AttachCommitResultV20;
        if (request.Operation == 14 && entry.AttachAbortRequestIdV20 == request.RequestId)
            return StageV20WireResult.AttachAborted;
        if (request.Operation == 15 && entry.CompletionPermitRequestIdV20 == request.RequestId)
        {
            StagedSeedCompletion.Require(entry);
            return StageV20WireResult.CompletionPermitted;
        }
        if (request.Operation == 16 && entry.RetireRequestIdV20 == request.RequestId &&
            entry.AttachmentStateV20 == StagedAttachmentStateV20.RetiredUnexposed &&
            entry.DiscardAcknowledgedAtUtc is not null)
            return StageV20WireResult.AttachRetiredUnexposed;
        if (request.Operation == 18 && entry.RetireRequestIdV20 == request.RequestId &&
            entry.AttachmentStateV20 == StagedAttachmentStateV20.RetiredAttachedPrivate &&
            entry.DiscardAcknowledgedAtUtc is not null)
            return StageV20WireResult.AttachRetiredPrivate;
        if (request.Operation == 19 && entry.HandleObservedRequestIdV20 == request.RequestId)
            return StageV20WireResult.HandleLifetimeObserved;
        return null;
    }

    // Caller holds _gate. This records intent only; physical deletion is kept
    // on the bounded background worker so the filter-port dispatcher remains
    // available to allocate a successor.
    private async Task<StagedDiscardStatus> BeginOrValidateDiscardCoreAsync(
        TransferJournalEntry current, StagedDiscardRequest request, CancellationToken token)
    {
        bool alreadyPending = current.DiscardRequestedAtUtc is not null;
        if (alreadyPending && (current.DiscardReservationId != request.ReservationId ||
            current.DiscardKind != request.Kind))
            throw new IOException("A different exact cleanup request already owns this stage.");

        if (request.Kind is StagedDiscardKind.PrivateVersion or StagedDiscardKind.UnattachedAllocation or
            StagedDiscardKind.RetireUnexposed or StagedDiscardKind.RetireAttachedPrivate)
        {
            if (request.Kind == StagedDiscardKind.UnattachedAllocation &&
                current.ParentVersionIdentity is { } parentIdentity)
            {
                TransferJournalEntry parent = await ReadCoreAsync(parentIdentity.TransferId, token)
                    .ConfigureAwait(false);
                if (VersionIdentity(parent) != parentIdentity)
                    throw new IOException("The unattached allocation lost its exact predecessor identity.");
                if (parent.DiscardKind == StagedDiscardKind.EmptyHeldPredecessor &&
                    parent.DiscardReservationId == current.Transfer.TransferId &&
                    parent.DiscardRequestedAtUtc is not null)
                    throw new IOException("The parent cleanup already committed the attached-child disposition.");
            }
            if (current.State == TransferJournalState.DiscardPending)
            {
                if (!alreadyPending || current.DiscardKind != request.Kind)
                    throw new IOException("The private version has a different pending disposition.");
                return current.DiscardAcknowledgedAtUtc is null
                    ? StagedDiscardStatus.Pending : StagedDiscardStatus.Acknowledged;
            }
            if (alreadyPending ||
                (current.CreateReservationId is { } expectedReservation &&
                    expectedReservation != request.ReservationId) ||
                (current.CreateReservationId is null && request.ReservationId != current.Transfer.TransferId))
                throw new IOException("The private delete reservation does not match this allocation.");
            if (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed or
                    TransferJournalState.SealPending or TransferJournalState.Sealed or
                    TransferJournalState.Retained) || current.StageCleanupStarted || current.StageDeleted ||
                (request.Kind == StagedDiscardKind.UnattachedAllocation &&
                    (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                     current.SealedOnce || current.SealedLength is not null ||
                     current.CreateReservationId != current.Transfer.TransferId ||
                     current.DriverInstanceId is null || request.ReservationId != current.Transfer.TransferId ||
                     current.AttachmentStateV20 is not (StagedAttachmentStateV20.None or
                         StagedAttachmentStateV20.Aborted))) ||
                (request.Kind == StagedDiscardKind.PrivateVersion &&
                    current.AttachmentStateV20 is not (StagedAttachmentStateV20.None or
                        StagedAttachmentStateV20.HandleObserved)) ||
                (request.Kind == StagedDiscardKind.PrivateVersion && current.DriverInstanceId is not null &&
                    current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved) ||
                (request.Kind == StagedDiscardKind.RetireUnexposed &&
                    (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                     current.SealedOnce || current.SealedLength is not null ||
                     current.CreateReservationId != current.Transfer.TransferId ||
                     request.ReservationId != current.Transfer.TransferId ||
                     current.AttachmentStateV20 != StagedAttachmentStateV20.Committed ||
                     current.CompletionPermitRequestIdV20 is not null ||
                     current.RetireRequestIdV20 is null)) ||
                (request.Kind == StagedDiscardKind.RetireAttachedPrivate &&
                    (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) ||
                     current.SealedOnce || current.SealedLength is not null ||
                     current.CreateReservationId != current.Transfer.TransferId ||
                     request.ReservationId != current.Transfer.TransferId ||
                     current.AttachmentStateV20 != StagedAttachmentStateV20.CompletionPermitted ||
                     current.HandleObservedRequestIdV20 is not null || current.RetireRequestIdV20 is null)) ||
                (request.Kind == StagedDiscardKind.RetireUnexposed &&
                    current.AttachmentStateV20 != StagedAttachmentStateV20.RetireUnexposedPending) ||
                (request.Kind == StagedDiscardKind.RetireAttachedPrivate &&
                    current.AttachmentStateV20 != StagedAttachmentStateV20.RetireAttachedPrivatePending))
                throw new IOException("The private version cannot enter DiscardPending.");
            if (request.Kind == StagedDiscardKind.RetireAttachedPrivate)
            {
                using StagedStageFile stage = StagedStageFile.Open(current.Transfer.StagePath);
                if (stage.Identity != request.Version.StageIdentity || stage.Stream.Length != 0)
                    throw new IOException("The attached private stage is not the exact zero-byte object.");
            }
            if (request.Kind == StagedDiscardKind.PrivateVersion &&
                current.AttachmentStateV20 != StagedAttachmentStateV20.None &&
                current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved)
                throw new IOException("An attached version requires the exact handle-lifetime receipt before discard.");
            // Exact retirement is independent of current-name ownership.
            // A later ordinary allocation already has a higher generation;
            // discarding this old identity cannot seal or cancel that child.
            IReadOnlyList<TransferJournalStateChange> history =
                AppendState(current, TransferJournalState.DiscardPending);
            var pending = current with
            {
                State = TransferJournalState.DiscardPending,
                DiscardReservationId = request.ReservationId,
                DiscardKind = request.Kind,
                DiscardRequestedAtUtc = DateTimeOffset.UtcNow,
                DiscardAcknowledgedAtUtc = null,
                UpdatedAtUtc = history.Count == 0 ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc,
                StateHistory = history
            };
            await ReplaceAsync(ManifestPath(request.Version.TransferId), pending, token).ConfigureAwait(false);
            return StagedDiscardStatus.Pending;
        }

        if (current.State != TransferJournalState.LegacyEmptyHeld || current.SealedLength != 0 ||
            current.StageIdentity != request.Version.StageIdentity)
            throw new IOException("Only an exact EmptyHeld stage can be cleaned through this operation.");
        if (current.DriverInstanceId is not null &&
            current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved)
            throw new IOException("A v20 EmptyHeld version needs its exact handle-lifetime receipt before cleanup.");
        if (current.AttachmentStateV20 != StagedAttachmentStateV20.None &&
            current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved)
            throw new IOException("An attached EmptyHeld version requires the exact handle-lifetime receipt.");

        if (request.Kind is StagedDiscardKind.OwnerExitEmpty or StagedDiscardKind.DriverUnloadEmpty)
        {
            if (request.ReservationId != current.Transfer.TransferId)
                throw new IOException("EmptyHeld retirement must be reserved to the exact version.");
            if (!alreadyPending) await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
        }
        else if (request.Kind == StagedDiscardKind.EmptyHeldPredecessor)
        {
            TransferJournalEntry child = await ReadCoreAsync(request.ReservationId, token).ConfigureAwait(false);
            if (child.Transfer.TransferId != request.ReservationId ||
                child.CreateReservationId != request.ReservationId ||
                child.ParentVersionIdentity != request.Version ||
                child.Transfer.DestinationPath != current.Transfer.DestinationPath ||
                !SameWriter(child.Transfer, current.Transfer) ||
                child.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed or
                    TransferJournalState.SealPending or TransferJournalState.Sealed or
                    TransferJournalState.Retained or TransferJournalState.LegacyEmptyHeld or TransferJournalState.Released or
                    TransferJournalState.DiscardPending))
                throw new IOException("The EmptyHeld cleanup reservation has no exact committed child ancestry.");
            if (current.DriverInstanceId is not { } parentDriverInstance || parentDriverInstance == Guid.Empty ||
                child.DriverInstanceId != parentDriverInstance || child.DriverInstanceId == Guid.Empty)
                throw new IOException("The EmptyHeld cleanup chain is missing one exact driver epoch.");
            if (child.DeleteVersionIdentity is { } deletedIdentity)
            {
                if (child.CreateAfterReservationId is not null)
                    throw new IOException("The CREATE_AFTER predecessor must be retired using its V3 reservation.");
                TransferJournalEntry deleted = await ReadCoreAsync(deletedIdentity.TransferId, token)
                    .ConfigureAwait(false);
                if (VersionIdentity(deleted) != deletedIdentity || deleted.ParentVersionIdentity != request.Version ||
                    deleted.DiscardReservationId != deleted.Transfer.TransferId ||
                    deleted.CreateAfterReservationId != request.ReservationId ||
                    deleted.DiscardKind != StagedDiscardKind.PrivateVersion ||
                    deleted.State != TransferJournalState.DiscardPending ||
                    deleted.DiscardAcknowledgedAtUtc is null ||
                    child.AllocationDisposition != 5 ||
                    child.AllocationReferenceId != deleted.Transfer.TransferId ||
                    child.AllocationReferenceKind != 1 || child.DriverInstanceId is null ||
                    child.DriverInstanceId != deleted.DriverInstanceId ||
                    deleted.DriverInstanceId != current.DriverInstanceId ||
                    !SameWriter(deleted.Transfer, child.Transfer))
                    throw new IOException("The EmptyHeld cleanup ancestry does not match the exact deleted version.");
                if (!StagedStageFile.TryConfirmAbsent(deleted.Transfer.StagePath, out Exception? deletedAbsenceFailure))
                    throw new IOException("The exact CREATE_AFTER delete predecessor is not absent.",
                        deletedAbsenceFailure);

                // A successful attached V3 has no discard intent yet. Once a
                // V3 cleanup disposition exists, however, V1 may not retire
                // ahead of that exact terminal ACK and absence proof. This
                // closes out-of-order/replayed V1 kind-2 requests on the
                // failed-attach path.
                if (child.State == TransferJournalState.DiscardPending ||
                    child.DiscardRequestedAtUtc is not null || child.DiscardAcknowledgedAtUtc is not null)
                {
                    bool privateDeleteAck = child.State == TransferJournalState.DiscardPending &&
                        child.DiscardKind is (StagedDiscardKind.UnattachedAllocation or
                            StagedDiscardKind.PrivateVersion or StagedDiscardKind.RetireUnexposed or
                            StagedDiscardKind.RetireAttachedPrivate) &&
                        child.DiscardReservationId == child.Transfer.TransferId &&
                        child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null &&
                        (child.DiscardKind switch
                        {
                            StagedDiscardKind.UnattachedAllocation =>
                                !child.SealedOnce && child.SealedLength is null,
                            StagedDiscardKind.RetireUnexposed =>
                                !child.SealedOnce && child.SealedLength is null &&
                                child.AttachmentStateV20 == StagedAttachmentStateV20.RetiredUnexposed &&
                                child.RetireRequestIdV20 is > 0,
                            StagedDiscardKind.RetireAttachedPrivate =>
                                !child.SealedOnce && child.SealedLength is null &&
                                child.AttachmentStateV20 == StagedAttachmentStateV20.RetiredAttachedPrivate &&
                                child.RetireRequestIdV20 is > 0,
                            _ => true
                        });
                    bool emptyRetirementAck = child.State == TransferJournalState.LegacyEmptyHeld &&
                        child.SealedLength == 0 &&
                        child.DiscardKind is (StagedDiscardKind.OwnerExitEmpty or
                            StagedDiscardKind.DriverUnloadEmpty) &&
                        child.DiscardReservationId == child.Transfer.TransferId &&
                        child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null;
                    if (!privateDeleteAck && !emptyRetirementAck)
                        throw new IOException("The CREATE_AFTER child has no exact terminal cleanup ACK.");
                    if (!StagedStageFile.TryConfirmAbsent(child.Transfer.StagePath,
                            out Exception? childAbsenceFailure))
                        throw new IOException("The exact CREATE_AFTER child is not absent.", childAbsenceFailure);
                }
                else if (child.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved ||
                    child.HandleObservedRequestIdV20 is not > 0 ||
                    child.CompletionPermitRequestIdV20 is not > 0)
                {
                    throw new IOException("The live CREATE_AFTER child has no exact HandleObserved receipt.");
                }
            }
            else
            {
                if (child.CreateAfterReservationId is not null)
                    throw new IOException("A direct cleanup cannot consume a CREATE_AFTER reservation.");
                RequireDirectEmptyHeldChildTerminal(current, child, requireReleasedStageDeleted: false);
            }
            if (!alreadyPending) await RequireCurrentDestinationAsync(child, token).ConfigureAwait(false);
        }

        if (alreadyPending)
            return current.DiscardAcknowledgedAtUtc is null
                ? StagedDiscardStatus.Pending : StagedDiscardStatus.Acknowledged;

        var cleanup = current with
        {
            DiscardReservationId = request.ReservationId,
            DiscardKind = request.Kind,
            DiscardRequestedAtUtc = DateTimeOffset.UtcNow,
            DiscardAcknowledgedAtUtc = null,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        await ReplaceAsync(ManifestPath(request.Version.TransferId), cleanup, token).ConfigureAwait(false);
        return StagedDiscardStatus.Pending;
    }

    /// <summary>Durable cleanup work for the background worker; unacked requests survive restart.</summary>
    public async Task<IReadOnlyList<StagedDiscardRequest>> ReadDiscardPendingAsync(
        CancellationToken cancellationToken)
    {
        var pending = new List<StagedDiscardRequest>();
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            TransferJournalEntry entry;
            try { entry = await ReadScannedAsync(file, id, cancellationToken).ConfigureAwait(false); }
            finally { _gate.Release(); }
            if (entry.DiscardRequestedAtUtc is null || entry.DiscardAcknowledgedAtUtc is not null ||
                entry.DiscardReservationId is not { } reservation || entry.DiscardKind is not { } kind ||
                entry.StageIdentity is not { } identity || entry.DestinationGeneration <= 0)
                continue;
            pending.Add(new StagedDiscardRequest(reservation,
                new StagedVersionIdentity(entry.Transfer.TransferId, entry.DestinationGeneration, identity), kind));
        }
        return pending;
    }

    /// <summary>
    /// Records ACK only when the exact manifest stage path is absent after
    /// identity-qualified deletion. A fabricated success result cannot bypass
    /// this check.
    /// </summary>
    public async Task<StagedDiscardStatus> CompleteDiscardAsync(
        StagedDiscardRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateDiscardRequest(request);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        TransferJournalEntry before;
        try
        {
            before = await ReadCoreAsync(request.Version.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (VersionIdentity(before) != request.Version || before.DiscardReservationId != request.ReservationId ||
                before.DiscardKind != request.Kind || before.DiscardRequestedAtUtc is null ||
                before.PendingRename is not null)
                throw new IOException("The exact durable cleanup request changed before completion.");
            if (request.Kind is (StagedDiscardKind.PrivateVersion or StagedDiscardKind.UnattachedAllocation) &&
                before.State != TransferJournalState.DiscardPending)
                throw new IOException("The private version is no longer terminally pending deletion.");
            if (request.Kind is (StagedDiscardKind.RetireUnexposed or StagedDiscardKind.RetireAttachedPrivate) &&
                before.State != TransferJournalState.DiscardPending)
                throw new IOException("The v20 attachment retirement is no longer terminally pending deletion.");
            if (request.Kind is (StagedDiscardKind.EmptyHeldPredecessor or StagedDiscardKind.OwnerExitEmpty or
                    StagedDiscardKind.DriverUnloadEmpty) &&
                before.State != TransferJournalState.LegacyEmptyHeld)
                throw new IOException("The EmptyHeld cleanup target changed state.");
            await BeginOrValidateDiscardCoreAsync(before, request, cancellationToken).ConfigureAwait(false);
            before = await ReadCoreAsync(request.Version.TransferId, cancellationToken).ConfigureAwait(false);
            if (before.DiscardAcknowledgedAtUtc is not null) return StagedDiscardStatus.Acknowledged;
        }
        finally { _gate.Release(); }

        if (request.Kind == StagedDiscardKind.EmptyHeldPredecessor)
            await RequireReleasedDirectChildDisposedAsync(request, cancellationToken).ConfigureAwait(false);

        // Filesystem deletion may block on an open handle. Never hold the
        // journal gate or filter-port callback while doing it. The handle is
        // no-follow and must still identify the manifest's exact single-link
        // object before Windows marks that handle for deletion.
        long? expectedLength = request.Kind == StagedDiscardKind.RetireAttachedPrivate ? 0 : null;
        if (!StagedStageFile.TryDeleteExactAndConfirmAbsent(before.Transfer.StagePath,
                request.Version.StageIdentity, out Exception? deletionFailure, expectedLength))
            throw new IOException("The exact private stage could not be deleted and verified.", deletionFailure);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(request.Version.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (VersionIdentity(current) != request.Version || current.DiscardReservationId != request.ReservationId ||
                current.DiscardKind != request.Kind || current.DiscardRequestedAtUtc is null ||
                current.PendingRename is not null || current.State != before.State)
                throw new IOException("The exact cleanup disposition changed while removing its stage.");
            await BeginOrValidateDiscardCoreAsync(current, request, cancellationToken).ConfigureAwait(false);
            if (current.DiscardAcknowledgedAtUtc is not null) return StagedDiscardStatus.Acknowledged;
            if (!StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out Exception? absenceFailure))
                throw new IOException("The stage path is not confirmed absent after cleanup.", absenceFailure);
            StagedAttachmentStateV20 attachmentState = request.Kind switch
            {
                StagedDiscardKind.RetireUnexposed => StagedAttachmentStateV20.RetiredUnexposed,
                StagedDiscardKind.RetireAttachedPrivate => StagedAttachmentStateV20.RetiredAttachedPrivate,
                _ => current.AttachmentStateV20
            };
            var acknowledged = current with
            {
                AttachmentStateV20 = attachmentState,
                DiscardAcknowledgedAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(request.Version.TransferId), acknowledged, cancellationToken)
                .ConfigureAwait(false);
            return StagedDiscardStatus.Acknowledged;
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> ReadAsync(Guid transferId, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await ReadCoreAsync(transferId, cancellationToken).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    // Internal callers already hold _gate. Readers and replacement must not
    // race the brief interval before the renamed write handle closes.
    private async Task<TransferJournalEntry> ReadCoreAsync(
        Guid transferId, CancellationToken cancellationToken)
    {
        using var phaseTiming = StagedRequestTiming.Measure("journal-scan");
        var entry = await ReadManifestCoreAsync(transferId, cancellationToken).ConfigureAwait(false);
        var child = entry;
        // Keep only one edge in memory. Strictly decreasing captured generations
        // exclude cycles without recursive calls or an unbounded ancestry cache.
        while (child.BoundAllocation is not null &&
            child.SeedProvenance is { Origin: StagedSeedOrigin.PrivatePredecessor } seed)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TransferJournalEntry parent;
            try { parent = await ReadManifestCoreAsync(seed.Predecessor!.TransferId, cancellationToken).ConfigureAwait(false); }
            catch (IOException error) when (error is FileNotFoundException or DirectoryNotFoundException)
            {
                // A missing committed ancestor must not look like a missing
                // allocation to the orphan-backing deletion path.
                throw new InvalidDataException("writer_metadata_seed_predecessor_missing", error);
            }
            if (parent.BoundAllocation is null || parent.SeedProvenance is null ||
                VersionIdentity(parent) != seed.Predecessor ||
                parent.DriverInstanceId != child.DriverInstanceId ||
                parent.BoundAllocation.Destination != seed.AllocationBinding!.Destination ||
                seed != StagedSeedProvenance.Inherit(child with
                {
                    BoundAllocation = seed.AllocationBinding,
                    DestinationGeneration = seed.Allocation.DestinationGeneration
                }, parent))
                throw new InvalidDataException("writer_metadata_seed_lineage_mismatch");
            child = parent;
        }
        return entry;
    }

    private async Task<TransferJournalEntry> ReadManifestCoreAsync(
        Guid transferId, CancellationToken cancellationToken)
    {
        string path = ManifestPath(transferId);
        Interlocked.Increment(ref _manifestReads);
        await using var stream = StagedJournalFile.Open(path);
        if (_owner is not null)
        {
            var security = stream.GetAccessControl();
            if (_owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                RequireTrustedOwner(security, "journal manifest");
            RequireNoUntrustedWriters(security, _owner);
        }
        TransferJournalEntry? entry;
        try
        {
            entry = await JsonSerializer.DeserializeAsync<TransferJournalEntry>(
                stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException error) { throw new InvalidDataException("The transfer manifest is invalid JSON.", error); }
        ValidateEntry(entry, transferId);
        if (entry!.AllocationSecurity is not null)
        {
            var security = await ReadAllocationSecurityCoreAsync(entry, cancellationToken).ConfigureAwait(false);
            security.RequireWriterMetadata(OriginalAllocationSecurityBinding(entry), entry.Transfer);
            security.RequireCapturedSeedProvenance(entry);
        }
        if (entry!.SeedProvenance is { SourceSecurity: not null, SourceBinding: not null } seed)
        {
            var sourceSecurity = await ReadAllocationSecurityCoreAsync(entry with
                { AllocationSecurity = seed.SourceSecurity, BoundAllocation = seed.SourceBinding }, cancellationToken, seed.SourceBinding)
                .ConfigureAwait(false);
            if (sourceSecurity.WriterMetadataEnvelopeHex is not null && seed.ExportEvidence !=
                sourceSecurity.CapturedSeedEvidence())
                throw new InvalidDataException("writer_metadata_export_mismatch");
        }
        return entry!;
    }

    private static ManifestStamp StampOf(FileInfo file) => new(file.Length,
        file.LastWriteTimeUtc.Ticks, file.CreationTimeUtc.Ticks, file.Attributes);

    // Caller holds _gate. The stamp is taken from the enumeration BEFORE the read: if the manifest changes in between,
    // the cached stamp is older than the content and the next scan simply reads again.
    private async Task<TransferJournalEntry> ReadScannedAsync(
        FileInfo file, Guid id, CancellationToken token, bool pendingProjection = false)
    {
        using var phaseTiming = StagedRequestTiming.Measure("journal-scan");
        ManifestStamp stamp = StampOf(file);
        if ((stamp.Attributes & FileAttributes.ReparsePoint) == 0)
        {
            lock (_scanCache)
            {
                // A bound child's own stamp says nothing about its committed
                // ancestors. Revalidate it for authority and unfinished work.
                // A terminal pending-projection hit only omits dispatch.
                if (_scanCache.TryGetValue(id, out var cached) && cached.Stamp == stamp &&
                    (cached.Entry.BoundAllocation is null || pendingProjection && !PendingDispatchRequired(cached.Entry)))
                {
                    _scanUses.Remove(cached.Use);
                    _scanUses.AddLast(cached.Use);
                    return cached.Entry;
                }
            }
        }
        Interlocked.Increment(ref _scanManifestReads);
        var entry = await ReadCoreAsync(id, token).ConfigureAwait(false);
        lock (_scanCache)
        {
            if (_scanCache.Remove(id, out var prior)) _scanUses.Remove(prior.Use);
            if (_scanCache.Count >= _scanCacheCapacity)
            {
                // Scans walk the full history repeatedly. LRU would evict the
                // next item the scan needs and reread every manifest when the
                // history exceeds capacity. Evict just the most recently used
                // scan entry instead, preserving the rest of the validated
                // history. Authoritative reads still bypass this cache.
                var victim = _scanUses.Last!;
                _scanCache.Remove(victim.Value);
                _scanUses.Remove(victim);
                Interlocked.Increment(ref _scanCacheEvictions);
            }
            var use = _scanUses.AddLast(id);
            _scanCache[id] = (stamp, entry, use);
        }
        return entry;
    }

    private void ForgetScanned(Guid id)
    {
        lock (_scanCache)
        {
            if (_scanCache.Remove(id, out var entry)) _scanUses.Remove(entry.Use);
        }
    }

    private static void ValidateEntry(TransferJournalEntry? entry, Guid id)
    {
        if (id == Guid.Empty || entry?.Transfer is not { } transfer || transfer.TransferId != id ||
            !Enum.IsDefined(entry.State) || !Enum.IsDefined(transfer.Destination) ||
            transfer.ProcessId <= 0 || string.IsNullOrWhiteSpace(transfer.ProcessName) ||
            transfer.ProcessName.Length > 63 || entry.DestinationGeneration < 0 ||
            entry.BlockedPolicyVersion < 0 ||
            (entry.BlockedInspectionFailure is { } failure && !Enum.IsDefined(failure)) ||
            (entry.State == TransferJournalState.Blocked && entry.BlockedPolicyVersion <= 0 &&
                transfer.RequestorSid is not null) ||
            entry.UpdatedAtUtc == default ||
            (transfer.RequestorSid is { } requestorSid &&
                (requestorSid.Length > 184 || !requestorSid.StartsWith("S-", StringComparison.OrdinalIgnoreCase) ||
                 requestorSid.Any(char.IsWhiteSpace))) ||
            (transfer.RequestorProcessCreationTime is <= 0))
            throw new InvalidDataException("The transfer manifest has invalid identity or state.");
        if (entry.AllocationExtensionVersion is not null || entry.BoundAllocation is not null || entry.AllocationSecurity is not null)
        {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            if (entry.AllocationExtensionVersion != 23 || entry.BoundAllocation is not { } bound)
                throw new InvalidDataException("The bound allocation marker and descriptor must agree.");
            // Pre-provenance bound manifests have none of these three fields.
            // Read them for restricted recovery; StagedSeedExport keeps them
            // Unproven. Once any seed/security evidence exists, absent required
            // fields are corruption, never a downgrade to that legacy case.
            if ((entry.AllocationSecurity is not null || entry.SeedProvenance is not null || entry.SeedCompletion is not null) &&
                (entry.AllocationSecurity is null || entry.SeedProvenance is null))
                throw new InvalidDataException("writer_metadata_seed_provenance_missing");
            bound.Validate();
            entry.AllocationSecurity?.Validate();
            if (bound.ReservationId != id || entry.CreateReservationId != id ||
                entry.DriverInstanceId != bound.DriverInstanceId ||
                entry.AllocationDisposition != bound.Disposition ||
                entry.AllocationReferenceKind != bound.ReferenceKind ||
                entry.AllocationReferenceId != (bound.ParentTransferId == Guid.Empty ? null : bound.ParentTransferId) ||
                entry.ParentDirectoryIdentity != bound.Parent || entry.DestinationGeneration <= 0 || entry.StageIdentity is null ||
                !bound.Destination.LeafEquals(Path.GetFileName(transfer.DestinationPath)))
                throw new InvalidDataException("The bound allocation manifest lost its exact committed tuple.");
#else
            throw new InvalidDataException("This build cannot recover or publish bound allocation manifests.");
#endif
        }
        entry.SeedProvenance?.Validate(entry);
        if (entry.SeedCompletion is { } completion && (entry.SeedProvenance is null ||
            completion.Allocation != entry.SeedProvenance.Allocation || completion.Length < 0))
            throw new InvalidDataException("Invalid seed completion receipt.");
        RequireManifestPath(transfer.StagePath);
        RequireManifestPath(transfer.DestinationPath);
        if (entry.Sha256Hex is not null && (entry.Sha256Hex.Length != 64 || !entry.Sha256Hex.All(Uri.IsHexDigit)))
            throw new InvalidDataException("The transfer manifest has an invalid digest.");
        if (entry.UnboundCancellation is { } cancellation &&
            (entry.BoundAllocation is not null || cancellation.OperationId == Guid.Empty ||
             cancellation.Version != VersionIdentity(entry) || cancellation.Generation <= entry.DestinationGeneration ||
             !entry.SealedOnce || entry.PendingRename is not null || entry.State != TransferJournalState.Retained))
            throw new InvalidDataException("Invalid unbound cancellation receipt.");
        bool requiresSeal = entry.State is TransferJournalState.SealPending or TransferJournalState.LegacyEmptyHeld or
            TransferJournalState.Sealed or TransferJournalState.Inspecting or
            TransferJournalState.Approved or TransferJournalState.Publishing or TransferJournalState.Released or
            TransferJournalState.Blocked;
        if ((requiresSeal && !entry.SealedOnce) ||
            (entry.State is TransferJournalState.Allocated or TransferJournalState.Unsealed or TransferJournalState.Discarded &&
                entry.SealedOnce) ||
            (entry.State == TransferJournalState.Discarded && entry.Sha256Hex is not null) ||
            ((entry.State is TransferJournalState.Publishing or TransferJournalState.Released or
                TransferJournalState.Blocked) && entry.Sha256Hex is null))
            throw new InvalidDataException("The transfer manifest has invalid seal/publication evidence.");
        if ((entry.SealedLength is < 0) ||
            (entry.SealedLength == 0 && entry.Sha256Hex is { } emptyDigest &&
                !string.Equals(emptyDigest, EmptySha256Hex, StringComparison.OrdinalIgnoreCase)) ||
            (entry.SealedLength is { } positive && positive > 0 && entry.StageIdentity is null) ||
            (entry.StageIdentity is { } stageIdentity && (stageIdentity.FileIdHigh | stageIdentity.FileIdLow) == 0) ||
            (entry.State == TransferJournalState.SealPending &&
                (entry.SealedLength is not null || entry.StageIdentity is null)) ||
            (entry.State == TransferJournalState.LegacyEmptyHeld &&
                (entry.SealedLength != 0 || entry.StageIdentity is null || entry.Sha256Hex is not null ||
                 entry.BlockedPolicyVersion != 0 || entry.BlockedPolicyFingerprint is not null || entry.BlockedInspectionFailure is not null ||
                 entry.HandbackState != StagedHandbackState.NotAttempted || entry.HandbackPath is not null ||
                 entry.HandbackLength is not null || entry.HandbackFailureReason is not null ||
                 entry.JustificationExpiresAtUtc is not null || entry.JustificationWindowClosed ||
                 entry.StageCleanupStarted || entry.StageDeleted)) ||
            (entry.SealedLength is not null && entry.StageIdentity is null) ||
            (entry.EmptyHeldNotificationAttemptedAtUtc is { } attempt && attempt.Offset != TimeSpan.Zero) ||
            (entry.EmptyHeldNotificationQueuedAtUtc is { } queued && queued.Offset != TimeSpan.Zero) ||
            ((entry.EmptyHeldNotificationAttemptedAtUtc is null) !=
                (entry.EmptyHeldNotificationAttemptedByInstanceId is null)) ||
            ((entry.EmptyHeldNotificationQueuedAtUtc is null) !=
                (entry.EmptyHeldNotificationQueuedByInstanceId is null)) ||
            (entry.EmptyHeldNotificationAttemptedByInstanceId is { } attemptedBy && attemptedBy == Guid.Empty) ||
            (entry.EmptyHeldNotificationQueuedByInstanceId is { } queuedBy && queuedBy == Guid.Empty) ||
            (entry.EmptyHeldNotificationQueuedAtUtc is not null &&
                entry.EmptyHeldNotificationAttemptedAtUtc is null) ||
            (entry.EmptyHeldNotificationQueuedAtUtc is { } queuedAt &&
                entry.EmptyHeldNotificationAttemptedAtUtc is { } attemptedAt && queuedAt < attemptedAt) ||
            (entry.EmptyHeldNotificationQueuedByInstanceId is { } queuedByInstance &&
                entry.EmptyHeldNotificationAttemptedByInstanceId is { } attemptedByInstance &&
                queuedByInstance != attemptedByInstance) ||
            ((entry.EmptyHeldNotificationAttemptedAtUtc is not null ||
                entry.EmptyHeldNotificationQueuedAtUtc is not null) && entry.State != TransferJournalState.LegacyEmptyHeld))
            throw new InvalidDataException("The transfer manifest has invalid measured seal evidence.");
        bool discardPending = entry.State == TransferJournalState.DiscardPending;
        bool emptyCleanup = entry.State == TransferJournalState.LegacyEmptyHeld && entry.DiscardRequestedAtUtc is not null;
        if ((entry.DiscardReservationId is { } discardReservation && discardReservation == Guid.Empty) ||
            (entry.DiscardRequestedAtUtc is { } discardAt && discardAt.Offset != TimeSpan.Zero) ||
            (entry.DiscardAcknowledgedAtUtc is { } acknowledgedAt && acknowledgedAt.Offset != TimeSpan.Zero) ||
            (entry.DiscardAcknowledgedAtUtc is { } ackAt &&
                (entry.DiscardRequestedAtUtc is not { } requestedAt || ackAt < requestedAt)) ||
            (discardPending && (entry.StageIdentity is null || entry.DestinationGeneration <= 0 ||
                entry.DiscardReservationId is null || entry.DiscardKind is not
                    (StagedDiscardKind.PrivateVersion or StagedDiscardKind.UnattachedAllocation or
                     StagedDiscardKind.RetireUnexposed or StagedDiscardKind.RetireAttachedPrivate) ||
                entry.DiscardRequestedAtUtc is null || entry.PendingRename is not null ||
                entry.StageCleanupStarted || entry.StageDeleted)) ||
            (entry.DiscardKind == StagedDiscardKind.UnattachedAllocation &&
                (!discardPending || entry.SealedOnce || entry.SealedLength is not null ||
                 entry.CreateReservationId != entry.Transfer.TransferId ||
                 entry.DiscardReservationId != entry.Transfer.TransferId || entry.DriverInstanceId is null)) ||
            ((entry.DiscardKind is (StagedDiscardKind.RetireUnexposed or
                                    StagedDiscardKind.RetireAttachedPrivate)) &&
                (!discardPending || entry.CreateReservationId != entry.Transfer.TransferId ||
                 entry.DiscardReservationId != entry.Transfer.TransferId || entry.DriverInstanceId is null ||
                 entry.RetireRequestIdV20 is null || entry.SealedOnce || entry.SealedLength is not null)) ||
            (emptyCleanup && (entry.DiscardReservationId is null || entry.DiscardKind is not
                (StagedDiscardKind.EmptyHeldPredecessor or StagedDiscardKind.OwnerExitEmpty or
                 StagedDiscardKind.DriverUnloadEmpty))) ||
            (!discardPending && !emptyCleanup && (entry.DiscardReservationId is not null ||
                entry.DiscardKind is not null || entry.DiscardRequestedAtUtc is not null ||
                entry.DiscardAcknowledgedAtUtc is not null)) ||
            (entry.ParentVersionIdentity is { } parentVersion &&
                (parentVersion.TransferId == Guid.Empty || parentVersion.DestinationGeneration <= 0 ||
                 parentVersion.StageIdentity is null ||
                 (parentVersion.StageIdentity.FileIdHigh | parentVersion.StageIdentity.FileIdLow) == 0)) ||
            (entry.DeleteVersionIdentity is { } deletedVersion &&
                (deletedVersion.TransferId == Guid.Empty || deletedVersion.DestinationGeneration <= 0 ||
                 deletedVersion.StageIdentity is null ||
                 (deletedVersion.StageIdentity.FileIdHigh | deletedVersion.StageIdentity.FileIdLow) == 0 ||
                 entry.CreateReservationId != entry.Transfer.TransferId)) ||
            (entry.CreateReservationId is { } createReservation &&
                (createReservation == Guid.Empty || createReservation != entry.Transfer.TransferId)) ||
            (entry.CreateAfterReservationId is { } afterReservation &&
                (afterReservation == Guid.Empty || afterReservation == entry.Transfer.TransferId ||
                 entry.State != TransferJournalState.DiscardPending ||
                 entry.DiscardKind != StagedDiscardKind.PrivateVersion ||
                 entry.DiscardReservationId != entry.Transfer.TransferId)) ||
            (entry.AllocationReferenceId is { } allocationReference && allocationReference == Guid.Empty) ||
            (entry.AllocationReferenceKind is { } referenceKind && referenceKind > 2) ||
            (entry.DriverInstanceId is { } driverInstance && driverInstance == Guid.Empty) ||
            (entry.AllocationReferenceKind is { } referenceKindValue &&
                ((referenceKindValue == 0) != (entry.AllocationReferenceId is null))) ||
            (entry.AllocationReferenceKind is null && entry.AllocationReferenceId is not null) ||
            ((entry.DriverInstanceId is not null) != (entry.AllocationReferenceKind is not null)) ||
            (entry.ParentDirectoryIdentity is { } parentDirectory &&
                (entry.CreateReservationId is null ||
                 (parentDirectory.FileIdHigh | parentDirectory.FileIdLow) == 0)) ||
            (entry.AllocationDisposition is { } disposition && disposition > 5) ||
                (entry.State == TransferJournalState.LegacyEmptyHeld && entry.DiscardAcknowledgedAtUtc is not null &&
                entry.DiscardRequestedAtUtc is null))
            throw new InvalidDataException("The transfer manifest has invalid exact-version or cleanup evidence.");
        ValidateAttachmentEvidence(entry);
        if (entry.BlockedPolicyFingerprint is { } policyFingerprint && !IsExactDigest(policyFingerprint))
            throw new InvalidDataException("The blocked policy content binding is invalid.");
        if (entry.PendingRename is { } rename)
        {
            RequireManifestPath(rename.DestinationPath);
            if (rename.TransactionId == 0 || rename.SealedVersion != entry.SealedOnce)
                throw new InvalidDataException("The transfer manifest has an invalid pending rename.");
        }
        if (entry.PendingRename is { SourceV20: { } pendingSource } pendingExact)
        {
            ValidateRenameSourceV20(entry, pendingSource);
            RequireManifestPath(pendingExact.SourcePath!);
            if (pendingSource.TransactionId != pendingExact.TransactionId ||
                pendingSource.DestinationPath != pendingExact.DestinationPath ||
                pendingSource.SealedVersion != pendingExact.SealedVersion ||
                pendingSource.Version.DestinationGeneration != entry.DestinationGeneration ||
                pendingExact.SourcePath != entry.Transfer.DestinationPath)
                throw new InvalidDataException("The pending rename lost its exact source evidence.");
        }
        if (entry.LastRenameReceiptV20 is { } receipt)
        {
            ValidateRenameSourceV20(entry, receipt.Source, historical: true);
            RequireHistoricalManifestPath(receipt.SourcePath);
            RequireHistoricalManifestPath(receipt.DestinationPath);
            if (receipt.Source.TransactionId != entry.LastRenameTransactionId ||
                receipt.Source.DestinationPath != entry.LastRenameDestination ||
                receipt.Committed != entry.LastRenameCommitted || receipt.DestinationGeneration <= 0 ||
                receipt.DestinationGeneration != entry.DestinationGeneration ||
                receipt.DestinationPath != entry.Transfer.DestinationPath ||
                receipt.DestinationPath != (receipt.Committed ? receipt.Source.DestinationPath : receipt.SourcePath) ||
                (!receipt.Committed && receipt.DestinationGeneration != receipt.Source.Version.DestinationGeneration) ||
                (receipt.Committed && !HasRenameSourceBarrier(entry, receipt)))
                throw new InvalidDataException("The completed rename lost its exact commit receipt.");
        }
        if (entry.LastRenameDestination is not null) RequireHistoricalManifestPath(entry.LastRenameDestination);
        if ((entry.LastRenameTransactionId == 0 && (entry.LastRenameDestination is not null || entry.LastRenameCommitted)) ||
            (entry.LastRenameTransactionId != 0 && entry.LastRenameDestination is null))
            throw new InvalidDataException("The transfer manifest has invalid completed rename evidence.");
        int count = 0;
        for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
        {
            RequireHistoricalManifestPath(name.DestinationPath);
            if (name.AllocationBindingV23 is { } tombstoneBinding)
            {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                tombstoneBinding.Validate();
                if (!tombstoneBinding.Destination.LeafEquals(Path.GetFileName(name.DestinationPath)) ||
                    tombstoneBinding.DriverInstanceId != entry.DriverInstanceId || entry.BoundAllocation is null)
                    throw new InvalidDataException("The namespace tombstone lost its bound authority.");
#else
                throw new InvalidDataException("This build cannot recover identity-bound namespace tombstones.");
#endif
            }
            // Generations belong to independent destination slots. A source
            // tombstone may be greater than the current target generation.
            if (++count > 16 || name.Generation <= 0)
                throw new InvalidDataException("The transfer manifest has invalid namespace history.");
        }

        if (entry.StateHistory is { Count: > 0 } history)
        {
            if (history.Count > TransferJournalEntry.MaximumStateHistory ||
                history[0].State != TransferJournalState.Allocated ||
                history[^1].State != entry.State)
                throw new InvalidDataException("The transfer manifest has invalid state history.");
            for (int index = 0; index < history.Count; index++)
            {
                TransferJournalStateChange change = history[index];
                if (!Enum.IsDefined(change.State) || change.OccurredAtUtc == default ||
                    change.OccurredAtUtc.Offset != TimeSpan.Zero ||
                    (index > 0 && (change.OccurredAtUtc <= history[index - 1].OccurredAtUtc ||
                        !IsTransitionAllowed(history[index - 1].State, change.State))))
                    throw new InvalidDataException("The transfer manifest has invalid state history.");
            }
        }
        else if (entry.StateHistory is null || entry.StateHistory.Count != 0)
        {
            throw new InvalidDataException("The transfer manifest has invalid state history.");
        }

        if (entry.BlockedDeletionReceipt is not null &&
            (!MatchesBlockedDeletionReceipt(entry) ||
             entry.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
             entry.HandbackState != StagedHandbackState.Verified || !entry.JustificationWindowClosed))
            throw new InvalidDataException("The manifest has mismatched blocked-disposition evidence.");

        if (!Enum.IsDefined(entry.HandbackState))
            throw new InvalidDataException("The transfer manifest has an invalid hand-back state.");
        if (entry.HandbackPath is not null) RequireManifestPath(entry.HandbackPath);
        if (entry.HandbackFailureReason is { Length: > 256 } ||
            (entry.HandbackState == StagedHandbackState.Verified && entry.HandbackPath is null) ||
            (entry.HandbackState != StagedHandbackState.Verified && entry.HandbackPath is not null) ||
            (entry.HandbackLength is < 0) ||
            (entry.HandbackState == StagedHandbackState.Verified && entry.HandbackLength is null &&
                transfer.RequestorSid is not null) ||
            (entry.HandbackState != StagedHandbackState.Verified && entry.HandbackLength is not null) ||
            (entry.HandbackState == StagedHandbackState.Failed && entry.HandbackFailureReason is null) ||
            (entry.HandbackState != StagedHandbackState.Failed && entry.HandbackFailureReason is not null) ||
            (entry.JustificationExpiresAtUtc is { } expiry && expiry.Offset != TimeSpan.Zero) ||
            (entry.HandbackLastAttemptAtUtc is { } handbackAttempt && handbackAttempt.Offset != TimeSpan.Zero) ||
            (entry.StageCleanupStarted && (entry.HandbackState != StagedHandbackState.Verified ||
                !entry.JustificationWindowClosed)) ||
            (entry.StageDeleted && !(
                entry.UnboundCancellation is not null ||
                (entry.State == TransferJournalState.Released &&
                 entry.HandbackState == StagedHandbackState.NotAttempted && entry.SealedOnce &&
                 entry.SealedLength is >= 0 && entry.Sha256Hex is not null && !entry.StageCleanupStarted) ||
                ((entry.State == TransferJournalState.Blocked || entry.State == TransferJournalState.Released) &&
                 entry.HandbackState == StagedHandbackState.Verified && entry.JustificationWindowClosed &&
                 !entry.StageCleanupStarted))))
            throw new InvalidDataException("The transfer manifest has invalid hand-back evidence.");
    }

    private static void ValidateRenameSourceV20(TransferJournalEntry entry, StagedRenameRequestV20 source,
        bool historical = false)
    {
        if (source is null) throw new InvalidDataException("The rename receipt has no source authority.");
        if (historical) RequireHistoricalManifestPath(source.DestinationPath);
        else RequireManifestPath(source.DestinationPath);
        if (source.TransactionId == 0 || source.Version is null ||
            source.Version.TransferId != entry.Transfer.TransferId || source.Version.DestinationGeneration <= 0 ||
            source.Version.StageIdentity != entry.StageIdentity || source.Version.StageIdentity is null ||
            source.DriverInstanceId == Guid.Empty || source.DriverInstanceId != entry.DriverInstanceId ||
            source.ParentDirectoryIdentity is null || source.ParentDirectoryIdentity != entry.ParentDirectoryIdentity ||
            source.ViewGeneration == 0 || source.OwnerProcessId != entry.Transfer.ProcessId ||
            string.IsNullOrWhiteSpace(source.DestinationName) || source.DestinationName.Length > 511 ||
            source.DestinationName.Contains('\0'))
            throw new InvalidDataException("The rename receipt has invalid source authority.");
    }

    private static bool HasRenameSourceBarrier(TransferJournalEntry entry, StagedRenameReceiptV20 receipt)
    {
        for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
            if (name.DestinationPath == receipt.SourcePath &&
                name.Generation == checked(receipt.Source.Version.DestinationGeneration + 1)) return true;
        return false;
    }

    private static void ValidateAttachmentEvidence(TransferJournalEntry entry)
    {
        static bool ValidRequest(ulong? id) => id is null or > 0;
        bool hasLifecycle = entry.AttachmentStateV20 != StagedAttachmentStateV20.None ||
            entry.AttachPrepareRequestIdV20 is not null || entry.AttachCommitRequestIdV20 is not null ||
            entry.AttachCommitResultV20 is not null ||
            entry.AttachAbortRequestIdV20 is not null || entry.CompletionPermitRequestIdV20 is not null ||
            entry.RetireRequestIdV20 is not null || entry.HandleObservedRequestIdV20 is not null;
        if (!Enum.IsDefined(entry.AttachmentStateV20) ||
            (entry.AttachCommitResultV20 is not null && entry.AttachCommitResultV20 is not
                (StageV20WireResult.AttachCommitted or StageV20WireResult.AttachCommitDenied)) ||
            ((entry.AttachCommitRequestIdV20 is null) != (entry.AttachCommitResultV20 is null)) ||
            !ValidRequest(entry.AttachPrepareRequestIdV20) || !ValidRequest(entry.AttachCommitRequestIdV20) ||
            !ValidRequest(entry.AttachAbortRequestIdV20) || !ValidRequest(entry.CompletionPermitRequestIdV20) ||
            !ValidRequest(entry.RetireRequestIdV20) || !ValidRequest(entry.HandleObservedRequestIdV20))
            throw new InvalidDataException("The manifest has malformed v20 attachment receipts.");
        var requestIds = new HashSet<ulong>();
        foreach (ulong? requestId in new[] { entry.AttachPrepareRequestIdV20,
                     entry.AttachCommitRequestIdV20, entry.AttachAbortRequestIdV20,
                     entry.CompletionPermitRequestIdV20, entry.RetireRequestIdV20,
                     entry.HandleObservedRequestIdV20 })
        {
            if (requestId is { } value && !requestIds.Add(value))
                throw new InvalidDataException("The v20 manifest reuses a lifecycle RequestId across phases.");
        }
        if (!hasLifecycle) return;
        if (entry.DriverInstanceId is null || entry.CreateReservationId != entry.Transfer.TransferId ||
            entry.DestinationGeneration <= 0 || entry.StageIdentity is null || entry.ParentDirectoryIdentity is null ||
            entry.ParentDirectoryIdentity.FileIdHigh == 0 && entry.ParentDirectoryIdentity.FileIdLow == 0 ||
            entry.AttachPrepareRequestIdV20 is not > 0)
            throw new InvalidDataException("The v20 attachment receipt has no exact allocation identity.");

        bool hasCommit = entry.AttachCommitRequestIdV20 is > 0;
        bool commitDenied = entry.AttachCommitResultV20 == StageV20WireResult.AttachCommitDenied;
        bool hasAbort = entry.AttachAbortRequestIdV20 is > 0;
        bool hasPermit = entry.CompletionPermitRequestIdV20 is > 0;
        bool hasRetire = entry.RetireRequestIdV20 is > 0;
        bool hasHandle = entry.HandleObservedRequestIdV20 is > 0;
        switch (entry.AttachmentStateV20)
        {
            case StagedAttachmentStateV20.Prepared:
                if (hasCommit || hasAbort || hasPermit || hasRetire || hasHandle)
                    throw new InvalidDataException("Prepared attachment contains a later lifecycle receipt.");
                break;
            case StagedAttachmentStateV20.Committed:
            case StagedAttachmentStateV20.CommitDenied:
                if (!hasCommit || hasAbort || hasPermit || hasRetire || hasHandle)
                    throw new InvalidDataException("The commit receipt order is invalid.");
                if ((entry.AttachmentStateV20 == StagedAttachmentStateV20.CommitDenied) != commitDenied)
                    throw new InvalidDataException("The commit result disagrees with the attachment state.");
                break;
            case StagedAttachmentStateV20.Aborted:
                if (hasPermit || hasRetire || hasHandle || !hasAbort ||
                    (hasCommit && !commitDenied) ||
                    entry.State != TransferJournalState.DiscardPending ||
                    entry.DiscardKind != StagedDiscardKind.UnattachedAllocation ||
                    entry.DiscardReservationId != entry.Transfer.TransferId)
                    throw new InvalidDataException("The abort receipt is not bound to exact unattached cleanup.");
                break;
            case StagedAttachmentStateV20.CompletionPermitted:
                if (!hasCommit || commitDenied || hasAbort || !hasPermit || hasRetire || hasHandle)
                    throw new InvalidDataException("The completion-permission receipt order is invalid.");
                break;
            case StagedAttachmentStateV20.HandleObserved:
                if (!hasCommit || commitDenied || hasAbort || !hasPermit || hasRetire || !hasHandle)
                    throw new InvalidDataException("The handle-lifetime receipt order is invalid.");
                break;
            case StagedAttachmentStateV20.RetireUnexposedPending:
            case StagedAttachmentStateV20.RetiredUnexposed:
                if (!hasCommit || commitDenied || hasPermit || hasAbort || !hasRetire || hasHandle ||
                    entry.DiscardKind != StagedDiscardKind.RetireUnexposed ||
                    entry.DiscardReservationId != entry.Transfer.TransferId ||
                    entry.State != TransferJournalState.DiscardPending ||
                    entry.SealedOnce || entry.SealedLength is not null ||
                    (entry.AttachmentStateV20 == StagedAttachmentStateV20.RetiredUnexposed) !=
                        (entry.DiscardAcknowledgedAtUtc is not null))
                    throw new InvalidDataException("The unexposed retirement receipt is invalid.");
                break;
            case StagedAttachmentStateV20.RetireAttachedPrivatePending:
            case StagedAttachmentStateV20.RetiredAttachedPrivate:
                if (!hasCommit || commitDenied || !hasPermit || hasAbort || !hasRetire || hasHandle ||
                    entry.DiscardKind != StagedDiscardKind.RetireAttachedPrivate ||
                    entry.DiscardReservationId != entry.Transfer.TransferId ||
                    entry.State != TransferJournalState.DiscardPending ||
                    entry.SealedOnce || entry.SealedLength is not null ||
                    (entry.AttachmentStateV20 == StagedAttachmentStateV20.RetiredAttachedPrivate) !=
                        (entry.DiscardAcknowledgedAtUtc is not null))
                    throw new InvalidDataException("The attached-private retirement receipt is invalid.");
                break;
            default:
                throw new InvalidDataException("Unknown v20 attachment state.");
        }
    }

    private static void RequireManifestPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 511 || !Path.IsPathFullyQualified(path) ||
            string.IsNullOrEmpty(Path.GetFileName(path)))
            throw new InvalidDataException("The transfer manifest has an invalid path.");
        try
        {
            if (!string.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The transfer manifest path is not normalized.");
        }
        catch (ArgumentException error) { throw new InvalidDataException("The transfer manifest has an invalid path.", error); }
    }

    // Historical names are namespace barriers, not live object locators. On
    // Windows GetFullPath expands '~' through GetLongPathNameW, probing old or
    // reused names. Validate their canonical spelling without that lookup;
    // authorization/mutation still perform their existing exact object opens.
    internal static void RequireHistoricalManifestPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 511 || path.Contains('\0') ||
            !Path.IsPathFullyQualified(path) || string.IsNullOrEmpty(Path.GetFileName(path)) ||
            (OperatingSystem.IsWindows() && path.Contains('/')))
            throw new InvalidDataException("The historical manifest path is invalid.");
        string root = Path.GetPathRoot(path)!;
        foreach (string component in path[root.Length..].Split(Path.DirectorySeparatorChar))
            if (component.Length == 0 || component is "." or "..")
                throw new InvalidDataException("The historical manifest path is not normalized.");
    }

    internal static void RequireNoUntrustedWriters(FileSystemSecurity security, SecurityIdentifier owner)
    {
        const FileSystemRights mutations = FileSystemRights.Write | FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                (rule.FileSystemRights & mutations) == 0) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (!sid.Equals(owner) && !sid.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
                !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                throw new UnauthorizedAccessException("Journal object grants mutation rights to an untrusted identity.");
        }
    }

    public async Task<TransferJournalEntry> TransitionAsync(
        Guid transferId,
        TransferJournalState expected,
        TransferJournalState next,
        string? sha256Hex,
        CancellationToken cancellationToken,
        StagedTransfer? expectedTransfer = null,
        BlockedTransferEvidence? blockedEvidence = null,
        bool closeJustificationWindow = false,
        long? expectedGeneration = null)
    {
        // Sealed is never a caller-supplied assertion. Legacy callers still
        // pass through this API, but the journal performs the same durable
        // SealPending -> measured classification as SealAsync and ignores any
        // digest/size-like metadata supplied by the caller.
        if (next == TransferJournalState.Sealed)
        {
            TransferJournalEntry before = await ReadAsync(transferId, cancellationToken)
                .ConfigureAwait(false);
            if (before.State != expected || (expectedTransfer is not null && before.Transfer != expectedTransfer))
                throw new InvalidOperationException("The staged version changed before seal classification.");
            if (expected is not (TransferJournalState.Allocated or TransferJournalState.Unsealed))
                throw new InvalidOperationException("Only an unsealed allocation can be classified as sealed.");
            return await SealAsync(transferId, before.Transfer.ProcessId,
                before.Transfer.StagePath, cancellationToken).ConfigureAwait(false);
        }
        if (next == TransferJournalState.LegacyEmptyHeld)
            throw new InvalidOperationException("Journal state 11 is reserved for legacy recovery.");
        if (next == TransferJournalState.DiscardPending)
            throw new InvalidOperationException("DiscardPending can only be written by an exact identity-bound request.");
        if (!IsTransitionAllowed(expected, next))
        {
            throw new InvalidOperationException($"Invalid transfer transition: {expected} -> {next}.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(transferId, cancellationToken).ConfigureAwait(false);
            if (current.UnboundCancellation is not null ||
                (expectedGeneration is not null && current.DestinationGeneration != expectedGeneration))
                throw new IOException("The staged version was cancelled or retargeted.");
            if (current.PendingRename is not null)
                throw new IOException("A pending namespace transaction holds this version locally.");
            if (current.BoundAllocation is not null && next == TransferJournalState.Released)
                throw new IOException("Bound Released requires an exact Published head and native receipt.");
            if (current.DriverInstanceId is not null &&
                next is (TransferJournalState.Inspecting or TransferJournalState.Approved or
                    TransferJournalState.Publishing or TransferJournalState.Released or TransferJournalState.Blocked) &&
                current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved)
                throw new IOException("A v20 stage cannot enter inspection or publication before its exact handle-lifetime receipt.");
            if (next is TransferJournalState.SealPending or TransferJournalState.Inspecting or
                TransferJournalState.Approved or TransferJournalState.Publishing)
                StagedSeedCompletion.Require(current);
            if (next is TransferJournalState.Inspecting or TransferJournalState.Approved or TransferJournalState.Publishing)
                await RequireCurrentDestinationAsync(current, cancellationToken).ConfigureAwait(false);
            if (expectedTransfer is not null && current.Transfer != expectedTransfer)
                throw new InvalidOperationException("The staged namespace changed before inspection.");
            if (current.State != expected)
            {
                throw new InvalidOperationException(
                    $"Transfer {transferId} is {current.State}; expected {expected}.");
            }
            if (next == TransferJournalState.Inspecting &&
                (current.StageCleanupStarted || current.StageDeleted))
                throw new IOException("Staging cleanup has already started.");
            if (expected == TransferJournalState.Blocked && next == TransferJournalState.Inspecting &&
                (current.JustificationWindowClosed || current.HandbackState != StagedHandbackState.Verified ||
                 StagedSeedExport.Failure(current) is not null))
                throw new IOException("The justification window is already closed.");

            // Old prototype manifests can say Retained after recovering an
            // Allocated transfer. Missing SealedOnce deserializes as false;
            // those files must remain local instead of becoming inspectable.
            if (next is (TransferJournalState.Inspecting or TransferJournalState.Approved or
                    TransferJournalState.Publishing or TransferJournalState.Released or TransferJournalState.Blocked) &&
                (!HasMeasuredSeal(current) || !current.SealedOnce))
            {
                throw new InvalidOperationException("Inspection and publication require an exact measured stage length.");
            }

            string? digest = sha256Hex ?? current.Sha256Hex;
            if ((next is TransferJournalState.Publishing or TransferJournalState.Released or
                    TransferJournalState.Blocked) &&
                (digest is null || digest.Length != 64 || !digest.All(Uri.IsHexDigit)))
            {
                throw new InvalidOperationException("Publication and blocked transfers require the sealed content digest.");
            }
            if (next == TransferJournalState.Blocked &&
                (blockedEvidence is null || blockedEvidence.PolicyVersion <= 0))
                throw new InvalidOperationException("A blocked transfer needs a positive policy version.");
            if (blockedEvidence?.InspectionFailure is { } failure && !Enum.IsDefined(failure))
                throw new InvalidOperationException("Invalid blocked inspection failure classification.");
            if (blockedEvidence?.PolicyFingerprint is { } policyFingerprint && !IsExactDigest(policyFingerprint))
                throw new InvalidOperationException("Invalid blocked policy content binding.");

            IReadOnlyList<TransferJournalStateChange> history = next == current.State
                ? current.StateHistory : AppendState(current, next);
            DateTimeOffset updatedAtUtc = next == current.State
                ? current.UpdatedAtUtc : history.Count == 0
                    ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc;
            var updated = current with
            {
                State = next,
                Sha256Hex = digest,
                SealedOnce = current.SealedOnce || next == TransferJournalState.Sealed,
                UpdatedAtUtc = updatedAtUtc,
                StateHistory = history,
                BlockedPolicyVersion = next == TransferJournalState.Blocked
                    ? blockedEvidence?.PolicyVersion ?? throw new InvalidOperationException(
                        "A blocked transfer needs its policy version.")
                    : current.BlockedPolicyVersion,
                BlockedInspectionFailure = next == TransferJournalState.Blocked
                    ? blockedEvidence?.InspectionFailure : current.BlockedInspectionFailure,
                BlockedPolicyFingerprint = next == TransferJournalState.Blocked
                    ? blockedEvidence?.PolicyFingerprint : current.BlockedPolicyFingerprint,
                JustificationExpiresAtUtc = next == TransferJournalState.Blocked
                    ? blockedEvidence?.JustificationExpiresAtUtc
                    : current.JustificationExpiresAtUtc,
                JustificationWindowClosed = next == TransferJournalState.Blocked
                    ? blockedEvidence?.WindowClosed ?? throw new InvalidOperationException(
                        "A blocked transfer needs its justification window state.")
                    : closeJustificationWindow ? true
                    : current.JustificationWindowClosed,
                HandbackState = next == TransferJournalState.Blocked
                    ? StagedHandbackState.NotAttempted : current.HandbackState,
                HandbackPath = next == TransferJournalState.Blocked ? null : current.HandbackPath,
                HandbackLength = next == TransferJournalState.Blocked ? null : current.HandbackLength,
                HandbackFailureReason = next == TransferJournalState.Blocked ? null : current.HandbackFailureReason,
                HandbackLastAttemptAtUtc = next == TransferJournalState.Blocked
                    ? null : current.HandbackLastAttemptAtUtc,
                StageDeleted = next == TransferJournalState.Blocked ? false : current.StageDeleted,
                BlockedDeletionReceipt = next == TransferJournalState.Blocked ? null : current.BlockedDeletionReceipt,
                StageCleanupStarted = next == TransferJournalState.Blocked ? false : current.StageCleanupStarted
            };
            if (next == TransferJournalState.Blocked && (StagedSeedExport.Failure(updated) ?? StagedSeedExport.Failure(current)) is { } seedFailure)
                updated = StagedSeedExport.PrivateBlocked(updated, seedFailure);
            await ReplaceAsync(ManifestPath(transferId), updated, cancellationToken)
                .ConfigureAwait(false);
            if (next == TransferJournalState.Publishing && current.BoundAllocation is null)
                _unboundPublicationAttempts.Add(transferId);
            else _unboundPublicationAttempts.Remove(transferId);
            return updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    // A disconnected kernel may retry after the first durable reply was lost.
    // Acknowledge the same frozen version without resetting inspection or a
    // publication that has already progressed beyond Sealed.
    public async Task<TransferJournalEntry> SealAsync(Guid id, int ownerProcessId,
        string stagePath, CancellationToken token, StagedVersionIdentity? expectedVersion = null)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId ||
                !string.Equals(current.Transfer.StagePath, Path.GetFullPath(stagePath),
                    StringComparison.OrdinalIgnoreCase) || current.PendingRename is not null)
                throw new IOException("The seal does not identify an available version owned by this writer.");
            StagedSeedCompletion.Require(current);
            if (expectedVersion is not null && VersionIdentity(current) != expectedVersion)
                throw new IOException("The exact v19 seal generation or stage identity changed.");
            if (current.DriverInstanceId is not null &&
                current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved)
                throw new IOException("A v20 stage cannot be sealed before its exact handle-lifetime receipt.");
            if (current.StageCleanupStarted || current.StageDeleted)
                throw new IOException("The staged version is being cleaned up or has already been removed.");
            if (current.SealedOnce && (HasMeasuredSeal(current) || current.State == TransferJournalState.LegacyEmptyHeld))
            {
                await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
                if (current.State != TransferJournalState.LegacyEmptyHeld)
                {
                    using StagedStageFile replay = StagedStageFile.Open(current.Transfer.StagePath);
                    if (replay.Identity != current.StageIdentity || replay.Stream.Length != current.SealedLength)
                        throw new IOException("The measured stage identity or length changed before seal replay.");
                }
                return current;
            }
            if (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed or
                    TransferJournalState.SealPending))
                throw new IOException("The version cannot be sealed from its current state.");
            await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
            if (current.State != TransferJournalState.SealPending)
            {
                if (current.StageIdentity is null)
                    throw new IOException("The stage identity was not captured before the writer received the stage.");
                IReadOnlyList<TransferJournalStateChange> history = AppendState(current, TransferJournalState.SealPending);
                current = current with
                {
                    State = TransferJournalState.SealPending,
                    SealedOnce = true,
                    SealedLength = null,
                    Sha256Hex = null,
                    UpdatedAtUtc = history.Count == 0 ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc,
                    StateHistory = history
                };
                await ReplaceAsync(ManifestPath(id), current, token).ConfigureAwait(false);
            }

            // SealPending is durable before the no-follow open. If this process
            // exits at any point below, startup retries this same classification.
            using StagedStageFile stage = StagedStageFile.Open(current.Transfer.StagePath);
            if (current.StageIdentity is null || stage.Identity != current.StageIdentity)
                throw new IOException("The staged file identity changed before seal classification.");
            long length = stage.Stream.Length;
            if (length < 0) throw new IOException("The stage reported an invalid length.");
            await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
            if (stage.Stream.Length != length)
                throw new IOException("The stage length changed during seal measurement.");
            TransferJournalState finalState = TransferJournalState.Sealed;
            IReadOnlyList<TransferJournalStateChange> finalHistory = AppendState(current, finalState);
            var classified = current with
            {
                State = finalState,
                SealedOnce = true,
                SealedLength = length,
                Sha256Hex = length == 0 ? EmptySha256Hex : null,
                UpdatedAtUtc = finalHistory.Count == 0 ? DateTimeOffset.UtcNow : finalHistory[^1].OccurredAtUtc,
                StateHistory = finalHistory
            };
            await ReplaceAsync(ManifestPath(id), classified, token).ConfigureAwait(false);
            return classified;
        }
        finally { _gate.Release(); }
    }

    private static void ValidateDiscardRequest(StagedDiscardRequest request)
    {
        if (request.ReservationId == Guid.Empty || request.Version.TransferId == Guid.Empty ||
            request.Version.DestinationGeneration <= 0 || request.Version.StageIdentity is null ||
            !Enum.IsDefined(request.Kind))
            throw new ArgumentException("The exact discard request is invalid.", nameof(request));
    }

    internal static StagedVersionIdentity VersionIdentity(TransferJournalEntry entry) =>
        new(entry.Transfer.TransferId, entry.DestinationGeneration,
            entry.StageIdentity ?? throw new IOException("The journal has no captured stage identity."));

    private static bool SameWriter(StagedTransfer left, StagedTransfer right) =>
        left.ProcessId == right.ProcessId && left.SessionId == right.SessionId &&
        string.Equals(left.RequestorSid, right.RequestorSid, StringComparison.OrdinalIgnoreCase) &&
        left.RequestorProcessCreationTime == right.RequestorProcessCreationTime;

    private static void RequireFollowupOwner(TransferJournalEntry parent, StagedTransfer child)
    {
        if (!SameWriter(parent.Transfer, child) ||
            !string.Equals(parent.Transfer.DestinationPath, child.DestinationPath,
                StringComparison.OrdinalIgnoreCase) || parent.Transfer.Destination != child.Destination)
            throw new IOException("The followup predecessor does not belong to this writer and destination.");
    }

    private static bool MatchesCreateAfterRequest(TransferJournalEntry entry, StagedTransfer child,
        StagedCreateAfterDiscardRequest request) =>
        entry.Transfer == child && entry.CreateReservationId == request.ReservationId &&
        entry.DeleteVersionIdentity == request.DeleteVersion &&
        entry.ParentDirectoryIdentity == request.ParentDirectoryIdentity &&
        entry.AllocationDisposition == request.Disposition &&
        entry.DriverInstanceId == request.DriverInstanceId &&
        entry.AllocationReferenceId == (request.DriverInstanceId is null
            ? null : request.DeleteVersion.TransferId) &&
        entry.AllocationReferenceKind == (request.DriverInstanceId is null ? null : 1u) &&
        entry.State == TransferJournalState.Allocated;

    private static bool PathExists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    /// <summary>
    /// Migrates reserved journal state 11 only after exact retirement/epoch
    /// reconciliation and a fresh no-follow, locked measurement. Ambiguous
    /// legacy entries stay private; the historical zero length is no approval.
    /// </summary>
    public async Task<TransferJournalEntry> TryMigrateLegacyEmptyAsync(Guid id, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.State != TransferJournalState.LegacyEmptyHeld) return current;
            StagedSeedCompletion.Require(current);
            if (!current.SealedOnce || current.StageIdentity is null || current.PendingRename is not null ||
                current.DiscardReservationId is not null || current.DiscardKind is not null ||
                current.DiscardRequestedAtUtc is not null || current.DiscardAcknowledgedAtUtc is not null ||
                current.StageCleanupStarted || current.StageDeleted || current.ParentVersionIdentity is not null ||
                current.DeleteVersionIdentity is not null ||
                (current.CreateReservationId is { } allocationId && allocationId != id) ||
                current.CreateAfterReservationId is not null || current.AllocationReferenceId is not null ||
                current.RetireRequestIdV20 is not null ||
                current.DriverInstanceId is not { } driver ||
                current.AttachmentStateV20 != StagedAttachmentStateV20.HandleObserved ||
                current.HandleObservedRequestIdV20 is not > 0 ||
                !await IsCurrentDestinationAsync(current, token).ConfigureAwait(false))
                return current;
            DriverEpochRecord? epoch = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
            if (epoch is null || epoch.DriverInstanceId != driver || epoch.DrainNonce is not null) return current;
            foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
            {
                token.ThrowIfCancellationRequested();
                if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid childId))
                    throw new InvalidDataException("Unexpected legacy journal filename.");
                if (childId == id) continue;
                TransferJournalEntry child = await ReadScannedAsync(file, childId, token).ConfigureAwait(false);
                if (child.ParentVersionIdentity?.TransferId == id || child.DeleteVersionIdentity?.TransferId == id ||
                    child.AllocationReferenceId == id) return current;
            }
            using StagedStageFile stage = StagedStageFile.Open(current.Transfer.StagePath);
            if (stage.Identity != current.StageIdentity)
                throw new IOException("Legacy empty stage identity changed before migration.");
            long length = stage.Stream.Length;
            string digest = Convert.ToHexString(await SHA256.HashDataAsync(stage.Stream, token).ConfigureAwait(false));
            if (length < 0 || stage.Stream.Length != length)
                throw new IOException("Legacy stage length changed during migration.");
            await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
            IReadOnlyList<TransferJournalStateChange> history = AppendState(current, TransferJournalState.Sealed);
            TransferJournalEntry migrated = current with
            {
                State = TransferJournalState.Sealed,
                SealedLength = length,
                Sha256Hex = digest,
                EmptyHeldNotificationAttemptedAtUtc = null,
                EmptyHeldNotificationAttemptedByInstanceId = null,
                EmptyHeldNotificationQueuedAtUtc = null,
                EmptyHeldNotificationQueuedByInstanceId = null,
                UpdatedAtUtc = history.Count == 0 ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc,
                StateHistory = history
            };
            await ReplaceAsync(ManifestPath(id), migrated, token).ConfigureAwait(false);
            return migrated;
        }
        finally { _gate.Release(); }
    }

    private static bool HasMeasuredSeal(TransferJournalEntry entry) =>
        entry.SealedOnce && entry.SealedLength is >= 0 && entry.StageIdentity is not null;

    /// <summary>
    /// T5: the writer deleted its private version (disposition or delete-on-close on its staged handle) before the version was
    /// sealed. The version becomes Discarded: it is never inspected or published, and it keeps its destination generation, so an
    /// older version of the name (sealed before the delete) can never be approved or published after it. Idempotent for a
    /// retried request; a sealed version cannot be discarded (a delete after the seal creates a newer version instead).
    /// </summary>
    public async Task<TransferJournalEntry> DiscardAsync(Guid id, int ownerProcessId,
        string stagePath, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId ||
                !string.Equals(current.Transfer.StagePath, Path.GetFullPath(stagePath),
                    StringComparison.OrdinalIgnoreCase) || current.PendingRename is not null)
                throw new IOException("The discard does not identify an available version owned by this writer.");
            if (current.State == TransferJournalState.Discarded) return current;
            if (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed) || current.SealedOnce)
                throw new IOException("Only a version that was never sealed can be discarded.");
            IReadOnlyList<TransferJournalStateChange> history =
                AppendState(current, TransferJournalState.Discarded);
            var updated = current with
            {
                State = TransferJournalState.Discarded,
                UpdatedAtUtc = history.Count == 0 ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc,
                StateHistory = history
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Discarded versions whose stage file is still on disk, for removal when the service starts.</summary>
    public async Task<IReadOnlyList<TransferJournalEntry>> ReadDiscardedWithStageAsync(CancellationToken cancellationToken)
    {
        var entries = new List<TransferJournalEntry>();
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
            TransferJournalEntry entry;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { entry = await ReadScannedAsync(file, id, cancellationToken).ConfigureAwait(false); }
            finally { _gate.Release(); }
            if (entry.State == TransferJournalState.Discarded &&
                !StagedStageFile.TryConfirmAbsent(entry.Transfer.StagePath, out _))
                entries.Add(entry);
        }
        return entries;
    }

    public async Task<TransferJournalEntry> PrepareRenameAsync(Guid id, ulong transactionId,
        int ownerProcessId, string destination, bool sealedVersion, CancellationToken token,
        StagedRenameRequestV20? exactRequest = null)
    {
        if (transactionId == 0) throw new ArgumentOutOfRangeException(nameof(transactionId));
        destination = Path.GetFullPath(destination);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId)
                throw StagedRequestRefusal.Create("The staged version belongs to another writer.");
            if (current.DriverInstanceId is not null && current.AttachmentStateV20 is not
                    (StagedAttachmentStateV20.CompletionPermitted or StagedAttachmentStateV20.HandleObserved))
                throw StagedRequestRefusal.Create("A v20 rename requires a completed attachment transaction.");
            if (current.StageCleanupStarted || current.StageDeleted)
                throw StagedRequestRefusal.Create("The staged version is being cleaned up or has already been removed.");
            if (current.State == TransferJournalState.SealPending)
                throw StagedRequestRefusal.Create("A seal classification is pending recovery.");
            if (current.DriverInstanceId is not null || exactRequest is not null)
                await RequireRenameSourceV20Async(current, exactRequest, transactionId,
                    ownerProcessId, destination, sealedVersion, token).ConfigureAwait(false);
            var pending = new StagedRename(transactionId, destination, sealedVersion)
            {
                SourceV20 = exactRequest,
                SourcePath = exactRequest is null ? null : current.Transfer.DestinationPath
            };
            if (current.PendingRename == pending) return current;
            if (current.UnboundCancellation is not null || _unboundCommitted.Contains(id) ||
                current.State == TransferJournalState.Released ||
                current.State == TransferJournalState.Publishing && !_unboundPublicationAttempts.Contains(id) ||
                current.PendingRename is not null || current.LastRenameTransactionId == transactionId ||
                current.BoundAllocation is not null && current.State is (TransferJournalState.Inspecting or
                    TransferJournalState.Approved or TransferJournalState.Publishing) ||
                (current.State == TransferJournalState.Blocked && !current.JustificationWindowClosed))
                throw StagedRequestRefusal.Create("The staged version is busy.");
            if (sealedVersion != current.SealedOnce)
                throw StagedRequestRefusal.Create("The kernel and journal disagree about the version seal.");
            await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
            int moves = 0;
            for (var name = current.NamespaceTombstones; name is not null; name = name.Previous)
                if (++moves >= 16) throw StagedRequestRefusal.Create("The version's namespace history is full.");
            var targets = await DestinationVersionsAsync(destination, token).ConfigureAwait(false);
            if (targets.Any(e => e.Entry.Transfer.TransferId != id && e.Reserved))
                throw StagedRequestRefusal.Create("The rename destination is busy.");
            var updated = current with
            {
                PendingRename = pending,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> CompleteRenameAsync(Guid id, ulong transactionId,
        int ownerProcessId, string destination, bool commit, CancellationToken token,
        StagedRenameRequestV20? exactRequest = null)
    {
        if (transactionId == 0) throw new ArgumentOutOfRangeException(nameof(transactionId));
        destination = Path.GetFullPath(destination);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId)
                throw StagedRequestRefusal.Create("The namespace transaction belongs to another writer.");
            if (current.DriverInstanceId is not null && current.AttachmentStateV20 is not
                    (StagedAttachmentStateV20.CompletionPermitted or StagedAttachmentStateV20.HandleObserved))
                throw StagedRequestRefusal.Create("A v20 rename requires a completed attachment transaction.");
            if (current.LastRenameTransactionId == transactionId &&
                current.LastRenameDestination == destination && current.LastRenameCommitted == commit)
            {
                // Resolve the durable receipt against its ORIGINAL source tuple
                // before comparing the now-retargeted manifest generation.
                if (current.DriverInstanceId is not null || exactRequest is not null)
                {
                    var receipt = current.LastRenameReceiptV20;
                    if (receipt is null || receipt.Source != exactRequest || receipt.Committed != commit)
                        throw StagedRequestRefusal.Create("The rename replay does not match its exact stored receipt.");
                    await RequireRenameEpochV20Async(receipt.Source.DriverInstanceId, token).ConfigureAwait(false);
                }
                return current; // Reply loss must not retarget or inspect twice.
            }
            var pending = current.PendingRename;
            if (pending is null)
            {
                // An abort after a prepare was refused is a safe no-op. A
                // commit never invents a prepare or authorizes a new path.
                if (!commit && current.LastRenameTransactionId != transactionId)
                {
                    if (current.DriverInstanceId is not null || exactRequest is not null)
                        await RequireRenameSourceV20Async(current, exactRequest, transactionId, ownerProcessId,
                            destination, current.SealedOnce, token).ConfigureAwait(false);
                    return current;
                }
                throw StagedRequestRefusal.Create("No matching prepared namespace transaction.");
            }
            if (pending.TransactionId != transactionId || pending.DestinationPath != destination)
                throw StagedRequestRefusal.Create("The namespace transaction identity or destination changed.");
            if (current.DriverInstanceId is not null || exactRequest is not null)
            {
                if (pending.SourceV20 != exactRequest || pending.SourcePath != current.Transfer.DestinationPath)
                    throw StagedRequestRefusal.Create("The prepared rename source tuple changed.");
                await RequireRenameSourceV20Async(current, exactRequest, transactionId, ownerProcessId,
                    destination, pending.SealedVersion, token).ConfigureAwait(false);
            }
            long generation = current.DestinationGeneration;
            var tombstones = current.NamespaceTombstones;
            if (commit)
            {
                var targets = await DestinationVersionsAsync(destination, token).ConfigureAwait(false);
                generation = checked(targets.Select(e => e.Generation).DefaultIfEmpty(0).Max() + 1);
                // The source barrier and target head commit in ONE manifest.
                // An older source approval cannot resurrect after this move,
                // even after restart or another move of this same version.
                tombstones = new StagedNameTombstone(current.Transfer.DestinationPath,
                    checked(current.DestinationGeneration + 1), tombstones);
            }
            bool preserveEmptyHeld = current.State == TransferJournalState.LegacyEmptyHeld;
            bool emptyHeldPathChanged = commit && preserveEmptyHeld &&
                !string.Equals(current.Transfer.DestinationPath, destination, StringComparison.Ordinal);
            bool stateChanged = commit && pending.SealedVersion && !preserveEmptyHeld &&
                current.State != TransferJournalState.Sealed;
            IReadOnlyList<TransferJournalStateChange> history = stateChanged
                ? AppendState(current, TransferJournalState.Sealed) : current.StateHistory;
            var updated = current with
            {
                Transfer = commit ? current.Transfer with { DestinationPath = destination } : current.Transfer,
                State = commit && pending.SealedVersion && !preserveEmptyHeld
                    ? TransferJournalState.Sealed : current.State,
                Sha256Hex = commit ? null : current.Sha256Hex,
                DestinationGeneration = generation,
                NamespaceTombstones = tombstones,
                PendingRename = null,
                LastRenameTransactionId = transactionId,
                LastRenameDestination = destination,
                LastRenameCommitted = commit,
                LastRenameReceiptV20 = exactRequest is null ? null : new StagedRenameReceiptV20(
                    exactRequest, pending.SourcePath!, commit, commit ? destination : pending.SourcePath!, generation),
                EmptyHeldNotificationAttemptedAtUtc = emptyHeldPathChanged
                    ? null : current.EmptyHeldNotificationAttemptedAtUtc,
                EmptyHeldNotificationAttemptedByInstanceId = emptyHeldPathChanged
                    ? null : current.EmptyHeldNotificationAttemptedByInstanceId,
                EmptyHeldNotificationQueuedAtUtc = emptyHeldPathChanged
                    ? null : current.EmptyHeldNotificationQueuedAtUtc,
                EmptyHeldNotificationQueuedByInstanceId = emptyHeldPathChanged
                    ? null : current.EmptyHeldNotificationQueuedByInstanceId,
                UpdatedAtUtc = stateChanged && history.Count > 0
                    ? history[^1].OccurredAtUtc : DateTimeOffset.UtcNow,
                StateHistory = history
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            if (commit) _unboundPublicationAttempts.Remove(id);
            return updated;
        }
        finally { _gate.Release(); }
    }

    private async Task RequireRenameEpochV20Async(Guid driver, CancellationToken token)
    {
        DriverEpochRecord? epoch = await ReadDriverEpochCoreAsync(token).ConfigureAwait(false);
        if (epoch is null || epoch.DriverInstanceId != driver || epoch.DrainNonce is not null)
            throw StagedRequestRefusal.Create("The rename does not belong to the active v20 epoch.");
    }

    private async Task RequireRenameSourceV20Async(TransferJournalEntry current,
        StagedRenameRequestV20? source, ulong transactionId, int owner, string destination,
        bool sealedVersion, CancellationToken token)
    {
        if (source is null || source.TransactionId != transactionId || source.Version != VersionIdentity(current) ||
            source.DriverInstanceId != current.DriverInstanceId || source.DriverInstanceId == Guid.Empty ||
            source.ParentDirectoryIdentity != current.ParentDirectoryIdentity || source.ViewGeneration == 0 ||
            source.OwnerProcessId != owner || source.OwnerProcessId != current.Transfer.ProcessId ||
            source.DestinationPath != destination || source.SealedVersion != sealedVersion)
            throw StagedRequestRefusal.Create("The rename source does not match the exact version manifest.");
        await RequireRenameEpochV20Async(source.DriverInstanceId, token).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TransferJournalEntry>> ReadPendingAsync(
        CancellationToken cancellationToken)
    {
        var entries = new List<TransferJournalEntry>();
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
            {
                throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
            }

            TransferJournalEntry entry;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            // Terminal snapshots only answer whether to dispatch work. Every
            // live authority/destination scan and direct read retains fresh
            // bound-ancestry validation, even for a completed transfer.
            try { entry = await ReadScannedAsync(file, id, cancellationToken, pendingProjection: true).ConfigureAwait(false); }
            finally { _gate.Release(); }
            if (PendingDispatchRequired(entry))
            {
                entries.Add(entry);
            }
        }

        return entries;
    }

    internal static bool PendingDispatchRequired(TransferJournalEntry entry) =>
        entry.UnboundCancellation is not null ? !entry.StageDeleted :
        entry.PendingRename is not null ||
        !BlockedCleanupComplete(entry) && entry.State is not (TransferJournalState.Released or TransferJournalState.Discarded) ||
        entry.State == TransferJournalState.Released && entry.HandbackState == StagedHandbackState.Verified &&
        entry.JustificationWindowClosed && !entry.StageDeleted;

    /// <summary>
    /// T11 journal compaction: removes manifests whose transfer is finished and cleaned up and last changed before
    /// <paramref name="cutoffUtc"/> (the service passes a time safely before this boot, so no per-boot driver state, such as a
    /// writer's rename tombstone, can still name the transfer). Finished: no pending rename, the stage file is gone, and either
    /// Released (approved, or justified with its stage deleted) or Blocked with the window closed, the hand-back verified and the
    /// stage deleted. A Blocked version whose hand-back failed keeps its stage and is never removed.
    /// The greatest generation for each destination (including rename tombstones) is retained as a compact high-water claim.
    /// Bound claims use the complete destination identity; legacy claims use their pathname comparison rule.
    /// Exact parent/delete/allocation-reference manifests named by a retained entry are retained too, so compaction cannot
    /// reset a destination to generation one or break CREATE_AFTER/tombstone replay ancestry.
    /// </summary>
    public async Task<int> CompactAsync(DateTimeOffset cutoffUtc, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = new List<TransferJournalEntry>();
            foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                    throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
                entries.Add(await ReadCoreAsync(id, cancellationToken).ConfigureAwait(false));
            }
            bool Finished(TransferJournalEntry e) =>
                e.PendingRename is null && e.UpdatedAtUtc < cutoffUtc && !PathExists(e.Transfer.StagePath) &&
                (e.State == TransferJournalState.Discarded ||
                 (e.State == TransferJournalState.DiscardPending && e.DiscardAcknowledgedAtUtc is not null) ||
                 (e.State == TransferJournalState.LegacyEmptyHeld && e.DiscardAcknowledgedAtUtc is not null) ||
                 (e.State == TransferJournalState.Released &&
                  (e.HandbackState == StagedHandbackState.NotAttempted || e.StageDeleted)) ||
                 (e.State == TransferJournalState.Blocked && StagedSeedExport.Failure(e) is null &&
                  e.JustificationWindowClosed && e.StageDeleted &&
                  e.HandbackState == StagedHandbackState.Verified));
            var finished = entries.Where(Finished).Select(e => e.Transfer.TransferId).ToHashSet();
            // Retain the exact manifest, metadata and ancestry until V26 ACK
            // removal or exact private-cancellation cleanup. Normal builds
            // must also retain cancellation owners from a prior feature run.
            await foreach (var head in ReadAllDestinationHeadFilesCoreAsync(cancellationToken).ConfigureAwait(false))
            {
                if (head.PendingCommit is { } pending) finished.Remove(pending.TransferId);
                foreach (var delete in head.Deletes) finished.Remove(delete.Binding.TransferId);
                foreach (var relay in head.PublicRelayReceipts ?? [])
                {
                    finished.Remove(relay.Binding.TransferId);
                    finished.Remove(relay.Original.OpenTransferId);
                }
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                foreach (var attempt in head.PublicationAttempts ?? [])
                    finished.Remove(ReadPublicationRequest(attempt.CreateBase64,
                        SafeUpload.Agent.Minifilter.BoundPublicationPhase.Create).TransferId);
                foreach (var receipt in head.PublicationNativeReceipts ?? [])
                    finished.Remove(ReadPublicationReceipt(receipt).Facts.Create.TransferId);
#endif
                foreach (var cancellation in head.PrivateCancellations ?? [])
                    finished.Remove(cancellation.Version.TransferId);
            }
            var protectedIds = FindCompactionProtectedTransfers(entries, finished, cancellationToken);

            int removed = 0;
            foreach (TransferJournalEntry entry in entries)
            {
                Guid id = entry.Transfer.TransferId;
                if (!finished.Contains(id) || protectedIds.Contains(id)) continue;
                File.Delete(ManifestPath(id));
                ForgetScanned(id);
                removed++;
            }
            await CompactAllocationSecurityCoreAsync(entries.Where(e =>
                    !finished.Contains(e.Transfer.TransferId) || protectedIds.Contains(e.Transfer.TransferId))
                .SelectMany(e => new[] { e.AllocationSecurity?.SnapshotId, e.SeedProvenance?.SourceSecurity?.SnapshotId })
                .OfType<Guid>().ToHashSet(),
                cutoffUtc, cancellationToken).ConfigureAwait(false);
            return removed;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Released (approved and published) entries, for stage disposal when the service starts.</summary>
    public async Task<IReadOnlyList<TransferJournalEntry>> ReadReleasedAsync(CancellationToken cancellationToken)
    {
        var entries = new List<TransferJournalEntry>();
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
            {
                throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
            }

            TransferJournalEntry entry;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { entry = await ReadScannedAsync(file, id, cancellationToken).ConfigureAwait(false); }
            finally { _gate.Release(); }
            if (entry.State == TransferJournalState.Released && entry.PendingRename is null) entries.Add(entry);
        }

        return entries;
    }

    public async Task<TransferJournalEntry> BeginHandbackAttemptAsync(Guid id,
        CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (StagedSeedExport.Failure(current) is { } seedFailure)
            {
                await PersistSeedRestrictionCoreAsync(current, seedFailure, token).ConfigureAwait(false);
                throw new IOException(seedFailure);
            }
            if (current.State != TransferJournalState.Blocked || current.StageCleanupStarted ||
                current.HandbackState == StagedHandbackState.Verified)
                throw new IOException("The blocked version is not available for hand-back.");
            var updated = current with
            {
                HandbackState = StagedHandbackState.Copying,
                HandbackFailureReason = null,
                HandbackLastAttemptAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> CompleteHandbackAsync(Guid id,
        string? verifiedPath, long? verifiedLength, string? failureReason, CancellationToken token)
    {
        bool verified = verifiedPath is not null;
        if (verified == (failureReason is not null) || verified != verifiedLength.HasValue ||
            (verifiedLength is < 0))
            throw new ArgumentException("Supply either a verified path or a failure reason.");
        if (verified) RequireManifestPath(verifiedPath);
        if (failureReason is { Length: > 256 }) failureReason = failureReason[..256];

        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (StagedSeedExport.Failure(current) is { } seedFailure)
            {
                await PersistSeedRestrictionCoreAsync(current, seedFailure, token).ConfigureAwait(false);
                throw new IOException(seedFailure);
            }
            if (current.State != TransferJournalState.Blocked || current.StageCleanupStarted)
                throw new IOException("The blocked version is no longer available for hand-back.");
            var updated = current with
            {
                HandbackState = verified ? StagedHandbackState.Verified : StagedHandbackState.Failed,
                HandbackPath = verifiedPath,
                HandbackLength = verifiedLength,
                HandbackFailureReason = failureReason,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Permanently invalidates a previously verified hand-back after recovery
    /// or cleanup detects a missing, changed, or unlockable returned file.
    /// The closed window and Failed marker prevent automatic recopy loops.
    /// </summary>
    public async Task<(TransferJournalEntry Entry, bool Invalidated)> InvalidateHandbackAsync(Guid id,
        string failureReason, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(failureReason);
        if (failureReason.Length > 256) failureReason = failureReason[..256];
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.State is not (TransferJournalState.Blocked or TransferJournalState.Released))
                throw new IOException("The transfer is not eligible for hand-back invalidation.");
            if (current.BlockedDeletionReceipt is not null || current.HandbackState == StagedHandbackState.Failed)
                return (current, false);
            if (current.HandbackState != StagedHandbackState.Verified)
                throw new IOException("Only a verified hand-back can be invalidated.");
            var updated = current with
            {
                HandbackState = StagedHandbackState.Failed,
                HandbackPath = null,
                HandbackLength = null,
                HandbackFailureReason = failureReason,
                JustificationWindowClosed = true,
                StageCleanupStarted = false,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return (updated, true);
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> CloseJustificationWindowAsync(Guid id,
        DateTimeOffset nowUtc, CancellationToken token, bool force = false)
    {
        if (nowUtc.Offset != TimeSpan.Zero) throw new ArgumentException("Time must be UTC.", nameof(nowUtc));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.State != TransferJournalState.Blocked || current.JustificationWindowClosed ||
                (!force && current.JustificationExpiresAtUtc is { } expiry && expiry > nowUtc)) return current;
            var updated = current with { JustificationWindowClosed = true, UpdatedAtUtc = nowUtc };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> TryBeginStageCleanupAsync(Guid id,
        CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (StagedSeedExport.Failure(current) is { } seedFailure)
                return await PersistSeedRestrictionCoreAsync(current, seedFailure, token).ConfigureAwait(false);
            if (current.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
                current.PendingRename is not null ||
                current.HandbackState != StagedHandbackState.Verified ||
                StagedSeedExport.Failure(current) is not null ||
                !current.JustificationWindowClosed || current.StageDeleted)
                return current;
            if (current.StageCleanupStarted) return current;
            var updated = current with { StageCleanupStarted = true, UpdatedAtUtc = DateTimeOffset.UtcNow };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    // NamespaceTombstones is a chain (newest first), one link per committed rename of this version.
    internal static int CommittedRenameCount(StagedNameTombstone? head)
    {
        int count = 0;
        for (var name = head; name is not null; name = name.Previous) count++;
        return count;
    }

    internal static bool MatchesBlockedDeletionReceipt(TransferJournalEntry entry) =>
        entry.BlockedDeletionReceipt is { Version: { StageIdentity: not null } version } receipt &&
        entry.StageIdentity is not null &&
        version.TransferId == entry.Transfer.TransferId &&
        version.DestinationGeneration == entry.DestinationGeneration &&
        version.StageIdentity == entry.StageIdentity &&
        receipt.CommittedRenames == CommittedRenameCount(entry.NamespaceTombstones) &&
        receipt.Length == entry.SealedLength && receipt.Sha256Hex == entry.Sha256Hex;

    internal static bool BlockedCleanupComplete(TransferJournalEntry entry) =>
        entry.State is (TransferJournalState.Blocked or TransferJournalState.Released) &&
        entry.PendingRename is null && entry.StageDeleted && !entry.StageCleanupStarted &&
        entry.HandbackState == StagedHandbackState.Verified && entry.JustificationWindowClosed &&
        MatchesBlockedDeletionReceipt(entry);

    // Called only after successful disposition on the identity-checked owned
    // handle. A cleanup-start marker alone is never an accepted-delete receipt.
    internal async Task<TransferJournalEntry> RecordBlockedDeletionAsync(Guid id,
        StagedBlockedDeletionReceipt receipt, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            var updated = current with { BlockedDeletionReceipt = receipt };
            if (!current.StageCleanupStarted || current.StageDeleted || current.PendingRename is not null ||
                current.HandbackState != StagedHandbackState.Verified || !current.JustificationWindowClosed ||
                current.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
                StagedSeedExport.Failure(current) is not null || !MatchesBlockedDeletionReceipt(updated))
                throw new IOException("The blocked disposition receipt no longer matches its cleanup intent.");
            if (current.BlockedDeletionReceipt == receipt) return current;
            updated = updated with { UpdatedAtUtc = DateTimeOffset.UtcNow };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> CompleteStageCleanupAsync(Guid id,
        CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
                current.HandbackState != StagedHandbackState.Verified ||
                StagedSeedExport.Failure(current) is not null ||
                !current.JustificationWindowClosed || !current.StageCleanupStarted ||
                !MatchesBlockedDeletionReceipt(current))
                throw new IOException("Staging cleanup prerequisites are not satisfied.");
            if (!StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out Exception? absenceFailure))
                throw new IOException("Staging cleanup cannot be recorded until the path is confirmed absent.",
                    absenceFailure);
            var updated = current with
            {
                StageDeleted = true,
                StageCleanupStarted = false,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Records exact disposal of a normally published stage. This is separate
    /// from publication: the Released state proves approved public bytes, while
    /// StageDeleted proves the captured private stage path was observed absent.
    /// </summary>
    public async Task<TransferJournalEntry> CompleteReleasedStageDisposalAsync(
        StagedVersionIdentity expectedVersion, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(expectedVersion);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            TransferJournalEntry current = await ReadCoreAsync(expectedVersion.TransferId, token)
                .ConfigureAwait(false);
            if (VersionIdentity(current) != expectedVersion || current.State != TransferJournalState.Released ||
                current.PendingRename is not null || current.StageCleanupStarted ||
                current.HandbackState != StagedHandbackState.NotAttempted || !current.SealedOnce ||
                current.SealedLength is not >= 0 || current.Sha256Hex is null)
                throw new IOException("The exact normally released stage is not eligible for disposal ACK.");
            if (!StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out Exception? absenceFailure))
                throw new IOException("The released stage path is not confirmed absent.", absenceFailure);
            if (current.StageDeleted) return current;
            TransferJournalEntry disposed = current with
            {
                StageDeleted = true,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };
            await ReplaceAsync(ManifestPath(expectedVersion.TransferId), disposed, token).ConfigureAwait(false);
            return disposed;
        }
        finally { _gate.Release(); }
    }

    private static IReadOnlyList<TransferJournalStateChange> AppendState(
        TransferJournalEntry current, TransferJournalState next)
    {
        if (current.StateHistory.Count == 0 && current.State != TransferJournalState.Allocated)
            return Array.Empty<TransferJournalStateChange>(); // Preserve empty legacy history without inventing a chain.
        List<TransferJournalStateChange> history = current.StateHistory.Count > 0
            ? current.StateHistory.ToList()
            : [new(current.State, current.UpdatedAtUtc.ToUniversalTime())];
        if (history.Count >= TransferJournalEntry.MaximumStateHistory)
            throw new InvalidOperationException("Transfer state history is full.");
        DateTimeOffset timestamp = DateTimeOffset.UtcNow;
        if (timestamp <= history[^1].OccurredAtUtc) timestamp = history[^1].OccurredAtUtc.AddTicks(1);
        history.Add(new TransferJournalStateChange(next, timestamp));
        return history;
    }

    // Called under _gate. A single flushed manifest both selects a generation
    // and makes it durable; there is no second "head" file to commit atomically.
    // Pending renames reserve both names. Path identity is the bounded NTFS
    // milestone's key; alias/file-ID identity remains a namespace acceptance gate.
    private sealed record DestinationClaim(TransferJournalEntry Entry, long Generation,
        bool Tombstone, bool Reserved);

    private async Task<List<DestinationClaim>> DestinationVersionsAsync(string destination, CancellationToken token)
    {
        using var phaseTiming = StagedRequestTiming.Measure("journal-scan");
        var versions = new List<DestinationClaim>();
        foreach (FileInfo file in new DirectoryInfo(_directory).EnumerateFiles("*.json"))
        {
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file.Name), "N", out Guid id))
                throw new InvalidDataException($"Unexpected journal file: {file.FullName}");
            var entry = await ReadScannedAsync(file, id, token).ConfigureAwait(false);
            bool current = string.Equals(entry.Transfer.DestinationPath, destination, StringComparison.OrdinalIgnoreCase);
            bool pending = string.Equals(entry.PendingRename?.DestinationPath, destination, StringComparison.OrdinalIgnoreCase);
            long generation = current ? entry.DestinationGeneration : -1;
            bool tombstone = false;
            for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
            {
                if (string.Equals(name.DestinationPath, destination, StringComparison.OrdinalIgnoreCase) &&
                    name.Generation > generation)
                {
                    generation = name.Generation;
                    tombstone = true;
                }
            }
            if (generation >= 0 || pending)
                versions.Add(new(entry, Math.Max(0, generation), tombstone,
                    pending || (current && (entry.PendingRename is not null || entry.State == TransferJournalState.Publishing))));
        }
        return versions;
    }

    private static void RequireDirectEmptyHeldChildTerminal(TransferJournalEntry parent,
        TransferJournalEntry child, bool requireReleasedStageDeleted)
    {
        StagedVersionIdentity parentIdentity = VersionIdentity(parent);
        if (parent.State != TransferJournalState.LegacyEmptyHeld || parent.SealedLength != 0 ||
            child.Transfer.TransferId == parent.Transfer.TransferId ||
            child.ParentVersionIdentity != parentIdentity || child.DeleteVersionIdentity is not null ||
            child.CreateAfterReservationId is not null || child.CreateReservationId != child.Transfer.TransferId ||
            parent.DestinationGeneration == long.MaxValue ||
            child.DestinationGeneration != parent.DestinationGeneration + 1 ||
            !string.Equals(child.Transfer.DestinationPath, parent.Transfer.DestinationPath,
                StringComparison.OrdinalIgnoreCase) || child.Transfer.Destination != parent.Transfer.Destination ||
            !SameWriter(parent.Transfer, child.Transfer) || child.DriverInstanceId is null ||
            child.DriverInstanceId != parent.DriverInstanceId || child.AllocationDisposition is null ||
            child.AllocationReferenceKind != 1 ||
            child.AllocationReferenceId != parent.Transfer.TransferId || child.StageIdentity is null ||
            child.StageIdentity == parent.StageIdentity ||
            child.PendingRename is not null)
            throw new IOException("The direct EmptyHeld successor does not match its exact parent allocation.");

        bool privateDeleteAck = child.State == TransferJournalState.DiscardPending &&
            child.DiscardKind == StagedDiscardKind.PrivateVersion &&
            child.DiscardReservationId == child.Transfer.TransferId &&
            child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null;
        bool unattachedDeleteAck = child.State == TransferJournalState.DiscardPending &&
            child.DiscardKind == StagedDiscardKind.UnattachedAllocation &&
            child.DiscardReservationId == child.Transfer.TransferId &&
            child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null &&
            !child.SealedOnce && child.SealedLength is null;
        bool retiredUnexposedAck = child.State == TransferJournalState.DiscardPending &&
            child.DiscardKind == StagedDiscardKind.RetireUnexposed &&
            child.DiscardReservationId == child.Transfer.TransferId &&
            child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null &&
            child.RetireRequestIdV20 is > 0 &&
            child.AttachmentStateV20 == StagedAttachmentStateV20.RetiredUnexposed &&
            !child.SealedOnce && child.SealedLength is null;
        bool retiredAttachedPrivateAck = child.State == TransferJournalState.DiscardPending &&
            child.DiscardKind == StagedDiscardKind.RetireAttachedPrivate &&
            child.DiscardReservationId == child.Transfer.TransferId &&
            child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null &&
            child.RetireRequestIdV20 is > 0 &&
            child.AttachmentStateV20 == StagedAttachmentStateV20.RetiredAttachedPrivate &&
            !child.SealedOnce && child.SealedLength is null;
        bool emptyOwnerExitAck = child.State == TransferJournalState.LegacyEmptyHeld && child.SealedLength == 0 &&
            child.DiscardKind is (StagedDiscardKind.OwnerExitEmpty or StagedDiscardKind.DriverUnloadEmpty) &&
            child.DiscardReservationId == child.Transfer.TransferId &&
            child.DiscardRequestedAtUtc is not null && child.DiscardAcknowledgedAtUtc is not null;
        bool releasedStage = child.State == TransferJournalState.Released && child.SealedOnce &&
            child.SealedLength is >= 0 && child.Sha256Hex is not null && !child.StageCleanupStarted &&
            (child.HandbackState == StagedHandbackState.NotAttempted ||
             (child.HandbackState == StagedHandbackState.Verified && child.JustificationWindowClosed &&
              child.StageDeleted));
        if (!privateDeleteAck && !unattachedDeleteAck && !retiredUnexposedAck &&
            !retiredAttachedPrivateAck && !emptyOwnerExitAck && !releasedStage)
            throw new IOException("The direct EmptyHeld successor is not in a terminal, acknowledged state.");
        if (releasedStage && requireReleasedStageDeleted && !child.StageDeleted)
            throw new IOException("The released direct successor has no durable stage-disposal ACK.");
        if (!releasedStage || child.StageDeleted)
        {
            if (!StagedStageFile.TryConfirmAbsent(child.Transfer.StagePath, out Exception? childAbsenceFailure))
                throw new IOException("The direct EmptyHeld successor path is not confirmed absent.",
                    childAbsenceFailure);
        }
    }

    private async Task RequireReleasedDirectChildDisposedAsync(StagedDiscardRequest request,
        CancellationToken token)
    {
        TransferJournalEntry parent;
        TransferJournalEntry child;
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            parent = await ReadCoreAsync(request.Version.TransferId, token).ConfigureAwait(false);
            child = await ReadCoreAsync(request.ReservationId, token).ConfigureAwait(false);
            if (VersionIdentity(parent) != request.Version || parent.DiscardReservationId != request.ReservationId ||
                parent.DiscardKind != StagedDiscardKind.EmptyHeldPredecessor ||
                parent.DiscardRequestedAtUtc is null || parent.DiscardAcknowledgedAtUtc is not null ||
                child.DeleteVersionIdentity is not null || child.CreateAfterReservationId is not null ||
                child.State != TransferJournalState.Released)
                return;
            RequireDirectEmptyHeldChildTerminal(parent, child, requireReleasedStageDeleted: true);
        }
        finally { _gate.Release(); }

        if (!StagedStageFile.TryConfirmAbsent(child.Transfer.StagePath, out Exception? absenceFailure))
            throw new IOException("The released direct successor has no gate-confirmed absent-stage receipt.",
                absenceFailure);
    }

    private async Task RequireCurrentDestinationAsync(TransferJournalEntry current, CancellationToken token)
    {
        if (!await IsCurrentDestinationAsync(current, token).ConfigureAwait(false))
            throw new IOException("A later save or pending rename supersedes this destination version.");
    }

    private async Task<bool> IsCurrentDestinationAsync(TransferJournalEntry current, CancellationToken token)
    {
        if (current.UnboundCancellation is not null) return false;
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (current.BoundAllocation is { } bound)
        {
            var head = await ReadDestinationHeadCoreAsync(bound.Destination, token).ConfigureAwait(false);
            return head is not null && head.CurrentSaveTransferId == current.Transfer.TransferId &&
                head.CurrentSaveGeneration == current.DestinationGeneration &&
                current.DestinationGeneration > PublicationGenerationFloor(head) &&
                head.PendingCommit is null && current.PendingRename is null;
        }
#endif
        var versions = await DestinationVersionsAsync(current.Transfer.DestinationPath, token).ConfigureAwait(false);
        long generation = versions.Select(e => e.Generation).DefaultIfEmpty(0).Max();
        return current.DestinationGeneration == generation &&
            versions.Count(e => e.Generation == generation) == 1 &&
            !versions.Any(e => e.Generation == generation && e.Tombstone) &&
            !versions.Any(e => e.Entry.Transfer.TransferId != current.Transfer.TransferId && e.Reserved);
    }

    /// <summary>
    /// Validate unresolved legacy publications at startup. A digest match
    /// cannot prove this transfer's rename committed. Without an exact native
    /// receipt, retain Publishing and its destination reservation; the live
    /// recovery dispatcher reports the hold without publishing again.
    /// </summary>
    public async Task ReconcilePublishingAsync(CancellationToken cancellationToken,
        Func<TransferJournalEntry, CancellationToken, Task>? reconcileBound = null)
    {
        foreach (var entry in await ReadPendingAsync(cancellationToken).ConfigureAwait(false))
        {
            if (entry.State != TransferJournalState.Publishing)
            {
                continue;
            }
            if (entry.BoundAllocation is not null)
            {
                if (reconcileBound is null)
                    throw new IOException("Bound publishing recovery requires the anchored head/permit dispatcher.");
                await reconcileBound(entry, cancellationToken).ConfigureAwait(false);
            }

        }
    }

    /// <summary>
    /// A process or service crash leaves no trustworthy final-close signal.
    /// An allocation that was never sealed must not become eligible for
    /// inspection merely because recovery ran. Sealed versions interrupted
    /// during inspection or publication approval can be inspected again.
    /// Publishing is handled separately because a public rename may already
    /// have succeeded, and only its exact receipt can finish the bookkeeping.
    /// </summary>
    public async Task RetainInterruptedAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in await ReadPendingAsync(cancellationToken).ConfigureAwait(false))
        {
            // A surviving driver retries its exact commit/abort. After driver
            // loss there is no evidence of which virtual rename completed:
            // retain both names in the manifest and never infer approval.
            if (entry.PendingRename is not null) continue;
            if (entry.State == TransferJournalState.LegacyEmptyHeld)
            {
                try { await TryMigrateLegacyEmptyAsync(entry.Transfer.TransferId, cancellationToken).ConfigureAwait(false); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    // Missing, replaced or unmeasurable legacy content remains private.
                }
                continue;
            }
            if (entry.State == TransferJournalState.SealPending)
            {
                try
                {
                    await SealAsync(entry.Transfer.TransferId, entry.Transfer.ProcessId,
                        entry.Transfer.StagePath, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    // No exact stage object/length means it remains private and
                    // non-publishable. Keep SealPending for the next restart.
                }
                continue;
            }
            if (entry.State == TransferJournalState.Allocated)
            {
                // CREATE_AFTER has a durable ReservationId and may need to
                // recreate/capture its backing after a crash between the
                // journal-first transaction and the typed reply. Keep that
                // exact intent replayable until the driver acknowledges it.
                if (entry.DeleteVersionIdentity is not null) continue;
                await TransitionAsync(entry.Transfer.TransferId,
                    TransferJournalState.Allocated, TransferJournalState.Unsealed,
                    null, cancellationToken).ConfigureAwait(false);
            }
            else if (entry.State is TransferJournalState.Inspecting or
                     TransferJournalState.Approved)
            {
                await TransitionAsync(entry.Transfer.TransferId,
                    entry.State, TransferJournalState.Retained,
                    null, cancellationToken).ConfigureAwait(false);
            }
            else if (entry.State == TransferJournalState.Sealed && !HasMeasuredSeal(entry))
            {
                // Legacy Sealed manifests have no measured EOF/identity. Retain
                // them; historical state alone is not evidence to inspect.
                await TransitionAsync(entry.Transfer.TransferId, TransferJournalState.Sealed,
                    TransferJournalState.Retained, null, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ReplaceAsync(
        string manifestPath,
        TransferJournalEntry entry,
        CancellationToken cancellationToken)
    {
        using var phaseTiming = StagedRequestTiming.Measure("journal-write");
        ValidateEntry(entry, entry.Transfer.TransferId);
        string temporary = manifestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        string step = "create-temporary";
        bool replacementReturned = false;
        Exception? writeFailure = null;
        string? failureEvidence = null;
        try
        {
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                step = "serialize";
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                if (stream.Length > StagedJournalFile.MaximumManifestBytes)
                    throw new InvalidDataException("Journal manifest exceeds the qualified size bound.");
                step = "replace";
                try
                {
                    _writeObserver?.Invoke(StagedJournalWritePoint.BeforeReplacement, entry);
                    await StagedJournalReplacement.CommitAsync(stream, temporary, manifestPath,
                        cancellationToken).ConfigureAwait(false);
                    replacementReturned = true;
                    _writeObserver?.Invoke(StagedJournalWritePoint.AfterReplacement, entry);
                }
                catch (Exception error) when (error is not InvalidDataException &&
                    error is (IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception))
                {
                    failureEvidence = StagedJournalPersistenceException.CaptureEvidence(stream, manifestPath);
                    throw;
                }
                step = "close-temporary";
            }
        }
        catch (Exception error) when (error is not InvalidDataException &&
            error is (IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception))
        {
            writeFailure = error;
            throw new StagedJournalPersistenceException(manifestPath, temporary, entry,
                step, replacementReturned, error, failureEvidence);
        }
        finally
        {
            // The replacement can have succeeded even when disposal or its
            // caller failed. Never keep a cached pre-write state after an
            // uncertain outcome; the next operation reads the actual file.
            ForgetScanned(entry.Transfer.TransferId);
            try
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
            catch (Exception cleanup) when (writeFailure is not null &&
                cleanup is (IOException or UnauthorizedAccessException))
            { writeFailure.Data["TemporaryCleanupFailure"] = cleanup.ToString(); }
        }
    }

    private string ManifestPath(Guid id) =>
        Path.Combine(_directory, id.ToString("N") + ".json");

    private FileStream CreatePrivateTemporary(string path) => _fileSecurity is null
        ? new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.Asynchronous | FileOptions.WriteThrough)
        : new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl,
            FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough,
            _fileSecurity);

    private static bool HasSameProtectedDacl(FileSystemSecurity existing, FileSystemSecurity required)
    {
        // Match protection and the complete ordered ACL, leaving NTFS's stored
        // auto-inheritance control bits (and owner/group/SACL) untouched.
        if (!existing.AreAccessRulesProtected) return false;
        var actual = new RawSecurityDescriptor(existing.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl;
        var expected = new RawSecurityDescriptor(required.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl;
        if (actual is null || expected is null) return false;
        var actualBytes = new byte[actual.BinaryLength];
        var expectedBytes = new byte[expected.BinaryLength];
        actual.GetBinaryForm(actualBytes, 0);
        expected.GetBinaryForm(expectedBytes, 0);
        return actualBytes.AsSpan().SequenceEqual(expectedBytes);
    }

    private static void AddPrivateRules(
        FileSystemSecurity security, SecurityIdentifier owner, bool inherit)
    {
        foreach (var sid in new[]
        {
            owner,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
        })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid,
                FileSystemRights.FullControl,
                inherit ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit
                        : InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow));
        }
    }

    internal static void RequireProtectedParent(string directory)
    {
        string parent = Path.GetDirectoryName(directory) ?? throw new IOException(
            "The journal needs a protected parent directory.");
        var security = StagedPrivateSecurity.ReadDirectory(parent);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new UnauthorizedAccessException("The journal parent has no Windows owner.");
        if (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
            !owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
        {
            throw new UnauthorizedAccessException("The journal parent has an untrusted owner.");
        }

        const FileSystemRights destructive = FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true, includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                (rule.PropagationFlags & PropagationFlags.InheritOnly) != 0 ||
                (rule.FileSystemRights & destructive) == 0 ||
                rule.IdentityReference is not SecurityIdentifier sid)
            {
                continue;
            }
            if (!sid.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
                !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                throw new UnauthorizedAccessException(
                    "The journal parent allows ordinary users to remove its children.");
            }
        }
    }

    internal static void RequireTrustedOwner(FileSystemSecurity security, string objectName)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null ||
            (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid) &&
             !owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
        {
            throw new UnauthorizedAccessException($"The {objectName} has an untrusted owner.");
        }
    }

    private static bool IsTransitionAllowed(
        TransferJournalState from,
        TransferJournalState to) => (from, to) switch
    {
        (TransferJournalState.Allocated, TransferJournalState.SealPending) => true,
        (TransferJournalState.Unsealed, TransferJournalState.SealPending) => true,
        (TransferJournalState.Allocated, TransferJournalState.DiscardPending) => true,
        (TransferJournalState.Unsealed, TransferJournalState.DiscardPending) => true,
        (TransferJournalState.SealPending, TransferJournalState.DiscardPending) => true,
        (TransferJournalState.Sealed, TransferJournalState.DiscardPending) => true,
        (TransferJournalState.Retained, TransferJournalState.DiscardPending) => true,
        (TransferJournalState.SealPending, TransferJournalState.Sealed) => true,
        (TransferJournalState.SealPending, TransferJournalState.LegacyEmptyHeld) => true,
        (TransferJournalState.Sealed, TransferJournalState.LegacyEmptyHeld) => true,
        (TransferJournalState.Retained, TransferJournalState.LegacyEmptyHeld) => true,
        (TransferJournalState.Inspecting, TransferJournalState.LegacyEmptyHeld) => true,
        (TransferJournalState.LegacyEmptyHeld, TransferJournalState.Sealed) => true, // read legacy migration history only
        (TransferJournalState.Allocated, TransferJournalState.Sealed) => true,
        (TransferJournalState.Allocated, TransferJournalState.Unsealed) => true,
        (TransferJournalState.Unsealed, TransferJournalState.Sealed) => true,
        (TransferJournalState.Sealed, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Sealed, TransferJournalState.Retained) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Approved) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Blocked) => true,
        // A previously blocked stage whose identity or measured bytes change
        // can no longer use its old justification. Keep the file private and
        // close that window instead of leaving a stale Blocked state attached
        // to different bytes.
        (TransferJournalState.Blocked, TransferJournalState.Retained) => true,
        (TransferJournalState.Blocked, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Blocked, TransferJournalState.Sealed) => true,
        (TransferJournalState.Retained, TransferJournalState.Sealed) => true,
        // CompleteRenameAsync clears approval and reinspects a still-owned
        // released version at its new name. TransitionAsync independently
        // refuses direct resealing of Released entries.
        (TransferJournalState.Released, TransferJournalState.Sealed) => true,
        (TransferJournalState.Approved, TransferJournalState.Sealed) => true,
        (TransferJournalState.Publishing, TransferJournalState.Sealed) => true, // only live, uncommitted retarget
        (TransferJournalState.Inspecting, TransferJournalState.Retained) => true,
        (TransferJournalState.Approved, TransferJournalState.Retained) => true,
        (TransferJournalState.Approved, TransferJournalState.Publishing) => true,
        (TransferJournalState.Publishing, TransferJournalState.Released) => true,
        (TransferJournalState.Publishing, TransferJournalState.Retained) => true,
        (TransferJournalState.Retained, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Sealed) => true,
        (TransferJournalState.Allocated, TransferJournalState.Discarded) => true,
        (TransferJournalState.Unsealed, TransferJournalState.Discarded) => true,
        _ => false
    };
}

public sealed record TransferJournalEntry(
    StagedTransfer Transfer,
    TransferJournalState State,
    string? Sha256Hex,
    DateTimeOffset UpdatedAtUtc)
{
    public const int MaximumStateHistory = 64;
    public IReadOnlyList<TransferJournalStateChange> StateHistory { get; init; } = [];
    public bool SealedOnce { get; init; }
    public StagedStageIdentity? StageIdentity { get; init; }
    public long? SealedLength { get; init; }
    /// <summary>Exact predecessor tuple captured from the journal under the destination gate.</summary>
    public StagedVersionIdentity? ParentVersionIdentity { get; init; }
    /// <summary>Exact private version discarded by a manifest-first replacement allocation.</summary>
    public StagedVersionIdentity? DeleteVersionIdentity { get; init; }
    /// <summary>Stable transfer ID used as the create-after reservation key.</summary>
    public Guid? CreateReservationId { get; init; }
    /// <summary>Stable V3 child reservation authorized by a pending V2 private delete.</summary>
    public Guid? CreateAfterReservationId { get; init; }
    /// <summary>Exact parent/tombstone request reference used by v19 allocation replay.</summary>
    public Guid? AllocationReferenceId { get; init; }
    /// <summary>0=none, 1=sealed predecessor, 2=rename tombstone owner.</summary>
    public uint? AllocationReferenceKind { get; init; }
    /// <summary>Kernel driver instance that owns this v19 allocation epoch.</summary>
    public Guid? DriverInstanceId { get; init; }
    public StagedStageIdentity? ParentDirectoryIdentity { get; init; }
    public uint? AllocationDisposition { get; init; }
    public uint? AllocationExtensionVersion { get; init; }
    public StagedAllocationBindingV23? BoundAllocation { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public StagedAllocationSecurityReference? AllocationSecurity { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public StagedSeedProvenance? SeedProvenance { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public StagedSeedCompletion? SeedCompletion { get; init; }
    /// <summary>Durable attachment transaction state; None is legacy/unattached v18 data.</summary>
    public StagedAttachmentStateV20 AttachmentStateV20 { get; init; }
    public ulong? AttachPrepareRequestIdV20 { get; init; }
    public ulong? AttachCommitRequestIdV20 { get; init; }
    public uint? AttachCommitResultV20 { get; init; }
    public ulong? AttachAbortRequestIdV20 { get; init; }
    public ulong? CompletionPermitRequestIdV20 { get; init; }
    public ulong? RetireRequestIdV20 { get; init; }
    public ulong? HandleObservedRequestIdV20 { get; init; }
    /// <summary>Reservation bound to a pending private delete or EmptyHeld cleanup.</summary>
    public Guid? DiscardReservationId { get; init; }
    public StagedDiscardKind? DiscardKind { get; init; }
    public DateTimeOffset? DiscardRequestedAtUtc { get; init; }
    public DateTimeOffset? DiscardAcknowledgedAtUtc { get; init; }
    public DateTimeOffset? EmptyHeldNotificationAttemptedAtUtc { get; init; }
    public Guid? EmptyHeldNotificationAttemptedByInstanceId { get; init; }
    public DateTimeOffset? EmptyHeldNotificationQueuedAtUtc { get; init; }
    public Guid? EmptyHeldNotificationQueuedByInstanceId { get; init; }
    public long DestinationGeneration { get; init; }
    public StagedNameTombstone? NamespaceTombstones { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public StagedUnboundCancellation? UnboundCancellation { get; init; }
    public StagedRename? PendingRename { get; init; }
    public ulong LastRenameTransactionId { get; init; }
    public string? LastRenameDestination { get; init; }
    public bool LastRenameCommitted { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public StagedRenameReceiptV20? LastRenameReceiptV20 { get; init; }
    public int BlockedPolicyVersion { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? BlockedPolicyFingerprint { get; init; }
    public InspectionFailureKind? BlockedInspectionFailure { get; init; }
    public DateTimeOffset? JustificationExpiresAtUtc { get; init; }
    public bool JustificationWindowClosed { get; init; }
    public StagedHandbackState HandbackState { get; init; }
    public string? HandbackPath { get; init; }
    public long? HandbackLength { get; init; }
    public string? HandbackFailureReason { get; init; }
    public DateTimeOffset? HandbackLastAttemptAtUtc { get; init; }
    public bool StageCleanupStarted { get; init; }
    public StagedBlockedDeletionReceipt? BlockedDeletionReceipt { get; init; }
    public bool StageDeleted { get; init; }

    public bool Equals(TransferJournalEntry? other)
    {
        if (ReferenceEquals(this, other)) return true;
        return other is not null && UnboundCancellation == other.UnboundCancellation && Transfer == other.Transfer && State == other.State &&
            Sha256Hex == other.Sha256Hex && UpdatedAtUtc == other.UpdatedAtUtc &&
            StateHistory.SequenceEqual(other.StateHistory) && SealedOnce == other.SealedOnce &&
            StageIdentity == other.StageIdentity && SealedLength == other.SealedLength &&
            ParentVersionIdentity == other.ParentVersionIdentity && DeleteVersionIdentity == other.DeleteVersionIdentity &&
            CreateReservationId == other.CreateReservationId &&
            CreateAfterReservationId == other.CreateAfterReservationId &&
            AllocationReferenceId == other.AllocationReferenceId &&
            AllocationReferenceKind == other.AllocationReferenceKind && DriverInstanceId == other.DriverInstanceId &&
            ParentDirectoryIdentity == other.ParentDirectoryIdentity &&
            AllocationExtensionVersion == other.AllocationExtensionVersion && BoundAllocation == other.BoundAllocation &&
            AllocationSecurity == other.AllocationSecurity && SeedProvenance == other.SeedProvenance &&
            SeedCompletion == other.SeedCompletion &&
            AllocationDisposition == other.AllocationDisposition && DiscardReservationId == other.DiscardReservationId &&
            AttachmentStateV20 == other.AttachmentStateV20 &&
            AttachPrepareRequestIdV20 == other.AttachPrepareRequestIdV20 &&
            AttachCommitRequestIdV20 == other.AttachCommitRequestIdV20 &&
            AttachCommitResultV20 == other.AttachCommitResultV20 &&
            AttachAbortRequestIdV20 == other.AttachAbortRequestIdV20 &&
            CompletionPermitRequestIdV20 == other.CompletionPermitRequestIdV20 &&
            RetireRequestIdV20 == other.RetireRequestIdV20 &&
            HandleObservedRequestIdV20 == other.HandleObservedRequestIdV20 &&
            DiscardKind == other.DiscardKind && DiscardRequestedAtUtc == other.DiscardRequestedAtUtc &&
            DiscardAcknowledgedAtUtc == other.DiscardAcknowledgedAtUtc &&
            EmptyHeldNotificationAttemptedAtUtc == other.EmptyHeldNotificationAttemptedAtUtc &&
            EmptyHeldNotificationAttemptedByInstanceId == other.EmptyHeldNotificationAttemptedByInstanceId &&
            EmptyHeldNotificationQueuedAtUtc == other.EmptyHeldNotificationQueuedAtUtc &&
            EmptyHeldNotificationQueuedByInstanceId == other.EmptyHeldNotificationQueuedByInstanceId &&
            DestinationGeneration == other.DestinationGeneration && NamespaceTombstones == other.NamespaceTombstones &&
            PendingRename == other.PendingRename && LastRenameTransactionId == other.LastRenameTransactionId &&
            LastRenameDestination == other.LastRenameDestination && LastRenameCommitted == other.LastRenameCommitted &&
            LastRenameReceiptV20 == other.LastRenameReceiptV20 &&
            BlockedPolicyVersion == other.BlockedPolicyVersion && BlockedPolicyFingerprint == other.BlockedPolicyFingerprint &&
            BlockedInspectionFailure == other.BlockedInspectionFailure &&
            JustificationExpiresAtUtc == other.JustificationExpiresAtUtc &&
            JustificationWindowClosed == other.JustificationWindowClosed && HandbackState == other.HandbackState &&
            HandbackPath == other.HandbackPath && HandbackLength == other.HandbackLength &&
            HandbackFailureReason == other.HandbackFailureReason &&
            HandbackLastAttemptAtUtc == other.HandbackLastAttemptAtUtc &&
            BlockedDeletionReceipt == other.BlockedDeletionReceipt &&
            StageCleanupStarted == other.StageCleanupStarted && StageDeleted == other.StageDeleted;
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Transfer);
        hash.Add(State);
        hash.Add(Sha256Hex);
        hash.Add(UpdatedAtUtc);
        foreach (TransferJournalStateChange change in StateHistory) hash.Add(change);
        hash.Add(UnboundCancellation);
        hash.Add(SealedOnce);
        hash.Add(StageIdentity);
        hash.Add(SealedLength);
        hash.Add(ParentVersionIdentity);
        hash.Add(DeleteVersionIdentity);
        hash.Add(CreateReservationId);
        hash.Add(CreateAfterReservationId);
        hash.Add(AllocationReferenceId);
        hash.Add(AllocationReferenceKind);
        hash.Add(DriverInstanceId);
        hash.Add(ParentDirectoryIdentity);
        hash.Add(AllocationDisposition);
        hash.Add(AllocationExtensionVersion);
        hash.Add(BoundAllocation);
        hash.Add(AllocationSecurity);
        hash.Add(SeedProvenance);
        hash.Add(SeedCompletion);
        hash.Add(AttachmentStateV20);
        hash.Add(AttachPrepareRequestIdV20);
        hash.Add(AttachCommitRequestIdV20);
        hash.Add(AttachCommitResultV20);
        hash.Add(AttachAbortRequestIdV20);
        hash.Add(CompletionPermitRequestIdV20);
        hash.Add(RetireRequestIdV20);
        hash.Add(HandleObservedRequestIdV20);
        hash.Add(DiscardReservationId);
        hash.Add(DiscardKind);
        hash.Add(DiscardRequestedAtUtc);
        hash.Add(DiscardAcknowledgedAtUtc);
        hash.Add(EmptyHeldNotificationAttemptedAtUtc);
        hash.Add(EmptyHeldNotificationAttemptedByInstanceId);
        hash.Add(EmptyHeldNotificationQueuedAtUtc);
        hash.Add(EmptyHeldNotificationQueuedByInstanceId);
        hash.Add(DestinationGeneration);
        hash.Add(NamespaceTombstones);
        hash.Add(PendingRename);
        hash.Add(LastRenameTransactionId);
        hash.Add(LastRenameDestination);
        hash.Add(LastRenameCommitted);
        hash.Add(LastRenameReceiptV20);
        hash.Add(BlockedPolicyVersion);
        hash.Add(BlockedPolicyFingerprint);
        hash.Add(BlockedInspectionFailure);
        hash.Add(JustificationExpiresAtUtc);
        hash.Add(JustificationWindowClosed);
        hash.Add(HandbackState);
        hash.Add(HandbackPath);
        hash.Add(HandbackLength);
        hash.Add(HandbackFailureReason);
        hash.Add(HandbackLastAttemptAtUtc);
        hash.Add(BlockedDeletionReceipt);
        hash.Add(StageCleanupStarted);
        hash.Add(StageDeleted);
        return hash.ToHashCode();
    }
}

public sealed record TransferJournalStateChange(TransferJournalState State, DateTimeOffset OccurredAtUtc);

public sealed record StagedVersionIdentity(Guid TransferId, long DestinationGeneration,
    StagedStageIdentity StageIdentity);

public enum StagedDiscardKind : uint
{
    PrivateVersion = 1,
    EmptyHeldPredecessor = 2,
    OwnerExitEmpty = 3,
    DriverUnloadEmpty = 4,
    UnattachedAllocation = 5,
    RetireUnexposed = 6,
    RetireAttachedPrivate = 7
}

/// <summary>
/// A freshly authenticated v20 channel either owns the active epoch, is
/// allowed only to replay the exact already-durable drain tuple, or is refused.
/// DrainReplayOnly never authorizes allocation, publication, or other stage work.
/// </summary>
public enum StagedDriverEpochReconcileV20 : uint
{
    Rejected = 0,
    Active = 1,
    DrainReplayOnly = 2
}

public enum StagedAttachmentStateV20 : uint
{
    None,
    Prepared,
    Committed,
    CommitDenied,
    Aborted,
    CompletionPermitted,
    HandleObserved,
    RetireUnexposedPending,
    RetiredUnexposed,
    RetireAttachedPrivatePending,
    RetiredAttachedPrivate
}

internal static class StageV20WireResult
{
    public const uint CapabilitiesAccepted = 5;
    public const uint AttachPrepared = 6;
    public const uint AttachCommitted = 7;
    public const uint AttachAborted = 8;
    public const uint AttachCommitDenied = 9;
    public const uint AttachAlreadyCommitted = 10;
    public const uint AttachRetiredUnexposed = 12;
    public const uint EpochBusy = 13;
    public const uint EpochDrained = 14;
    public const uint AttachRetiredPrivate = 15;
    public const uint CompletionPermitted = 16;
    public const uint HandleLifetimeObserved = 17;
}

public sealed record StagedAttachmentRequestV20(uint Operation, ulong RequestId,
    StagedVersionIdentity Version, Guid DriverInstanceId,
    StagedStageIdentity ParentDirectoryIdentity, string DestinationPath,
    int RequestorProcessId);

public enum StagedDiscardStatus : uint
{
    Pending = 1,
    Acknowledged = 2
}

public sealed record StagedDiscardRequest(Guid ReservationId, StagedVersionIdentity Version,
    StagedDiscardKind Kind);

public sealed record StagedCreateAfterDiscardRequest(Guid ReservationId,
    StagedVersionIdentity DeleteVersion, StagedStageIdentity ParentDirectoryIdentity,
    uint Disposition, string DestinationPath, DestinationKind Destination,
    int ProcessId, uint SessionId, string RequestorSid, long RequestorProcessCreationTime,
    Guid? DriverInstanceId = null);

public sealed record StagedCreateAfterIntentResult(TransferJournalEntry Entry, bool IsReplay);

public sealed record StagedAllocationIntentV19(Guid ReservationId, Guid ParentTransferId,
    uint Disposition, uint ReferenceKind, Guid DriverInstanceId);

public sealed record StagedAllocationReply(StagedTransfer Transfer, long DestinationGeneration,
    StagedStageIdentity StageIdentity, long InitialLength);

public sealed record StagedBlockedDeletionReceipt(StagedVersionIdentity Version,
    int CommittedRenames, long Length, string Sha256Hex);

public sealed record BlockedTransferEvidence(int PolicyVersion,
    DateTimeOffset? JustificationExpiresAtUtc, bool WindowClosed,
    InspectionFailureKind? InspectionFailure = null)
{
    public string? PolicyFingerprint { get; init; }
}

public enum StagedHandbackState
{
    NotAttempted,
    Copying,
    Verified,
    Failed
}

// Linked records provide value equality across serialization/reply-loss retries.
public sealed record StagedNameTombstone(string DestinationPath, long Generation,
    StagedNameTombstone? Previous)
{
    public StagedAllocationBindingV23? AllocationBindingV23 { get; init; }
}

public sealed record StagedRename(ulong TransactionId, string DestinationPath, bool SealedVersion)
{
    public StagedRenameRequestV20? SourceV20 { get; init; }
    public string? SourcePath { get; init; }
}

public sealed record StagedRenameRequestV20(ulong TransactionId, StagedVersionIdentity Version,
    Guid DriverInstanceId, StagedStageIdentity ParentDirectoryIdentity, ulong ViewGeneration,
    int OwnerProcessId, string DestinationPath, bool SealedVersion, string DestinationName);

public sealed record StagedRenameReceiptV20(StagedRenameRequestV20 Source, string SourcePath,
    bool Committed, string DestinationPath, long DestinationGeneration);

/// <summary>Explicit protocol refusals, distinguished from transient storage failures.</summary>
internal static class StagedRequestRefusal
{
    private const string Key = "SafeUpload.ExactProtocolRefusal";
    internal static IOException Create(string message)
    {
        var error = new IOException(message);
        error.Data[Key] = true;
        return error;
    }
    internal static bool IsPermanent(Exception error) =>
        error is InvalidDataException || error.Data[Key] is true ||
        error is not (IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or TimeoutException);
}

public enum TransferJournalState
{
    Allocated,
    Sealed,
    Inspecting,
    Approved,
    Publishing,
    Released,
    Blocked,
    Retained,
    // Appended to preserve the numeric values in existing durable manifests.
    Unsealed,
    // T5: the writer deleted its private version before it was sealed. Terminal: never inspected or published; it keeps its
    // destination generation, so no older version of the name can publish after the delete.
    Discarded,
    // Seal classification was durably requested but has not yet been measured.
    SealPending,
    // Reserved persisted value: never emitted for a new save. Only guarded
    // legacy recovery may migrate it after a fresh measured seal.
    LegacyEmptyHeld = 11,
    // Appended terminal delete workflow. It cannot be sealed, inspected or
    // published; only an exact identity-qualified background cleanup can ack it.
    DiscardPending
}
