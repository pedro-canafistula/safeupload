using System.Text.Json;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Durable state for transfers held off the protected destination. Each state
/// change replaces one manifest on the same local volume. A service restart
/// can therefore distinguish an unapproved file from a published one.
/// The journal directory must be writable only by the service account.
/// </summary>
public sealed class StagedTransferJournal
{
    private readonly string _directory;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly FileSecurity? _fileSecurity;
    private readonly SecurityIdentifier? _owner;

    public StagedTransferJournal(string directory, bool requireProtectedParent = false)
    {
        _directory = Path.GetFullPath(directory);
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
                if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    RequireTrustedOwner(info.GetAccessControl(), "journal directory");
                }
                RequireNoUntrustedWriters(info.GetAccessControl(), owner);
                // Setting an inheritable directory DACL can update a child's
                // shared object before its own ACL is visited. Preflight ALL
                // children before allowing that propagation, then reopen and
                // validate each object again for its handle-based ACL update.
                foreach (string path in Directory.EnumerateFileSystemEntries(_directory))
                {
                    using var file = StagedJournalFile.Open(path);
                    var security = file.GetAccessControl();
                    if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                        RequireTrustedOwner(security, "journal manifest");
                    RequireNoUntrustedWriters(security, owner);
                }
                info.SetAccessControl(directorySecurity);
            }

            _fileSecurity = new FileSecurity();
            _fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddPrivateRules(_fileSecurity, owner, inherit: false);
            foreach (string path in Directory.EnumerateFiles(_directory))
            {
                using var file = StagedJournalFile.Open(path, recoverAcl: true);
                var security = file.GetAccessControl();
                if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    RequireTrustedOwner(security, "journal manifest");
                }
                RequireNoUntrustedWriters(security, owner);
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
        Guid? tombstoneOwner = null)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        if (transfer.TransferId == Guid.Empty)
        {
            throw new ArgumentException("A transfer needs a nonempty ID.", nameof(transfer));
        }

        DateTimeOffset createdAtUtc = DateTimeOffset.UtcNow;
        var entry = new TransferJournalEntry(
            transfer, TransferJournalState.Allocated, null, createdAtUtc)
        {
            StateHistory = [new TransferJournalStateChange(TransferJournalState.Allocated, createdAtUtc)]
        };
        ValidateEntry(entry, transfer.TransferId);
        string path = ManifestPath(transfer.TransferId);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
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
            entry = entry with { DestinationGeneration = checked(versions.Select(e => e.Generation)
                .DefaultIfEmpty(0).Max() + 1) };
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
            File.Move(temporary, path);
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
        string path = ManifestPath(transferId);
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
        return entry!;
    }

    private static void ValidateEntry(TransferJournalEntry? entry, Guid id)
    {
        if (id == Guid.Empty || entry?.Transfer is not { } transfer || transfer.TransferId != id ||
            !Enum.IsDefined(entry.State) || !Enum.IsDefined(transfer.Destination) ||
            transfer.ProcessId <= 0 || string.IsNullOrWhiteSpace(transfer.ProcessName) ||
            transfer.ProcessName.Length > 63 || entry.DestinationGeneration < 0 ||
            entry.BlockedPolicyVersion < 0 ||
            (entry.State == TransferJournalState.Blocked && entry.BlockedPolicyVersion <= 0 &&
                transfer.RequestorSid is not null) ||
            entry.UpdatedAtUtc == default ||
            (transfer.RequestorSid is { } requestorSid &&
                (requestorSid.Length > 184 || !requestorSid.StartsWith("S-", StringComparison.OrdinalIgnoreCase) ||
                 requestorSid.Any(char.IsWhiteSpace))) ||
            (transfer.RequestorProcessCreationTime is <= 0))
            throw new InvalidDataException("The transfer manifest has invalid identity or state.");
        RequireManifestPath(transfer.StagePath);
        RequireManifestPath(transfer.DestinationPath);
        if (entry.Sha256Hex is not null && (entry.Sha256Hex.Length != 64 || !entry.Sha256Hex.All(Uri.IsHexDigit)))
            throw new InvalidDataException("The transfer manifest has an invalid digest.");
        bool requiresSeal = entry.State is TransferJournalState.Sealed or TransferJournalState.Inspecting or
            TransferJournalState.Approved or TransferJournalState.Publishing or TransferJournalState.Released or
            TransferJournalState.Blocked;
        if ((requiresSeal && !entry.SealedOnce) ||
            (entry.State is TransferJournalState.Allocated or TransferJournalState.Unsealed && entry.SealedOnce) ||
            ((entry.State is TransferJournalState.Publishing or TransferJournalState.Released or
                TransferJournalState.Blocked) && entry.Sha256Hex is null))
            throw new InvalidDataException("The transfer manifest has invalid seal/publication evidence.");
        if (entry.PendingRename is { } rename)
        {
            RequireManifestPath(rename.DestinationPath);
            if (rename.TransactionId == 0 || rename.SealedVersion != entry.SealedOnce)
                throw new InvalidDataException("The transfer manifest has an invalid pending rename.");
        }
        if (entry.LastRenameDestination is not null) RequireManifestPath(entry.LastRenameDestination);
        if ((entry.LastRenameTransactionId == 0 && (entry.LastRenameDestination is not null || entry.LastRenameCommitted)) ||
            (entry.LastRenameTransactionId != 0 && entry.LastRenameDestination is null))
            throw new InvalidDataException("The transfer manifest has invalid completed rename evidence.");
        int count = 0;
        for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous)
        {
            RequireManifestPath(name.DestinationPath);
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
            (entry.HandbackLastAttemptAtUtc is { } attempt && attempt.Offset != TimeSpan.Zero) ||
            (entry.StageCleanupStarted && (entry.HandbackState != StagedHandbackState.Verified ||
                !entry.JustificationWindowClosed)) ||
            (entry.StageDeleted && (entry.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
                entry.HandbackState != StagedHandbackState.Verified || !entry.JustificationWindowClosed ||
                entry.StageCleanupStarted)))
            throw new InvalidDataException("The transfer manifest has invalid hand-back evidence.");
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
        bool closeJustificationWindow = false)
    {
        if (!IsTransitionAllowed(expected, next))
        {
            throw new InvalidOperationException($"Invalid transfer transition: {expected} -> {next}.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(transferId, cancellationToken).ConfigureAwait(false);
            if (current.PendingRename is not null)
                throw new IOException("A pending namespace transaction holds this version locally.");
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
                current.JustificationWindowClosed)
                throw new IOException("The justification window is already closed.");

            // Old prototype manifests can say Retained after recovering an
            // Allocated transfer. Missing SealedOnce deserializes as false;
            // those files must remain local instead of becoming inspectable.
            if (next == TransferJournalState.Inspecting && !current.SealedOnce)
            {
                throw new InvalidOperationException("An unsealed transfer cannot be inspected.");
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
                StageCleanupStarted = next == TransferJournalState.Blocked ? false : current.StageCleanupStarted
            };
            await ReplaceAsync(ManifestPath(transferId), updated, cancellationToken)
                .ConfigureAwait(false);
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
        string stagePath, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId ||
                !string.Equals(current.Transfer.StagePath, Path.GetFullPath(stagePath),
                    StringComparison.OrdinalIgnoreCase) || current.PendingRename is not null)
                throw new IOException("The seal does not identify an available version owned by this writer.");
            if (current.StageCleanupStarted || current.StageDeleted)
                throw new IOException("The staged version is being cleaned up or has already been removed.");
            if (current.SealedOnce) return current;
            if (current.State is not (TransferJournalState.Allocated or TransferJournalState.Unsealed))
                throw new IOException("The version cannot be sealed from its current state.");
            IReadOnlyList<TransferJournalStateChange> history =
                AppendState(current, TransferJournalState.Sealed);
            var updated = current with
            {
                State = TransferJournalState.Sealed,
                SealedOnce = true,
                UpdatedAtUtc = history.Count == 0 ? DateTimeOffset.UtcNow : history[^1].OccurredAtUtc,
                StateHistory = history
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<TransferJournalEntry> PrepareRenameAsync(Guid id, ulong transactionId,
        int ownerProcessId, string destination, bool sealedVersion, CancellationToken token)
    {
        if (transactionId == 0) throw new ArgumentOutOfRangeException(nameof(transactionId));
        destination = Path.GetFullPath(destination);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId)
                throw new IOException("The staged version belongs to another writer.");
            if (current.StageCleanupStarted || current.StageDeleted)
                throw new IOException("The staged version is being cleaned up or has already been removed.");
            var pending = new StagedRename(transactionId, destination, sealedVersion);
            if (current.PendingRename == pending) return current;
            if (current.PendingRename is not null || current.LastRenameTransactionId == transactionId ||
                current.State is TransferJournalState.Inspecting or
                    TransferJournalState.Approved or TransferJournalState.Publishing ||
                (current.State == TransferJournalState.Blocked && !current.JustificationWindowClosed))
                throw new IOException("The staged version is busy.");
            if (sealedVersion != current.SealedOnce)
                throw new IOException("The kernel and journal disagree about the version seal.");
            await RequireCurrentDestinationAsync(current, token).ConfigureAwait(false);
            int moves = 0;
            for (var name = current.NamespaceTombstones; name is not null; name = name.Previous)
                if (++moves >= 16) throw new IOException("The version's namespace history is full.");
            var targets = await DestinationVersionsAsync(destination, token).ConfigureAwait(false);
            if (targets.Any(e => e.Entry.Transfer.TransferId != id && e.Reserved))
                throw new IOException("The rename destination is busy.");
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
        int ownerProcessId, string destination, bool commit, CancellationToken token)
    {
        if (transactionId == 0) throw new ArgumentOutOfRangeException(nameof(transactionId));
        destination = Path.GetFullPath(destination);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var current = await ReadCoreAsync(id, token).ConfigureAwait(false);
            if (current.Transfer.ProcessId != ownerProcessId)
                throw new IOException("The namespace transaction belongs to another writer.");
            if (current.LastRenameTransactionId == transactionId &&
                current.LastRenameDestination == destination && current.LastRenameCommitted == commit)
                return current; // Reply loss must not retarget or inspect twice.
            var pending = current.PendingRename;
            if (pending is null)
            {
                // An abort after a prepare was refused is a safe no-op. A
                // commit never invents a prepare or authorizes a new path.
                if (!commit && current.LastRenameTransactionId != transactionId) return current;
                throw new IOException("No matching prepared namespace transaction.");
            }
            if (pending.TransactionId != transactionId || pending.DestinationPath != destination)
                throw new IOException("The namespace transaction identity or destination changed.");
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
            bool stateChanged = commit && pending.SealedVersion &&
                current.State != TransferJournalState.Sealed;
            IReadOnlyList<TransferJournalStateChange> history = stateChanged
                ? AppendState(current, TransferJournalState.Sealed) : current.StateHistory;
            var updated = current with
            {
                Transfer = commit ? current.Transfer with { DestinationPath = destination } : current.Transfer,
                State = commit && pending.SealedVersion ? TransferJournalState.Sealed : current.State,
                Sha256Hex = commit ? null : current.Sha256Hex,
                DestinationGeneration = generation,
                NamespaceTombstones = tombstones,
                PendingRename = null,
                LastRenameTransactionId = transactionId,
                LastRenameDestination = destination,
                LastRenameCommitted = commit,
                UpdatedAtUtc = stateChanged && history.Count > 0
                    ? history[^1].OccurredAtUtc : DateTimeOffset.UtcNow,
                StateHistory = history
            };
            await ReplaceAsync(ManifestPath(id), updated, token).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<TransferJournalEntry>> ReadPendingAsync(
        CancellationToken cancellationToken)
    {
        var entries = new List<TransferJournalEntry>();
        foreach (string path in Directory.EnumerateFiles(_directory, "*.json"))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out Guid id))
            {
                throw new InvalidDataException($"Unexpected journal file: {path}");
            }

            var entry = await ReadAsync(id, cancellationToken).ConfigureAwait(false);
            bool releaseCleanupPending = entry.State == TransferJournalState.Released &&
                entry.HandbackState == StagedHandbackState.Verified &&
                entry.JustificationWindowClosed && !entry.StageDeleted;
            if (entry.PendingRename is not null || entry.State != TransferJournalState.Released || releaseCleanupPending)
            {
                entries.Add(entry);
            }
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
            if (current.HandbackState == StagedHandbackState.Failed) return (current, false);
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
            if (current.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
                current.PendingRename is not null ||
                current.HandbackState != StagedHandbackState.Verified ||
                !current.JustificationWindowClosed || current.StageDeleted)
                return current;
            if (current.StageCleanupStarted) return current;
            var updated = current with { StageCleanupStarted = true, UpdatedAtUtc = DateTimeOffset.UtcNow };
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
                !current.JustificationWindowClosed || !current.StageCleanupStarted)
                throw new IOException("Staging cleanup prerequisites are not satisfied.");
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
        var versions = new List<DestinationClaim>();
        foreach (string path in Directory.EnumerateFiles(_directory, "*.json"))
        {
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out Guid id))
                throw new InvalidDataException($"Unexpected journal file: {path}");
            var entry = await ReadCoreAsync(id, token).ConfigureAwait(false);
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

    private async Task RequireCurrentDestinationAsync(TransferJournalEntry current, CancellationToken token)
    {
        var versions = await DestinationVersionsAsync(current.Transfer.DestinationPath, token).ConfigureAwait(false);
        long generation = versions.Select(e => e.Generation).DefaultIfEmpty(0).Max();
        if (current.DestinationGeneration != generation ||
            versions.Count(e => e.Generation == generation) != 1 ||
            versions.Any(e => e.Generation == generation && e.Tombstone) ||
            versions.Any(e => e.Entry.Transfer.TransferId != current.Transfer.TransferId && e.Reserved))
            throw new IOException("A later save or pending rename supersedes this destination version.");
    }

    /// <summary>
    /// Resolve a crash after publication started without copying again over
    /// a destination another process may have changed. An exact digest match
    /// proves the approved bytes landed; a mismatch retains the stage for
    /// review. An unreachable destination remains Publishing for a retry.
    /// </summary>
    public async Task ReconcilePublishingAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in await ReadPendingAsync(cancellationToken).ConfigureAwait(false))
        {
            if (entry.State != TransferJournalState.Publishing)
            {
                continue;
            }

            bool matches;
            try
            {
                await using var destination = new FileStream(
                    entry.Transfer.DestinationPath,
                    FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                string digest = Convert.ToHexString(
                    await SHA256.HashDataAsync(destination, cancellationToken).ConfigureAwait(false));
                matches = string.Equals(digest, entry.Sha256Hex,
                    StringComparison.OrdinalIgnoreCase);
            }
            catch (FileNotFoundException)
            {
                matches = false;
            }
            catch (DirectoryNotFoundException)
            {
                // A USB drive or network share may return later.
                continue;
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            await TransitionAsync(entry.Transfer.TransferId,
                TransferJournalState.Publishing,
                matches ? TransferJournalState.Released : TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A process or service crash leaves no trustworthy final-close signal.
    /// An allocation that was never sealed must not become eligible for
    /// inspection merely because recovery ran. Sealed versions interrupted
    /// during inspection or publication approval can be inspected again.
    /// Publishing is handled separately because its destination may already
    /// contain exactly the approved digest.
    /// </summary>
    public async Task RetainInterruptedAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in await ReadPendingAsync(cancellationToken).ConfigureAwait(false))
        {
            // A surviving driver retries its exact commit/abort. After driver
            // loss there is no evidence of which virtual rename completed:
            // retain both names in the manifest and never infer approval.
            if (entry.PendingRename is not null) continue;
            if (entry.State == TransferJournalState.Allocated)
            {
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
        }
    }

    private async Task ReplaceAsync(
        string manifestPath,
        TransferJournalEntry entry,
        CancellationToken cancellationToken)
    {
        ValidateEntry(entry, entry.Transfer.TransferId);
        string temporary = manifestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                if (stream.Length > StagedJournalFile.MaximumManifestBytes)
                    throw new InvalidDataException("Journal manifest exceeds the qualified size bound.");
                StagedDestinationFile.Commit(stream, temporary, manifestPath);
            }

        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
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
        var security = new DirectoryInfo(parent).GetAccessControl();
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
        (TransferJournalState.Allocated, TransferJournalState.Sealed) => true,
        (TransferJournalState.Allocated, TransferJournalState.Unsealed) => true,
        (TransferJournalState.Unsealed, TransferJournalState.Sealed) => true,
        (TransferJournalState.Sealed, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Sealed, TransferJournalState.Retained) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Approved) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Blocked) => true,
        (TransferJournalState.Blocked, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Blocked, TransferJournalState.Sealed) => true,
        (TransferJournalState.Retained, TransferJournalState.Sealed) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Retained) => true,
        (TransferJournalState.Approved, TransferJournalState.Retained) => true,
        (TransferJournalState.Approved, TransferJournalState.Publishing) => true,
        (TransferJournalState.Publishing, TransferJournalState.Released) => true,
        (TransferJournalState.Publishing, TransferJournalState.Retained) => true,
        (TransferJournalState.Retained, TransferJournalState.Inspecting) => true,
        (TransferJournalState.Inspecting, TransferJournalState.Sealed) => true,
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
    public long DestinationGeneration { get; init; }
    public StagedNameTombstone? NamespaceTombstones { get; init; }
    public StagedRename? PendingRename { get; init; }
    public ulong LastRenameTransactionId { get; init; }
    public string? LastRenameDestination { get; init; }
    public bool LastRenameCommitted { get; init; }
    public int BlockedPolicyVersion { get; init; }
    public DateTimeOffset? JustificationExpiresAtUtc { get; init; }
    public bool JustificationWindowClosed { get; init; }
    public StagedHandbackState HandbackState { get; init; }
    public string? HandbackPath { get; init; }
    public long? HandbackLength { get; init; }
    public string? HandbackFailureReason { get; init; }
    public DateTimeOffset? HandbackLastAttemptAtUtc { get; init; }
    public bool StageCleanupStarted { get; init; }
    public bool StageDeleted { get; init; }

    public bool Equals(TransferJournalEntry? other)
    {
        if (ReferenceEquals(this, other)) return true;
        return other is not null && Transfer == other.Transfer && State == other.State &&
            Sha256Hex == other.Sha256Hex && UpdatedAtUtc == other.UpdatedAtUtc &&
            StateHistory.SequenceEqual(other.StateHistory) && SealedOnce == other.SealedOnce &&
            DestinationGeneration == other.DestinationGeneration && NamespaceTombstones == other.NamespaceTombstones &&
            PendingRename == other.PendingRename && LastRenameTransactionId == other.LastRenameTransactionId &&
            LastRenameDestination == other.LastRenameDestination && LastRenameCommitted == other.LastRenameCommitted &&
            BlockedPolicyVersion == other.BlockedPolicyVersion &&
            JustificationExpiresAtUtc == other.JustificationExpiresAtUtc &&
            JustificationWindowClosed == other.JustificationWindowClosed && HandbackState == other.HandbackState &&
            HandbackPath == other.HandbackPath && HandbackLength == other.HandbackLength &&
            HandbackFailureReason == other.HandbackFailureReason &&
            HandbackLastAttemptAtUtc == other.HandbackLastAttemptAtUtc &&
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
        hash.Add(SealedOnce);
        hash.Add(DestinationGeneration);
        hash.Add(NamespaceTombstones);
        hash.Add(PendingRename);
        hash.Add(LastRenameTransactionId);
        hash.Add(LastRenameDestination);
        hash.Add(LastRenameCommitted);
        hash.Add(BlockedPolicyVersion);
        hash.Add(JustificationExpiresAtUtc);
        hash.Add(JustificationWindowClosed);
        hash.Add(HandbackState);
        hash.Add(HandbackPath);
        hash.Add(HandbackLength);
        hash.Add(HandbackFailureReason);
        hash.Add(HandbackLastAttemptAtUtc);
        hash.Add(StageCleanupStarted);
        hash.Add(StageDeleted);
        return hash.ToHashCode();
    }
}

public sealed record TransferJournalStateChange(TransferJournalState State, DateTimeOffset OccurredAtUtc);

public sealed record BlockedTransferEvidence(int PolicyVersion,
    DateTimeOffset? JustificationExpiresAtUtc, bool WindowClosed);

public enum StagedHandbackState
{
    NotAttempted,
    Copying,
    Verified,
    Failed
}

// Linked records provide value equality across serialization/reply-loss retries.
public sealed record StagedNameTombstone(string DestinationPath, long Generation,
    StagedNameTombstone? Previous);

public sealed record StagedRename(ulong TransactionId, string DestinationPath, bool SealedVersion);

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
    Unsealed
}
