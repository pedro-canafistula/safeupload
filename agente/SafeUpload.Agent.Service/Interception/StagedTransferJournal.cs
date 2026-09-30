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
                info.SetAccessControl(directorySecurity);
            }

            _fileSecurity = new FileSecurity();
            _fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddPrivateRules(_fileSecurity, owner, inherit: false);
            foreach (string path in Directory.EnumerateFiles(_directory))
            {
                var file = new FileInfo(path);
                if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid))
                {
                    RequireTrustedOwner(file.GetAccessControl(), "journal manifest");
                }
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        if (transfer.TransferId == Guid.Empty)
        {
            throw new ArgumentException("A transfer needs a nonempty ID.", nameof(transfer));
        }

        var entry = new TransferJournalEntry(
            transfer, TransferJournalState.Allocated, null, DateTimeOffset.UtcNow);
        string path = ManifestPath(transfer.TransferId);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
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

    public async Task<TransferJournalEntry> ReadAsync(
        Guid transferId,
        CancellationToken cancellationToken)
    {
        string path = ManifestPath(transferId);
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var entry = await JsonSerializer.DeserializeAsync<TransferJournalEntry>(
            stream, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (entry is null || entry.Transfer.TransferId != transferId)
        {
            throw new InvalidDataException("The transfer manifest has the wrong ID.");
        }

        return entry;
    }

    public async Task<TransferJournalEntry> TransitionAsync(
        Guid transferId,
        TransferJournalState expected,
        TransferJournalState next,
        string? sha256Hex,
        CancellationToken cancellationToken)
    {
        if (!IsTransitionAllowed(expected, next))
        {
            throw new InvalidOperationException($"Invalid transfer transition: {expected} -> {next}.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = await ReadAsync(transferId, cancellationToken).ConfigureAwait(false);
            if (current.State != expected)
            {
                throw new InvalidOperationException(
                    $"Transfer {transferId} is {current.State}; expected {expected}.");
            }

            // Old prototype manifests can say Retained after recovering an
            // Allocated transfer. Missing SealedOnce deserializes as false;
            // those files must remain local instead of becoming inspectable.
            if (next == TransferJournalState.Inspecting && !current.SealedOnce)
            {
                throw new InvalidOperationException("An unsealed transfer cannot be inspected.");
            }

            string? digest = sha256Hex ?? current.Sha256Hex;
            if (next is TransferJournalState.Publishing or TransferJournalState.Released &&
                (digest is null || digest.Length != 64 || !digest.All(Uri.IsHexDigit)))
            {
                throw new InvalidOperationException("Publishing requires the sealed content digest.");
            }

            var updated = current with
            {
                State = next,
                Sha256Hex = digest,
                SealedOnce = current.SealedOnce || next == TransferJournalState.Sealed,
                UpdatedAtUtc = DateTimeOffset.UtcNow
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
            if (entry.State != TransferJournalState.Released)
            {
                entries.Add(entry);
            }
        }

        return entries;
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
        string temporary = manifestPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = CreatePrivateTemporary(temporary))
            {
                await JsonSerializer.SerializeAsync(stream, entry, cancellationToken: cancellationToken)
                    .ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, manifestPath, overwrite: true);
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

    private static void RequireProtectedParent(string directory)
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
            if (sid.IsWellKnown(WellKnownSidType.WorldSid) ||
                sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid) ||
                sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) ||
                sid.IsWellKnown(WellKnownSidType.InteractiveSid))
            {
                throw new UnauthorizedAccessException(
                    "The journal parent allows ordinary users to remove its children.");
            }
        }
    }

    private static void RequireTrustedOwner(FileSystemSecurity security, string objectName)
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
    public bool SealedOnce { get; init; }
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
    Unsealed
}
