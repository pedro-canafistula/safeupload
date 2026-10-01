using SafeUpload.Agent.Core.Domain;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Reserves a unique local stage name and commits its transfer manifest before
/// returning that name to the driver. Only the service can independently open
/// the backing file; the driver authorizes the app's virtual destination.
/// </summary>
public sealed class StagedTransferAllocator
{
    private readonly string _root;
    private readonly StagedTransferJournal _journal;
    private readonly FileSecurity? _fileSecurity;

    public StagedTransferAllocator(string root, StagedTransferJournal journal,
        bool requireProtectedParent = false, bool requireSystemIdentity = false)
    {
        _root = Path.GetFullPath(root);
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));

        string? volumeRoot = Path.GetPathRoot(_root);
        if (string.IsNullOrEmpty(volumeRoot))
        {
            throw new ArgumentException("Staging requires a local fixed volume.", nameof(root));
        }

        var volume = new DriveInfo(volumeRoot);
        if (volume.DriveType != DriveType.Fixed || !volume.IsReady ||
            volume.DriveFormat is not ("NTFS" or "ReFS"))
        {
            throw new ArgumentException("Staging requires a ready local NTFS or ReFS volume.", nameof(root));
        }

        for (string? current = _root; current is not null;
             current = Path.GetDirectoryName(current))
        {
            if (Directory.Exists(current) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new ArgumentException("Staging root contains a reparse point.", nameof(root));
            }
        }
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            var owner = identity.User ?? throw new UnauthorizedAccessException(
                "Staging requires a service identity.");
            bool system = owner.IsWellKnown(WellKnownSidType.LocalSystemSid);
            if (requireSystemIdentity && !system)
            {
                throw new UnauthorizedAccessException("Private staging must run as LocalSystem.");
            }
            if (requireProtectedParent) StagedTransferJournal.RequireProtectedParent(_root);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(owner);
            foreach (var sid in new[] { owner,
                         new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            {
                security.AddAccessRule(new FileSystemAccessRule(sid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }
            var directory = new DirectoryInfo(_root);
            _fileSecurity = new FileSecurity();
            _fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            _fileSecurity.SetOwner(owner);
            foreach (var sid in new[] { owner,
                         new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            {
                _fileSecurity.AddAccessRule(new FileSystemAccessRule(sid,
                    FileSystemRights.FullControl, AccessControlType.Allow));
            }
            if (!directory.Exists) directory.Create(security);
            else
            {
                if (system) StagedTransferJournal.RequireTrustedOwner(
                    directory.GetAccessControl(), "stage directory");
                directory.SetAccessControl(security);
                foreach (var file in directory.EnumerateFiles())
                {
                    if ((file.Attributes & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Staging contains a reparse point.");
                    if (system) StagedTransferJournal.RequireTrustedOwner(
                        file.GetAccessControl(), "stage file");
                    file.SetAccessControl(_fileSecurity);
                }
            }
        }
        else Directory.CreateDirectory(_root);
    }

    public async Task<StagedTransfer> AllocateAsync(
        string destinationPath,
        DestinationKind destination,
        string processName,
        int processId,
        uint? sessionId,
        CancellationToken cancellationToken) =>
        await AllocateAsync(destinationPath, destination, processName, processId,
            sessionId, 2, null, cancellationToken).ConfigureAwait(false);

    // Dispositions are the FILE_* create values from the minifilter request.
    public async Task<StagedTransfer> AllocateAsync(
        string destinationPath,
        DestinationKind destination,
        string processName,
        int processId,
        uint? sessionId,
        uint disposition,
        StagedTransfer? previous,
        CancellationToken cancellationToken)
    {
        string fullDestination = Path.GetFullPath(destinationPath);
        if (string.IsNullOrEmpty(Path.GetFileName(fullDestination)) ||
            fullDestination.StartsWith(_root + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Invalid staged destination.", nameof(destinationPath));
        }

        string extension = Path.GetExtension(fullDestination);
        if (extension.Length > 16 || extension.IndexOfAny(['\\', '/', ':']) >= 0)
        {
            throw new ArgumentException("Invalid staged file extension.", nameof(destinationPath));
        }

        var id = Guid.NewGuid();
        var transfer = new StagedTransfer(
            id,
            Path.Combine(_root, id.ToString("N") + extension),
            fullDestination,
            destination,
            processName,
            processId,
            sessionId);

        if (disposition > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(disposition));
        }
        if (previous is not null &&
            (!string.Equals(previous.DestinationPath, fullDestination,
                StringComparison.OrdinalIgnoreCase) ||
             previous.ProcessId != processId ||
             !string.Equals(Path.GetDirectoryName(previous.StagePath), _root,
                 StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("The earlier stage does not belong to this writer and destination.");
        }

        // FILE_OPEN and FILE_OPEN_IF must see the previous bytes. Truncating
        // dispositions need a real empty file when the reparse is retried.
        string? source = previous?.StagePath;
        bool sourceExists = source is null ? File.Exists(fullDestination) : File.Exists(source);
        if (disposition == 2 && sourceExists) // FILE_CREATE
        {
            throw new IOException("The destination already exists.");
        }
        if (disposition is 1 or 4 && !sourceExists) // FILE_OPEN / FILE_OVERWRITE
        {
            throw new FileNotFoundException("The destination does not exist.", fullDestination);
        }

        bool copyExisting = disposition is 1 or 3 && sourceExists;
        try
        {
            if (copyExisting)
            {
                await using var input = new FileStream(source ?? fullDestination,
                    FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using var output = new FileStream(transfer.StagePath,
                    FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
                await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
            else
            {
                await using var output = new FileStream(transfer.StagePath,
                    FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    4096, FileOptions.WriteThrough);
                output.Flush(flushToDisk: true);
            }

            // Protect the file itself, so an alias or file-ID open cannot rely
            // on bypassing directory traversal. Do this before issuing a name.
            if (_fileSecurity is not null)
                new FileInfo(transfer.StagePath).SetAccessControl(_fileSecurity);

        // CreateAsync flushes the manifest to disk and atomically makes it
        // visible. Nothing is returned to the driver before this succeeds.
            await _journal.CreateAsync(transfer, cancellationToken).ConfigureAwait(false);
            return transfer;
        }
        catch
        {
            if (File.Exists(transfer.StagePath)) File.Delete(transfer.StagePath);
            throw;
        }
    }
}
