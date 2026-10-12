using SafeUpload.Agent.Core.Domain;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Reserves a unique local stage name and commits its transfer manifest before
/// returning that name to the driver. Only the service can independently open
/// the backing file; the driver authorizes the app's virtual destination.
/// </summary>
public sealed partial class StagedTransferAllocator
{
    // Matches the currently qualified owned-stream STAGE_MAX_BYTES bound.
    internal const long MaximumSeedBytes = 16 * 1024 * 1024;
    private readonly string _root;
    private readonly StagedTransferJournal _journal;
    private readonly FileSecurity? _fileSecurity;
    // Stable reservation replay must serialize the path check, backing-file
    // creation and manifest commit. Otherwise a concurrent duplicate could
    // mistake the first request's not-yet-journaled file for an orphan.
    private readonly SemaphoreSlim _v19AllocationGate = new(1, 1);

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
        CancellationToken cancellationToken,
        Guid? tombstoneOwner = null,
        string? requestorSid = null,
        long? requestorProcessCreationTime = null,
        Guid? allocationReservationId = null,
        Guid? allocationReferenceId = null,
        uint? allocationReferenceKind = null,
        Guid? driverInstanceId = null)
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

        var id = allocationReservationId ?? Guid.NewGuid();
        if (id == Guid.Empty) throw new ArgumentException("A transfer ID cannot be empty.", nameof(allocationReservationId));
        var transfer = new StagedTransfer(
            id,
            Path.Combine(_root, id.ToString("N") + extension),
            fullDestination,
            destination,
            processName,
            processId,
            sessionId)
        {
            RequestorSid = requestorSid,
            RequestorProcessCreationTime = requestorProcessCreationTime
        };

        if (disposition > 5)
        {
            throw new ArgumentOutOfRangeException(nameof(disposition));
        }
        if (tombstoneOwner is not null && (previous is not null || disposition != 2))
            throw new ArgumentException("Tombstone allocation requires a fresh FILE_CREATE.", nameof(tombstoneOwner));
        if (previous is not null &&
            (!string.Equals(previous.DestinationPath, fullDestination,
                StringComparison.OrdinalIgnoreCase) ||
             previous.ProcessId != processId ||
             !string.Equals(previous.RequestorSid, requestorSid, StringComparison.OrdinalIgnoreCase) ||
             previous.RequestorProcessCreationTime != requestorProcessCreationTime ||
             !string.Equals(Path.GetDirectoryName(previous.StagePath), _root,
                 StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("The earlier stage does not belong to this writer and destination.");
        }

        // FILE_OPEN and FILE_OPEN_IF must see the previous bytes. Truncating
        // dispositions need a real empty backing before upper-stream admission.
        string? source = previous?.StagePath;
        bool sourceExists = tombstoneOwner is null &&
            (source is null ? File.Exists(fullDestination) : File.Exists(source));
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
            if (OperatingSystem.IsWindows())
            {
                await StagedBackingFile.CreateAsync(copyExisting ? source ?? fullDestination : null,
                    transfer.StagePath, MaximumSeedBytes, cancellationToken).ConfigureAwait(false);
            }
            else if (copyExisting)
            {
                await using var input = new FileStream(source ?? fullDestination,
                    FileMode.Open, FileAccess.Read, FileShare.Read,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                if (input.Length > MaximumSeedBytes)
                    throw new IOException("The source exceeds the qualified private-version size limit.");
                await using var output = new FileStream(transfer.StagePath,
                    FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
                byte[] buffer = new byte[64 * 1024];
                long copied = 0;
                for (;;)
                {
                    int count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (count == 0) break;
                    if (count > MaximumSeedBytes - copied)
                        throw new IOException("The source grew beyond the qualified private-version size limit.");
                    await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                    copied += count;
                }
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
            StagedStageIdentity? parentDirectoryIdentity = allocationReservationId is null
                ? null : StagedStageFile.ReadDirectoryIdentity(Path.GetDirectoryName(fullDestination)!);
            await _journal.CreateAsync(transfer, cancellationToken, tombstoneOwner,
                previous?.TransferId, disposition, allocationReferenceId,
                allocationReferenceKind, driverInstanceId, parentDirectoryIdentity).ConfigureAwait(false);
            return transfer;
        }
        catch (Exception allocationFailure)
        {
            if (!StagedStageFile.TryDeleteUnjournaled(transfer.StagePath, out Exception? cleanupFailure))
                throw new IOException("The unjournaled allocation stage could not be safely removed.",
                    new AggregateException(allocationFailure, cleanupFailure ??
                        new IOException("The exact unjournaled stage could not be deleted.")));
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(allocationFailure).Throw();
            throw;
        }
    }

    /// <summary>
    /// Ordinary v19 allocate remains backing-first and one-shot. The exact
    /// stage identity and destination generation are committed before the
    /// typed reply, but a lost reply is not replayed as an idempotent create.
    /// </summary>
    public async Task<StagedAllocationReply> AllocateV19Async(
        string destinationPath, DestinationKind destination, string processName, int processId,
        uint sessionId, uint disposition, StagedTransfer? previous,
        CancellationToken cancellationToken, Guid? tombstoneOwner = null,
        string? requestorSid = null, long? requestorProcessCreationTime = null)
    {
        StagedTransfer transfer = await AllocateAsync(destinationPath, destination, processName,
            processId, sessionId, disposition, previous, cancellationToken, tombstoneOwner,
            requestorSid, requestorProcessCreationTime).ConfigureAwait(false);
        TransferJournalEntry entry = await _journal.ReadAsync(transfer.TransferId, cancellationToken)
            .ConfigureAwait(false);
        if (entry.State != TransferJournalState.Allocated || entry.SealedOnce ||
            entry.DestinationGeneration <= 0 || entry.StageIdentity is null)
            throw new IOException("The v19 allocation identity was not durably captured before reply.");
        entry = await _journal.ValidateAllocationReplyAsync(new StagedVersionIdentity(
                transfer.TransferId, entry.DestinationGeneration, entry.StageIdentity),
            transfer.TransferId, cancellationToken).ConfigureAwait(false);
        using StagedStageFile stage = StagedStageFile.Open(transfer.StagePath);
        if (stage.Identity != entry.StageIdentity || stage.Stream.Length < 0)
            throw new IOException("The v19 allocation stage changed before reply.");
        return new StagedAllocationReply(transfer, entry.DestinationGeneration,
            entry.StageIdentity, stage.Stream.Length);
    }

    /// <summary>
    /// Replayable ordinary v19 allocation keyed by the driver's stable
    /// reservation GUID. A manifest written before the typed reply resolves a
    /// lost reply to the exact same stage object and generation. If backing
    /// creation crashed before the manifest, the unjournaled reservation-name
    /// object is removed only by a no-follow identity-qualified delete and is
    /// recreated before the manifest becomes visible.
    /// </summary>
    public async Task<StagedAllocationReply> AllocateV19Async(
        string destinationPath, DestinationKind destination, string processName, int processId,
        uint sessionId, StagedAllocationIntentV19 intent, StagedTransfer? previous,
        Guid? tombstoneOwner, string requestorSid, long requestorProcessCreationTime,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (intent.ReservationId == Guid.Empty || intent.DriverInstanceId == Guid.Empty ||
            intent.Disposition > 5 || intent.ReferenceKind > 2 ||
            (intent.ReferenceKind == 0) != (intent.ParentTransferId == Guid.Empty) ||
            processId <= 0 || string.IsNullOrWhiteSpace(requestorSid) ||
            requestorProcessCreationTime <= 0)
            throw new ArgumentException("The v19 allocation intent is invalid.", nameof(intent));
        if ((intent.ReferenceKind == 1) != (previous is not null) ||
            (intent.ReferenceKind == 2) != (tombstoneOwner is not null) ||
            (previous is not null && previous.TransferId != intent.ParentTransferId) ||
            (tombstoneOwner is not null && tombstoneOwner != intent.ParentTransferId))
            throw new ArgumentException("The v19 allocation reference does not match its exact parent.", nameof(intent));

        await _v19AllocationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {

        string fullDestination = Path.GetFullPath(destinationPath);
        string extension = Path.GetExtension(fullDestination);
        if (string.IsNullOrEmpty(Path.GetFileName(fullDestination)) || extension.Length > 16 ||
            extension.IndexOfAny(['\\', '/', ':']) >= 0 ||
            fullDestination.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid staged destination.", nameof(destinationPath));

        var transfer = new StagedTransfer(intent.ReservationId,
            Path.Combine(_root, intent.ReservationId.ToString("N") + extension), fullDestination,
            destination, processName, processId, sessionId)
        {
            RequestorSid = requestorSid,
            RequestorProcessCreationTime = requestorProcessCreationTime
        };

        TransferJournalEntry existing;
        try
        {
            existing = await _journal.ResolveAllocationV19Async(transfer, intent, cancellationToken)
                .ConfigureAwait(false);
            using StagedStageFile stage = StagedStageFile.Open(transfer.StagePath);
            return new StagedAllocationReply(transfer, existing.DestinationGeneration,
                existing.StageIdentity!, stage.Stream.Length);
        }
        catch (FileNotFoundException)
        {
            // This reservation has no durable manifest. Any stage object at
            // its deterministic path was never returned to the driver.
        }
        catch (DirectoryNotFoundException)
        {
            // Same case: no reservation-derived manifest can be resolved.
        }

        if (!StagedStageFile.TryDeleteUnjournaled(transfer.StagePath, out Exception? cleanupFailure))
            throw new IOException("An unjournaled private reservation stage could not be safely replaced.",
                cleanupFailure);

        StagedTransfer created = await AllocateAsync(fullDestination, destination, processName,
            processId, sessionId, intent.Disposition, previous, cancellationToken,
            tombstoneOwner, requestorSid, requestorProcessCreationTime,
            intent.ReservationId, intent.ParentTransferId == Guid.Empty ? null : intent.ParentTransferId,
            intent.ReferenceKind, intent.DriverInstanceId).ConfigureAwait(false);
        TransferJournalEntry entry = await _journal.ReadAsync(created.TransferId, cancellationToken)
            .ConfigureAwait(false);
        if (entry.State != TransferJournalState.Allocated || entry.SealedOnce ||
            entry.DestinationGeneration <= 0 || entry.StageIdentity is null)
            throw new IOException("The v19 allocation identity was not durably captured before reply.");
        entry = await _journal.ValidateAllocationReplyAsync(new StagedVersionIdentity(
                created.TransferId, entry.DestinationGeneration, entry.StageIdentity),
            created.TransferId, cancellationToken).ConfigureAwait(false);
        using StagedStageFile createdStage = StagedStageFile.Open(created.StagePath);
        if (createdStage.Identity != entry.StageIdentity)
            throw new IOException("The v19 allocation stage changed before reply.");
        return new StagedAllocationReply(created, entry.DestinationGeneration,
            entry.StageIdentity, createdStage.Stream.Length);
        }
        finally
        {
            _v19AllocationGate.Release();
        }
    }

    /// <summary>
    /// CREATE_AFTER_DISCARD is journal-first and replayable by its stable
    /// reservation. The V2 delete/head and V3 allocated manifest commit before
    /// this method creates the V3 backing file or returns it to the driver.
    /// </summary>
    public async Task<StagedAllocationReply> CreateAfterPrivateDiscardAsync(
        StagedCreateAfterDiscardRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _v19AllocationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
        string destination = Path.GetFullPath(request.DestinationPath);
        string extension = Path.GetExtension(destination);
        if (extension.Length > 16 || extension.IndexOfAny(['\\', '/', ':']) >= 0 ||
            string.IsNullOrEmpty(Path.GetFileName(destination)) ||
            destination.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid staged destination.", nameof(request));

        TransferJournalEntry delete = await _journal.ReadAsync(request.DeleteVersion.TransferId,
            cancellationToken).ConfigureAwait(false);
        var transfer = new StagedTransfer(request.ReservationId,
            Path.Combine(_root, request.ReservationId.ToString("N") + extension), destination,
            request.Destination, delete.Transfer.ProcessName, request.ProcessId, request.SessionId)
        {
            RequestorSid = request.RequestorSid,
            RequestorProcessCreationTime = request.RequestorProcessCreationTime
        };

        StagedCreateAfterIntentResult intentResult = await _journal.CreateAfterPrivateDiscardIntentAsync(
            request with { DestinationPath = destination }, transfer, cancellationToken).ConfigureAwait(false);
        TransferJournalEntry intent = intentResult.Entry;
        if (intent.StageIdentity is null && !File.Exists(transfer.StagePath))
        {
            if (OperatingSystem.IsWindows())
            {
                await StagedBackingFile.CreateAsync(null, transfer.StagePath, MaximumSeedBytes,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await using var output = new FileStream(transfer.StagePath, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
                output.Flush(flushToDisk: true);
            }
        }

        if (_fileSecurity is not null)
            new FileInfo(transfer.StagePath).SetAccessControl(_fileSecurity);
        TransferJournalEntry captured = await _journal.CaptureAllocationIdentityAsync(
            transfer.TransferId, request.ReservationId, cancellationToken,
            requireCurrentDestination: !intentResult.IsReplay).ConfigureAwait(false);
        if (captured.State != TransferJournalState.Allocated || captured.SealedOnce ||
            captured.StageIdentity is null || captured.DestinationGeneration <= 0)
            throw new IOException("The create-after stage identity was not durably captured before reply.");
        captured = await _journal.ValidateAllocationReplyAsync(new StagedVersionIdentity(
                transfer.TransferId, captured.DestinationGeneration, captured.StageIdentity),
            request.ReservationId, cancellationToken,
            requireCurrentDestination: !intentResult.IsReplay).ConfigureAwait(false);
        using StagedStageFile stage = StagedStageFile.Open(transfer.StagePath);
        if (stage.Identity != captured.StageIdentity || stage.Stream.Length < 0)
            throw new IOException("The create-after stage changed before reply.");
        return new StagedAllocationReply(transfer, captured.DestinationGeneration,
            captured.StageIdentity, stage.Stream.Length);
        }
        finally
        {
            _v19AllocationGate.Release();
        }
    }
}
