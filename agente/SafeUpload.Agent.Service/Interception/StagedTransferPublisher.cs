using System.Security.Cryptography;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Releases a completed local staging file only after its immutable version
/// has received an inspected approval. The minifilter must supply the staging
/// file and must keep every direct write to the destination behind its gate.
/// </summary>
public sealed class StagedTransferPublisher
{
    private readonly InspectionService _inspection;
    private readonly NotificationHub _notifications;
    private readonly StagedTransferJournal _journal;
    private readonly string _stagingRoot;
    private readonly StagedJustifications? _justifications;
    private readonly IStagedPublicationGate _publicationGate;
    private readonly IStagedHandbackCopier? _handbackCopier;
    private readonly Func<uint, string?> _sessionUserSidResolver;
    private readonly ILogger? _logger;
    private sealed record JustifiedVersion(string Digest, int PolicyVersion);

    public StagedTransferPublisher(
        InspectionService inspection,
        NotificationHub notifications,
        StagedTransferJournal journal,
        string stagingRoot,
        IStagedPublicationGate publicationGate,
        StagedJustifications? justifications = null,
        ILogger? logger = null,
        IPolicyStore? policyStore = null,
        IStagedHandbackCopier? handbackCopier = null,
        Func<uint, string?>? sessionUserSidResolver = null)
    {
        _inspection = inspection ?? throw new ArgumentNullException(nameof(inspection));
        _notifications = notifications ?? throw new ArgumentNullException(nameof(notifications));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _stagingRoot = Path.GetFullPath(stagingRoot);
        _justifications = justifications;
        _publicationGate = publicationGate ?? throw new ArgumentNullException(nameof(publicationGate));
        _handbackCopier = handbackCopier ?? (policyStore is null ? null : new StagedHandbackCopier(policyStore));
        _sessionUserSidResolver = sessionUserSidResolver ??
            (sessionId => SessionResolver.TryGetSessionUserSid(sessionId)?.Value);
        _logger = logger;
    }

    public Task<StagedTransferOutcome> PublishAsync(
        StagedTransfer transfer,
        CancellationToken cancellationToken)
        => PublishCoreAsync(transfer, null, cancellationToken);

    private async Task<StagedTransferOutcome> PublishCoreAsync(
        StagedTransfer transfer, JustifiedVersion? justified,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transfer);

        string stagePath = Path.GetFullPath(transfer.StagePath);
        string relativePath = Path.GetRelativePath(_stagingRoot, stagePath);
        if (relativePath is "." or ".." ||
            Path.IsPathRooted(relativePath) ||
            relativePath.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException("The staging file must be inside the private staging root.", nameof(transfer));
        }

        string destinationPath = Path.GetFullPath(transfer.DestinationPath);
        string fileName = Path.GetFileName(destinationPath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentException("The destination must name a file.", nameof(transfer));
        }

        var journalEntry = await _journal.ReadAsync(transfer.TransferId, cancellationToken)
            .ConfigureAwait(false);
        if (journalEntry.PendingRename is not null || journalEntry.Transfer != transfer || !journalEntry.SealedOnce ||
            (justified is null
                ? journalEntry.State is not (TransferJournalState.Sealed or TransferJournalState.Retained)
                : journalEntry.State != TransferJournalState.Blocked))
        {
            throw new InvalidOperationException("The transfer must be sealed in the service journal.");
        }

        // Reject symbolic links and junctions in the stage path. A service
        // must never scan one file and publish another through a reparse point.
        for (string? path = stagePath; path is not null &&
             !string.Equals(path, Path.GetDirectoryName(_stagingRoot), StringComparison.OrdinalIgnoreCase);
             path = Path.GetDirectoryName(path))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("Staging contains a reparse point.");
            }
        }

        // FileShare.Read lets the inspector open the same bytes, but denies
        // existing and new writable handles until publication completes.
        FileStream sealedFile;
        try
        {
            sealedFile = new FileStream(
                stagePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete,
                bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (IOException)
        {
            // The last cleanup signal can reach the journal before NTFS has
            // finished closing the writer. Leave Sealed for the worker's next
            // attempt; no analysis or publication has started yet.
            return StagedTransferOutcome.Retained;
        }

        await using var lockedFile = sealedFile;
        await _journal.TransitionAsync(transfer.TransferId, journalEntry.State,
            TransferJournalState.Inspecting, null, cancellationToken, transfer,
            closeJustificationWindow: justified is not null).ConfigureAwait(false);
        // File sharing does not revoke an already mapped writable section.
        // Inspect and publish a separate service-only snapshot, so even a
        // delayed paging write cannot change the inspected publication bytes.
        await using var snapshot = await InspectionSnapshot.CreateAsync(
            sealedFile, _stagingRoot, Path.GetExtension(destinationPath), cancellationToken)
            .ConfigureAwait(false);
        FileStream inspectedFile = snapshot.Stream;
        string inspectedDigest = Convert.ToHexString(
            await SHA256.HashDataAsync(inspectedFile, cancellationToken).ConfigureAwait(false));
        inspectedFile.Position = 0;
        if (justified is not null && !string.Equals(inspectedDigest, justified.Digest,
                StringComparison.Ordinal))
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }
        PublishTransferNotification(transfer, new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Analyzing));

        var info = new FileInfo(stagePath);
        var operation = new FileOperation(
            snapshot.Path,
            fileName,
            Path.GetExtension(destinationPath).ToLowerInvariant(),
            inspectedFile.Length,
            info.LastWriteTimeUtc,
            transfer.ProcessName,
            transfer.ProcessId,
            destinationPath,
            transfer.Destination);

        InspectionResult result;
        try
        {
            result = await _inspection.InspectStagedAsync(operation, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged inspection failed for {TransferId}.", transfer.TransferId);
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, CancellationToken.None).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }

        // A justification authorizes precisely the previously inspected
        // digest and policy. Reinspect under the read lock and recheck policy;
        // service restart, changed bytes or changed policy revoke it.
        bool justifiedApproval = justified is not null && result.IsBlocked &&
            result.PolicyVersion == justified.PolicyVersion &&
            await _inspection.IsCurrentStagedJustificationAllowedAsync(
                operation, result, cancellationToken).ConfigureAwait(false);
        if (result.IsBlocked && !justifiedApproval)
        {
            bool ownerSessionMatches = TryGetBoundSession(transfer, out _, out _);
            bool canJustify = false;
            if (ownerSessionMatches && _justifications is not null)
            {
                try
                {
                    canJustify = await _inspection.IsCurrentStagedJustificationAllowedAsync(
                        operation, result, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception) when (!cancellationToken.IsCancellationRequested)
                {
                    // Policy read failure closes the exception window, but
                    // does not suppress the required blocked hand-back.
                }
            }
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset? expires = canJustify ? now + PendingOverrides.Window : null;
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Blocked,
                inspectedDigest, cancellationToken, blockedEvidence: new BlockedTransferEvidence(
                    result.PolicyVersion, expires, WindowClosed: !canJustify)).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Blocked, result.Reason, cancellationToken,
                transfer.TransferId).ConfigureAwait(false);
            TransferJournalEntry blocked = ownerSessionMatches
                ? await HandbackSnapshotAsync(transfer, snapshot.Stream, inspectedFile.Length,
                    inspectedDigest, operation, result, cancellationToken).ConfigureAwait(false)
                : await RecordHandbackFailureAsync(transfer, operation, result,
                    "requestor_identity_unavailable", CancellationToken.None).ConfigureAwait(false);
            canJustify = canJustify && blocked.HandbackState == StagedHandbackState.Verified &&
                expires is { } expiryAfterCopy && expiryAfterCopy > DateTimeOffset.UtcNow;
            if (!canJustify && !blocked.JustificationWindowClosed)
            {
                blocked = await _journal.CloseJustificationWindowAsync(transfer.TransferId,
                    DateTimeOffset.UtcNow, CancellationToken.None, force: true).ConfigureAwait(false);
            }
            if (canJustify)
            {
                var version = new JustifiedVersion(inspectedDigest, result.PolicyVersion);
                _justifications!.Remember(transfer.TransferId, transfer.SessionId!.Value,
                    transfer.RequestorSid!,
                    async token => await PublishCoreAsync(transfer, version, token).ConfigureAwait(false)
                        == StagedTransferOutcome.Released, expires);
            }
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Blocked,
                Findings: result.Findings,
                OverrideAllowed: canJustify,
                HandbackPath: blocked.HandbackPath,
                HandbackVerified: blocked.HandbackState == StagedHandbackState.Verified,
                SnapshotSha256Hex: inspectedDigest));
            return StagedTransferOutcome.Blocked;
        }

        bool currentApproval = justifiedApproval;
        if (result.InScope && result.Verdict == Verdict.Approved)
        {
            try
            {
                currentApproval = await _inspection.IsCurrentStagedApprovalAsync(
                    operation, result, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // An unreadable policy is not permission to publish.
            }
        }

        if (!currentApproval)
        {
            // Oversize, timeout, unsupported format, parser errors, and a
            // changed policy all keep the staged bytes local.
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained,
                result.Verdict == Verdict.Approved ? "policy_changed" : result.Reason ?? "not_inspected",
                cancellationToken, transfer.TransferId).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }

        string directory = Path.GetDirectoryName(destinationPath)!;
        string temporaryDestination = Path.Combine(directory, ".safeupload-" +
            transfer.TransferId.ToString("N") + ".pending");

        // The digest belongs to the same locked version the inspector read.
        sealedFile.Position = 0;
        string digest = Convert.ToHexString(
            await SHA256.HashDataAsync(sealedFile, cancellationToken).ConfigureAwait(false));
        sealedFile.Position = 0;
        if (!string.Equals(digest, inspectedDigest, StringComparison.Ordinal))
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, "stage_changed_during_inspection", cancellationToken,
                transfer.TransferId).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            digest, cancellationToken).ConfigureAwait(false);
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Approved, TransferJournalState.Publishing,
            null, cancellationToken).ConfigureAwait(false);

        bool committed = false;
        try
        {
            _logger?.LogDebug("Requesting kernel publication permission for {TransferId}.", transfer.TransferId);
            using var permit = _publicationGate.Authorize(transfer, temporaryDestination, digest);
            _logger?.LogDebug("Creating approved publication file for {TransferId}.", transfer.TransferId);
            using (var output = StagedDestinationFile.CreateUnbuffered(temporaryDestination))
            {
                try
                {
                    _logger?.LogDebug("Approved publication file opened for {TransferId}.", transfer.TransferId);
                    await StagedDestinationFile.WriteUnbufferedAsync(output, inspectedFile, cancellationToken)
                        .ConfigureAwait(false);
                    _logger?.LogDebug("Approved publication bytes copied for {TransferId}.", transfer.TransferId);
                    _logger?.LogDebug("Renaming approved publication file for {TransferId}.", transfer.TransferId);
                    StagedDestinationFile.CommitHandle(output, destinationPath);
                    committed = true;
                }
                finally
                {
                    if (!committed) StagedDestinationFile.TryDeleteUncommitted(output);
                }
            }
            _logger?.LogDebug("Approved publication rename completed for {TransferId}.", transfer.TransferId);
        }
        catch (Exception ex) when (committed)
        {
            // A successful native rename is the publication commit point.
            // Losing the port while revoking its already-consumed permit, or
            // cancellation during disposal, cannot undo those approved bytes.
            _logger?.LogWarning(ex, "Publication committed for {TransferId}; final handle/permit cleanup failed.",
                transfer.TransferId);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged publication failed for {TransferId}.", transfer.TransferId);
            // The handle already marked an uncommitted temporary for deletion; reopening the
            // name can be refused (its permit is spent), and nothing here may skip Retained.
            try { File.Delete(temporaryDestination); } catch (Exception) { }
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Publishing, TransferJournalState.Retained,
                null, CancellationToken.None).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, "publication_failed", CancellationToken.None,
                transfer.TransferId).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }

        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Publishing, TransferJournalState.Released,
            null, CancellationToken.None).ConfigureAwait(false);
        await _inspection.RecordTransferOutcomeAsync(operation, result,
            Verdict.Approved, justifiedApproval ? "justified_version" : null,
            CancellationToken.None, transfer.TransferId, digest).ConfigureAwait(false);

        PublishTransferNotification(transfer, new TransferNotification(
            transfer.TransferId, fileName, TransferPhase.Released,
            PublishedSha256Hex: digest));
        if (justifiedApproval)
        {
            TransferJournalEntry releasedEntry = await _journal.ReadAsync(
                transfer.TransferId, CancellationToken.None).ConfigureAwait(false);
            await ProcessBlockedCleanupAsync(releasedEntry, CancellationToken.None).ConfigureAwait(false);
        }
        return StagedTransferOutcome.Released;
    }

    /// <summary>Restores a blocked hand-back and lease after a service restart.</summary>
    public async Task RecoverBlockedAsync(TransferJournalEntry entry, CancellationToken token)
    {
        if (entry.State != TransferJournalState.Blocked || entry.PendingRename is not null) return;
        TransferJournalEntry current = entry;
        if (!TryGetBoundSession(current.Transfer, out _, out _))
        {
            await RecordOwnerIdentityFailureAsync(current, "requestor_identity_unavailable", token)
                .ConfigureAwait(false);
            return;
        }

        if (entry.HandbackState is StagedHandbackState.NotAttempted or
            StagedHandbackState.Copying)
        {
            string stagePath = Path.GetFullPath(entry.Transfer.StagePath);
            try
            {
                RequirePrivateStagePath(stagePath);
                await using var source = new FileStream(stagePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using InspectionSnapshot snapshot = await InspectionSnapshot.CreateAsync(
                    source, _stagingRoot, Path.GetExtension(entry.Transfer.DestinationPath), token)
                    .ConfigureAwait(false);
                string digest = Convert.ToHexString(await SHA256.HashDataAsync(
                    snapshot.Stream, token).ConfigureAwait(false));
                if (snapshot.Stream.Length != source.Length ||
                    !string.Equals(digest, entry.Sha256Hex, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("The blocked staging version no longer matches its journal digest.");
                var operation = OperationFor(entry.Transfer, snapshot.Stream.Length,
                    new DateTimeOffset(File.GetLastWriteTimeUtc(stagePath), TimeSpan.Zero));
                var result = new InspectionResult(Verdict.Blocked, [], null, 0, false,
                    entry.BlockedPolicyVersion, true);
                current = await HandbackSnapshotAsync(entry.Transfer, snapshot.Stream,
                    snapshot.Stream.Length, digest, operation, result, token).ConfigureAwait(false);
            }
            catch (Exception ex) when (!token.IsCancellationRequested)
            {
                _logger?.LogWarning(ex, "Could not recover staged hand-back for {TransferId}.",
                    entry.Transfer.TransferId);
                current = await RecordHandbackFailureAsync(entry.Transfer,
                    OperationFor(entry.Transfer, 0, DateTimeOffset.UtcNow),
                    new InspectionResult(Verdict.Blocked, [], null, 0, false,
                        entry.BlockedPolicyVersion, true), "sealed_snapshot_unavailable", CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
        else if (entry.HandbackState == StagedHandbackState.Failed && _handbackCopier is not null)
        {
            try { _handbackCopier.CleanupUncommittedTemporary(entry.Transfer); }
            catch (Exception ex) when (!token.IsCancellationRequested)
            {
                _logger?.LogWarning(ex, "Could not clean the service temporary for {TransferId}.",
                    entry.Transfer.TransferId);
            }
        }

        if (current.State != TransferJournalState.Blocked) return;
        if (current.HandbackState == StagedHandbackState.Verified)
        {
            try
            {
                if (_handbackCopier is null || current.HandbackPath is null ||
                    current.HandbackLength is not { } handbackLength || current.Sha256Hex is null)
                    throw new IOException("The verified hand-back evidence is incomplete.");
                using IDisposable lease = _handbackCopier.OpenVerifiedReadLease(current.Transfer,
                    current.HandbackPath, handbackLength, current.Sha256Hex);
            }
            catch (Exception ex) when (!token.IsCancellationRequested)
            {
                _logger?.LogWarning(ex, "Recovered hand-back no longer verifies for {TransferId}.",
                    current.Transfer.TransferId);
                current = await RecordInvalidHandbackAsync(current, "handback_reverification_failed",
                    CancellationToken.None).ConfigureAwait(false);
            }
        }
        bool justificationOpen = !current.JustificationWindowClosed &&
            current.JustificationExpiresAtUtc is { } expiry && expiry > DateTimeOffset.UtcNow;
        if (justificationOpen && current.HandbackState == StagedHandbackState.Verified &&
            current.BlockedPolicyVersion > 0 && current.JustificationExpiresAtUtc is { } expiryAt &&
            current.Transfer.SessionId is { } session &&
            _justifications is not null && current.Sha256Hex is { } sealedDigest)
        {
            var version = new JustifiedVersion(sealedDigest, current.BlockedPolicyVersion);
            _justifications.Remember(current.Transfer.TransferId, session,
                current.Transfer.RequestorSid!,
                async retry => await PublishCoreAsync(current.Transfer, version, retry).ConfigureAwait(false)
                    == StagedTransferOutcome.Released, expiryAt);
        }

        if (current.HandbackState is StagedHandbackState.Verified or StagedHandbackState.Failed)
        {
            PublishTransferNotification(current.Transfer, new TransferNotification(current.Transfer.TransferId,
                Path.GetFileName(current.Transfer.DestinationPath), TransferPhase.Blocked,
                OverrideAllowed: justificationOpen && current.HandbackState == StagedHandbackState.Verified,
                HandbackPath: current.HandbackPath,
                HandbackVerified: current.HandbackState == StagedHandbackState.Verified,
                SnapshotSha256Hex: current.Sha256Hex));
        }
        if (current.HandbackState != StagedHandbackState.Verified && !current.JustificationWindowClosed)
            current = await _journal.CloseJustificationWindowAsync(current.Transfer.TransferId,
                DateTimeOffset.UtcNow, token, force: true).ConfigureAwait(false);
        await ProcessBlockedCleanupAsync(current, token).ConfigureAwait(false);
    }

    public async Task ProcessBlockedCleanupAsync(TransferJournalEntry entry, CancellationToken token)
    {
        if (entry.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
            entry.StageDeleted) return;
        TransferJournalEntry current = entry;
        if (!TryGetBoundSession(current.Transfer, out _, out _))
        {
            await RecordOwnerIdentityFailureAsync(current, "requestor_identity_unavailable", token)
                .ConfigureAwait(false);
            return;
        }
        if (current.State == TransferJournalState.Blocked && !current.JustificationWindowClosed)
            current = await _journal.CloseJustificationWindowAsync(current.Transfer.TransferId,
                DateTimeOffset.UtcNow, token).ConfigureAwait(false);
        if (current.HandbackState != StagedHandbackState.Verified || !current.JustificationWindowClosed)
            return;
        if (current.StageCleanupStarted &&
            DateTimeOffset.UtcNow - current.UpdatedAtUtc < TimeSpan.FromSeconds(30))
            return;

        current = await _journal.TryBeginStageCleanupAsync(current.Transfer.TransferId, token)
            .ConfigureAwait(false);
        if (!current.StageCleanupStarted || current.StageDeleted) return;

        try
        {
            bool stageMissing = false;
            long stageLength = current.HandbackLength ?? 0;
            try
            {
                RequirePrivateStagePath(current.Transfer.StagePath);
                await using var stage = new FileStream(current.Transfer.StagePath, FileMode.Open,
                    FileAccess.Read, FileShare.Read, 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                long length = stage.Length;
                stageLength = length;
                string digest = Convert.ToHexString(await SHA256.HashDataAsync(stage, token)
                    .ConfigureAwait(false));
                if (stage.Length != length || length < 0 ||
                    !string.Equals(digest, current.Sha256Hex, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Staging changed after hand-back verification; it was retained.");
            }
            catch (FileNotFoundException) { stageMissing = true; }
            catch (DirectoryNotFoundException) { stageMissing = true; }

            if (_handbackCopier is null || current.HandbackPath is null || current.Sha256Hex is null)
                throw new IOException("The verified hand-back cannot be reopened for cleanup.");
            IDisposable handbackLease;
            try
            {
                handbackLease = _handbackCopier.OpenVerifiedReadLease(current.Transfer,
                    current.HandbackPath, current.HandbackLength ?? stageLength, current.Sha256Hex);
            }
            catch (Exception ex) when (!token.IsCancellationRequested)
            {
                _logger?.LogWarning(ex, "Hand-back changed before stage cleanup for {TransferId}.",
                    current.Transfer.TransferId);
                await RecordInvalidHandbackAsync(current, "handback_reverification_failed",
                    CancellationToken.None).ConfigureAwait(false);
                return;
            }

            using (handbackLease)
            {
            if (!stageMissing)
                File.Delete(current.Transfer.StagePath);
            await _journal.CompleteStageCleanupAsync(current.Transfer.TransferId, token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (!token.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Could not remove verified blocked stage {TransferId}.",
                current.Transfer.TransferId);
            var operation = OperationFor(current.Transfer, 0, DateTimeOffset.UtcNow);
            var result = new InspectionResult(Verdict.Blocked, [], null, 0, false,
                current.BlockedPolicyVersion, true);
            await _inspection.RecordTransferOutcomeAsync(operation, result, Verdict.Retained,
                "blocked_cleanup_failed", CancellationToken.None, Guid.NewGuid()).ConfigureAwait(false);
        }
    }

    private async Task<TransferJournalEntry> HandbackSnapshotAsync(StagedTransfer transfer,
        FileStream snapshot, long length, string digest, FileOperation operation,
        InspectionResult result, CancellationToken token)
    {
        try
        {
            if (!TryGetBoundSession(transfer, out _, out _))
                throw new UnauthorizedAccessException("The current session does not match the staged requestor SID.");
            await _journal.BeginHandbackAttemptAsync(transfer.TransferId, token).ConfigureAwait(false);
            if (_handbackCopier is null)
                throw new IOException("No Windows user-profile hand-back provider is available.");
            string path = await _handbackCopier.CopyVerifiedAsync(transfer, snapshot, length,
                digest, token).ConfigureAwait(false);
            return await _journal.CompleteHandbackAsync(transfer.TransferId, path, length, null, token)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (!token.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged hand-back failed for {TransferId}.", transfer.TransferId);
            return await RecordHandbackFailureAsync(transfer, operation, result,
                "handback_failed", CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task<TransferJournalEntry> RecordHandbackFailureAsync(StagedTransfer transfer,
        FileOperation operation, InspectionResult result, string reason,
        CancellationToken token)
    {
        TransferJournalEntry current = await _journal.ReadAsync(transfer.TransferId, token).ConfigureAwait(false);
        if (current.State == TransferJournalState.Blocked && !current.StageCleanupStarted &&
            current.HandbackState is not (StagedHandbackState.Verified or StagedHandbackState.Failed))
        {
            current = await _journal.CompleteHandbackAsync(transfer.TransferId, null, null, reason, token)
                .ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result, Verdict.Retained,
                reason, CancellationToken.None, Guid.NewGuid()).ConfigureAwait(false);
        }
        return current;
    }

    private bool TryGetBoundSession(StagedTransfer transfer, out uint sessionId, out string sid)
    {
        sessionId = 0;
        sid = string.Empty;
        if (transfer.SessionId is not { } storedSession || string.IsNullOrWhiteSpace(transfer.RequestorSid) ||
            transfer.RequestorSid.Length > 184 || !transfer.RequestorSid.StartsWith("S-",
                StringComparison.OrdinalIgnoreCase))
            return false;
        string? currentSid;
        try { currentSid = _sessionUserSidResolver(storedSession); }
        catch { return false; }
        if (string.IsNullOrWhiteSpace(currentSid) ||
            !string.Equals(currentSid, transfer.RequestorSid, StringComparison.OrdinalIgnoreCase))
            return false;
        sessionId = storedSession;
        sid = transfer.RequestorSid;
        return true;
    }

    private void PublishTransferNotification(StagedTransfer transfer, TransferNotification notification)
    {
        if (TryGetBoundSession(transfer, out uint sessionId, out string sid))
            _notifications.Publish(notification, sessionId, sid);
    }

    private async Task<TransferJournalEntry> RecordOwnerIdentityFailureAsync(
        TransferJournalEntry current, string reason, CancellationToken token)
    {
        if (current.HandbackState == StagedHandbackState.Failed) return current;
        TransferJournalEntry failed;
        if (current.HandbackState == StagedHandbackState.Verified)
        {
            var invalidation = await _journal.InvalidateHandbackAsync(
                current.Transfer.TransferId, reason, token).ConfigureAwait(false);
            failed = invalidation.Entry;
            bool invalidated = invalidation.Invalidated;
            if (!invalidated && failed.State == TransferJournalState.Blocked &&
                !failed.JustificationWindowClosed)
                failed = await _journal.CloseJustificationWindowAsync(failed.Transfer.TransferId,
                    DateTimeOffset.UtcNow, token, force: true).ConfigureAwait(false);
            if (!invalidated) return failed;
        }
        else if (current.State == TransferJournalState.Blocked && !current.StageCleanupStarted)
        {
            failed = await _journal.CompleteHandbackAsync(current.Transfer.TransferId,
                null, null, reason, token).ConfigureAwait(false);
        }
        else return current;

        if (failed.State == TransferJournalState.Blocked && !failed.JustificationWindowClosed)
            failed = await _journal.CloseJustificationWindowAsync(failed.Transfer.TransferId,
                DateTimeOffset.UtcNow, token, force: true).ConfigureAwait(false);
        var operation = OperationFor(failed.Transfer, failed.HandbackLength ?? 0, DateTimeOffset.UtcNow);
        var result = new InspectionResult(Verdict.Blocked, [], null, 0, false,
            failed.BlockedPolicyVersion, true);
        await _inspection.RecordTransferOutcomeAsync(operation, result, Verdict.Retained,
            reason, CancellationToken.None, Guid.NewGuid()).ConfigureAwait(false);
        return failed;
    }

    private async Task<TransferJournalEntry> RecordInvalidHandbackAsync(
        TransferJournalEntry current, string reason, CancellationToken token)
    {
        if (current.HandbackState == StagedHandbackState.Failed) return current;
        var invalidation = await _journal.InvalidateHandbackAsync(
            current.Transfer.TransferId, reason, token).ConfigureAwait(false);
        TransferJournalEntry failed = invalidation.Entry;
        bool invalidated = invalidation.Invalidated;
        if (!invalidated) return failed;
        var operation = OperationFor(failed.Transfer, failed.HandbackLength ?? 0, DateTimeOffset.UtcNow);
        var result = new InspectionResult(Verdict.Blocked, [], null, 0, false,
            failed.BlockedPolicyVersion, true);
        await _inspection.RecordTransferOutcomeAsync(operation, result, Verdict.Retained,
            reason, CancellationToken.None, Guid.NewGuid()).ConfigureAwait(false);
        return failed;
    }

    private static FileOperation OperationFor(StagedTransfer transfer, long length,
        DateTimeOffset lastWriteUtc) => new(transfer.StagePath,
        Path.GetFileName(transfer.DestinationPath), Path.GetExtension(transfer.DestinationPath),
        length, lastWriteUtc, transfer.ProcessName, transfer.ProcessId,
        transfer.DestinationPath, transfer.Destination);

    private void RequirePrivateStagePath(string path)
    {
        string relative = Path.GetRelativePath(_stagingRoot, path);
        if (relative is "." or ".." || Path.IsPathRooted(relative) ||
            relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new IOException("The blocked stage is outside the private staging root.");
        for (string? current = Path.GetDirectoryName(path); current is not null &&
             !string.Equals(current, Path.GetDirectoryName(_stagingRoot), StringComparison.OrdinalIgnoreCase);
             current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Blocked staging contains a reparse point.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Blocked staging contains a reparse point.");
    }

    private sealed class InspectionSnapshot : IAsyncDisposable
    {
        public string Path { get; }
        public FileStream Stream { get; }
        private InspectionSnapshot(string path, FileStream stream) => (Path, Stream) = (path, stream);

        public static async Task<InspectionSnapshot> CreateAsync(FileStream source,
            string root, string extension, CancellationToken token)
        {
            string path = System.IO.Path.Combine(root, Guid.NewGuid().ToString("N") +
                ".inspection" + extension);
            try
            {
                await using (var output = new FileStream(path, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 64 * 1024,
                    FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    source.Position = 0;
                    await source.CopyToAsync(output, token).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                source.Position = 0;
                return new(path, new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan));
            }
            catch
            {
                if (File.Exists(path)) File.Delete(path);
                throw;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Stream.DisposeAsync().ConfigureAwait(false);
            File.Delete(Path);
        }
    }
}

public sealed record StagedTransfer(
    Guid TransferId,
    string StagePath,
    string DestinationPath,
    DestinationKind Destination,
    string ProcessName,
    int ProcessId,
    uint? SessionId)
{
    /// <summary>Requestor token SID captured while handling the kernel allocation request.</summary>
    public string? RequestorSid { get; init; }

    /// <summary>Process creation FILETIME captured with RequestorSid to detect PID reuse.</summary>
    public long? RequestorProcessCreationTime { get; init; }
}

public enum StagedTransferOutcome
{
    Released,
    Blocked,
    Retained
}
