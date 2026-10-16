using System.Security.Cryptography;
using SafeUpload.Agent.Core.Application;
using SafeUpload.Agent.Core.Contracts;
using SafeUpload.Agent.Core.Domain;
using StageDisposeOutcome = SafeUpload.Agent.Minifilter.StageDisposeOutcome;
using SafeUpload.Agent.Service.Notifications;

namespace SafeUpload.Agent.Service.Interception;

/// <summary>
/// Releases a completed local staging file only after its immutable version
/// has received an inspected approval. The minifilter must supply the staging
/// file and must keep every direct write to the destination behind its gate.
/// </summary>
public sealed partial class StagedTransferPublisher
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
    private readonly SemaphoreSlim _blockedCleanupGate = new(1, 1);
    // Native acceptance survives a failed journal acknowledgement during this
    // service run. It authorizes bookkeeping only; losing it in a process crash
    // before durable acceptance leaves an explicit recovery hold.
    private readonly Dictionary<Guid, StagedBlockedDeletionReceipt> _blockedDeletionReceipts = new();
#if SAFEUPLOAD_ADMISSION_EVIDENCE
    // Rebound only after the preceding connection's workers/continuations drain.
    internal StagedBoundPublicationDispatcher? BoundPublication { get; set; }
#endif
    private sealed record JustifiedVersion(string Digest, int PolicyVersion, string PolicyFingerprint);

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
        _handbackCopier = handbackCopier ?? (policyStore is null ? null : new StagedHandbackCopier(policyStore, journal));
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
        if (HasConfirmedPublication(transfer.TransferId))
            throw new IOException("The prior publication result must be recorded before this transfer can publish again.");

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
        if (justified is not null)
        {
            journalEntry = await _journal.EnforceSeedExportAsync(transfer.TransferId, cancellationToken).ConfigureAwait(false);
            if (StagedSeedExport.Failure(journalEntry) is not null ||
                journalEntry.HandbackState != StagedHandbackState.Verified || journalEntry.JustificationWindowClosed)
                return StagedTransferOutcome.Blocked;
        }
        if (journalEntry.BoundAllocation is not null)
        {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            if (BoundPublication is null)
                throw new IOException("Bound publication requires the anchored head/permit dispatcher.");
            if (journalEntry.State is TransferJournalState.Publishing or TransferJournalState.Released ||
                await BoundPublication.HasAttemptAsync(journalEntry, cancellationToken).ConfigureAwait(false))
            {
                var recovered = await BoundPublication.ReconcileAsync(journalEntry, cancellationToken).ConfigureAwait(false);
                if (!recovered.Released) ReportRecoveryHold(journalEntry, recovered.Diagnostic!, null);
                return recovered.Released ? StagedTransferOutcome.Released : StagedTransferOutcome.Retained;
            }
#else
            throw new IOException("Bound publication requires the anchored head/permit dispatcher.");
#endif
        }
        if (journalEntry.State == TransferJournalState.LegacyEmptyHeld)
        {
            journalEntry = await _journal.TryMigrateLegacyEmptyAsync(transfer.TransferId, cancellationToken)
                .ConfigureAwait(false);
            if (journalEntry.State == TransferJournalState.LegacyEmptyHeld) return StagedTransferOutcome.Retained;
        }
        if (journalEntry.UnboundCancellation is not null) return StagedTransferOutcome.Retained;
        if (journalEntry.PendingRename is not null || journalEntry.Transfer != transfer || !journalEntry.SealedOnce ||
            journalEntry.SealedLength is not >= 0 || journalEntry.StageIdentity is null ||
            (justified is null
                ? journalEntry.State is not (TransferJournalState.Sealed or TransferJournalState.Retained)
                : journalEntry.State != TransferJournalState.Blocked))
        {
            throw new InvalidOperationException("The transfer needs an identity-bound measured seal.");
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
        StagedStageFile stageFile;
        try
        {
            stageFile = StagedStageFile.Open(stagePath);
        }
        catch (IOException)
        {
            // The last cleanup signal can reach the journal before NTFS has
            // finished closing the writer. Leave Sealed for the worker's next
            // attempt; no analysis or publication has started yet.
            return StagedTransferOutcome.Retained;
        }

        using var lockedFile = stageFile;
        FileStream sealedFile = stageFile.Stream;
        if (stageFile.Identity != journalEntry.StageIdentity)
        {
            await RetainUninspectedAsync(transfer, cancellationToken).ConfigureAwait(false);
            return StagedTransferOutcome.Retained;
        }
        if (sealedFile.Length != journalEntry.SealedLength)
        {
            await RetainUninspectedAsync(transfer, cancellationToken).ConfigureAwait(false);
            return StagedTransferOutcome.Retained;
        }

        StagedFileMetadata metadata;
        try
        {
            // Also inventory the real stage: the logical seal never licenses
            // an extra stream/EA or unsupported storage on the backing object.
            StagedFileMetadata actual = StagedFileMetadata.Capture(sealedFile.SafeFileHandle);
            metadata = journalEntry.FileMetadata ?? actual;
            metadata.Validate();
        }
        catch (StagedMetadataException error)
        {
            await RetainUninspectedAsync(transfer, cancellationToken).ConfigureAwait(false);
            _logger?.LogWarning(error, "Staged metadata refused for {TransferId}: {Reason}.", transfer.TransferId, error.Reason);
            PublishTransferNotification(transfer, new TransferNotification(transfer.TransferId, fileName, TransferPhase.Retained,
                RecoveryAdvice: StagedRecoveryAdvice.UnsupportedMetadata, MetadataFailure: error.Reason));
            return StagedTransferOutcome.Retained;
        }

        await _journal.TransitionAsync(transfer.TransferId, journalEntry.State,
            TransferJournalState.Inspecting, null, cancellationToken, expectedTransfer: transfer,
            closeJustificationWindow: justified is not null, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
        // File sharing does not revoke an already mapped writable section.
        // Inspect and publish a separate service-only snapshot, so even a
        // delayed paging write cannot change the inspected publication bytes.
        StagedInspectionSnapshot snapshot;
        try
        {
            snapshot = await StagedInspectionSnapshot.CreateAsync(sealedFile, _stagingRoot,
                Path.GetExtension(destinationPath), journalEntry.SealedLength.Value, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception error) when ((error is IOException or UnauthorizedAccessException) &&
            !cancellationToken.IsCancellationRequested)
        {
            _logger?.LogWarning(error, "Staged inspection snapshot failed for {TransferId}.", transfer.TransferId);
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, CancellationToken.None, expectedTransfer: transfer, closeJustificationWindow: true, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained,
                InspectionFailure: InspectionFailureKind.ReadOrParse));
            return StagedTransferOutcome.Retained;
        }
        await using var snapshotLifetime = snapshot;
        FileStream inspectedFile = snapshot.Stream;
        string inspectedDigest = snapshot.Digest;
        if (justified is not null && !string.Equals(inspectedDigest, justified.Digest,
                StringComparison.Ordinal))
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
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
            result = await _inspection.InspectStagedAsync(operation, snapshot.OpenRead, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged inspection failed for {TransferId}.", transfer.TransferId);
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, CancellationToken.None, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained,
                InspectionFailure: InspectionFailureKind.ReadOrParse));
            return StagedTransferOutcome.Retained;
        }

        // A justification authorizes precisely the previously inspected
        // digest and policy. Reinspect under the read lock and recheck policy;
        // service restart, changed bytes or changed policy revoke it.
        bool justifiedApproval = justified is not null && result.IsBlocked &&
            result.PolicyVersion == justified.PolicyVersion &&
            result.PolicyContentFingerprint == justified.PolicyFingerprint &&
            await _inspection.IsCurrentStagedJustificationAllowedAsync(
                operation, result, cancellationToken).ConfigureAwait(false);
        if (result.IsBlocked && !justifiedApproval)
        {
            bool ownerSessionMatches = TryGetBoundSession(transfer, out _, out _);
            bool canJustify = false;
            if (ownerSessionMatches && _justifications is not null && StagedSeedExport.Failure(journalEntry) is null)
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
                    result.PolicyVersion, expires, WindowClosed: !canJustify,
                    InspectionFailure: result.FailureKind) { PolicyFingerprint = result.PolicyContentFingerprint }, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Blocked, result.Reason, cancellationToken,
                transfer.TransferId).ConfigureAwait(false);
            TransferJournalEntry blocked = await _journal.EnforceSeedExportAsync(transfer.TransferId, cancellationToken)
                .ConfigureAwait(false);
            blocked = StagedSeedExport.Failure(blocked) is not null ? blocked : HasRequestorIdentity(transfer)
                ? await HandbackSnapshotAsync(transfer, snapshot.Stream, inspectedFile.Length,
                    inspectedDigest, operation, result, cancellationToken).ConfigureAwait(false)
                : await RecordHandbackFailureAsync(transfer, operation, result,
                    "requestor_identity_unavailable", CancellationToken.None).ConfigureAwait(false);
            canJustify = canJustify && StagedSeedExport.Failure(blocked) is null &&
                blocked.HandbackState == StagedHandbackState.Verified &&
                expires is { } expiryAfterCopy && expiryAfterCopy > DateTimeOffset.UtcNow;
            if (!canJustify && !blocked.JustificationWindowClosed)
            {
                blocked = await _journal.CloseJustificationWindowAsync(transfer.TransferId,
                    DateTimeOffset.UtcNow, CancellationToken.None, force: true).ConfigureAwait(false);
            }
            if (canJustify)
            {
                var version = new JustifiedVersion(inspectedDigest, result.PolicyVersion, result.PolicyContentFingerprint!);
                canJustify = await _justifications!.RememberAsync(_journal, transfer.TransferId, transfer.SessionId!.Value,
                    transfer.RequestorSid!,
                    async token => await PublishCoreAsync(transfer, version, token).ConfigureAwait(false)
                        == StagedTransferOutcome.Released, expires, cancellationToken).ConfigureAwait(false);
            }
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Blocked,
                Findings: result.Findings,
                OverrideAllowed: canJustify,
                HandbackPath: blocked.HandbackPath,
                HandbackVerified: blocked.HandbackState == StagedHandbackState.Verified,
                SnapshotSha256Hex: inspectedDigest,
                InspectionFailure: result.FailureKind,
                BlockReason: StagedSeedExport.Failure(blocked) is null ? null : StagedBlockReason.SeedExportRestricted));
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
            // An out-of-scope result or changed/unreadable policy cannot
            // authorize publication. In-scope inspection failures take the
            // Blocked hand-back path above.
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained,
                result.Verdict == Verdict.Approved ? "policy_changed" : result.Reason ?? "not_inspected",
                cancellationToken, transfer.TransferId).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }

        string directory = Path.GetDirectoryName(destinationPath)!;
        // The digest belongs to the same locked version the inspector read.
        sealedFile.Position = 0;
        string digest = Convert.ToHexString(
            await SHA256.HashDataAsync(sealedFile, cancellationToken).ConfigureAwait(false));
        sealedFile.Position = 0;
        if (!string.Equals(digest, inspectedDigest, StringComparison.Ordinal))
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, "stage_changed_during_inspection", cancellationToken,
                transfer.TransferId).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }
        if (sealedFile.Length < 0 || inspectedFile.Length < 0 ||
            sealedFile.Length != journalEntry.SealedLength || inspectedFile.Length != journalEntry.SealedLength ||
            stageFile.Identity != journalEntry.StageIdentity)
        {
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Inspecting, TransferJournalState.Retained,
                null, cancellationToken, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, "stage_measurement_changed", cancellationToken, transfer.TransferId)
                .ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained));
            return StagedTransferOutcome.Retained;
        }
        await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Inspecting, TransferJournalState.Approved,
            digest, cancellationToken, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
        TransferJournalEntry publicationIntent = await _journal.TransitionAsync(transfer.TransferId,
            TransferJournalState.Approved, TransferJournalState.Publishing,
            null, cancellationToken, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);

#if SAFEUPLOAD_ADMISSION_EVIDENCE
        if (journalEntry.BoundAllocation is not null)
        {
            // Everything above is shared: extraction, snapshot/digest, policy,
            // justification and option-1 export checks. Never enter legacy I/O.
            var bound = await BoundPublication!.PublishAsync(publicationIntent, inspectedFile,
                async token => justifiedApproval
                    ? StagedSeedExport.Failure(await _journal.ReadAsync(transfer.TransferId, token).ConfigureAwait(false)) is null &&
                        await _inspection.IsCurrentStagedJustificationAllowedAsync(operation, result, token).ConfigureAwait(false)
                    : await _inspection.IsCurrentStagedApprovalAsync(operation, result, token).ConfigureAwait(false),
                async () => { lockedFile.Dispose(); await snapshot.DisposeAsync().ConfigureAwait(false); },
                cancellationToken).ConfigureAwait(false);
            if (!bound.Released)
            {
                QueueJournalProgress(publicationIntent);
                ReportRecoveryHold(publicationIntent, bound.Diagnostic ?? "publication_outcome_unresolved", null);
                return StagedTransferOutcome.Retained;
            }
            lockedFile.Dispose();
            await _inspection.RecordTransferOutcomeAsync(operation, result, Verdict.Approved,
                justifiedApproval ? "justified_version" : null, CancellationToken.None, transfer.TransferId, digest).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(transfer.TransferId, fileName,
                TransferPhase.Released, PublishedSha256Hex: digest));
            if (justifiedApproval) await ProcessBlockedCleanupAsync(publicationIntent, CancellationToken.None).ConfigureAwait(false);
            else await DisposeReleasedStageAsync(transfer.TransferId, CancellationToken.None).ConfigureAwait(false);
            return StagedTransferOutcome.Released;
        }
#endif

        bool committed = false;
        int publicationAttempt = 0;
        try
        {
            await StagedPublicationRetry.ExecuteAsync(async token =>
            {
                _ = StagedFileMetadata.TryCapturePath(destinationPath);
                string temporaryDestination = Path.Combine(directory, ".safeupload-" +
                    transfer.TransferId.ToString("N") +
                    (publicationAttempt++ == 0 ? "" : "-" + Guid.NewGuid().ToString("N")) + ".pending");
                _logger?.LogDebug("Requesting kernel publication permission for {TransferId}.", transfer.TransferId);
                using var permit = _publicationGate.Authorize(transfer, temporaryDestination, digest);
                using var output = StagedDestinationFile.CreateUnbuffered(temporaryDestination);
                try
                {
                    _ = StagedFileMetadata.Capture(output); // check actual inherited storage, not CREATE's NORMAL input
                    inspectedFile.Position = 0;
                    _logger?.LogDebug("Approved publication file opened for {TransferId}.", transfer.TransferId);
                    await StagedDestinationFile.WriteUnbufferedAsync(output, inspectedFile, token)
                        .ConfigureAwait(false);
                    metadata.Apply(output);
                    _logger?.LogDebug("Approved publication bytes copied for {TransferId}.", transfer.TransferId);
                    _logger?.LogDebug("Renaming approved publication file for {TransferId}.", transfer.TransferId);
                    StagedStageIdentity publishedObject = StagedDestinationFile.ReadIdentity(output);
                    var completion = new ConfirmedPublication(publicationIntent, publishedObject,
                        operation, result, justifiedApproval);
                    await _journal.CommitUnboundPublicationAsync(publicationIntent, () =>
                    {
                        // Re-inventory supported storage on the exact output.
                        // The seal's logical attributes are already applied.
                        _ = StagedFileMetadata.Capture(output);
                        _ = StagedFileMetadata.TryCapturePath(destinationPath);
                        StagedDestinationFile.CommitHandle(output, destinationPath);
                        committed = true;
                    }, cancellationToken).ConfigureAwait(false);
                    lock (_confirmedPublications) _confirmedPublications.Add(transfer.TransferId, completion);
                }
                finally
                {
                    if (!committed && !StagedDestinationFile.TryDeleteUncommitted(output))
                        throw new IOException("Uncommitted publication cleanup is unresolved; retry refused.");
                }
            }, async token =>
            {
                var current = await _journal.ReadAsync(transfer.TransferId, token).ConfigureAwait(false);
                if (current.Transfer != transfer || current.State != TransferJournalState.Publishing ||
                    current.PendingRename is not null || current.StageCleanupStarted || current.StageDeleted ||
                    current.StageIdentity != stageFile.Identity || current.SealedLength != sealedFile.Length ||
                    current.SealedLength != inspectedFile.Length || current.Sha256Hex != digest ||
                    current.FileMetadata != journalEntry.FileMetadata)
                    return false;
                sealedFile.Position = 0;
                string currentDigest = Convert.ToHexString(await SHA256.HashDataAsync(sealedFile, token).ConfigureAwait(false));
                sealedFile.Position = 0;
                if (currentDigest != digest) return false;
                return justifiedApproval
                    ? StagedSeedExport.Failure(current) is null &&
                        await _inspection.IsCurrentStagedJustificationAllowedAsync(operation, result, token).ConfigureAwait(false)
                    : await _inspection.IsCurrentStagedApprovalAsync(operation, result, token).ConfigureAwait(false);
            }, () => committed, cancellationToken).ConfigureAwait(false);
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
            // A typed sharing refusal survived successful cleanup/revocation
            // and exhausted the live retry budget. Unknown outcomes stay held.
            bool busy = ex is StagedPublicationBusyException;
            await _journal.TransitionAsync(transfer.TransferId,
                TransferJournalState.Publishing, TransferJournalState.Retained,
                null, CancellationToken.None, expectedTransfer: transfer, expectedGeneration: journalEntry.DestinationGeneration).ConfigureAwait(false);
            await _inspection.RecordTransferOutcomeAsync(operation, result,
                Verdict.Retained, ex is StagedMetadataException failure ? failure.Reason : busy ? "publication_busy" : "publication_failed", CancellationToken.None,
                transfer.TransferId).ConfigureAwait(false);
            PublishTransferNotification(transfer, new TransferNotification(
                transfer.TransferId, fileName, TransferPhase.Retained,
                RecoveryAdvice: ex is StagedMetadataException ? StagedRecoveryAdvice.UnsupportedMetadata :
                    busy ? StagedRecoveryAdvice.PublicationBusy : null,
                MetadataFailure: (ex as StagedMetadataException)?.Reason));
            return StagedTransferOutcome.Retained;
        }

        // No subsequent inspection or publication work needs the private
        // stage. Close its exact handle before the identity-bound disposer
        // runs; otherwise Windows correctly refuses deletion while it is open.
        lockedFile.Dispose();
        await FinishConfirmedPublicationAsync(transfer.TransferId, CancellationToken.None).ConfigureAwait(false);
        return StagedTransferOutcome.Released;
    }

    private async Task RetainUninspectedAsync(StagedTransfer transfer, CancellationToken token)
    {
        TransferJournalEntry current = await _journal.ReadAsync(transfer.TransferId, token).ConfigureAwait(false);
        if (current.Transfer != transfer || current.PendingRename is not null ||
            current.State is not (TransferJournalState.Sealed or TransferJournalState.Blocked) ||
            current.StageCleanupStarted || current.StageDeleted)
            return;
        await _journal.TransitionAsync(transfer.TransferId, current.State,
            TransferJournalState.Retained, null, token, transfer,
            closeJustificationWindow: current.State == TransferJournalState.Blocked).ConfigureAwait(false);
    }

    /// <summary>
    /// An approved version is published, so its stage is no longer needed. The driver may still hold the version (a
    /// program can keep the file open, rename through its handle, or start a follow-up version from the stage); then
    /// it deletes the stage once nothing references it. Otherwise the service deletes it now. A failure leaves the stage
    /// for the next service start (DisposeReleasedStagesAsync).
    /// </summary>
    public async Task DisposeReleasedStageAsync(Guid transferId, CancellationToken token)
    {
        try
        {
            TransferJournalEntry entry = await _journal.ReadAsync(transferId, token).ConfigureAwait(false);
            if (!IsDisposableRelease(entry)) return;
            uint renames = CommittedRenames(entry);
            if (_publicationGate.DisposeStage(transferId, StageDisposeOutcome.Released, renames)) return;
            // Nothing in the driver references the version, so no rename can change it any more; the journal may still
            // have moved on before the disposal was sent (a committed rename re-inspects the version): check again.
            entry = await _journal.ReadAsync(transferId, token).ConfigureAwait(false);
            if (!IsDisposableRelease(entry) || CommittedRenames(entry) != renames) return;
            RequirePrivateStagePath(entry.Transfer.StagePath);
            if (!StagedDiscardCleanup.TryDeleteExactAndConfirmAbsent(entry.Transfer.StagePath,
                    entry.StageIdentity, out Exception? deletionFailure))
                throw new IOException("The released stage identity did not match the manifest or absence was not confirmed.",
                    deletionFailure);
            var disposed = await _journal.CompleteReleasedStageDisposalAsync(
                new StagedVersionIdentity(entry.Transfer.TransferId, entry.DestinationGeneration,
                    entry.StageIdentity ?? throw new IOException("The released stage has no captured identity.")),
                token).ConfigureAwait(false);
            await _journal.ArchiveCompletedAsync(disposed, token).ConfigureAwait(false);
        }
        catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or UnauthorizedAccessException or
            System.ComponentModel.Win32Exception or InvalidOperationException or ArgumentException)
        {
            _logger?.LogWarning(ex, "Could not dispose of released stage {TransferId}; retried at the next service start.",
                transferId);
        }
    }

    private static bool IsDisposableRelease(TransferJournalEntry entry) =>
        entry.State == TransferJournalState.Released && entry.PendingRename is null &&
        entry.HandbackState == StagedHandbackState.NotAttempted && !entry.StageDeleted;

    /// <summary>Each committed rename pushes one NamespaceTombstone; the driver counts the same commits.</summary>
    private static uint CommittedRenames(TransferJournalEntry entry)
    {
        uint count = 0;
        for (var name = entry.NamespaceTombstones; name is not null; name = name.Previous) count++;
        return count;
    }

    /// <summary>Service start: approved versions whose stage is still on disk (the driver kept or lost it).</summary>
    public async Task DisposeReleasedStagesAsync(CancellationToken token)
    {
        foreach (TransferJournalEntry entry in await _journal.ReadReleasedAsync(token).ConfigureAwait(false))
        {
            token.ThrowIfCancellationRequested();
            if (HasUnfinishedCallerWork(entry.Transfer.TransferId)) continue;
            if (IsDisposableRelease(entry))
                await DisposeReleasedStageAsync(entry.Transfer.TransferId, token).ConfigureAwait(false);
            else if (entry.StageDeleted)
                await _journal.ArchiveCompletedAsync(entry, token).ConfigureAwait(false);
        }
    }

    internal async Task ArchiveCompletedTransfersAsync(CancellationToken token)
    {
        var candidates = await _journal.ReadCompletedCandidatesAsync(token).ConfigureAwait(false);
        foreach (var batch in candidates.Where(e => !HasUnfinishedCallerWork(e.Transfer.TransferId)).Chunk(16))
            await _journal.ArchiveCompletedBatchAsync(batch, token).ConfigureAwait(false);
    }

    /// <summary>The service deleted a blocked or justified stage: the driver may release the version now.</summary>
    private void DisposeCleanedUpStage(TransferJournalEntry entry)
    {
        StagedTransfer transfer = entry.Transfer;
        try { _ = _publicationGate.DisposeStage(transfer.TransferId, StageDisposeOutcome.CleanedUp, CommittedRenames(entry)); }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or ArgumentException)
        {
            // The driver also retires a version whose stage is delete-pending at its next event or service connect.
            _logger?.LogWarning(ex, "Could not report the cleaned-up stage {TransferId} to the driver.",
                transfer.TransferId);
        }
    }

    /// <summary>Restores a blocked hand-back and lease after a service restart.</summary>
    public async Task RecoverBlockedAsync(TransferJournalEntry entry, CancellationToken token)
    {
        // Recovery callers may hold an old scan result. A failed persistence
        // call may nevertheless have committed Verified, or justification may
        // already have changed the version. Always start from durable state.
        entry = await _journal.ReadAsync(entry.Transfer.TransferId, token).ConfigureAwait(false);
        if (entry.State != TransferJournalState.Blocked || entry.PendingRename is not null ||
            entry.SealedLength is not >= 0 || entry.StageIdentity is null) return;
        TransferJournalEntry current = await _journal.EnforceSeedExportAsync(entry.Transfer.TransferId, token)
            .ConfigureAwait(false);
        if (StagedSeedExport.Failure(current) is not null)
        {
            PublishSeedRestriction(current);
            return;
        }
        if (!HasRequestorIdentity(current.Transfer))
        {
            await RecordOwnerIdentityFailureAsync(current, "requestor_identity_unavailable", token)
                .ConfigureAwait(false);
            return;
        }

        if (current.StageDeleted) return;
        if (current.StageCleanupStarted || StagedTransferJournal.MatchesBlockedDeletionReceipt(current))
        {
            await ProcessBlockedCleanupAsync(current, token).ConfigureAwait(false);
            return;
        }

        if (current.BlockedPolicyFingerprint is null)
        {
            // A historical version number alone cannot restore an exception.
            // Preserve its exact backing for a fresh inspection instead of
            // reconstructing authority from today's policy or cleaning it up.
            await _journal.TransitionAsync(current.Transfer.TransferId, TransferJournalState.Blocked,
                TransferJournalState.Retained, null, token, closeJustificationWindow: true).ConfigureAwait(false);
            PublishTransferNotification(current.Transfer, new TransferNotification(current.Transfer.TransferId,
                Path.GetFileName(current.Transfer.DestinationPath), TransferPhase.Retained));
            return;
        }

        if (entry.HandbackState is StagedHandbackState.NotAttempted or
            StagedHandbackState.Copying)
        {
            string stagePath = Path.GetFullPath(entry.Transfer.StagePath);
            try
            {
                RequirePrivateStagePath(stagePath);
                using var sourceFile = StagedStageFile.Open(stagePath);
                FileStream source = sourceFile.Stream;
                if (sourceFile.Identity != entry.StageIdentity || source.Length != entry.SealedLength)
                    throw new IOException("The blocked stage no longer has its measured identity and length.");
                await using StagedInspectionSnapshot snapshot = await StagedInspectionSnapshot.CreateAsync(
                    source, _stagingRoot, Path.GetExtension(entry.Transfer.DestinationPath), entry.SealedLength.Value, token)
                    .ConfigureAwait(false);
                string digest = snapshot.Digest;
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
            catch (StagedJournalPersistenceException)
            {
                // NotAttempted/Copying remains an obligation, including if
                // the replacement succeeded but its acknowledgement failed.
                // The same recovery path retries it during this service run.
                throw;
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
        bool justificationOpen = StagedSeedExport.Failure(current) is null && !current.JustificationWindowClosed &&
            current.JustificationExpiresAtUtc is { } expiry && expiry > DateTimeOffset.UtcNow;
        if (justificationOpen && current.HandbackState == StagedHandbackState.Verified &&
            current.BlockedPolicyVersion > 0 && current.JustificationExpiresAtUtc is { } expiryAt &&
            current.Transfer.SessionId is { } session &&
            _justifications is not null && current.Sha256Hex is { } sealedDigest &&
            current.BlockedPolicyFingerprint is { } policyFingerprint)
        {
            var originalResult = new InspectionResult(Verdict.Blocked, [], null, 0, false,
                current.BlockedPolicyVersion, true) { PolicyContentFingerprint = policyFingerprint };
            bool policyStillAllows = false;
            try
            {
                policyStillAllows = await _inspection.IsCurrentStagedJustificationAllowedAsync(
                    OperationFor(current.Transfer, current.SealedLength!.Value, DateTimeOffset.UtcNow),
                    originalResult, token).ConfigureAwait(false);
            }
            catch (Exception) when (!token.IsCancellationRequested) { }
            if (!policyStillAllows)
            {
                await _journal.TransitionAsync(current.Transfer.TransferId, TransferJournalState.Blocked,
                    TransferJournalState.Retained, null, token, closeJustificationWindow: true).ConfigureAwait(false);
                PublishTransferNotification(current.Transfer, new TransferNotification(current.Transfer.TransferId,
                    Path.GetFileName(current.Transfer.DestinationPath), TransferPhase.Retained));
                return;
            }
            var version = new JustifiedVersion(sealedDigest, current.BlockedPolicyVersion, policyFingerprint);
            justificationOpen = await _justifications.RememberAsync(_journal, current.Transfer.TransferId, session,
                current.Transfer.RequestorSid!,
                async retry => await PublishCoreAsync(current.Transfer, version, retry).ConfigureAwait(false)
                    == StagedTransferOutcome.Released, expiryAt, token).ConfigureAwait(false);
        }

        if (current.HandbackState is StagedHandbackState.Verified or StagedHandbackState.Failed)
        {
            PublishTransferNotification(current.Transfer, new TransferNotification(current.Transfer.TransferId,
                Path.GetFileName(current.Transfer.DestinationPath), TransferPhase.Blocked,
                OverrideAllowed: justificationOpen && current.HandbackState == StagedHandbackState.Verified,
                HandbackPath: current.HandbackPath,
                HandbackVerified: current.HandbackState == StagedHandbackState.Verified,
                SnapshotSha256Hex: current.Sha256Hex,
                InspectionFailure: current.BlockedInspectionFailure));
        }
        if (current.HandbackState != StagedHandbackState.Verified && !current.JustificationWindowClosed)
            current = await _journal.CloseJustificationWindowAsync(current.Transfer.TransferId,
                DateTimeOffset.UtcNow, token, force: true).ConfigureAwait(false);
        await ProcessBlockedCleanupAsync(current, token).ConfigureAwait(false);
    }

    public async Task ProcessBlockedCleanupAsync(TransferJournalEntry entry, CancellationToken token)
    {
        await _blockedCleanupGate.WaitAsync(token).ConfigureAwait(false);
        try { await ProcessBlockedCleanupCoreAsync(entry, token).ConfigureAwait(false); }
        finally { _blockedCleanupGate.Release(); }
    }

    private async Task ProcessBlockedCleanupCoreAsync(TransferJournalEntry entry, CancellationToken token)
    {
        if (StagedTransferJournal.BlockedCleanupComplete(entry))
        {
            await _journal.ArchiveCompletedAsync(entry, token).ConfigureAwait(false);
            return;
        }
        entry = await _journal.ReadAsync(entry.Transfer.TransferId, token).ConfigureAwait(false);
        if (entry.SealedLength is not >= 0 || entry.StageIdentity is null ||
            entry.State is not (TransferJournalState.Blocked or TransferJournalState.Released) ||
            entry.StageDeleted) return;
        TransferJournalEntry current = await _journal.EnforceSeedExportAsync(entry.Transfer.TransferId, token)
            .ConfigureAwait(false);
        if (StagedSeedExport.Failure(current) is not null)
        {
            PublishSeedRestriction(current);
            return;
        }
        if (!HasRequestorIdentity(current.Transfer))
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
        StagedStageIdentity expectedStageIdentity = current.StageIdentity ??
            throw new IOException("The verified stage has no exact manifest identity for cleanup.");
        current = await _journal.TryBeginStageCleanupAsync(current.Transfer.TransferId, token)
            .ConfigureAwait(false);
        if (!current.StageCleanupStarted || current.StageDeleted) return;

        try
        {
            // Accepted disposition is durable before disposal. Replays finish
            // bookkeeping only, without reopening a pending object, copying a
            // hand-back, inspecting again or repeating publication.
            if (!StagedTransferJournal.MatchesBlockedDeletionReceipt(current))
            {
                if (_blockedDeletionReceipts.TryGetValue(current.Transfer.TransferId, out var accepted))
                {
                    current = await _journal.RecordBlockedDeletionAsync(current.Transfer.TransferId,
                        accepted, CancellationToken.None).ConfigureAwait(false);
                    _blockedDeletionReceipts.Remove(current.Transfer.TransferId);
                }
                else
                {
                    RequirePrivateStagePath(current.Transfer.StagePath);
                    using StagedStageFile stage = StagedStageFile.OpenBlockedDeletion(
                        current.Transfer.StagePath, expectedStageIdentity);
                    long length = stage.Stream.Length;
                    string digest = Convert.ToHexString(await SHA256.HashDataAsync(stage.Stream, token)
                        .ConfigureAwait(false));
                    if (stage.Stream.Length != length || length != current.SealedLength ||
                        !string.Equals(digest, current.Sha256Hex, StringComparison.OrdinalIgnoreCase))
                        throw new IOException("Staging changed after hand-back verification; it was retained.");
                    if (_handbackCopier is null || current.HandbackPath is null || current.Sha256Hex is null)
                        throw new IOException("The verified hand-back cannot be reopened for cleanup.");
                    IDisposable handbackLease;
                    try
                    {
                        handbackLease = _handbackCopier.OpenVerifiedReadLease(current.Transfer,
                            current.HandbackPath, current.HandbackLength ?? length, current.Sha256Hex);
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
                        stage.MarkBlockedDeletion(current.Transfer.StagePath);
                        accepted = new StagedBlockedDeletionReceipt(new StagedVersionIdentity(current.Transfer.TransferId,
                                current.DestinationGeneration, expectedStageIdentity),
                                StagedTransferJournal.CommittedRenameCount(current.NamespaceTombstones), length, current.Sha256Hex);
                        _blockedDeletionReceipts[current.Transfer.TransferId] = accepted;
                        current = await _journal.RecordBlockedDeletionAsync(current.Transfer.TransferId, accepted,
                            CancellationToken.None).ConfigureAwait(false);
                    }
                    _blockedDeletionReceipts.Remove(current.Transfer.TransferId);
                }
            }
            else _blockedDeletionReceipts.Remove(current.Transfer.TransferId);
            // NTFS may still have the driver's read handle open. Wake its
            // existing exact lifetime retirement BEFORE checking last-close
            // absence. Pending deletion is not StageDeleted.
            DisposeCleanedUpStage(current);
            if (StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out Exception? absenceFailure))
            {
                var completed = await _journal.CompleteStageCleanupAsync(current.Transfer.TransferId, token).ConfigureAwait(false);
                await _journal.ArchiveCompletedAsync(completed, token).ConfigureAwait(false);
            }
            else if (absenceFailure is not null)
                throw new IOException("Blocked stage absence could not be established.", absenceFailure);
        }
        catch (Exception ex) when (!token.IsCancellationRequested)
        {
            if (ex is StagedJournalPersistenceException)
                QueueJournalProgress(current);
            if (!StagedTransferJournal.MatchesBlockedDeletionReceipt(current) &&
                !_blockedDeletionReceipts.ContainsKey(current.Transfer.TransferId) &&
                (StagedStageFile.TryConfirmAbsent(current.Transfer.StagePath, out _) ||
                 ex is IOException { InnerException: System.ComponentModel.Win32Exception { NativeErrorCode: 5 or 303 } }))
                ReportRecoveryHold(current, "blocked_disposition_receipt_unavailable", ex);
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
        TransferJournalEntry export = await _journal.EnforceSeedExportAsync(transfer.TransferId, token).ConfigureAwait(false);
        if (StagedSeedExport.Failure(export) is not null) return export;
        try
        {
            if (!HasRequestorIdentity(transfer))
                throw new UnauthorizedAccessException("The staged transfer has no valid requestor SID.");
            await _journal.BeginHandbackAttemptAsync(transfer.TransferId, token).ConfigureAwait(false);
            if (_handbackCopier is null)
                throw new IOException("No Windows user-profile hand-back provider is available.");
            await _journal.RequireSeedExportAsync(transfer, token).ConfigureAwait(false);
            string path = await _handbackCopier.CopyVerifiedAsync(transfer, snapshot, length,
                digest, token).ConfigureAwait(false);
            return await _journal.CompleteHandbackAsync(transfer.TransferId, path, length, null, token)
                .ConfigureAwait(false);
        }
        catch (StagedJournalPersistenceException)
        {
            // Intent failure did not authorize a copy. Completion failure
            // may follow a successful copy: keep Copying and let the existing
            // transfer-specific copier verify it, without overwriting it.
            throw;
        }
        catch (Exception ex) when (!token.IsCancellationRequested)
        {
            _logger?.LogWarning(ex, "Staged hand-back failed for {TransferId}.", transfer.TransferId);
            return await RecordHandbackFailureAsync(transfer, operation, result,
                "handback_failed", CancellationToken.None).ConfigureAwait(false);
        }
    }

    private void PublishSeedRestriction(TransferJournalEntry entry) =>
        PublishTransferNotification(entry.Transfer, new TransferNotification(entry.Transfer.TransferId,
            Path.GetFileName(entry.Transfer.DestinationPath), TransferPhase.Blocked,
            HandbackVerified: false, SnapshotSha256Hex: entry.Sha256Hex,
            BlockReason: StagedBlockReason.SeedExportRestricted));

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

    // Hand-back belongs to the requestor SID read from the requesting process token at
    // allocation; it never depends on who currently uses a session number (session reuse)
    // nor on an interactive session existing (session 0 batch/service requestors, logoff,
    // reboot). Session binding is required only for UI delivery and justification.
    private static bool HasRequestorIdentity(StagedTransfer transfer)
    {
        if (string.IsNullOrWhiteSpace(transfer.RequestorSid) || transfer.RequestorSid.Length > 184) return false;
        try
        {
            var sid = new System.Security.Principal.SecurityIdentifier(transfer.RequestorSid);
            return !sid.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid);
        }
        catch (ArgumentException) { return false; }
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
        else if (transfer.SessionId is { } ownerSession)
            _notifications.RecordOnly(notification, ownerSession);
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
