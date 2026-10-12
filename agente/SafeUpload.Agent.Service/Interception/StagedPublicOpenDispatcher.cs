#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;
using PortVerdict = SafeUpload.Agent.Minifilter.Verdict;

namespace SafeUpload.Agent.Service.Interception;

// Per connection. A short open-binding reservation serializes the original
// CREATE with publication; it creates no delete version and grants no access.
// The original NTFS open supplies the grant. The outer capability stays off
// until private writers, physical publication and startup share this head.
internal sealed class StagedPublicOpenDispatcher : IDisposable
{
    private sealed class BindingCell
    {
        internal readonly SemaphoreSlim Gate = new(1, 1);
        internal StagedTransferJournal.DestinationCommitTurn? Turn;
        internal NativeRecordReplayRow? Original;
        internal ulong Published;
        internal SafeUploadStageIdentityV19 Identity;
        internal int References;
        internal bool Terminal;
        internal StagedPublicRelayReceipt? Mutation;
        internal StagedTransferJournal.DestinationCommitTurn? MutationTurn;
    }
    private readonly object _sync = new();
    private readonly Dictionary<Guid, BindingCell> _cells = new();
    private readonly StagedTransferJournal _journal;
    private readonly Func<PublicOpenReplay> _read;
    private readonly Func<NativeNameObservationRequest, NativeNameObservation> _observe;
    private readonly Func<NativeRecordReplayRow, string> _locator;
    private readonly Action<NativeRecordReplayRow> _checkCreator;
    private bool _disposed;

    internal StagedPublicOpenDispatcher(StagedTransferJournal journal, Func<PublicOpenReplay> read,
        Func<NativeNameObservationRequest, NativeNameObservation> observe,
        Func<NativeRecordReplayRow, string> locator, Action<NativeRecordReplayRow> checkCreator)
        => (_journal, _read, _observe, _locator, _checkCreator) = (journal, read, observe, locator, checkCreator);

    internal async Task<PublicDispositionReplyV25> ProcessAsync(PublicDispositionRequestV25 request,
        uint pid, Guid driver, CancellationToken token)
    {
        if (!PublicDispositionV25.Valid(request))
            throw new IOException("Ordinary disposition integration is not ready.");
        PublicOpenReplay replay = RequireReplay(request, driver);
        var row = replay.Records.SingleOrDefault(r => r.Open.RequestNonce == request.OpenNonce);
        if (row is null && request.Phase == PublicDispositionV25.OpenFacts)
            return await ConfirmRemovedOpenAsync(request, pid, replay, token).ConfigureAwait(false);
        if (row is null) throw new IOException("The ordinary open has no exact native record.");
        bool mutation = request.Phase is PublicDispositionV25.DispositionPrepare or PublicDispositionV25.DispositionFacts;
        if ((mutation ? row.MutationOperationId != request.OperationId || row.MutationNonce != request.MutationNonce ||
                row.OperationSequence != request.OperationSequence || row.ActorProcessId != pid :
                row.Open.OperationId != request.OperationId || row.Open.CallerProcessId != pid) ||
            row.Open.OsBootSequence != replay.OsBootSequence || row.Open.OriginalConnectionEpoch > replay.ConnectionEpoch)
            throw new IOException("Ordinary binding changed its immutable operation or caller.");
        BindingCell cell;
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_cells.TryGetValue(request.OpenNonce, out cell!))
            {
                if (_cells.Count >= 1024) throw new IOException("Ordinary binding continuations are full.");
                _cells.Add(request.OpenNonce, cell = new());
            }
            cell.References++;
        }
        bool entered = false;
        try
        {
            await cell.Gate.WaitAsync(token).ConfigureAwait(false);
            entered = true;
            var destination = StagedNativeStartupRecovery.Destination(row.Open);
            if (mutation)
                return await ProcessMutationAsync(request, row, replay, cell, destination, token).ConfigureAwait(false);
            if (request.Phase == PublicDispositionV25.OpenPrepare)
            {
                if (row.Open.Facts != 0 || row.OperationSequence != 0 || row.PublishedGeneration != 0 ||
                    row.Open.OriginalConnectionEpoch != replay.ConnectionEpoch)
                    throw new IOException("Ordinary preparation is no longer an unforwarded open.");
                _checkCreator(row.Open);
                if (cell.Turn is null)
                {
                    var turn = await _journal.EnterDestinationCommitTurnAsync(destination,
                        StagedDestinationTurnPurpose.Allocation, token).ConfigureAwait(false);
                    try
                    {
                        RequireSameReplay(request, replay);
                        var expected = new NativeNameObservationRequest(replay.DriverInstanceId, replay.ConnectionEpoch,
                            replay.Revision, replay.OsBootSequence, row.Open.MountManagerVolumeId,
                            row.Open.VolumeRootIdentity, row.Open.ParentIdentity, row.Open.ParentCaseSensitive, row.Open.CanonicalLeaf);
                        NativeNameObservation name = _observe(expected);
                        if (name.Binding != expected || name.ChildIdentity is not { } child ||
                            !SameIdentity(child, row.Open.PublicIdentity))
                            throw new IOException("Ordinary preparation changed its exact public link.");
                        var checkedName = new StagedDestinationNameObservation(destination, destination.Parent,
                            destination.Parent, true, Identity(child));
                        var head = await _journal.CapturePublicOpenHeadAsync(turn, Identity(child), _locator(row.Open),
                            checkedName, token).ConfigureAwait(false);
                        RequireSameReplay(request, replay); _checkCreator(row.Open);
                        cell.Original = row.Open;
                        cell.Published = checked((ulong)head.LatestPublished);
                        cell.Identity = head.PublishedIdentity is { } published ? Wire(published) : default;
                        cell.Turn = turn;
                        turn = null!; // Ownership transferred to the connection cell.
                    }
                    finally { turn?.Dispose(); }
                }
                else if (cell.Original != row.Open)
                    throw new IOException("Ordinary preparation replay changed the original open.");
                RequireSameReplay(request, replay);
                return Reply(request, cell.Published, cell.Identity, PublicDispositionV25.Prepared);
            }

            // Exact original outcome/fallback facts release only this short
            // binding reservation. They neither clear a delete nor invent one.
            if (!row.Open.Facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown) &&
                !row.Open.Facts.HasFlag(NativeRecordFacts.CancelledBeforeHandle) &&
                !row.Open.Facts.HasFlag(NativeRecordFacts.CancelledCloseObserved) &&
                !row.Open.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost))
                return Reply(request, row.PublishedGeneration, row.PublishedIdentity, PublicDispositionV25.Progress);
            if (cell.Original is { } original && !SameOriginal(original, row.Open))
                throw new IOException("Ordinary completion changed its pre-CREATE binding.");
            if (cell.Turn is not null && row.Open.Facts.HasFlag(NativeRecordFacts.Forwarded) &&
                (cell.Published != row.PublishedGeneration || !SameIdentity(cell.Identity, row.PublishedIdentity)))
                throw new IOException("Ordinary completion changed its Published snapshot.");
            RequireSameReplay(request, replay);
            cell.Turn?.Dispose(); cell.Turn = null;
            if (!await ReconcileOpenReceiptsAsync(row, replay, destination, token).ConfigureAwait(false))
                return Reply(request, row.PublishedGeneration, row.PublishedIdentity, PublicDispositionV25.Progress);
            RequireSameReplay(request, replay);
            cell.Terminal = row.Open.Facts.HasFlag(NativeRecordFacts.LastHandleCleanedUp) ||
                row.Open.Facts.HasFlag(NativeRecordFacts.CancelledBeforeHandle) ||
                row.Open.Facts.HasFlag(NativeRecordFacts.CancelledCloseObserved) ||
                row.Open.Facts.HasFlag(NativeRecordFacts.CleanupCoverageLost) ||
                (row.Open.Facts.HasFlag(NativeRecordFacts.CreateOutcomeKnown) &&
                 !row.Open.Facts.HasFlag(NativeRecordFacts.CreateAccepted));
            return Reply(request, row.PublishedGeneration, row.PublishedIdentity, PublicDispositionV25.Recorded);
        }
        finally
        {
            if (entered) cell.Gate.Release();
            bool retire = false;
            lock (_sync)
                if (--cell.References == 0 && cell.MutationTurn is null &&
                    (cell.Terminal || (cell.Turn is null && cell.Original is null)))
                {
                    _cells.Remove(request.OpenNonce); retire = true;
                }
            if (retire) cell.Gate.Dispose();
        }
    }

    private async Task<PublicDispositionReplyV25> ProcessMutationAsync(PublicDispositionRequestV25 request,
        PublicOpenReplayRow row, PublicOpenReplay replay, BindingCell cell,
        StagedDestinationIdentity destination, CancellationToken token)
    {
        if (!row.Open.Facts.HasFlag(NativeRecordFacts.IdentityChecked) ||
            !row.OperationFacts.HasFlag(PublicOperationFacts.Captured) || row.ActorSid is null)
            throw new IOException("Disposition has no original native grant and captured operation.");
        var binding = new StagedPublicDeleteBinding(row.MutationTransferId, row.MutationNonce,
            row.Open.DriverInstanceId, row.Open.OriginalConnectionEpoch, Identity(row.Open.PublicIdentity),
            checked((int)row.ActorProcessId), row.ActorProcessCreationTime, row.ActorSessionId, row.ActorSid,
            row.Open.OsBootSequence, row.Open.MountManagerVolumeId);
        var original = new StagedPublicRelayIntent(row.Open.TransferId, row.Open.RequestNonce, row.Open.OperationId,
            row.OperationSequence, checked((long)row.PublishedGeneration),
            row.PublishedGeneration == 0 ? null : Identity(row.PublishedIdentity),
            row.InformationClass, row.DispositionFlags, row.RequestorMode, row.GrantedAccess, checked((int)row.Open.CallerProcessId));
        if (cell.Turn is not null)
        {
            if (cell.Original is not { } opened || !SameOriginal(opened, row.Open) ||
                cell.Published != row.PublishedGeneration || !SameIdentity(cell.Identity, row.PublishedIdentity))
                throw new IOException("Disposition changed its original open reservation.");
            cell.Turn.Dispose(); cell.Turn = null;
        }
        if (cell.Mutation is { } prior && prior.OperationId != request.OperationId)
        {
            if (prior.NativeStatus is null) throw new IOException("The earlier native result remains unresolved.");
            cell.Mutation = null;
        }
        if (request.Phase == PublicDispositionV25.DispositionPrepare && cell.MutationTurn is null)
            _ = await ReconcileOpenReceiptsAsync(row, replay, destination, token).ConfigureAwait(false);
        cell.MutationTurn ??= await _journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        RequireSameReplay(request, replay);
        if (request.Phase == PublicDispositionV25.DispositionPrepare)
        {
            if ((row.OperationFacts & ~PublicOperationFacts.CleanupOutstanding) != PublicOperationFacts.Captured || row.MutationGeneration != 0)
                throw new IOException("Disposition preparation has already left capture.");
            var expected = new NativeNameObservationRequest(replay.DriverInstanceId, replay.ConnectionEpoch,
                replay.Revision, replay.OsBootSequence, row.Open.MountManagerVolumeId, row.Open.VolumeRootIdentity,
                row.Open.ParentIdentity, row.Open.ParentCaseSensitive, row.Open.CanonicalLeaf);
            try
            {
                var observed = _observe(expected);
                if (observed.Binding != expected) throw new IOException("Disposition name observation is stale.");
                RequireSameReplay(request, replay);
                cell.Mutation = await _journal.BeginPublicRelayAsync(cell.MutationTurn, binding, request.OperationId,
                    original, new(destination, destination.Parent, destination.Parent, true,
                        observed.ChildIdentity is { } id ? Identity(id) : null), token).ConfigureAwait(false);
                if (cell.Mutation.NativeStatus is not null)
                    throw new IOException("A recorded native result can never authorize a second forwarding.");
            }
            catch
            {
                // The durable head, rather than this ephemeral semaphore,
                // retains any flushed intent after a lost result/connection.
                cell.MutationTurn.Dispose(); cell.MutationTurn = null;
                throw;
            }
            RequireSameReplay(request, replay);
            return new() { Request = request, PublishedGeneration = row.PublishedGeneration,
                PublishedIdentity = row.PublishedIdentity, MutationGeneration = checked((ulong)cell.Mutation.Generation),
                Result = cell.Mutation.NoNameEffect ? PublicDispositionV25.PreparedNoNameEffect : PublicDispositionV25.Prepared };
        }
        bool notForwarded = row.OperationFacts.HasFlag(PublicOperationFacts.NotForwarded);
        if (notForwarded)
        {
            var head = await _journal.ReadDestinationHeadAsync(destination, token).ConfigureAwait(false);
            if (head?.PublicRelayReceipts?.Any(r => r.OperationId == request.OperationId && r.Binding == binding) != true)
            {
                RequireSameReplay(request, replay);
                cell.MutationTurn.Dispose(); cell.MutationTurn = null;
                return new() { Request = request, PublishedGeneration = row.PublishedGeneration,
                    PublishedIdentity = row.PublishedIdentity, Result = PublicDispositionV25.Recorded };
            }
        }
        if (!notForwarded && !row.OperationFacts.HasFlag(PublicOperationFacts.ResultKnown))
            return new() { Request = request, PublishedGeneration = row.PublishedGeneration,
                PublishedIdentity = row.PublishedIdentity, MutationGeneration = row.MutationGeneration,
                Result = PublicDispositionV25.Progress };
        var result = await _journal.RecordPublicRelayResultAsync(cell.MutationTurn, binding, request.OperationId,
            original, row.OperationStatus, notForwarded).ConfigureAwait(false);
        await _journal.ArmPublicRelayAcknowledgementAsync(cell.MutationTurn, binding, request.OperationId,
            replay.Revision, token).ConfigureAwait(false);
        RequireSameReplay(request, replay);
        cell.Mutation = result;
        cell.MutationTurn.Dispose(); cell.MutationTurn = null;
        return new() { Request = request, PublishedGeneration = row.PublishedGeneration,
            PublishedIdentity = row.PublishedIdentity, MutationGeneration = checked((ulong)result.Generation),
            Result = PublicDispositionV25.Recorded };
    }

    private async Task<bool> ReconcileOpenReceiptsAsync(PublicOpenReplayRow row, PublicOpenReplay replay,
        StagedDestinationIdentity destination, CancellationToken token)
    {
        var head = await _journal.ReadDestinationHeadAsync(destination, token).ConfigureAwait(false);
        bool outstanding = row.OperationFacts.HasFlag(PublicOperationFacts.CleanupOutstanding);
        if (head is null)
        {
            if (outstanding) throw new IOException("Native cleanup lost its destination head; retain the hold.");
            return true;
        }
        bool matching = (head.PublicRelayReceipts ?? []).Any(r => r.Original.OpenTransferId == row.Open.TransferId &&
            r.Original.OpenNonce == row.Open.RequestNonce && r.Original.OpenOperationId == row.Open.OperationId);
        if (!matching && !outstanding) return true;
        using var turn = await _journal.EnterDestinationCommitTurnAsync(destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        var check = new PublicDispositionRequestV25 { Version = 25, StructSize = 80, Phase = PublicDispositionV25.OpenFacts,
            OpenNonce = row.Open.RequestNonce, OperationId = row.Open.OperationId, NativeMapRevision = replay.Revision };
        RequireSameReplay(check, replay);
        var expected = new NativeNameObservationRequest(replay.DriverInstanceId, replay.ConnectionEpoch,
            replay.Revision, replay.OsBootSequence, row.Open.MountManagerVolumeId, row.Open.VolumeRootIdentity,
            row.Open.ParentIdentity, row.Open.ParentCaseSensitive, row.Open.CanonicalLeaf);
        var observed = _observe(expected);
        if (observed.Binding != expected) throw new IOException("Relay cleanup changed its anchored name observation.");
        RequireSameReplay(check, replay);
        bool complete = await _journal.ReconcilePublicRelayOpenAsync(turn, row.Open.DriverInstanceId,
            row.Open.TransferId, row.Open.RequestNonce, row.Open.OperationId, row.Open.OriginalConnectionEpoch,
            Identity(row.Open.PublicIdentity), replay.Revision, row.OperationSequence,
            row.Open.Facts.HasFlag(NativeRecordFacts.LastHandleCleanedUp), outstanding,
            new(destination, destination.Parent, destination.Parent, true,
                observed.ChildIdentity is { } child ? Identity(child) : null), token).ConfigureAwait(false);
        RequireSameReplay(check, replay);
        return complete;
    }

    private async Task<PublicDispositionReplyV25> ConfirmRemovedOpenAsync(PublicDispositionRequestV25 request,
        uint pid, PublicOpenReplay replay, CancellationToken token)
    {
        var heads = await _journal.ReadDestinationHeadsAsync(token).ConfigureAwait(false);
        var matches = heads.Select(h => (Head: h, Receipts: (h.PublicRelayReceipts ?? []).Where(r =>
            r.Original.OpenNonce == request.OpenNonce && r.Original.OpenOperationId == request.OperationId).ToArray()))
            .Where(p => p.Receipts.Length != 0).ToArray();
        if (matches.Length != 1) throw new IOException("Absent ordinary open has no exact retained cleanup receipt.");
        var saved = matches[0];
        using var turn = await _journal.EnterDestinationCommitTurnAsync(saved.Head.Destination,
            StagedDestinationTurnPurpose.Reconciliation, token).ConfigureAwait(false);
        RequireSameReplay(request, replay);
        await _journal.RetirePublicRelayRemovedOpenAsync(turn, replay.DriverInstanceId, request.OpenNonce,
            request.OperationId, checked((int)pid), replay.OsBootSequence, replay.Revision, token).ConfigureAwait(false);
        RequireSameReplay(request, replay);
        var original = saved.Receipts[0].Original;
        return Reply(request, checked((ulong)original.PublishedGeneration),
            original.PublishedIdentity is { } identity ? Wire(identity) : default, PublicDispositionV25.Recorded);
    }

    private PublicOpenReplay RequireReplay(PublicDispositionRequestV25 request, Guid driver)
    {
        var replay = _read();
        if (driver == Guid.Empty || replay.DriverInstanceId != driver || replay.ConnectionEpoch == 0 ||
            replay.Revision != request.NativeMapRevision)
            throw new IOException("Ordinary-open replay belongs to another driver/channel/revision.");
        return replay;
    }
    private void RequireSameReplay(PublicDispositionRequestV25 request, PublicOpenReplay expected)
    {
        var current = RequireReplay(request, expected.DriverInstanceId);
        if (current.ConnectionEpoch != expected.ConnectionEpoch || current.OsBootSequence != expected.OsBootSequence ||
            !current.Records.SequenceEqual(expected.Records))
            throw new IOException("Ordinary-open facts changed during binding.");
    }
    private static bool SameOriginal(NativeRecordReplayRow original, NativeRecordReplayRow current) =>
        original with { Facts = current.Facts, CreateStatus = current.CreateStatus, IdentityStatus = current.IdentityStatus,
            TeardownReason = current.TeardownReason } == current;
    private static bool SameIdentity(SafeUploadStageIdentityV19 a, SafeUploadStageIdentityV19 b) =>
        a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileIdHigh == b.FileIdHigh && a.FileIdLow == b.FileIdLow;
    private static StagedStageIdentity Identity(SafeUploadStageIdentityV19 value) =>
        new(value.VolumeSerialNumber, value.FileIdHigh, value.FileIdLow);
    private static SafeUploadStageIdentityV19 Wire(StagedStageIdentity value) =>
        new() { VolumeSerialNumber = value.VolumeSerialNumber, FileIdHigh = value.FileIdHigh, FileIdLow = value.FileIdLow };
    private static PublicDispositionReplyV25 Reply(PublicDispositionRequestV25 request, ulong published,
        SafeUploadStageIdentityV19 identity, uint result) =>
        new() { Request = request, PublishedGeneration = published, PublishedIdentity = identity, Result = result };

    internal static string ResolveLocator(NativeRecordReplayRow row)
    {
        var destination = StagedNativeStartupRecovery.Destination(row);
        var binding = new StagedAllocationBindingV23(row.TransferId, row.DriverInstanceId, Guid.Empty,
            1, StageV19AllocationReferenceKind.None, row.MountManagerVolumeId,
            destination.VolumeRoot, destination.Parent, destination.CaseSensitive, destination.CanonicalLeaf,
            Identity(row.PublicIdentity));
        using var parent = StagedDestinationDirectory.Open(binding);
        return parent.ReadLocator();
    }

    public void Dispose()
    {
        // Connection continuations must drain before this call, just as for
        // the FilterPort itself. No semaphore/turn is destroyed under a user.
        lock (_sync)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var cell in _cells.Values) { cell.Turn?.Dispose(); cell.MutationTurn?.Dispose(); cell.Gate.Dispose(); }
            _cells.Clear();
        }
    }
}

public sealed partial class MinifilterInterceptor
{
    private async Task ReplyPublicOpenAsync(FilterPort port, SafeUploadRequest request, ulong messageId,
        Guid? driver, CancellationToken token)
    {
        try
        {
            if (!_stageBoundHeadReady || !_stageV20Ready || !_stagingRecoveryReady ||
                driver is not { } current || _activeDriverInstanceId != current ||
                _publicOpenDispatcher is not { } dispatcher || !request.TryReadPublicDispositionV25(out var payload))
                throw new IOException("The complete ordinary public pipeline is not ready.");
            var reply = await dispatcher.ProcessAsync(payload, request.RequestorProcessId, current, token).ConfigureAwait(false);
            if (token.IsCancellationRequested || !_stageBoundHeadReady || _activeDriverInstanceId != current)
                throw new IOException("Ordinary completion belongs to a revoked channel.");
            port.ReplyPublicDispositionV25(messageId, request.RequestId, reply);
            Interlocked.Increment(ref _answered);
        }
        catch (Exception error)
        {
            _logger.LogWarning(error, "Ordinary public request {RequestId} could not acquire authority.", request.RequestId);
            try { port.Reply(messageId, request.RequestId, PortVerdict.Deny); }
            catch (Exception replyError) { _logger.LogWarning(replyError, "Ordinary denial delivery failed."); }
        }
    }
}
#endif
