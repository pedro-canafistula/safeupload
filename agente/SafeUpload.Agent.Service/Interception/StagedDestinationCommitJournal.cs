using System.Globalization;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SafeUpload.Agent.Service.Interception;

// This identity is supplied by the checked, anchored namespace binding, never
// reconstructed from a drive letter or a caller's path. Different locators for
// the same volume root/parent/name must reach this same durable head and queue.
internal sealed record StagedDestinationIdentity
{
    public StagedStageIdentity VolumeRoot { get; }
    public StagedStageIdentity Parent { get; }
    public bool CaseSensitive { get; }
    public string CanonicalLeaf { get; }
    public Guid? MountManagerVolumeId { get; }

    [System.Text.Json.Serialization.JsonConstructor]
    public StagedDestinationIdentity(StagedStageIdentity volumeRoot, StagedStageIdentity parent,
        bool caseSensitive, string canonicalLeaf, Guid? mountManagerVolumeId = null)
    {
        ArgumentNullException.ThrowIfNull(volumeRoot);
        ArgumentNullException.ThrowIfNull(parent);
        ArgumentException.ThrowIfNullOrWhiteSpace(canonicalLeaf);
        if (mountManagerVolumeId == Guid.Empty) throw new ArgumentException("A captured volume GUID cannot be empty.");
        if ((volumeRoot.FileIdHigh | volumeRoot.FileIdLow) == 0 ||
            (parent.FileIdHigh | parent.FileIdLow) == 0 ||
            volumeRoot.VolumeSerialNumber != parent.VolumeSerialNumber ||
            canonicalLeaf.Length > 255 || canonicalLeaf is "." or ".." ||
            canonicalLeaf.EndsWith('.') || canonicalLeaf.EndsWith(' ') ||
            canonicalLeaf.Any(c => c < 32 || "<>:\"/\\|?*".Contains(c)) ||
            !IsWellFormedUtf16(canonicalLeaf))
            throw new ArgumentException("The destination needs an unambiguous checked parent and leaf.");
        VolumeRoot = volumeRoot;
        Parent = parent;
        CaseSensitive = caseSensitive;
        CanonicalLeaf = canonicalLeaf;
        MountManagerVolumeId = mountManagerVolumeId;
    }

    internal bool LeafEquals(string leaf) => StagedDestinationLeafComparer.Equals(CanonicalLeaf, leaf, CaseSensitive);

    public bool Equals(StagedDestinationIdentity? other) => other is not null &&
        VolumeRoot == other.VolumeRoot && Parent == other.Parent && CaseSensitive == other.CaseSensitive &&
        MountManagerVolumeId == other.MountManagerVolumeId && LeafEquals(other.CanonicalLeaf);

    // A bucket hash deliberately omits the leaf. Its Windows equality cannot
    // be replaced by an independently folded managed hash. Same-bucket names
    // may collide in this in-memory hash; only the comparator selects a head.
    public override int GetHashCode() => HashCode.Combine(VolumeRoot, Parent, CaseSensitive, MountManagerVolumeId);

    private static bool IsWellFormedUtf16(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            if (char.IsHighSurrogate(value[i]))
            {
                if (++i == value.Length || !char.IsLowSurrogate(value[i])) return false;
            }
            else if (char.IsLowSurrogate(value[i])) return false;
        }
        return true;
    }

    // Exact serialization address, not an insensitive-name authority. Legacy
    // heads already store their folded leaf, so their original address stays
    // readable; alias resolution must search and reject conflicting heads.
    internal string StorageKey => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        string.Create(CultureInfo.InvariantCulture,
            $"{VolumeRoot.VolumeSerialNumber:X16}:{VolumeRoot.FileIdHigh:X16}:{VolumeRoot.FileIdLow:X16}:{Parent.FileIdHigh:X16}:{Parent.FileIdLow:X16}:{(CaseSensitive ? 1 : 0)}:{CanonicalLeaf}") +
            (MountManagerVolumeId is { } volumeId ? $":{volumeId:N}" : ""))));
}

internal enum StagedDestinationTurnPurpose { Allocation, PhysicalCommit, Reconciliation }
// Persisted values are never renumbered. AcceptedUnresolved is the single
// exceptional native-CREATE recovery state approved by the owner.
internal enum StagedPublicDeleteState { Admitted = 1, Intent = 2, Accepted = 3, Canceled = 4, Superseded = 5, Complete = 6, Failed = 7, AcceptedUnresolved = 8 }
internal enum StagedPublicDeleteKind { Ordinary = 0, NativeOnClose = 1 }
internal enum StagedDestinationMutation { Publication = 1, DeleteDisposition = 2, ClearDisposition = 3 }

// Checked authorization is deliberately not represented by an "allowed" bool.
// The eventual dispatcher must validate the original caller's backend and its
// one-use driver permit before it invokes these internal journal operations.
// These records are durable ordering/replay evidence, not an access grant.
internal sealed record StagedPublicDeleteBinding(Guid TransferId, Guid RequestNonce,
    Guid DriverInstanceId, ulong ConnectionEpoch, StagedStageIdentity PublicIdentity,
    int OwnerProcessId, long OwnerProcessCreationTime, uint OwnerSessionId, string OwnerSid,
    uint? OsBootSequence = null, Guid? MountManagerVolumeId = null);
internal sealed record StagedPublicDeleteRecord(StagedPublicDeleteBinding Binding, long Generation,
    StagedPublicDeleteState State, DateTimeOffset UpdatedAtUtc, Guid? OperationId = null,
    StagedPublicDeleteKind Kind = StagedPublicDeleteKind.Ordinary, bool? NativeCreateAccepted = null,
    StagedNativeCreateIntent? NativeIntent = null, StagedNativeCreateOutcome? NativeOutcome = null,
    ulong? NativeAcknowledgementRevision = null);
internal sealed record StagedNativeCreateIntent(uint CreateOptions, uint DesiredAccess, uint ShareAccess);
internal sealed record StagedNativeCreateOutcome(uint Facts, int CreateStatus, int IdentityStatus);
// These are checked dispatcher inputs, not publication/delete permits. A
// complete anchored directory query proves a name mapping, never a native
// link's delete-pending state or an exact physical-cleanup acknowledgement.
internal sealed record StagedDestinationNameObservation(StagedDestinationIdentity Destination,
    StagedStageIdentity ParentBefore, StagedStageIdentity ParentAfter, bool CompleteEnumeration,
    StagedStageIdentity? PublicIdentity);
internal sealed record StagedDestinationCommitIntent(Guid OperationId, StagedDestinationMutation Mutation,
    Guid TransferId, long Generation, StagedStageIdentity? ExpectedPublicIdentity,
    StagedStageIdentity? TemporaryIdentity = null, long? Length = null, string? Sha256Hex = null);
internal sealed record StagedDestinationMutationResult(StagedDestinationCommitIntent Intent, bool Succeeded);
internal sealed record StagedDestinationHead(StagedDestinationIdentity Destination, string Locator,
    long MaxAllocated, Guid? CurrentSaveTransferId, long CurrentSaveGeneration,
    long LatestPublished, StagedStageIdentity? PublishedIdentity, long CommittedDelete,
    StagedDestinationCommitIntent? PendingCommit, StagedPublicDeleteRecord[] Deletes,
    StagedDestinationMutationResult? LastMutationResult = null);

public sealed partial class StagedTransferJournal
{
    private readonly Dictionary<StagedDestinationIdentity, DestinationQueueCell> _destinationQueues = new();

    internal sealed class DestinationQueueCell
    {
        internal readonly SemaphoreSlim Turn = new(1, 1);
        internal TaskCompletionSource Changed = NewSignal();
        internal int References;
        internal static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal sealed class DestinationCommitTurn : IDisposable
    {
        private readonly StagedTransferJournal _journal;
        private readonly DestinationQueueCell _cell;
        private int _disposed;
        internal StagedDestinationIdentity Destination { get; }
        internal StagedDestinationTurnPurpose Purpose { get; }

        internal DestinationCommitTurn(StagedTransferJournal journal, DestinationQueueCell cell,
            StagedDestinationIdentity destination, StagedDestinationTurnPurpose purpose)
            => (_journal, _cell, Destination, Purpose) = (journal, cell, destination, purpose);

        internal void Require(StagedTransferJournal journal, StagedDestinationTurnPurpose? purpose = null)
        {
            if (_disposed != 0 || !ReferenceEquals(_journal, journal) ||
                (purpose is not null && purpose != Purpose))
                throw new InvalidOperationException("A live matching destination turn is required.");
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _cell.Turn.Release();
            _journal.ReleaseQueueReference(Destination, _cell);
        }
    }

    // Reservation waits own a queue reference and a cancellable Task, not the
    // destination semaphore, manifest gate or a worker thread. Continuations
    // (clear/last-close/recovery) can enter the very reservation they resolve.
    internal async Task<DestinationCommitTurn> EnterDestinationCommitTurnAsync(
        StagedDestinationIdentity destination, StagedDestinationTurnPurpose purpose, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (!Enum.IsDefined(purpose)) throw new ArgumentOutOfRangeException(nameof(purpose));
        DestinationQueueCell cell;
        lock (_destinationQueues)
        {
            if (!_destinationQueues.TryGetValue(destination, out cell!))
                _destinationQueues.Add(destination, cell = new DestinationQueueCell());
            cell.References++;
        }
        try
        {
            while (true)
            {
                await cell.Turn.WaitAsync(token).ConfigureAwait(false);
                bool held = true;
                try
                {
                    Task changed;
                    lock (cell) changed = cell.Changed.Task;
                    StagedDestinationHead? head = await ReadDestinationHeadAsync(destination, token).ConfigureAwait(false);
                    bool blocked = purpose != StagedDestinationTurnPurpose.Reconciliation &&
                        (head?.PendingCommit is not null ||
                         (purpose == StagedDestinationTurnPurpose.PhysicalCommit &&
                          head?.Deletes.Any(IsPublicationReservation) == true));
                    if (!blocked)
                    {
                        var turn = new DestinationCommitTurn(this, cell, destination, purpose);
                        held = false; // The returned turn now owns the semaphore/reference.
                        return turn;
                    }
                    cell.Turn.Release();
                    held = false;
                    await changed.WaitAsync(token).ConfigureAwait(false);
                }
                finally { if (held) cell.Turn.Release(); }
            }
        }
        catch { ReleaseQueueReference(destination, cell); throw; }
    }

    private void ReleaseQueueReference(StagedDestinationIdentity destination, DestinationQueueCell cell)
    {
        lock (_destinationQueues)
        {
            if (--cell.References == 0)
            {
                _destinationQueues.Remove(destination);
                cell.Turn.Dispose();
            }
        }
    }

    private void SignalDestinationChanged(StagedDestinationIdentity destination)
    {
        lock (_destinationQueues)
        {
            if (!_destinationQueues.TryGetValue(destination, out var cell)) return;
            TaskCompletionSource signal;
            lock (cell) { signal = cell.Changed; cell.Changed = DestinationQueueCell.NewSignal(); }
            signal.TrySetResult();
        }
    }

    internal async Task<StagedDestinationHead?> ReadDestinationHeadAsync(
        StagedDestinationIdentity destination, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try { return await ReadDestinationHeadCoreAsync(destination, token).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    // Startup must discover durable native holds even when their original
    // driver is gone and cannot replay a live object. This read is metadata,
    // not permission to publish; recovery still takes and rereads each turn.
    internal async Task<IReadOnlyList<StagedDestinationHead>> ReadDestinationHeadsAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var heads = new List<StagedDestinationHead>();
            var identities = new HashSet<StagedDestinationIdentity>();
            foreach (string path in Directory.EnumerateFiles(_directory, "destination-*.state"))
            {
                token.ThrowIfCancellationRequested();
                var head = await ReadDestinationHeadFileCoreAsync(path, null, token).ConfigureAwait(false)
                    ?? throw new InvalidDataException("A destination head disappeared during startup recovery.");
                if (!identities.Add(head.Destination))
                    throw new InvalidDataException("Equivalent destination leaves have conflicting durable heads.");
                heads.Add(head);
            }
            return heads.AsReadOnly();
        }
        finally { _gate.Release(); }
    }

    // The caller imports retained manifest claims first and checks that the
    // transfer is a fresh allocation (or this current exact replay). Advancing
    // the high-water before committing its manifest can leave a harmless gap;
    // it cannot allow a generation to be reused after a crash.
    internal async Task<long> ReserveSaveGenerationAsync(DestinationCommitTurn turn, Guid transferId,
        string locator, long retainedManifestHighWater, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Allocation);
        if (transferId == Guid.Empty || retainedManifestHighWater < 0) throw new ArgumentException("Invalid allocation claim.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await ReadDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false)
                ?? NewDestinationHead(turn.Destination, locator);
            RequireNoPendingPhysicalCommit(head);
            if (head.Deletes.Any(d => d.Binding.TransferId == transferId))
                throw new IOException("A delete transfer ID cannot be reused for a save allocation.");
            if (head.CurrentSaveTransferId == transferId)
            {
                if (retainedManifestHighWater > head.MaxAllocated || head.CurrentSaveGeneration <= head.CommittedDelete)
                    throw new IOException("The allocation replay conflicts with a later manifest head.");
                return head.CurrentSaveGeneration;
            }
            long generation = checked(Math.Max(head.MaxAllocated, retainedManifestHighWater) + 1);
            await WriteDestinationHeadCoreAsync(head with
            {
                MaxAllocated = generation, CurrentSaveTransferId = transferId, CurrentSaveGeneration = generation
            }, token).ConfigureAwait(false);
            return generation;
        }
        finally { _gate.Release(); }
    }

    internal async Task<StagedPublicDeleteRecord> AdmitPublicDeleteAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, string locator, long retainedManifestHighWater, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Allocation);
        ValidatePublicDeleteBinding(binding, turn.Destination);
        if (retainedManifestHighWater < 0) throw new ArgumentOutOfRangeException(nameof(retainedManifestHighWater));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await ReadDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false)
                ?? NewDestinationHead(turn.Destination, locator);
            RequireNoPendingPhysicalCommit(head);
            if (head.CurrentSaveTransferId == binding.TransferId)
                throw new IOException("A save transfer ID cannot be reused for a public delete.");
            if (head.Deletes.FirstOrDefault(d => d.Binding.TransferId == binding.TransferId ||
                    d.Binding.RequestNonce == binding.RequestNonce) is { } replay)
            {
                if (replay.Binding != binding || replay.Kind != StagedPublicDeleteKind.Ordinary)
                    throw new IOException("The delete replay is bound to a different capability or kind.");
                return replay;
            }
            if (head.Deletes.Any(d => IsPublicationReservation(d) &&
                    d.Binding.PublicIdentity != binding.PublicIdentity))
                throw new IOException("The public object conflicts with an accepted deletion reservation.");
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            retainedManifestHighWater = Math.Max(retainedManifestHighWater,
                await BoundManifestHighWaterCoreAsync(turn.Destination, token).ConfigureAwait(false));
#endif
            long generation = checked(Math.Max(head.MaxAllocated, retainedManifestHighWater) + 1);
            var admitted = new StagedPublicDeleteRecord(binding, generation, StagedPublicDeleteState.Admitted,
                DateTimeOffset.UtcNow);
            await WriteDestinationHeadCoreAsync(head with { MaxAllocated = generation,
                Deletes = [.. head.Deletes, admitted] }, token).ConfigureAwait(false);
            return admitted;
        }
        finally { _gate.Release(); }
    }

    internal async Task<StagedPublicDeleteRecord> BeginPublicDeleteDispositionAsync(
        DestinationCommitTurn turn, StagedPublicDeleteBinding binding, Guid operationId, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (operationId == Guid.Empty) throw new ArgumentException("A mutation needs a unique operation ID.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            var delete = RequireExactDelete(head, binding);
            if (delete.Kind != StagedPublicDeleteKind.Ordinary)
                throw new IOException("A native on-close CREATE cannot be emulated by an ordinary disposition.");
            if (delete.OperationId == operationId && delete.State is (StagedPublicDeleteState.Accepted or
                    StagedPublicDeleteState.Complete or StagedPublicDeleteState.Canceled or StagedPublicDeleteState.Failed))
                return delete;
            if (delete.State == StagedPublicDeleteState.Superseded) return delete;
            if (head.PendingCommit is { } pending && pending.Mutation == StagedDestinationMutation.DeleteDisposition &&
                pending.OperationId == operationId && pending.TransferId == binding.TransferId)
                return delete; // Durable intent replay; it does not reauthorize a backend or repeat NTFS mutation.
            RequireNoPendingPhysicalCommit(head);
            if (delete.State != StagedPublicDeleteState.Admitted)
                throw new InvalidOperationException("This delete has already left admission.");
            if (head.LatestPublished > delete.Generation)
            {
                delete = delete with { State = StagedPublicDeleteState.Superseded, UpdatedAtUtc = DateTimeOffset.UtcNow };
                await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete), token).ConfigureAwait(false);
                return delete;
            }
            if (head.Deletes.Any(d => IsPublicationReservation(d) &&
                    d.Binding.PublicIdentity != binding.PublicIdentity))
                throw new IOException("An accepted reservation belongs to another public identity.");
            delete = delete with { State = StagedPublicDeleteState.Intent, UpdatedAtUtc = DateTimeOffset.UtcNow,
                OperationId = operationId };
            head = ReplaceDelete(head, delete) with { PendingCommit = new(operationId,
                StagedDestinationMutation.DeleteDisposition, binding.TransferId, delete.Generation, binding.PublicIdentity) };
            await WriteDestinationHeadCoreAsync(head, token).ConfigureAwait(false);
            return delete;
        }
        finally { _gate.Release(); }
    }

    // Persist before forwarding original native CREATE. The dispatcher has
    // already bound the caller, original target object and checked namespace.
    // This receipt never permits repeating CREATE after a lost response.
    internal async Task<StagedPublicDeleteRecord> BeginNativeDeleteOnCloseCreateAsync(
        DestinationCommitTurn turn, StagedPublicDeleteBinding binding, Guid operationId,
        string locator, long retainedManifestHighWater, CancellationToken token,
        StagedNativeCreateIntent? nativeIntent = null)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Allocation);
        ValidatePublicDeleteBinding(binding, turn.Destination);
        if (operationId == Guid.Empty || binding.OsBootSequence is null || retainedManifestHighWater < 0 ||
            turn.Destination.MountManagerVolumeId is null || binding.MountManagerVolumeId != turn.Destination.MountManagerVolumeId)
            throw new ArgumentException("Native CREATE requires its exact operation and OS boot sequence.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await ReadDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false)
                ?? NewDestinationHead(turn.Destination, locator);
            RequireNoPendingPhysicalCommit(head);
            if (head.CurrentSaveTransferId == binding.TransferId)
                throw new IOException("A save transfer cannot be reused for native CREATE.");
            if (head.Deletes.FirstOrDefault(d => d.Binding.TransferId == binding.TransferId ||
                    d.Binding.RequestNonce == binding.RequestNonce) is { } replay)
            {
                if (replay.Binding != binding || replay.OperationId != operationId || replay.NativeIntent != nativeIntent ||
                    replay.Kind != StagedPublicDeleteKind.NativeOnClose)
                    throw new IOException("Native CREATE replay changed its capability or operation.");
                return replay;
            }
            if (head.Deletes.Any(IsPublicationReservation))
                throw new IOException("An unresolved native or physical delete already holds this destination.");
#if SAFEUPLOAD_ADMISSION_EVIDENCE
            // The turn and journal gate protect the scan and the claim together.
            // A dispatcher scalar cannot omit a retained bound manifest/tombstone.
            retainedManifestHighWater = Math.Max(retainedManifestHighWater,
                await BoundManifestHighWaterCoreAsync(turn.Destination, token).ConfigureAwait(false));
#endif
            long generation = checked(Math.Max(head.MaxAllocated, retainedManifestHighWater) + 1);
            var intent = new StagedPublicDeleteRecord(binding, generation,
                StagedPublicDeleteState.AcceptedUnresolved, DateTimeOffset.UtcNow, operationId,
                StagedPublicDeleteKind.NativeOnClose, NativeIntent: nativeIntent);
            await WriteDestinationHeadCoreAsync(head with { MaxAllocated = generation,
                Deletes = [.. head.Deletes, intent] }, token).ConfigureAwait(false);
            return intent;
        }
        finally { _gate.Release(); }
    }

    // Only the original checked CREATE's NTSTATUS and preallocated record
    // binding may supply these inputs. Failed bookkeeping cannot change an
    // NTFS-accepted result or authorize another open/mutation.
    internal async Task<StagedPublicDeleteRecord> RecordNativeDeleteOnCloseCreateResultAsync(
        DestinationCommitTurn turn, StagedPublicDeleteBinding binding, Guid operationId,
        bool ntfsAccepted, bool trackingBound, StagedNativeCreateOutcome? nativeOutcome = null)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (!ntfsAccepted && trackingBound) throw new ArgumentException("A failed CREATE cannot own a live native record.");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactNativeDelete(head, binding, operationId);
            if (delete.NativeCreateAccepted is { } recorded)
            {
                if (recorded != ntfsAccepted || (delete.NativeOutcome is not null && delete.NativeOutcome != nativeOutcome))
                    throw new IOException("The native CREATE result changed on replay.");
                return delete; // An unresolved receipt is released only by reconciliation, never a later bool.
            }
            if (delete.State != StagedPublicDeleteState.AcceptedUnresolved)
                throw new IOException("No unresolved pre-CREATE intent remains for this result.");
            delete = delete with { NativeCreateAccepted = ntfsAccepted, NativeOutcome = nativeOutcome,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                State = !ntfsAccepted ? StagedPublicDeleteState.Failed :
                    trackingBound ? StagedPublicDeleteState.Admitted : StagedPublicDeleteState.AcceptedUnresolved };
            await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete), CancellationToken.None).ConfigureAwait(false);
            return delete;
        }
        finally { _gate.Release(); }
    }

    // A previously tracked native open can lose cleanup coverage later. This
    // uses the existing exceptional state; accepted CREATE facts stay immutable.
    internal async Task<StagedPublicDeleteRecord> RetainNativeReconciliationHoldAsync(
        DestinationCommitTurn turn, StagedPublicDeleteBinding binding, Guid operationId, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactNativeDelete(head, binding, operationId);
            if (delete.State != StagedPublicDeleteState.Admitted) return delete;
            if (delete.NativeCreateAccepted == false)
                throw new IOException("A failed original CREATE cannot regain a publication hold.");
            delete = delete with { State = StagedPublicDeleteState.AcceptedUnresolved, UpdatedAtUtc = DateTimeOffset.UtcNow };
            await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete), token).ConfigureAwait(false);
            return delete;
        }
        finally { _gate.Release(); }
    }

    // Called by exact last-handle CLEANUP or startup recovery, after a checked
    // complete parent enumeration and session-bound native-record replay. A
    // boot counter alone, new service epoch or driver GUID is not lifetime
    // evidence; the proof also rejects a stale/partial/unfinished boot replay.
    internal async Task<StagedPublicDeleteRecord> ReconcileNativeDeleteOnCloseAsync(
        DestinationCommitTurn turn, StagedPublicDeleteBinding binding, Guid operationId,
        StagedNativeRecoverySession.Proof lifetimeProof,
        StagedDestinationNameObservation observation, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        ArgumentNullException.ThrowIfNull(lifetimeProof);
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.Destination != turn.Destination || !observation.CompleteEnumeration ||
            observation.ParentBefore != turn.Destination.Parent || observation.ParentAfter != turn.Destination.Parent)
            throw new IOException("Native recovery needs a complete enumeration of the exact stable anchored parent.");
        if (observation.PublicIdentity is not null) RequireSameVolumeIdentity(turn.Destination, observation.PublicIdentity);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactNativeDelete(head, binding, operationId);
            lifetimeProof.RequireExactLifetimeEnded(binding, operationId);
            if (delete.State == StagedPublicDeleteState.Admitted) return delete;
            if (delete.State != StagedPublicDeleteState.AcceptedUnresolved)
                throw new IOException("This native intent is no longer awaiting exceptional reconciliation.");
            bool newerPublished = observation.PublicIdentity is not null && head.LatestPublished > delete.Generation &&
                head.PublishedIdentity == observation.PublicIdentity;
            if (observation.PublicIdentity is not null && observation.PublicIdentity != binding.PublicIdentity && !newerPublished)
                throw new IOException("An unexplained replacement retains the native recovery hold.");
            delete = delete with { State = newerPublished ? StagedPublicDeleteState.Superseded : StagedPublicDeleteState.Admitted,
                UpdatedAtUtc = DateTimeOffset.UtcNow };
            // Neither original identity nor name absence is a physical ACK.
            // Keep the original scheduled intent and its generation floor.
            await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete), token).ConfigureAwait(false);
            return delete;
        }
        finally { _gate.Release(); }
    }

    // Terminal native-link evidence is stronger than releasing the exceptional
    // hold. The dispatcher must retain this receipt until exact driver-record
    // removal is confirmed; this method does not acknowledge the kernel map.
    internal async Task<StagedPublicDeleteRecord> CompleteNativeDeleteOnCloseAsync(
        DestinationCommitTurn turn, StagedPublicDeleteBinding binding, Guid operationId,
        StagedNativeRecoverySession.Proof lifetimeProof,
        StagedDestinationNameObservation observation, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        ArgumentNullException.ThrowIfNull(lifetimeProof);
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.Destination != turn.Destination || !observation.CompleteEnumeration ||
            observation.ParentBefore != turn.Destination.Parent || observation.ParentAfter != turn.Destination.Parent)
            throw new IOException("Native completion requires the exact stable anchored name observation.");
        if (observation.PublicIdentity is not null) RequireSameVolumeIdentity(turn.Destination, observation.PublicIdentity);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactNativeDelete(head, binding, operationId);
            lifetimeProof.RequireExactLifetimeEnded(binding, operationId);
            if (delete.State is StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded) return delete;
            if (delete.State is not (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.AcceptedUnresolved))
                throw new IOException("Native completion has no retained scheduled-link intent.");
            if (observation.PublicIdentity is null)
            {
                delete = delete with { State = StagedPublicDeleteState.Complete, UpdatedAtUtc = DateTimeOffset.UtcNow };
                await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete) with
                    { CommittedDelete = Math.Max(head.CommittedDelete, delete.Generation) }, token).ConfigureAwait(false);
                return delete;
            }
            if (head.LatestPublished > delete.Generation && head.PublishedIdentity == observation.PublicIdentity)
            {
                delete = delete with { State = StagedPublicDeleteState.Superseded, UpdatedAtUtc = DateTimeOffset.UtcNow };
                await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete), token).ConfigureAwait(false);
                return delete;
            }
            if (observation.PublicIdentity != binding.PublicIdentity)
                throw new IOException("An unexplained replacement cannot complete the native link.");
            return delete; // The original may still be delete-pending behind another reader.
        }
        finally { _gate.Release(); }
    }

    // Invoke only after the exact permitted backend operation returned its
    // real NTFS result. Do not cancel this durable receipt after mutation.
    internal async Task RecordPublicDeleteDispositionResultAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, Guid operationId, bool ntfsAccepted)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            var delete = RequireExactDelete(head, binding);
            if (delete.Kind != StagedPublicDeleteKind.Ordinary)
                throw new IOException("An ordinary disposition result cannot resolve a native CREATE intent.");
            if (delete.OperationId == operationId &&
                ((ntfsAccepted && delete.State is (StagedPublicDeleteState.Accepted or StagedPublicDeleteState.Complete or
                    StagedPublicDeleteState.Canceled)) ||
                 (!ntfsAccepted && delete.State == StagedPublicDeleteState.Failed))) return;
            var intent = RequirePendingCommit(head, operationId, StagedDestinationMutation.DeleteDisposition, binding.TransferId);
            if (delete.State != StagedPublicDeleteState.Intent) throw new InvalidDataException("No exact delete intent exists.");
            delete = delete with { State = ntfsAccepted ? StagedPublicDeleteState.Accepted : StagedPublicDeleteState.Failed,
                UpdatedAtUtc = DateTimeOffset.UtcNow };
            await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete) with { PendingCommit = null,
                LastMutationResult = new(intent, ntfsAccepted) },
                CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task BeginPublicDeleteClearAsync(DestinationCommitTurn turn, Guid operationId,
        StagedStageIdentity exactPublicIdentity, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (operationId == Guid.Empty) throw new ArgumentException("A clear needs a unique operation ID.");
        RequireSameVolumeIdentity(turn.Destination, exactPublicIdentity);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            if (!head.Deletes.Any(d => d.Kind == StagedPublicDeleteKind.Ordinary && d.Binding.PublicIdentity == exactPublicIdentity &&
                    d.State is (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.Accepted)))
                throw new IOException("No provisional disposition is bound to this exact public object.");
            await WriteDestinationHeadCoreAsync(head with { PendingCommit = new(operationId,
                StagedDestinationMutation.ClearDisposition, Guid.Empty, 0, exactPublicIdentity) }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // The dispatcher verifies that ordinary FALSE actually cleared NTFS state
    // using an independently checked DELETE handle. This clears every owner's
    // provisional ordinary intent for that exact object; scheduled ON_CLOSE
    // must use a separate handle-intent record in the forthcoming kernel path.
    internal async Task RecordPublicDeleteClearResultAsync(DestinationCommitTurn turn, Guid operationId,
        StagedStageIdentity exactPublicIdentity, bool ntfsCleared)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            if (IsResultReplay(head, operationId, StagedDestinationMutation.ClearDisposition, Guid.Empty,
                    exactPublicIdentity, ntfsCleared)) return;
            var intent = RequirePendingCommit(head, operationId, StagedDestinationMutation.ClearDisposition, Guid.Empty);
            if (intent.ExpectedPublicIdentity != exactPublicIdentity)
                throw new IOException("Clear completion belongs to another public object.");
            if (ntfsCleared)
                head = head with { Deletes = head.Deletes.Select(d => d.Kind == StagedPublicDeleteKind.Ordinary &&
                    d.Binding.PublicIdentity == exactPublicIdentity &&
                    d.State is (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.Accepted)
                    ? d with { State = StagedPublicDeleteState.Canceled, UpdatedAtUtc = DateTimeOffset.UtcNow } : d).ToArray() };
            await WriteDestinationHeadCoreAsync(head with { PendingCommit = null,
                LastMutationResult = new(intent, ntfsCleared) }, CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // Only an exact accepted operation plus independently reconciled physical
    // link removal may call this. Mere locator absence is never such proof.
    internal async Task RecordPublicDeletePhysicalCompleteAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactDelete(head, binding);
            if (delete.State == StagedPublicDeleteState.Complete) return;
            if (delete.State != StagedPublicDeleteState.Accepted)
                throw new IOException("Physical completion has no exact durable accepted disposition.");
            var completed = head.Deletes.Where(d => d.Binding.PublicIdentity == binding.PublicIdentity &&
                d.State == StagedPublicDeleteState.Accepted).ToArray();
            long barrier = Math.Max(head.CommittedDelete, completed.Max(d => d.Generation));
            await WriteDestinationHeadCoreAsync(head with { CommittedDelete = barrier,
                Deletes = head.Deletes.Select(d => completed.Contains(d)
                    ? d with { State = StagedPublicDeleteState.Complete, UpdatedAtUtc = DateTimeOffset.UtcNow } : d).ToArray() },
                token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task CancelAdmittedPublicDeleteAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactDelete(head, binding);
            if (delete.State == StagedPublicDeleteState.Canceled) return;
            if (delete.Kind != StagedPublicDeleteKind.Ordinary || delete.State != StagedPublicDeleteState.Admitted)
                throw new IOException("Cancellation cannot undo an attempted or accepted NTFS disposition.");
            await WriteDestinationHeadCoreAsync(ReplaceDelete(head, delete with
                { State = StagedPublicDeleteState.Canceled, UpdatedAtUtc = DateTimeOffset.UtcNow }), token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task BeginDestinationPublicationAsync(DestinationCommitTurn turn, Guid operationId,
        Guid transferId, long generation, StagedStageIdentity? expectedPublicIdentity,
        StagedStageIdentity temporaryIdentity, long length, string digest, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.PhysicalCommit);
        if (operationId == Guid.Empty || transferId == Guid.Empty || length < 0 || !IsMeasuredDigest(length, digest))
            throw new ArgumentException("Publication requires an exact measured intent.");
        RequireSameVolumeIdentity(turn.Destination, temporaryIdentity);
        if (expectedPublicIdentity is not null) RequireSameVolumeIdentity(turn.Destination, expectedPublicIdentity);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            if (head.CurrentSaveTransferId != transferId || head.CurrentSaveGeneration != generation ||
                generation <= PublicationGenerationFloor(head) || generation <= head.LatestPublished ||
                head.Deletes.Any(IsPublicationReservation))
                throw new IOException("A newer save, committed delete or accepted reservation bars publication.");
            await WriteDestinationHeadCoreAsync(head with { PendingCommit = new(operationId,
                StagedDestinationMutation.Publication, transferId, generation, expectedPublicIdentity,
                temporaryIdentity, length, digest) }, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task RecordDestinationPublicationResultAsync(DestinationCommitTurn turn, Guid operationId,
        Guid transferId, StagedStageIdentity exactRenamedIdentity, bool renameCommitted)
    {
        turn.Require(this);
        if (turn.Purpose == StagedDestinationTurnPurpose.Allocation)
            throw new InvalidOperationException("An allocation turn cannot complete a physical commit.");
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, CancellationToken.None).ConfigureAwait(false);
            if (IsResultReplay(head, operationId, StagedDestinationMutation.Publication, transferId,
                    exactRenamedIdentity, renameCommitted)) return;
            var intent = RequirePendingCommit(head, operationId, StagedDestinationMutation.Publication, transferId);
            if (intent.TemporaryIdentity != exactRenamedIdentity)
                throw new IOException("The publication result belongs to a different file identity.");
            await WriteDestinationHeadCoreAsync(head with { PendingCommit = null,
                LatestPublished = renameCommitted ? intent.Generation : head.LatestPublished,
                PublishedIdentity = renameCommitted ? exactRenamedIdentity : head.PublishedIdentity,
                LastMutationResult = new(intent, renameCommitted) },
                CancellationToken.None).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // Exact driver acknowledgement permits receipt retirement. The separate
    // head always retains high-water/published/delete barriers after manifests
    // and terminal receipts have been compacted.
    internal async Task RetirePublicDeleteReceiptAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactDelete(head, binding);
            if (delete.Kind == StagedPublicDeleteKind.NativeOnClose)
                throw new IOException("Native receipt retirement requires confirmed kernel-record removal.");
            if (delete.State is not (StagedPublicDeleteState.Canceled or StagedPublicDeleteState.Superseded or
                StagedPublicDeleteState.Complete or StagedPublicDeleteState.Failed))
                throw new IOException("An unresolved delete receipt cannot be compacted.");
            await WriteDestinationHeadCoreAsync(head with { Deletes = head.Deletes.Where(d => d != delete).ToArray() },
                token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task ArmNativeAcknowledgementAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, Guid operationId, ulong mapRevision, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        if (mapRevision == 0) throw new ArgumentOutOfRangeException(nameof(mapRevision));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactNativeDelete(head, binding, operationId);
            if (delete.State is not (StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded or
                StagedPublicDeleteState.Failed)) throw new IOException("A live native link cannot be acknowledged.");
            if (delete.NativeAcknowledgementRevision is { } previous && previous > mapRevision)
                throw new IOException("The native acknowledgement revision went backwards.");
            await WriteDestinationHeadCoreAsync(ReplaceDelete(head,
                delete with { NativeAcknowledgementRevision = mapRevision }), token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task RetireNativeDeleteReceiptAsync(DestinationCommitTurn turn,
        StagedPublicDeleteBinding binding, Guid operationId, StagedNativeRecoverySession.Proof removalProof,
        ulong acknowledgedMapRevision, CancellationToken token)
    {
        turn.Require(this, StagedDestinationTurnPurpose.Reconciliation);
        ArgumentNullException.ThrowIfNull(removalProof);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var head = await RequireDestinationHeadCoreAsync(turn.Destination, token).ConfigureAwait(false);
            RequireNoPendingPhysicalCommit(head);
            var delete = RequireExactNativeDelete(head, binding, operationId);
            if (delete.State is not (StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded or
                StagedPublicDeleteState.Failed))
                throw new IOException("A nonterminal native receipt cannot be retired.");
            removalProof.RequireExactRecordRemoved(binding, operationId, acknowledgedMapRevision);
            await WriteDestinationHeadCoreAsync(head with { Deletes = head.Deletes.Where(d => d != delete).ToArray() },
                token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static StagedDestinationHead ReplaceDelete(StagedDestinationHead head, StagedPublicDeleteRecord delete) =>
        head with { Deletes = head.Deletes.Select(d => d.Binding.TransferId == delete.Binding.TransferId ? delete : d).ToArray() };

    private static StagedPublicDeleteRecord RequireExactDelete(StagedDestinationHead head, StagedPublicDeleteBinding binding) =>
        head.Deletes.SingleOrDefault(d => d.Binding == binding)
        ?? throw new IOException("No delete receipt matches the exact capability binding.");

    private static StagedPublicDeleteRecord RequireExactNativeDelete(StagedDestinationHead head,
        StagedPublicDeleteBinding binding, Guid operationId)
    {
        var delete = RequireExactDelete(head, binding);
        if (head.Destination.MountManagerVolumeId is null || binding.MountManagerVolumeId != head.Destination.MountManagerVolumeId ||
            operationId == Guid.Empty || delete.OperationId != operationId ||
            delete.Kind != StagedPublicDeleteKind.NativeOnClose)
            throw new IOException("No native CREATE intent matches the exact capability and operation.");
        return delete;
    }

    private static bool IsPublicationReservation(StagedPublicDeleteRecord delete) =>
        delete.State is StagedPublicDeleteState.Accepted or StagedPublicDeleteState.AcceptedUnresolved ||
        (delete.Kind == StagedPublicDeleteKind.NativeOnClose && delete.Binding.MountManagerVolumeId is null &&
         delete.State == StagedPublicDeleteState.Admitted);

    private static long PublicationGenerationFloor(StagedDestinationHead head) => Math.Max(head.CommittedDelete,
        head.Deletes.Where(d => d.Kind == StagedPublicDeleteKind.NativeOnClose &&
            d.State is (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.AcceptedUnresolved))
            .Select(d => d.Generation).DefaultIfEmpty(0).Max());

    private static StagedDestinationCommitIntent RequirePendingCommit(StagedDestinationHead head, Guid operationId,
        StagedDestinationMutation mutation, Guid transferId) => head.PendingCommit is { } intent &&
        intent.OperationId == operationId && intent.Mutation == mutation && intent.TransferId == transferId
        ? intent : throw new IOException("The physical result has no matching durable operation intent.");

    private static bool IsResultReplay(StagedDestinationHead head, Guid operationId, StagedDestinationMutation mutation,
        Guid transferId, StagedStageIdentity identity, bool succeeded) =>
        head.LastMutationResult is { } result && result.Intent.OperationId == operationId &&
        result.Intent.Mutation == mutation && result.Intent.TransferId == transferId && result.Succeeded == succeeded &&
        (mutation == StagedDestinationMutation.Publication ? result.Intent.TemporaryIdentity : result.Intent.ExpectedPublicIdentity) == identity;

    private static void RequireNoPendingPhysicalCommit(StagedDestinationHead head)
    {
        if (head.PendingCommit is not null) throw new IOException("An unresolved physical intent requires exact recovery.");
    }

    private static StagedDestinationHead NewDestinationHead(StagedDestinationIdentity destination, string locator) =>
        new(destination, Path.GetFullPath(locator), 0, null, 0, 0, null, 0, null, []);

    private static void RequireSameVolumeIdentity(StagedDestinationIdentity destination, StagedStageIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.VolumeSerialNumber != destination.VolumeRoot.VolumeSerialNumber ||
            (identity.FileIdHigh | identity.FileIdLow) == 0)
            throw new ArgumentException("The object is not bound to the destination volume.");
    }

    private static void ValidatePublicDeleteBinding(StagedPublicDeleteBinding binding, StagedDestinationIdentity destination)
    {
        ArgumentNullException.ThrowIfNull(binding);
        RequireSameVolumeIdentity(destination, binding.PublicIdentity);
        if (binding.MountManagerVolumeId == Guid.Empty ||
            (binding.MountManagerVolumeId is not null && binding.MountManagerVolumeId != destination.MountManagerVolumeId))
            throw new ArgumentException("A delete changed its captured Mount Manager volume identity.");
        if (binding.TransferId == Guid.Empty || binding.RequestNonce == Guid.Empty ||
            binding.DriverInstanceId == Guid.Empty || binding.ConnectionEpoch == 0 ||
            binding.OwnerProcessId <= 0 || binding.OwnerProcessCreationTime <= 0 ||
            string.IsNullOrWhiteSpace(binding.OwnerSid) || binding.OwnerSid.Length > 184)
            throw new ArgumentException("A delete needs an exact epoch, request and owner binding.");
        if (OperatingSystem.IsWindows()) _ = new SecurityIdentifier(binding.OwnerSid);
    }

    private static bool IsExactDigest(string? digest) => digest is { Length: 64 } &&
        digest.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static bool IsMeasuredDigest(long? length, string? digest) => length is >= 0 && IsExactDigest(digest) &&
        (length != 0 || digest == EmptySha256Hex);

    private string DestinationHeadPath(StagedDestinationIdentity destination) =>
        Path.Combine(_directory, "destination-" + destination.StorageKey + ".state");

    private async Task<StagedDestinationHead> RequireDestinationHeadCoreAsync(StagedDestinationIdentity destination,
        CancellationToken token) => await ReadDestinationHeadCoreAsync(destination, token).ConfigureAwait(false)
        ?? throw new IOException("The destination has no durable head.");

    private async Task<StagedDestinationHead?> ReadDestinationHeadCoreAsync(StagedDestinationIdentity destination,
        CancellationToken token)
    {
        // Never select authority by the exact-leaf filename alone: a legacy
        // folded spelling or another Windows-equivalent spelling must select
        // the same retained head, and duplicates must stop every commit path.
        StagedDestinationHead? selected = null;
        foreach (string path in Directory.EnumerateFiles(_directory, "destination-*.state"))
        {
            token.ThrowIfCancellationRequested();
            var head = await ReadDestinationHeadFileCoreAsync(path, null, token).ConfigureAwait(false)
                ?? throw new InvalidDataException("A destination head disappeared during resolution.");
            if (head.Destination != destination) continue;
            if (selected is not null)
                throw new InvalidDataException("Equivalent destination leaves have conflicting durable heads.");
            selected = head;
        }
        return selected;
    }

    private async Task<StagedDestinationHead?> ReadDestinationHeadFileCoreAsync(string path,
        StagedDestinationIdentity? expectedDestination, CancellationToken token)
    {
        FileStream stream;
        try { stream = StagedJournalFile.Open(path); }
        catch (FileNotFoundException) { return null; }
        await using (stream)
        {
            if (_owner is not null)
            {
                var security = stream.GetAccessControl();
                if (_owner.IsWellKnown(WellKnownSidType.LocalSystemSid)) RequireTrustedOwner(security, "destination head");
                RequireNoUntrustedWriters(security, _owner);
            }
            StagedDestinationHead? head = await JsonSerializer.DeserializeAsync<StagedDestinationHead>(stream,
                cancellationToken: token).ConfigureAwait(false);
            if (head?.Destination is null) throw new InvalidDataException("The destination head has no identity.");
            ValidateDestinationHead(head, expectedDestination ?? head.Destination);
            if (!string.Equals(Path.GetFileName(path), Path.GetFileName(DestinationHeadPath(head.Destination)), StringComparison.Ordinal))
                throw new InvalidDataException("The destination head filename does not match its exact namespace identity.");
            return head;
        }
    }

    private async Task WriteDestinationHeadCoreAsync(StagedDestinationHead head, CancellationToken token)
    {
        ValidateDestinationHead(head, head.Destination);
        string path = DestinationHeadPath(head.Destination);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using var stream = CreatePrivateTemporary(temporary);
            await JsonSerializer.SerializeAsync(stream, head, cancellationToken: token).ConfigureAwait(false);
            if (stream.Length > StagedJournalFile.MaximumManifestBytes)
                throw new InvalidDataException("The destination head exceeds its qualified size bound.");
            StagedDestinationFile.Commit(stream, temporary, path);
            SignalDestinationChanged(head.Destination);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static void ValidateDestinationHead(StagedDestinationHead? head, StagedDestinationIdentity destination)
    {
        if (head is null || head.Destination != destination || !Path.IsPathFullyQualified(head.Locator) ||
            !destination.LeafEquals(Path.GetFileName(head.Locator)) ||
            head.MaxAllocated < 0 || head.CurrentSaveGeneration < 0 || head.CurrentSaveGeneration > head.MaxAllocated ||
            ((head.CurrentSaveTransferId is null) != (head.CurrentSaveGeneration == 0)) ||
            head.CurrentSaveTransferId == Guid.Empty || head.LatestPublished < 0 || head.LatestPublished > head.MaxAllocated ||
            ((head.PublishedIdentity is null) != (head.LatestPublished == 0)) ||
            head.CommittedDelete < 0 || head.CommittedDelete > head.MaxAllocated ||
            head.Deletes is null)
            throw new InvalidDataException("The durable destination head is invalid.");
        if (head.PublishedIdentity is not null) RequireSameVolumeIdentity(destination, head.PublishedIdentity);
        var ids = new HashSet<Guid>(); var nonces = new HashSet<Guid>(); var generations = new HashSet<long>();
        foreach (var delete in head.Deletes)
        {
            if (delete is null) throw new InvalidDataException("Null delete receipt.");
            ValidatePublicDeleteBinding(delete.Binding, destination);
            if (!ids.Add(delete.Binding.TransferId) || !nonces.Add(delete.Binding.RequestNonce) ||
                !generations.Add(delete.Generation) || delete.Generation <= 0 || delete.Generation > head.MaxAllocated ||
                delete.Generation == head.CurrentSaveGeneration || delete.OperationId == Guid.Empty ||
                (delete.State is (StagedPublicDeleteState.Intent or StagedPublicDeleteState.Accepted or
                    StagedPublicDeleteState.Complete or StagedPublicDeleteState.Failed or
                    StagedPublicDeleteState.AcceptedUnresolved) && delete.OperationId is null) ||
                !Enum.IsDefined(delete.State) || !Enum.IsDefined(delete.Kind) ||
                (delete.Kind == StagedPublicDeleteKind.Ordinary &&
                    (delete.State == StagedPublicDeleteState.AcceptedUnresolved || delete.NativeCreateAccepted is not null ||
                     delete.NativeIntent is not null || delete.NativeOutcome is not null || delete.NativeAcknowledgementRevision is not null)) ||
                (delete.Kind == StagedPublicDeleteKind.NativeOnClose &&
                    (delete.Binding.OsBootSequence is null || delete.OperationId is null ||
                     delete.State is (StagedPublicDeleteState.Intent or StagedPublicDeleteState.Accepted or StagedPublicDeleteState.Canceled) ||
                     (delete.State == StagedPublicDeleteState.Failed && delete.NativeCreateAccepted != false) ||
                     (delete.State != StagedPublicDeleteState.Failed && delete.NativeCreateAccepted == false))) ||
                delete.UpdatedAtUtc == default || delete.UpdatedAtUtc.Offset != TimeSpan.Zero ||
                (delete.NativeAcknowledgementRevision is { } ack && (ack == 0 ||
                    delete.State is not (StagedPublicDeleteState.Complete or StagedPublicDeleteState.Superseded or StagedPublicDeleteState.Failed))) ||
                (delete.NativeOutcome is { } outcome && ((outcome.Facts & ~0x0fu) != 0 || (outcome.Facts & 2) == 0 ||
                    delete.NativeCreateAccepted is null || delete.NativeCreateAccepted != ((outcome.Facts & 4) != 0))) ||
                (delete.State == StagedPublicDeleteState.Complete && delete.Generation > head.CommittedDelete))
                throw new InvalidDataException("The durable public-delete receipt is invalid.");
        }
        var acceptedIdentities = head.Deletes.Where(IsPublicationReservation)
            .Select(d => d.Binding.PublicIdentity).Distinct().ToArray();
        if (acceptedIdentities.Length > 1) throw new InvalidDataException("Conflicting delete reservations.");
        if (head.PendingCommit is { } intent)
        {
            if (intent.OperationId == Guid.Empty || !Enum.IsDefined(intent.Mutation))
                throw new InvalidDataException("Invalid physical commit intent.");
            if (intent.ExpectedPublicIdentity is not null) RequireSameVolumeIdentity(destination, intent.ExpectedPublicIdentity);
            switch (intent.Mutation)
            {
                case StagedDestinationMutation.Publication:
                    if (intent.TransferId != head.CurrentSaveTransferId || intent.Generation != head.CurrentSaveGeneration ||
                        intent.Generation <= PublicationGenerationFloor(head) || intent.Generation <= head.LatestPublished ||
                        intent.TemporaryIdentity is null || !IsMeasuredDigest(intent.Length, intent.Sha256Hex) ||
                        acceptedIdentities.Length != 0) throw new InvalidDataException("Invalid publication intent.");
                    RequireSameVolumeIdentity(destination, intent.TemporaryIdentity);
                    break;
                case StagedDestinationMutation.DeleteDisposition:
                    if (!head.Deletes.Any(d => d.State == StagedPublicDeleteState.Intent &&
                            d.Binding.TransferId == intent.TransferId && d.Generation == intent.Generation &&
                            d.Binding.PublicIdentity == intent.ExpectedPublicIdentity && d.OperationId == intent.OperationId) ||
                        intent.TemporaryIdentity is not null || intent.Length is not null || intent.Sha256Hex is not null)
                        throw new InvalidDataException("Invalid delete disposition intent.");
                    break;
                case StagedDestinationMutation.ClearDisposition:
                    if (intent.TransferId != Guid.Empty || intent.Generation != 0 || intent.ExpectedPublicIdentity is null ||
                        intent.TemporaryIdentity is not null || intent.Length is not null || intent.Sha256Hex is not null ||
                        !head.Deletes.Any(d => d.Kind == StagedPublicDeleteKind.Ordinary &&
                            d.Binding.PublicIdentity == intent.ExpectedPublicIdentity &&
                            d.State is (StagedPublicDeleteState.Admitted or StagedPublicDeleteState.Accepted)))
                        throw new InvalidDataException("Invalid ordinary clear intent.");
                    break;
            }
        }
        if (head.Deletes.Any(d => d.State == StagedPublicDeleteState.Intent &&
                (head.PendingCommit?.Mutation != StagedDestinationMutation.DeleteDisposition ||
                 head.PendingCommit.TransferId != d.Binding.TransferId)))
            throw new InvalidDataException("A provisional physical mutation lost its durable intent.");
        if (head.LastMutationResult is { } result)
        {
            var completedIntent = result.Intent;
            if (completedIntent is null || completedIntent.OperationId == Guid.Empty || !Enum.IsDefined(completedIntent.Mutation) ||
                completedIntent.Generation < 0 || completedIntent.Generation > head.MaxAllocated)
                throw new InvalidDataException("Invalid physical mutation result.");
            if (completedIntent.ExpectedPublicIdentity is not null) RequireSameVolumeIdentity(destination, completedIntent.ExpectedPublicIdentity);
            switch (completedIntent.Mutation)
            {
                case StagedDestinationMutation.Publication:
                    if (completedIntent.TransferId == Guid.Empty || completedIntent.Generation == 0 || completedIntent.TemporaryIdentity is null ||
                        !IsMeasuredDigest(completedIntent.Length, completedIntent.Sha256Hex) ||
                        (result.Succeeded && (head.LatestPublished != completedIntent.Generation ||
                            head.PublishedIdentity != completedIntent.TemporaryIdentity)))
                        throw new InvalidDataException("Invalid durable publication result.");
                    RequireSameVolumeIdentity(destination, completedIntent.TemporaryIdentity);
                    break;
                case StagedDestinationMutation.DeleteDisposition:
                    if (completedIntent.TransferId == Guid.Empty || completedIntent.Generation == 0 || completedIntent.ExpectedPublicIdentity is null ||
                        completedIntent.TemporaryIdentity is not null || completedIntent.Length is not null || completedIntent.Sha256Hex is not null)
                        throw new InvalidDataException("Invalid durable disposition result.");
                    break;
                case StagedDestinationMutation.ClearDisposition:
                    if (completedIntent.TransferId != Guid.Empty || completedIntent.Generation != 0 || completedIntent.ExpectedPublicIdentity is null ||
                        completedIntent.TemporaryIdentity is not null || completedIntent.Length is not null || completedIntent.Sha256Hex is not null)
                        throw new InvalidDataException("Invalid durable clear result.");
                    break;
            }
        }
    }
}
