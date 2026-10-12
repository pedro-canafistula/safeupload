namespace SafeUpload.Agent.Service.Interception;

// Checked inputs from the authenticated driver replay, not path/PID inference.
// LastHandleCleanedUp describes the preallocated original FILE_OBJECT record.
// Cancellation receipts are the two reviewed before-any-app-handle cases;
// they cannot be inferred from a failed NTSTATUS, path, or arbitrary CLOSE.
// These are lifetime evidence, never physical deletion acknowledgements.
internal sealed record StagedNativeRecordReplay(StagedPublicDeleteBinding Binding,
    Guid OperationId, bool LastHandleCleanedUp, bool CancelledBeforeHandle = false,
    bool CancelledCloseObserved = false);

// The dispatcher creates this only after the driver/connection handshake and
// invalidates it on disconnect. A replay must be reconciled against the actual
// driver map before producing evidence. No live dispatcher uses it yet.
internal sealed class StagedNativeRecoverySession
{
    private readonly object _sync = new();
    private readonly Guid _driverInstanceId;
    private readonly ulong _connectionEpoch;
    private readonly uint? _osBootSequence;
    private bool _active = true;
    private long _replayRevision;
    private Proof? _currentProof;

    internal StagedNativeRecoverySession(Guid driverInstanceId, ulong connectionEpoch, uint? osBootSequence)
    {
        if (driverInstanceId == Guid.Empty || connectionEpoch == 0)
            throw new ArgumentException("Native recovery requires the checked live driver connection.");
        (_driverInstanceId, _connectionEpoch, _osBootSequence) = (driverInstanceId, connectionEpoch, osBootSequence);
    }

    internal void Invalidate()
    {
        lock (_sync) { _active = false; _replayRevision++; _currentProof = null; }
    }

    internal Proof ReconcileReplay(Guid replayDriverInstanceId, ulong replayConnectionEpoch,
        bool complete, bool reconciled, IReadOnlyList<StagedNativeRecordReplay> records,
        ulong? nativeMapRevision = null)
    {
        ArgumentNullException.ThrowIfNull(records);
        lock (_sync)
        {
            // A new or rejected replay invalidates an earlier snapshot; a
            // partial result must never inherit its complete/absent conclusion.
            long revision = ++_replayRevision;
            _currentProof = null;
            if (!_active || replayDriverInstanceId != _driverInstanceId || replayConnectionEpoch != _connectionEpoch)
                throw new IOException("The native replay is not bound to the active driver connection.");
            var copy = records.ToArray();
            var operations = new HashSet<Guid>();
            var transfers = new HashSet<Guid>();
            var nonces = new HashSet<Guid>();
            foreach (var record in copy)
            {
                if (record is null || record.Binding is null || record.OperationId == Guid.Empty ||
                    record.Binding.DriverInstanceId != _driverInstanceId || record.Binding.ConnectionEpoch == 0 ||
                    record.Binding.ConnectionEpoch > _connectionEpoch || record.Binding.TransferId == Guid.Empty ||
                    record.Binding.RequestNonce == Guid.Empty || !operations.Add(record.OperationId) ||
                    !transfers.Add(record.Binding.TransferId) || !nonces.Add(record.Binding.RequestNonce))
                    throw new IOException("The native replay contains an unbound or duplicate original-object record.");
            }
            return _currentProof = new Proof(this, revision, complete, reconciled, copy, nativeMapRevision);
        }
    }

    // Only the exact proof installed by this session is usable. An equivalent
    // binding, counter or reconstructed token is not authenticated evidence.
    internal sealed class Proof
    {
        private readonly StagedNativeRecoverySession _session;
        private readonly long _revision;
        private readonly bool _complete;
        private readonly bool _reconciled;
        private readonly StagedNativeRecordReplay[] _records;
        private readonly ulong? _nativeMapRevision;

        internal Proof(StagedNativeRecoverySession session, long revision, bool complete,
            bool reconciled, StagedNativeRecordReplay[] records, ulong? nativeMapRevision = null)
            => (_session, _revision, _complete, _reconciled, _records, _nativeMapRevision) =
                (session, revision, complete, reconciled, records, nativeMapRevision);

        internal void RequireExactRecordRemoved(StagedPublicDeleteBinding binding, Guid operationId,
            ulong acknowledgedMapRevision)
        {
            lock (_session._sync)
            {
                if (!_session._active || !ReferenceEquals(_session._currentProof, this) ||
                    _revision != _session._replayRevision || !_complete || !_reconciled ||
                    _records.Any(r => r.OperationId == operationId || r.Binding.TransferId == binding.TransferId ||
                        r.Binding.RequestNonce == binding.RequestNonce))
                    throw new IOException("Native receipt retirement requires complete authenticated record removal.");
                if (_session._driverInstanceId == binding.DriverInstanceId)
                {
                    if (_session._connectionEpoch < binding.ConnectionEpoch || acknowledgedMapRevision == 0 ||
                        _nativeMapRevision is not { } currentRevision || currentRevision <= acknowledgedMapRevision)
                        throw new IOException("The native replay does not follow the exact acknowledgement revision.");
                }
                else
                {
                    // A qualified full boot proves the old map cannot survive.
                    // Reload, a new service epoch or a counter alone does not.
                    RequireExactLifetimeEnded(binding, operationId);
                }
            }
        }

        // This authenticates current boot metadata only. It says nothing about
        // private staged objects: the epoch caller must separately complete
        // conservative private recovery with readiness/publication closed.
        internal uint RequireCurrentBoot(Guid expectedDriver)
        {
            lock (_session._sync)
            {
                if (!_session._active || !ReferenceEquals(_session._currentProof, this) ||
                    _revision != _session._replayRevision || !_complete || !_reconciled ||
                    _session._driverInstanceId != expectedDriver ||
                    _session._osBootSequence is not { } boot)
                    throw new IOException("Current boot metadata requires the complete reconciled authenticated replay.");
                return boot;
            }
        }

        internal void RequireExactLifetimeEnded(StagedPublicDeleteBinding binding, Guid operationId)
        {
            lock (_session._sync)
            {
                if (!_session._active || !ReferenceEquals(_session._currentProof, this) ||
                    _revision != _session._replayRevision || !_reconciled)
                    throw new IOException("Native recovery evidence is stale or has not been reconciled.");
                var matching = _records.FirstOrDefault(r => r.OperationId == operationId ||
                    r.Binding.TransferId == binding.TransferId || r.Binding.RequestNonce == binding.RequestNonce);
                if (matching is not null)
                {
                    if (matching.Binding != binding || matching.OperationId != operationId ||
                        !(matching.LastHandleCleanedUp || matching.CancelledBeforeHandle || matching.CancelledCloseObserved))
                        throw new IOException("The exact original native application handle is still live or unproven.");
                    return; // Exact authenticated lifetime receipt, regardless of boot-counter rollback/wrap.
                }
                if (!_complete || _session._driverInstanceId == binding.DriverInstanceId ||
                    binding.OsBootSequence is not { } originalBoot || _session._osBootSequence is not { } currentBoot ||
                    currentBoot <= originalBoot)
                    throw new IOException("The original driver lifetime has not been proven ended.");
                // Requires the service-stop prohibition and voluntary-unload
                // veto while native records remain, plus complete reconciled
                // replay. A new GUID alone, or a
                // resumed original driver even with a larger counter, cannot pass.
            }
        }
    }
}
