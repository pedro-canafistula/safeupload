#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

[Flags]
internal enum StagedBoundBlocker
{
    None = 0,
    Disconnected = 1,
    NegotiatedPathIncomplete = 2,
    StartupRecoveryIncomplete = 4,
    ReplayInvalidated = 8,
    ProtocolChanged = 16,
    PolicyChanged = 32,
    UnresolvedPrerequisite = 64,
    CoverageNotReady = 128,
    NativeDescriptorConstructionUnproved = 256,
    SeedCoherenceUnproved = 512,
    ExportAuthorityUnproved = 1024,
    VersionPublicationAuthorityUnproved = 2048
}

internal sealed record StagedBoundReadinessDecision(StagedBoundBlocker Blockers)
{
    internal bool IsReady => Blockers == StagedBoundBlocker.None;
    internal string Reason => IsReady ? "bound_ready" : "bound_not_ready:" + string.Join(",", Enum.GetValues<StagedBoundBlocker>()
        .Where(b => b != StagedBoundBlocker.None && Blockers.HasFlag(b)).Select(b => b switch
        {
            StagedBoundBlocker.NativeDescriptorConstructionUnproved => "native_create_security_unproved",
            StagedBoundBlocker.SeedCoherenceUnproved => "seed_coherence_unproved",
            StagedBoundBlocker.ExportAuthorityUnproved => "seed_export_authority_unproved",
            StagedBoundBlocker.VersionPublicationAuthorityUnproved => "version_publication_authority_unproved",
            _ => b.ToString()
        }));
}

internal sealed record StagedBoundRecoveryReceipt(Guid Driver, ulong Epoch, uint Boot, ulong NativeRevision,
    bool HasUnresolvedPrerequisites);

// One connection, one complete startup pass, one delivered negotiation. All
// mutations serialize with invalidation; late work cannot resurrect a ticket.
// There is deliberately no runtime/configuration switch for the native holds.
internal sealed class StagedBoundReadiness
{
    internal const uint BoundCapability = 0x40; // reserved V23 head bit; not in V20 Required
    internal const StagedBoundBlocker NativeHolds = StagedBoundBlocker.NativeDescriptorConstructionUnproved |
        StagedBoundBlocker.SeedCoherenceUnproved | StagedBoundBlocker.ExportAuthorityUnproved |
        StagedBoundBlocker.VersionPublicationAuthorityUnproved;
    private readonly object _sync = new();
    private long _ticket;
    private bool _connected, _negotiated, _coverageReady;
    private Guid _driver;
    private uint _policyGeneration;
    private ulong _authorityRevision;
    private StagedBoundRecoveryReceipt? _recovery;
    private StagedBoundBlocker _invalid = StagedBoundBlocker.Disconnected;
    private readonly Dictionary<string, (Guid Driver, ulong Epoch, uint Boot, ulong Revision)> _replays = new();

    internal long BeginConnection()
    {
        lock (_sync)
        {
            ++_ticket; _connected = true; _negotiated = false; _coverageReady = false;
            _driver = Guid.Empty; _recovery = null; _invalid = StagedBoundBlocker.None; _replays.Clear();
            _policyGeneration = 0; _authorityRevision = 0;
            return _ticket;
        }
    }

    internal void Invalidate(StagedBoundBlocker reason)
    {
        lock (_sync)
        {
            ++_ticket; _invalid |= reason; _negotiated = false; _recovery = null;
            if (reason.HasFlag(StagedBoundBlocker.Disconnected)) _connected = false;
        }
    }

    internal void CompleteNegotiation(long ticket, Guid driver, uint version, uint capabilities, bool delivered)
    {
        lock (_sync)
        {
            if (ticket != _ticket || !_connected || _invalid != StagedBoundBlocker.None) return;
            if (version != Contract.StageExtensionVersion || driver == Guid.Empty ||
                (_driver != Guid.Empty && driver != _driver))
            { Invalidate(StagedBoundBlocker.ProtocolChanged); return; }
            _driver = driver;
            _negotiated = delivered && capabilities == ((uint)StageV20Capability.Required | BoundCapability);
            if (!delivered) Invalidate(StagedBoundBlocker.NegotiatedPathIncomplete);
            if (_recovery is { } recovery && recovery.Driver != driver)
                Invalidate(StagedBoundBlocker.ReplayInvalidated);
        }
    }

    internal void CompleteRecovery(long ticket, StagedBoundRecoveryReceipt receipt)
    {
        lock (_sync)
        {
            if (ticket != _ticket || !_connected || _invalid != StagedBoundBlocker.None) return;
            if (receipt.Driver == Guid.Empty || receipt.Epoch == 0 || receipt.NativeRevision == 0 ||
                (_driver != Guid.Empty && _driver != receipt.Driver) ||
                (_replays.TryGetValue("native", out var latest) && latest !=
                    (receipt.Driver, receipt.Epoch, receipt.Boot, receipt.NativeRevision)))
            { Invalidate(StagedBoundBlocker.ReplayInvalidated); return; }
            _recovery = receipt;
        }
    }

    internal void ObserveReplay(string map, Guid driver, ulong epoch, uint boot, ulong revision)
    {
        lock (_sync)
        {
            var current = (driver, epoch, boot, revision);
            // Invalidate even before receipt consumption: a changed map must
            // not let a late completed startup pass restore old authority.
            // Recovery may keep doing bookkeeping, but readiness needs a new
            // connection and complete pass after any observed map change.
            if (driver == Guid.Empty || epoch == 0 || revision == 0 ||
                (_replays.TryGetValue(map, out var prior) && prior != current) ||
                (_recovery is { } recovered &&
                 (driver != recovered.Driver || epoch != recovered.Epoch || boot != recovered.Boot ||
                  (map == "native" && revision != recovered.NativeRevision))))
                Invalidate(StagedBoundBlocker.ReplayInvalidated);
            _replays[map] = current;
        }
    }

    internal void ObserveAuthority(Guid driver, ulong epoch, ulong revision)
    {
        lock (_sync)
        {
            if (revision == 0 || (_authorityRevision != 0 && revision != _authorityRevision) ||
                (_recovery is { } recovered && (driver != recovered.Driver || epoch != recovered.Epoch)))
                Invalidate(StagedBoundBlocker.ProtocolChanged);
            _authorityRevision = revision;
        }
    }

    internal void ObserveCoverage(AdmissionCoverageDecision coverage)
    {
        lock (_sync)
        {
            _coverageReady = coverage.Readiness == AdmissionCoverageReadiness.Ready;
            if (_policyGeneration != 0 && coverage.NativePolicyGeneration != 0 &&
                _policyGeneration != coverage.NativePolicyGeneration)
                Invalidate(StagedBoundBlocker.PolicyChanged);
            if (coverage.NativePolicyGeneration != 0) _policyGeneration = coverage.NativePolicyGeneration;
        }
    }

    internal StagedBoundReadinessDecision Snapshot
    {
        get
        {
            lock (_sync)
                return Compose(_connected, _negotiated, _recovery is not null,
                    _coverageReady, _invalid | (_recovery?.HasUnresolvedPrerequisites == true
                        ? StagedBoundBlocker.UnresolvedPrerequisite : StagedBoundBlocker.None), NativeHolds);
        }
    }

    // Pure composition control: synthetic proof inputs in tests confer no live
    // authority. Production Snapshot always supplies the fixed NativeHolds.
    internal static StagedBoundReadinessDecision Compose(bool connected, bool negotiated, bool recovered,
        bool coverageReady, StagedBoundBlocker invalid, StagedBoundBlocker nativeHolds) => new(invalid | nativeHolds |
        (connected ? StagedBoundBlocker.None : StagedBoundBlocker.Disconnected) |
        (negotiated ? StagedBoundBlocker.None : StagedBoundBlocker.NegotiatedPathIncomplete) |
        (recovered ? StagedBoundBlocker.None : StagedBoundBlocker.StartupRecoveryIncomplete) |
        (coverageReady ? StagedBoundBlocker.None : StagedBoundBlocker.CoverageNotReady));
}
#endif
