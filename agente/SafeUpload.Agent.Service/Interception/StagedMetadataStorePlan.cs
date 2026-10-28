#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal readonly record struct MetadataObjectKey(Guid Transaction, ulong Incarnation);
internal enum MetadataPhysicalClass { HotJournal, HotOther, Shared }
internal enum MetadataStoreDisposition { Committed, RecoverableBookkeeping, Held }
internal enum MetadataStoreStep { Create, Write, F1, EndOfFile, F2, Replace, F3, Append, Slot, Delete, Verify }

internal sealed record BoundedOutputPlan
{
    internal MetadataRoleV32 Role { get; }
    internal MetadataObjectKey Object { get; }
    internal long LogicalLength { get; }
    internal long Alignment { get; }
    internal long AllocationUnit { get; }
    internal long PaddedExtent { get; }
    internal long PeakAllocation { get; }
    internal StagedStageIdentity? ExpectedPredecessor { get; }
    internal long MaximumLogicalBytes { get; }

    internal BoundedOutputPlan(MetadataRoleV32 role, MetadataObjectKey key, long logicalLength,
        long verifiedAlignment, long verifiedAllocationUnit, long paddedExtent, long peakAllocation,
        StagedStageIdentity? expectedPredecessor, long maximumLogicalBytes)
    {
        if (!MetadataStoreRoles.CanOutput(role) || key.Transaction == Guid.Empty || key.Incarnation == 0 ||
            maximumLogicalBytes < 0 || maximumLogicalBytes > MetadataStoreRoles.Maximum(role) ||
            logicalLength < 0 || logicalLength > maximumLogicalBytes ||
            verifiedAlignment is < 4096 or > 65536 || !PowerOfTwo(verifiedAlignment) ||
            verifiedAllocationUnit < 512 || !PowerOfTwo(verifiedAllocationUnit))
            throw new ArgumentOutOfRangeException(nameof(logicalLength), "Invalid bounded metadata output plan.");
        long padded = Round(logicalLength, verifiedAlignment), peak = Round(padded, verifiedAllocationUnit);
        if (paddedExtent != padded || peakAllocation != peak ||
            expectedPredecessor is { FileIdHigh: 0, FileIdLow: 0 } ||
            expectedPredecessor is not null && !MetadataStoreRoles.CanReplace(role))
            throw new ArgumentException("The padded extent, peak or predecessor does not match the plan.");
        (Role, Object, LogicalLength, Alignment, AllocationUnit, PaddedExtent, PeakAllocation,
            ExpectedPredecessor, MaximumLogicalBytes) = (role, key, logicalLength, verifiedAlignment,
            verifiedAllocationUnit, padded, peak, expectedPredecessor, maximumLogicalBytes);
    }

    internal static BoundedOutputPlan Create(MetadataRoleV32 role, MetadataObjectKey key, long logical,
        long alignment, long unit, StagedStageIdentity? predecessor = null) =>
        new(role, key, logical, alignment, unit, Round(logical, alignment), Round(Round(logical, alignment), unit),
            predecessor, MetadataStoreRoles.Maximum(role));
    internal static bool PowerOfTwo(long value) => value > 0 && (value & (value - 1)) == 0;
    internal static long Round(long value, long unit)
    {
        if (value < 0 || unit < 512 || !PowerOfTwo(unit)) throw new ArgumentOutOfRangeException(nameof(value));
        return checked(checked(value + unit - 1) / unit * unit);
    }
}

internal static class MetadataStoreRoles
{
    internal const uint Read = 0x120081, ReadDelete = Read | 0x10000, Output = ReadDelete | 2;
    internal static bool CanReplace(MetadataRoleV32 role) => role is MetadataRoleV32.LedgerNew or
        MetadataRoleV32.CompanionNew or MetadataRoleV32.ManifestNew or MetadataRoleV32.InventoryNew or
        MetadataRoleV32.MarkerNew or MetadataRoleV32.EpochNew or MetadataRoleV32.AppendIntentNew or MetadataRoleV32.CompactionIntentNew;
    internal static bool CanOutput(MetadataRoleV32 role) => CanReplace(role) || role is MetadataRoleV32.Segment or MetadataRoleV32.HistoryCandidate;
    internal static bool CanDelete(MetadataRoleV32 role) => Enum.IsDefined(role) && role is not (MetadataRoleV32.MarkerCurrent or MetadataRoleV32.LegacySecurity or MetadataRoleV32.LegacyNegative);
    internal static uint Access(MetadataRoleV32 role) => !Enum.IsDefined(role) ? throw new ArgumentOutOfRangeException(nameof(role)) :
        CanOutput(role) ? (role == MetadataRoleV32.Segment ? Read | 2 : Output) : CanDelete(role) ? ReadDelete : Read;
    internal static long Maximum(MetadataRoleV32 role) => role switch
    {
        MetadataRoleV32.CompanionCurrent or MetadataRoleV32.CompanionNew => 192,
        MetadataRoleV32.InventoryCurrent or MetadataRoleV32.InventoryNew or MetadataRoleV32.MarkerCurrent or MetadataRoleV32.MarkerNew => 128,
        MetadataRoleV32.EpochCurrent or MetadataRoleV32.EpochNew => 4096,
        MetadataRoleV32.ManifestCurrent or MetadataRoleV32.ManifestNew or MetadataRoleV32.HistoryCandidate => 128 * 1024,
        MetadataRoleV32.Segment => 4 * 1024 * 1024,
        MetadataRoleV32.LegacyNegative => 1192,
        MetadataRoleV32.LegacySecurity => StagedAllocationSecuritySnapshot.MaximumBytes,
        _ when Enum.IsDefined(role) => 64 * 1024,
        _ => throw new ArgumentOutOfRangeException(nameof(role))
    };
}

// This inventory is reconstructed by a later durable consumer, never by a
// foreground directory walk. Native failures leave the original peak charged.
internal sealed class StagedMetadataStoreAccounting(long journalLimit, long otherLimit, long sharedLimit, int maximumObjects)
{
    private sealed record Held(BoundedOutputPlan Plan, MetadataPhysicalClass Class, long Charge,
        StagedStageIdentity? Identity, ulong Revision, bool Released = false, MetadataStorageTransition? Applied = null);
    private readonly object _gate = new();
    private readonly Dictionary<MetadataObjectKey, Held> _objects = new();
    private readonly Dictionary<StagedStageIdentity, MetadataObjectKey> _byIdentity = new();
    private readonly long[] _totals = new long[3];
    private readonly long[] _limits = [journalLimit, otherLimit, sharedLimit];
    private bool _faulted;

    internal (long HotJournal, long HotOther, long Shared) Totals
    { get { lock (_gate) return (_totals[0], _totals[1], _totals[2]); } }
    internal static long SharedDebit(long physical) => physical < 0 ? throw new ArgumentOutOfRangeException(nameof(physical)) : checked(2 * physical + 16 * 1024 * 1024);

    internal bool TryReserve(BoundedOutputPlan plan, MetadataPhysicalClass kind)
    {
        lock (_gate)
        {
            if (_faulted) throw new IOException("Metadata physical accounting is held.");
            if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
            if (_objects.ContainsKey(plan.Object)) throw new IOException("An output incarnation already owns its charge.");
            int index = (int)kind;
            long next = checked(_totals[index] + plan.PeakAllocation);
            if (_objects.Count >= maximumObjects || next > _limits[index]) return false;
            _objects.Add(plan.Object, new(plan, kind, plan.PeakAllocation, null, 0));
            _totals[index] = next;
            return true;
        }
    }
    internal void Bind(MetadataObjectKey key, StagedStageIdentity identity)
    {
        lock (_gate)
        {
            var held = _objects[key];
            if (held.Released || identity is { FileIdHigh: 0, FileIdLow: 0 } || held.Identity is not null && held.Identity != identity)
            { _faulted = true; throw new IOException("Metadata object identity changed."); }
            if (_byIdentity.TryGetValue(identity, out var prior) && prior != key)
            { _faulted = true; throw new IOException("Two metadata incarnations cannot own the same native object."); }
            _byIdentity[identity] = key;
            _objects[key] = held with { Identity = identity };
        }
    }
    internal bool Retains(StagedStageIdentity identity)
    { lock (_gate) return _byIdentity.TryGetValue(identity, out var key) && !_objects[key].Released; }
    internal bool TryExtend(BoundedOutputPlan plan)
    {
        lock (_gate)
        {
            if (_faulted) throw new IOException("Metadata accounting is held.");
            var held = _objects[plan.Object];
            if (held.Plan.Role != MetadataRoleV32.Segment || plan.Role != held.Plan.Role ||
                plan.Alignment != held.Plan.Alignment || plan.AllocationUnit != held.Plan.AllocationUnit ||
                plan.LogicalLength <= held.Plan.LogicalLength || held.Charge != held.Plan.PeakAllocation)
                throw new IOException("No monotonic exact segment extension claim.");
            long next = checked(_totals[(int)held.Class] + plan.PeakAllocation - held.Charge);
            if (next > _limits[(int)held.Class]) return false;
            _totals[(int)held.Class] = next;
            _objects[plan.Object] = held with { Plan = plan, Charge = plan.PeakAllocation };
            return true;
        }
    }
    internal long Charge(MetadataObjectKey key) { lock (_gate) return _objects[key].Charge; }
    internal void Observe(MetadataObjectKey key, StagedStageIdentity identity, long allocation)
    {
        lock (_gate)
        {
            var held = _objects[key];
            if (held.Released || held.Identity != identity || allocation < 0 || allocation > held.Charge)
            { _faulted = true; throw new IOException("Native allocation exceeds the admitted physical bound or changed identity."); }
        }
    }

    // The later persistence owner supplies an already-durable exact transition.
    // EOF normalization, selection, handle close and delete-pending are not proof.
    internal void Apply(MetadataStorageTransition transition)
    {
        lock (_gate)
        {
            var held = _objects[transition.Object];
            if (held.Applied == transition) return; // Replay finishes bookkeeping without a second delta.
            if (held.Released || transition.Allocation < 0 || transition.StorageReleased && transition.Allocation != 0 ||
                !transition.Persisted || held.Identity != transition.Identity || transition.Revision <= held.Revision ||
                !transition.OperationsDrained || (!transition.StorageReleased && !transition.F2MeasuredClosed))
                throw new IOException("No exact persisted storage transition.");
            long retained = transition.StorageReleased ? 0 : BoundedOutputPlan.Round(transition.Allocation, held.Plan.AllocationUnit);
            if (retained > held.Charge) { _faulted = true; throw new IOException("Measured allocation exceeds admission."); }
            _totals[(int)held.Class] = checked(_totals[(int)held.Class] - held.Charge + retained);
            _objects[transition.Object] = held with { Charge = retained, Revision = transition.Revision, Released = transition.StorageReleased, Applied = transition };
        }
    }
}
internal sealed record MetadataStorageTransition(MetadataObjectKey Object, StagedStageIdentity Identity,
    ulong Revision, long Allocation, bool Persisted, bool OperationsDrained, bool F2MeasuredClosed, bool StorageReleased);
#endif
