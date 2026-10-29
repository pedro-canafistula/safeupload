#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;

namespace SafeUpload.Agent.Service.Interception;

// The actual owner inventory is separate from persisted witness fields. Cancel
// does not remove owners; each admitted token must finish after admission closes.
internal sealed class ResourceOwnerInventoryV4(ResourceCustodyClaimV3 claim)
{
    private readonly HashSet<Guid> readers = [], operations = [], sections = [];
    private bool closed;
    internal void Admit(Guid token, int kind)
    {
        ResourceJsonV3.Id(token); EvidenceBinaryV1.Need(!closed, "Owner admission is closed.");
        EvidenceBinaryV1.Need(Set(kind).Add(token), "Duplicate owner token.");
    }
    internal void Complete(Guid token, int kind) => EvidenceBinaryV1.Need(Set(kind).Remove(token), "Unknown/already completed owner token.");
    internal void CloseAdmission() => closed = true;
    internal void RequireDrained(ResourceCustodyClaimV3 expected)
    {
        EvidenceBinaryV1.Need(expected.ClaimId == claim.ClaimId && expected.OwnerEpoch == claim.OwnerEpoch && expected.Slot == claim.Slot &&
            expected.Incarnation == claim.Incarnation && expected.ClaimRevision == claim.ClaimRevision && expected.Identity == claim.Identity &&
            closed && readers.Count == 0 && operations.Count == 0 && sections.Count == 0, "Actual owners/claim have not drained.");
    }
    private HashSet<Guid> Set(int kind) => kind switch { 1 => readers, 2 => operations, 3 => sections, _ => throw new InvalidDataException("Unknown owner kind.") };
}
internal enum EvidencePreparationBarrierV1 { Captured = 0, Written = 1, Flushed = 2, EofSet = 3, PostEofFlushed = 4, Immutable = 5 }
internal sealed record EvidencePreparationProgressV1(Guid RecordId, long Generation, StagedStageIdentity Identity, EvidencePreparationBarrierV1 Barrier)
{
    internal EvidencePreparationProgressV1 Complete(EvidencePreparationBarrierV1 next)
    {
        EvidenceBinaryV1.Need(Enum.IsDefined(next) && (int)next == (int)Barrier + 1, "Evidence I/O barrier skipped/repeated.");
        return this with { Barrier = next };
    }
}
internal sealed record EvidenceRootSnapshotV1(long InventoryRevision, long StoreRevision, ImmutableHashSet<Guid> ReachableRecordIds);
internal sealed record EvidenceStorageReleaseV1(Guid RecordId, long Generation, StagedStageIdentity? Identity,
    ResourceReleaseKindV3 Kind, Guid DrainWitnessId, Guid ReleaseWitnessId);
internal sealed record SharedEvidenceCustodyV1(long Revision, Guid InstallationId, ImmutableArray<EvidenceClaimV1> Claims);

internal static class EvidenceCustodyTransitionsV1
{
    internal static ResourceCandidateV4 Reserve(ResourceStateV4 state, long expectedRevision, int index, EvidenceClaimV1 claim, EvidenceCatalogV1 evidence)
    {
        Check(state, expectedRevision, index);
        EvidenceBinaryV1.Need(state.EvidenceClaims[index] is null or { Phase: EvidencePhaseV1.StorageReleased } &&
            claim.Phase == EvidencePhaseV1.ReservedNotIssued && claim.AccountingOwner == EvidenceAccountingOwnerV1.Transfer &&
            claim.Identity is null && claim.Length is null && claim.Sha256 is null && claim.MeasuredAllocation is null && claim.DrainWitnessId is null &&
            claim.ReleaseWitnessId is null && claim.ReleaseKind is null && claim.SharedOwnershipRevision is null, "Invalid evidence reservation.");
        return Commit(state, state with { EvidenceClaims = state.EvidenceClaims.SetItem(index, claim) }, evidence);
    }
    internal static ResourceCandidateV4 MayHaveCreated(ResourceStateV4 state, long revision, int index, EvidenceCatalogV1 evidence) =>
        Advance(state, revision, index, EvidencePhaseV1.ReservedNotIssued, claim => claim with { Phase = EvidencePhaseV1.CreationMayHaveStarted }, evidence);
    internal static ResourceCandidateV4 Capture(ResourceStateV4 state, long revision, int index, StagedStageIdentity identity, EvidenceCatalogV1 evidence)
    {
        ResourceJsonV3.Identity(identity);
        return Advance(state, revision, index, EvidencePhaseV1.CreationMayHaveStarted, claim => claim with { Phase = EvidencePhaseV1.Captured, Identity = identity }, evidence);
    }
    internal static ResourceCandidateV4 Prepared(ResourceStateV4 state, long revision, int index, EvidenceHeldImageV1 image,
        EvidencePreparationProgressV1 progress, long measuredAllocation, Guid drainWitness, ResourceOwnerInventoryV4 owners,
        ResourceCustodyClaimV3 nativeClaim, EvidenceCatalogV1 evidence)
    {
        Check(state, revision, index); var claim = state.EvidenceClaims[index]!;
        EvidenceBinaryV1.Need(claim is not null && claim.Phase == EvidencePhaseV1.Captured && image.Reference.Identity == claim.Identity &&
            image.Reference.Owner == Owner(state, claim) && progress.RecordId == claim.RecordId && progress.Generation == claim.Generation &&
            progress.Identity == claim.Identity && progress.Barrier == EvidencePreparationBarrierV1.Immutable &&
            measuredAllocation >= image.Bytes.Length && measuredAllocation <= claim.ReservedMax, "Evidence preparation is not complete/admitted.");
        owners.RequireDrained(nativeClaim); ResourceJsonV3.Id(drainWitness);
        _ = EvidencePackCodecV1.Deserialize(image.Reference, Owner(state, claim), image.Observed, image.Alignment, image.Bytes);
        return Commit(state, state with { EvidenceClaims = state.EvidenceClaims.SetItem(index, claim with { Phase = EvidencePhaseV1.Prepared,
            Length = image.Bytes.Length, Sha256 = image.Reference.Sha256, MeasuredAllocation = measuredAllocation, DrainWitnessId = drainWitness }) }, evidence);
    }
    internal static ResourceCandidateV4 Referenced(ResourceStateV4 state, long revision, int index, EvidenceReferenceV1 durableReference, EvidenceCatalogV1 evidence)
    {
        Check(state, revision, index); var claim = state.EvidenceClaims[index]!;
        EvidenceBinaryV1.Need(claim is not null && durableReference.Owner == Owner(state, claim) && durableReference.Identity == claim.Identity &&
            durableReference.Length == claim.Length && durableReference.Sha256 == claim.Sha256, "Durable reference differs from prepared evidence.");
        _ = evidence.Resolve(durableReference);
        return Advance(state, revision, index, EvidencePhaseV1.Prepared, c => c with { Phase = EvidencePhaseV1.Referenced }, evidence);
    }
    internal static SharedEvidenceCustodyV1 PrepareShared(ResourceStateV4 state, long expectedRevision, long sharedRevision,
        EvidenceRootSnapshotV1 before, EvidenceRootSnapshotV1 after)
    {
        EvidenceBinaryV1.Need(state.Revision == expectedRevision && sharedRevision > 0, "Stale sharing revision."); Stable(before, after);
        var claims = state.EvidenceClaims.OfType<EvidenceClaimV1>().Where(c => c.Phase != EvidencePhaseV1.StorageReleased).ToImmutableArray();
        EvidenceBinaryV1.Need(claims.All(c => c.Phase == EvidencePhaseV1.Referenced && before.ReachableRecordIds.Contains(c.RecordId)),
            "Shared selection has not retained all exact evidence roots.");
        return new(sharedRevision, state.InstallationId, claims.Select(c => c with
        { AccountingOwner = EvidenceAccountingOwnerV1.Shared, SharedOwnershipRevision = sharedRevision }).ToImmutableArray());
    }
    internal static ResourceCandidateV4 AdoptShared(ResourceStateV4 state, long expectedRevision, SharedEvidenceCustodyV1 shared,
        ReadOnlySpan<byte> selectedDurableSharedBytes, EvidenceCatalogV1 evidence)
    {
        EvidenceBinaryV1.Need(state.Revision == expectedRevision && shared.InstallationId == state.InstallationId &&
            selectedDurableSharedBytes.SequenceEqual(ResourceJsonV3.Serialize(shared, 65536)), "Shared evidence ownership is not durably selected.");
        var claims = state.EvidenceClaims;
        for (int index = 0; index < claims.Length; index++)
        {
            if (claims[index] is not { Phase: not EvidencePhaseV1.StorageReleased } claim) continue;
            var matches = shared.Claims.Where(c => c.RecordId == claim.RecordId).ToArray();
            var expected = claim with { AccountingOwner = EvidenceAccountingOwnerV1.Shared, SharedOwnershipRevision = shared.Revision };
            EvidenceBinaryV1.Need(matches.Length == 1 && matches[0] == expected, "Shared map differs from current evidence custody.");
            claims = claims.SetItem(index, expected);
        }
        return Commit(state, state with { EvidenceClaims = claims }, evidence);
    }
    internal static ResourceCandidateV4 Detach(ResourceStateV4 state, long revision, int index, EvidenceRootSnapshotV1 before,
        EvidenceRootSnapshotV1 after, ResourceOwnerInventoryV4 owners, ResourceCustodyClaimV3 claim, EvidenceCatalogV1 evidence)
    {
        Check(state, revision, index); Stable(before, after); var held = state.EvidenceClaims[index]!;
        EvidenceBinaryV1.Need(held is not null && !before.ReachableRecordIds.Contains(held.RecordId) &&
            held.Phase is EvidencePhaseV1.Prepared or EvidencePhaseV1.Referenced, "Evidence remains reachable or unresolved.");
        owners.RequireDrained(claim);
        EvidenceBinaryV1.Need(claim.Identity == held.Identity && claim.OwnerEpoch == held.OwnerEpoch, "GC owner differs from held object.");
        return Commit(state, state with { EvidenceClaims = state.EvidenceClaims.SetItem(index, held with { Phase = EvidencePhaseV1.Detached }) }, evidence);
    }
    internal static ResourceCandidateV4 MayDelete(ResourceStateV4 state, long revision, int index, EvidenceCatalogV1 evidence) =>
        Advance(state, revision, index, EvidencePhaseV1.Detached, claim => claim with { Phase = EvidencePhaseV1.DeleteMayHaveIssued }, evidence);
    internal static ResourceCandidateV4 StorageReleased(ResourceStateV4 state, long revision, int index, EvidenceStorageReleaseV1 proof,
        EvidenceRootSnapshotV1 before, EvidenceRootSnapshotV1 after, EvidenceCatalogV1 evidence)
    {
        Check(state, revision, index); Stable(before, after); var claim = state.EvidenceClaims[index]!;
        EvidenceBinaryV1.Need(claim is not null && !before.ReachableRecordIds.Contains(claim.RecordId) && proof.RecordId == claim.RecordId &&
            proof.Generation == claim.Generation && proof.Identity == claim.Identity && proof.DrainWitnessId != Guid.Empty && proof.ReleaseWitnessId != Guid.Empty &&
            (proof.Kind is ResourceReleaseKindV3.NeverIssued or ResourceReleaseKindV3.DefinitiveNonCreation ?
                claim.Identity is null && (proof.Kind == ResourceReleaseKindV3.NeverIssued ? claim.Phase == EvidencePhaseV1.ReservedNotIssued :
                    claim.Phase == EvidencePhaseV1.CreationMayHaveStarted) : proof.Kind is ResourceReleaseKindV3.FinalStorageRelease or ResourceReleaseKindV3.ExactAbsenceAfterDrain &&
                claim.Phase == EvidencePhaseV1.DeleteMayHaveIssued && claim.Identity is not null && proof.DrainWitnessId == claim.DrainWitnessId),
            "Evidence release lacks exact noncreation/final-storage proof.");
        return Commit(state, state with { EvidenceClaims = state.EvidenceClaims.SetItem(index, claim with { Phase = EvidencePhaseV1.StorageReleased,
            DrainWitnessId = proof.DrainWitnessId, ReleaseWitnessId = proof.ReleaseWitnessId, ReleaseKind = proof.Kind }) }, evidence);
    }
    private static void Stable(EvidenceRootSnapshotV1 before, EvidenceRootSnapshotV1 after) => EvidenceBinaryV1.Need(before.InventoryRevision > 0 && before.StoreRevision > 0 &&
        before.InventoryRevision == after.InventoryRevision && before.StoreRevision == after.StoreRevision &&
        before.ReachableRecordIds.SetEquals(after.ReachableRecordIds), "Reachability changed during selection/GC.");
    private static EvidenceOwnerV1 Owner(ResourceStateV4 state, EvidenceClaimV1 claim) => new(state.InstallationId, state.TransferId, claim.OperationId,
        claim.RecordId, claim.Generation, claim.Kind, claim.AllocationGeneration, claim.DestinationGeneration, claim.AuthorizationWitnessId);
    private static void Check(ResourceStateV4 state, long revision, int index) => EvidenceBinaryV1.Need(state.Revision == revision && index is >= 0 and < 4,
        "Stale evidence revision/index.");
    private static ResourceCandidateV4 Advance(ResourceStateV4 state, long revision, int index, EvidencePhaseV1 expected,
        Func<EvidenceClaimV1, EvidenceClaimV1> update, EvidenceCatalogV1 evidence)
    {
        Check(state, revision, index); var claim = state.EvidenceClaims[index];
        EvidenceBinaryV1.Need(claim is not null && claim.Phase == expected, "Invalid evidence custody transition/replay.");
        return Commit(state, state with { EvidenceClaims = state.EvidenceClaims.SetItem(index, update(claim)) }, evidence);
    }
    private static ResourceCandidateV4 Commit(ResourceStateV4 old, ResourceStateV4 next, EvidenceCatalogV1 evidence) => ResourceTransitionsV4.Prepare(old,
        old.Revision, next with { Revision = checked(old.Revision + 1), ChargeBytes = ResourceTransitionsV4.Measure(next) }, evidence);
}
#endif
