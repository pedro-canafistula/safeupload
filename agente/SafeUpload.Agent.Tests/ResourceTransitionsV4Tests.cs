#if SAFEUPLOAD_ADMISSION_EVIDENCE
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class ResourceTransitionsV4Tests
{
    [Fact]
    public void Durable_issue_survives_restart_and_unrelated_R_requires_recomputation_not_old_snapshot_adoption()
    {
        var x = ResourceStateV4Tests.Build(EvidencePackV1Tests.Fixture()); var state = x.State;
        var prepared = ResourceTransitionsV4.ReserveSlot(state, state.Revision, 2, ResourceSlotRoleV2.Snapshot, 1, Guid.NewGuid(), state.InstallationId, x.Catalog);
        Assert.Throws<InvalidDataException>(() => ResourceTransitionsV4.Adopt(state, prepared, ResourcePersistenceV4.Ambiguous, prepared.Bytes, x.Catalog));
        state = Adopt(state, prepared, x.Catalog); long claimRevision = state.Slots[2]!.CustodyClaim!.ClaimRevision;
        state = Adopt(state, ResourceTransitionsV4.MayHaveIssued(state, state.Revision, state.Slots[2]!.CustodyClaim!, x.Catalog), x.Catalog);
        state = ResourceStateCodecV4.Deserialize(ResourceStateCodecV4.Serialize(state, x.Catalog), x.Catalog);
        var issuedClaim = state.Slots[2]!.CustodyClaim!; long previousR = state.Revision;
        Assert.Equal(ResourceRecoveryDecisionV4.ReconcileOrHeld, ResourceTransitionsV4.Recovery(issuedClaim));
        Assert.Throws<InvalidDataException>(() => ResourceTransitionsV4.MayHaveIssued(state, state.Revision, issuedClaim, x.Catalog));
        state = Adopt(state, ResourceTransitionsV4.ReserveSlot(state, state.Revision, 3, ResourceSlotRoleV2.Snapshot, 1, Guid.NewGuid(), state.InstallationId, x.Catalog), x.Catalog);
        var identity = new StagedStageIdentity(ulong.MaxValue, 1000, 1001);
        Assert.Throws<InvalidDataException>(() => ResourceTransitionsV4.Capture(state, previousR, issuedClaim, identity, x.Catalog));
        state = Adopt(state, ResourceTransitionsV4.Capture(state, state.Revision, issuedClaim, identity, x.Catalog), x.Catalog);
        Assert.Equal(claimRevision, state.Slots[2]!.CustodyClaim!.ClaimRevision);
        Assert.Equal(identity, state.Slots[2]!.Identity);
    }

    [Fact]
    public void Copy_freeze_and_exact_disposal_progress_without_refunding_a_reader_or_repeating_native_success()
    {
        var x = ResourceStateV4Tests.Build(EvidencePackV1Tests.Fixture()); var state = x.State;
        state = Adopt(state, ResourceTransitionsV4.ReserveSlot(state, state.Revision, 2, ResourceSlotRoleV2.Snapshot, 1, Guid.NewGuid(), state.InstallationId, x.Catalog), x.Catalog);
        state = Issue(state, 2, x.Catalog);
        state = Adopt(state, ResourceTransitionsV4.Capture(state, state.Revision, state.Slots[2]!.CustodyClaim!, new(ulong.MaxValue, 1000, 1001), x.Catalog), x.Catalog);
        state = CompleteDrain(state, 2, null, null, x.Catalog);
        long fullCharge = state.ChargeBytes;
        state = Adopt(state, ResourceTransitionsV4.BeginClaim(state, state.Revision, 2, ResourceClaimKindV3.FreezeMeasure, Guid.NewGuid(), state.InstallationId, x.Catalog), x.Catalog);
        state = Issue(state, 2, x.Catalog); state = CompleteDrain(state, 2, 1, 4096, x.Catalog);
        Assert.True(state.ChargeBytes < fullCharge);
        state = Adopt(state, ResourceTransitionsV4.BeginClaim(state, state.Revision, 2, ResourceClaimKindV3.Dispose, Guid.NewGuid(), state.InstallationId, x.Catalog), x.Catalog);
        state = Issue(state, 2, x.Catalog); state = CompleteDrain(state, 2, null, null, x.Catalog);
        var claim = state.Slots[2]!.CustodyClaim!; var owners = new ResourceOwnerInventoryV4(claim);
        Guid reader = Guid.NewGuid(); owners.Admit(reader, 1); owners.CloseAdmission();
        var proof = new ResourceReleaseStateV3 { Kind = ResourceReleaseKindV3.FinalStorageRelease, Slot = 2, Incarnation = claim.Incarnation,
            Identity = claim.Identity, WitnessId = Guid.NewGuid(), CustodyTransferReceiptId = null, ClaimRevision = claim.ClaimRevision };
        Assert.Throws<InvalidDataException>(() => ResourceTransitionsV4.ReleaseSlot(state, state.Revision, claim, proof, owners, x.Catalog));
        owners.Complete(reader, 1);
        state = Adopt(state, ResourceTransitionsV4.ReleaseSlot(state, state.Revision, claim, proof, owners, x.Catalog), x.Catalog);
        state = Adopt(state, ResourceTransitionsV4.MetadataOnly(state, state.Revision, x.Catalog), x.Catalog);
        Assert.Equal(x.State.ChargeBytes, state.ChargeBytes);
    }

    [Fact]
    public void Original_zero_acceptance_completion_replays_before_reused_slot_lookup_without_another_refund()
    {
        var x = ResourceStateV4Tests.Build(EvidencePackV1Tests.Fixture()); var state = x.State;
        var completion = state.CustodyTransfers[0]!.Completion;
        state = Adopt(state, ResourceTransitionsV4.ReserveSlot(state, state.Revision, 2, ResourceSlotRoleV2.Snapshot, 1, Guid.NewGuid(), state.InstallationId, x.Catalog), x.Catalog);
        var replay = ResourceTransitionsV4.AcceptCustody(state, state.Revision, completion, x.Catalog);
        Assert.Equal(state.Revision, replay.State.Revision); Assert.Equal(state.ChargeBytes, replay.State.ChargeBytes);
        Assert.Equal(state.Slots[2], replay.State.Slots[2]);
        Assert.Throws<InvalidDataException>(() => ResourceTransitionsV4.AcceptCustody(state, state.Revision,
            completion with { Authorization = completion.Authorization with { WitnessId = Guid.NewGuid() } }, x.Catalog));
    }
    private static ResourceStateV4 Issue(ResourceStateV4 state, int index, EvidenceCatalogV1 catalog) => Adopt(state,
        ResourceTransitionsV4.MayHaveIssued(state, state.Revision, state.Slots[index]!.CustodyClaim!, catalog), catalog);
    private static ResourceStateV4 CompleteDrain(ResourceStateV4 state, int index, long? eof, long? allocation, EvidenceCatalogV1 catalog)
    {
        state = Adopt(state, ResourceTransitionsV4.NativeComplete(state, state.Revision, state.Slots[index]!.CustodyClaim!, catalog), catalog);
        var claim = state.Slots[index]!.CustodyClaim!; var owners = new ResourceOwnerInventoryV4(claim); owners.CloseAdmission();
        return Adopt(state, ResourceTransitionsV4.Drained(state, state.Revision, claim, owners, Guid.NewGuid(), eof, allocation, catalog), catalog);
    }
    private static ResourceStateV4 Adopt(ResourceStateV4 state, ResourceCandidateV4 candidate, EvidenceCatalogV1 catalog) =>
        ResourceTransitionsV4.Adopt(state, candidate, ResourcePersistenceV4.Committed, candidate.Bytes, catalog);
}
#endif
