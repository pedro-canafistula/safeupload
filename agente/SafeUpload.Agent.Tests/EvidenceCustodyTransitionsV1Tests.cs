#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using SafeUpload.Agent.Service.Interception;

namespace SafeUpload.Agent.Tests;

public sealed class EvidenceCustodyTransitionsV1Tests
{
    [Fact]
    public void Every_preparation_barrier_retains_charge_until_the_exact_reference_is_durable()
    {
        var x = Setup(); var state = x.State; long initial = state.ChargeBytes;
        var reservation = EvidenceCustodyTransitionsV1.Reserve(state, state.Revision, 2, x.Claim, x.Catalog);
        Assert.Equal(initial, state.ChargeBytes);
        Assert.Throws<InvalidDataException>(() => ResourceTransitionsV4.Adopt(state, reservation, ResourcePersistenceV4.Ambiguous, reservation.Bytes, x.Catalog));
        state = Adopt(state, reservation, x.Catalog); Assert.Equal(initial + x.Claim.ReservedMax, state.ChargeBytes);
        var reserved = state;
        state = Adopt(state, EvidenceCustodyTransitionsV1.MayHaveCreated(state, state.Revision, 2, x.Catalog), x.Catalog);
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.MayHaveCreated(state, state.Revision, 2, x.Catalog));
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Capture(state, reserved.Revision, 2, x.Image.Reference.Identity, x.Catalog));
        state = Adopt(state, EvidenceCustodyTransitionsV1.Capture(state, state.Revision, 2, x.Image.Reference.Identity, x.Catalog), x.Catalog);
        var nativeClaim = NativeClaim(state, x.Image.Reference.Identity); var owners = new ResourceOwnerInventoryV4(nativeClaim);
        Guid reader = Guid.NewGuid(); owners.Admit(reader, 1); owners.CloseAdmission();
        var progress = new EvidencePreparationProgressV1(x.Claim.RecordId, x.Claim.Generation, x.Image.Reference.Identity, EvidencePreparationBarrierV1.Captured);
        foreach (var step in Enum.GetValues<EvidencePreparationBarrierV1>().Skip(1))
        {
            Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Prepared(state, state.Revision, 2, x.Image,
                progress, x.Image.Bytes.Length, Witness, owners, nativeClaim, x.Catalog));
            Assert.Equal(initial + x.Claim.ReservedMax, state.ChargeBytes);
            progress = progress.Complete(step);
        }
        // Cancellation/restart cannot dispose the independently retained reader.
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Prepared(state, state.Revision, 2, x.Image,
            progress, x.Image.Bytes.Length, Witness, owners, nativeClaim, x.Catalog));
        owners.Complete(reader, 1);
        state = Adopt(state, EvidenceCustodyTransitionsV1.Prepared(state, state.Revision, 2, x.Image, progress,
            x.Image.Bytes.Length, Witness, owners, nativeClaim, x.Catalog), x.Catalog);
        Assert.Equal(initial + x.Image.Bytes.Length, state.ChargeBytes);
        state = Adopt(state, EvidenceCustodyTransitionsV1.Referenced(state, state.Revision, 2, x.Image.Reference, x.Catalog), x.Catalog);
        Assert.Equal(EvidencePhaseV1.Referenced, state.EvidenceClaims[2]!.Phase);
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Referenced(state, state.Revision, 2, x.Image.Reference, x.Catalog));
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)]
    public void Actual_reader_operation_and_section_owners_survive_cancellation_and_block_GC(int kind)
    {
        var x = Prepared(); var state = x.State; var claim = NativeClaim(state, x.Image.Reference.Identity);
        var owners = new ResourceOwnerInventoryV4(claim); Guid token = Guid.NewGuid(); owners.Admit(token, kind); owners.CloseAdmission();
        var absent = Roots(state, false);
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Detach(state, state.Revision, 2, absent, absent, owners, claim, x.Catalog));
        Assert.Throws<InvalidDataException>(() => owners.Admit(Guid.NewGuid(), kind));
        owners.Complete(token, kind);
        var candidate = EvidenceCustodyTransitionsV1.Detach(state, state.Revision, 2, absent, absent, owners, claim, x.Catalog);
        Assert.Equal(state.ChargeBytes, candidate.State.ChargeBytes);
    }

    [Fact]
    public void Reachability_shared_handoff_and_exact_delete_each_require_their_own_persisted_boundary()
    {
        var x = Prepared(); var state = x.State; var claim = NativeClaim(state, x.Image.Reference.Identity);
        var owners = new ResourceOwnerInventoryV4(claim); owners.CloseAdmission();
        var absent = Roots(state, false); var present = Roots(state, true);
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Detach(state, state.Revision, 2, present, present, owners, claim, x.Catalog));
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Detach(state, state.Revision, 2, absent,
            absent with { StoreRevision = 2 }, owners, claim, x.Catalog));
        state = Adopt(state, EvidenceCustodyTransitionsV1.Detach(state, state.Revision, 2, absent, absent, owners, claim, x.Catalog), x.Catalog);
        long charged = state.ChargeBytes;
        var release = new EvidenceStorageReleaseV1(x.Claim.RecordId, 1, x.Image.Reference.Identity,
            ResourceReleaseKindV3.FinalStorageRelease, Witness, Guid.NewGuid());
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.StorageReleased(state, state.Revision, 2, release, absent, absent, x.Catalog));
        state = Adopt(state, EvidenceCustodyTransitionsV1.MayDelete(state, state.Revision, 2, x.Catalog), x.Catalog);
        Assert.Equal(charged, state.ChargeBytes); // Lost delete reply stays charged.
        var candidate = EvidenceCustodyTransitionsV1.StorageReleased(state, state.Revision, 2, release, absent, absent, x.Catalog);
        Assert.Equal(charged, state.ChargeBytes);
        state = Adopt(state, candidate, x.Catalog); Assert.Equal(charged - x.Image.Bytes.Length, state.ChargeBytes);
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.StorageReleased(state, state.Revision, 2, release, absent, absent, x.Catalog));
        var core = ResourceStateV4Tests.Build(EvidencePackV1Tests.Fixture());
        var roots = new EvidenceRootSnapshotV1(1, 1, core.State.EvidenceClaims.OfType<EvidenceClaimV1>().Select(c => c.RecordId).ToImmutableHashSet());
        var shared = EvidenceCustodyTransitionsV1.PrepareShared(core.State, core.State.Revision, 42, roots, roots);
        byte[] bytes = ResourceJsonV3.Serialize(shared, 65536);
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.AdoptShared(core.State, core.State.Revision, shared, [], core.Catalog));
        var sharedCandidate = EvidenceCustodyTransitionsV1.AdoptShared(core.State, core.State.Revision, shared, bytes, core.Catalog);
        Assert.Equal(1048576, sharedCandidate.State.ChargeBytes);
        Assert.Equal(core.State.ChargeBytes - 1048576, shared.Claims.Sum(c => c.MeasuredAllocation!.Value));
    }

    [Fact]
    public void Durable_unknown_creation_cannot_reset_or_release_from_a_missing_name()
    {
        var x = Setup(); var state = Adopt(x.State, EvidenceCustodyTransitionsV1.Reserve(x.State, x.State.Revision, 2, x.Claim, x.Catalog), x.Catalog);
        state = Adopt(state, EvidenceCustodyTransitionsV1.MayHaveCreated(state, state.Revision, 2, x.Catalog), x.Catalog);
        var absent = Roots(state, false);
        var fake = new EvidenceStorageReleaseV1(x.Claim.RecordId, 1, null, ResourceReleaseKindV3.NeverIssued, Witness, Guid.NewGuid());
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.StorageReleased(state, state.Revision, 2, fake, absent, absent, x.Catalog));
        Assert.Throws<InvalidDataException>(() => EvidenceCustodyTransitionsV1.Reserve(state, state.Revision, 2, x.Claim, x.Catalog));
    }

    private static readonly Guid Witness = Guid.Parse("40000000-1111-2222-3333-444444444444");
    private sealed record Fixture(ResourceStateV4 State, EvidenceClaimV1 Claim, EvidenceHeldImageV1 Image, EvidenceCatalogV1 Catalog);
    private static Fixture Setup()
    {
        var f = EvidencePackV1Tests.Fixture(); var x = ResourceStateV4Tests.Build(f);
        var owner = f.Owner with { Kind = EvidenceKindV1.EntryCore, RecordId = Guid.Parse("40000001-1111-2222-3333-444444444444") };
        var image = EvidencePackCodecV1.Serialize(EvidencePackCodecV1.Preflight(owner, 4096, f.Entry, null), new(ulong.MaxValue, 800, 801));
        var held = new EvidenceHeldImageV1(image.Reference, new(image.Reference.Identity, true, true, false), 4096, image.Bytes);
        var claim = x.State.EvidenceClaims[0]! with { RecordId = owner.RecordId, Kind = owner.Kind, Phase = EvidencePhaseV1.ReservedNotIssued,
            Identity = null, Length = null, Sha256 = null, ReservedMax = image.Bytes.Length + 4096, MeasuredAllocation = null, DrainWitnessId = null };
        return new(x.State, claim, held, new(x.Images.Add(held)));
    }
    private static Fixture Prepared()
    {
        var x = Setup(); var state = x.State with { EvidenceClaims = x.State.EvidenceClaims.SetItem(2, x.Claim with
        { Phase = EvidencePhaseV1.Prepared, Identity = x.Image.Reference.Identity, Length = x.Image.Bytes.Length,
            Sha256 = x.Image.Reference.Sha256, MeasuredAllocation = x.Image.Bytes.Length, DrainWitnessId = Witness }),
            ChargeBytes = x.State.ChargeBytes + x.Image.Bytes.Length };
        ResourceStateCodecV4.Validate(state, x.Catalog); return x with { State = state };
    }
    private static ResourceCustodyClaimV3 NativeClaim(ResourceStateV4 state, StagedStageIdentity identity) => new(Witness, state.InstallationId, 2, 1, 11,
        ResourceClaimKindV3.CreateCopy, ResourceClaimPhaseV3.NativeComplete, identity, null, null);
    private static EvidenceRootSnapshotV1 Roots(ResourceStateV4 state, bool include) => new(1, 1,
        include ? state.EvidenceClaims.OfType<EvidenceClaimV1>().Select(c => c.RecordId).ToImmutableHashSet() : ImmutableHashSet<Guid>.Empty);
    private static ResourceStateV4 Adopt(ResourceStateV4 state, ResourceCandidateV4 candidate, EvidenceCatalogV1 catalog) =>
        ResourceTransitionsV4.Adopt(state, candidate, ResourcePersistenceV4.Committed, candidate.Bytes, catalog);
}
#endif
