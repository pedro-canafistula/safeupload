#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal sealed record ResourceCandidateV4(long ExpectedRevision, ResourceStateV4 State, byte[] Bytes);
internal enum ResourcePersistenceV4 { NotCommitted = 0, Committed = 1, Ambiguous = 2 }
internal enum ResourceRecoveryDecisionV4 { IssueOnce = 1, ReconcileOrHeld = 2, BookkeepingOnly = 3 }

internal static class ResourceTransitionsV4
{
    internal static ResourceCandidateV4 Prepare(ResourceStateV4 current, long expectedRevision, ResourceStateV4 candidate, EvidenceCatalogV1 evidence)
    {
        EvidenceBinaryV1.Need(current.Revision == expectedRevision && current.Revision < long.MaxValue && candidate.Revision == current.Revision + 1 &&
            candidate.TransferId == current.TransferId && candidate.InstallationId == current.InstallationId && candidate.DriverInstanceId == current.DriverInstanceId &&
            candidate.OriginalRequest == current.OriginalRequest && candidate.Sid == current.Sid && candidate.InitialCapacity == current.InitialCapacity,
            "Stale revision/changed immutable allocation.");
        return new(current.Revision, candidate, ResourceStateCodecV4.Serialize(candidate, evidence));
    }
    internal static ResourceStateV4 Adopt(ResourceStateV4 current, ResourceCandidateV4 candidate, ResourcePersistenceV4 result,
        ReadOnlySpan<byte> selectedDurableBytes, EvidenceCatalogV1 evidence)
    {
        EvidenceBinaryV1.Need(result == ResourcePersistenceV4.Committed && current.Revision == candidate.ExpectedRevision &&
            selectedDurableBytes.SequenceEqual(candidate.Bytes), "Uncertain/stale persistence cannot adopt totals.");
        var selected = ResourceStateCodecV4.Deserialize(selectedDurableBytes, evidence);
        EvidenceBinaryV1.Need(selected.Revision == candidate.State.Revision, "Selected another ledger revision."); return selected;
    }
    internal static ResourceRecoveryDecisionV4 Recovery(ResourceCustodyClaimV3 claim) => claim.State switch
    {
        ResourceClaimPhaseV3.Prepared => ResourceRecoveryDecisionV4.IssueOnce,
        ResourceClaimPhaseV3.MayHaveIssued => ResourceRecoveryDecisionV4.ReconcileOrHeld,
        ResourceClaimPhaseV3.NativeComplete or ResourceClaimPhaseV3.Drained => ResourceRecoveryDecisionV4.BookkeepingOnly,
        _ => throw new InvalidDataException("Unknown claim phase.")
    };
    internal static ResourceCandidateV4 ReserveSlot(ResourceStateV4 state, long revision, int index, ResourceSlotRoleV2 role,
        long expectedLength, Guid claimId, Guid ownerEpoch, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); EvidenceBinaryV1.Need(index is >= 0 and < 4 && role is not ResourceSlotRoleV2.Stage && Enum.IsDefined(role) &&
            (state.Slots[index] is null or { Phase: ResourceSlotPhaseV2.Released }) && expectedLength >= 0 && expectedLength <= state.AuthorizedCapacity,
            "No free content slot/admitted copy ceiling.");
        long incarnation = checked((state.Slots[index]?.Incarnation ?? 0) + 1);
        var claim = new ResourceCustodyClaimV3(claimId, ownerEpoch, (uint)index, incarnation, checked(state.Revision + 1),
            ResourceClaimKindV3.CreateCopy, ResourceClaimPhaseV3.Prepared, null, null, null);
        var slot = new ResourceSlotStateV3 { Index = index, Incarnation = incarnation, Role = role, Phase = ResourceSlotPhaseV2.ReservedNotIssued,
            ReservedMax = state.AuthorizedCapacity, ExpectedLength = expectedLength, Identity = null, Locator = null,
            EndOfFile = null, AllocationSize = null, Release = null, CustodyClaim = claim };
        return Commit(state, state with { Slots = state.Slots.SetItem(index, slot), Phase = state.Phase == ResourceStatePhaseV2.MetadataOnly ?
            ResourceStatePhaseV2.WriteRetired : state.Phase }, evidence);
    }
    internal static ResourceCandidateV4 BeginClaim(ResourceStateV4 state, long revision, int index, ResourceClaimKindV3 kind,
        Guid claimId, Guid ownerEpoch, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); EvidenceBinaryV1.Need(index is >= 0 and < 4 && kind is ResourceClaimKindV3.FreezeMeasure or
            ResourceClaimKindV3.Dispose or ResourceClaimKindV3.Promote, "Invalid role claim kind/index.");
        var slot = state.Slots[index];
        EvidenceBinaryV1.Need(slot is { CustodyClaim.State: ResourceClaimPhaseV3.Drained, Identity: not null } &&
            slot.Phase != ResourceSlotPhaseV2.Released, "The previous exclusive owner has not drained.");
        var claim = new ResourceCustodyClaimV3(claimId, ownerEpoch, (uint)index, slot.Incarnation, checked(state.Revision + 1),
            kind, ResourceClaimPhaseV3.Prepared, slot.Identity, slot.Role == ResourceSlotRoleV2.Stage ? state.RetirementWitnessId : null, null);
        return Commit(state, state with { Slots = state.Slots.SetItem(index, slot with { CustodyClaim = claim }) }, evidence);
    }
    internal static ResourceCandidateV4 MayHaveIssued(ResourceStateV4 state, long revision, ResourceCustodyClaimV3 immutableClaim,
        EvidenceCatalogV1 evidence)
    {
        var slot = Find(state, revision, immutableClaim);
        EvidenceBinaryV1.Need(immutableClaim.State == ResourceClaimPhaseV3.Prepared, "Issued native mutation must not be repeated.");
        var next = slot with { CustodyClaim = immutableClaim with { State = ResourceClaimPhaseV3.MayHaveIssued },
            Phase = slot.Phase == ResourceSlotPhaseV2.ReservedNotIssued ? ResourceSlotPhaseV2.CreationMayHaveStarted :
                immutableClaim.Kind == ResourceClaimKindV3.Dispose ? slot.EndOfFile.HasValue ? ResourceSlotPhaseV2.ImmutableReleasePending : ResourceSlotPhaseV2.ReleasePending : slot.Phase };
        return Commit(state, state with { Slots = state.Slots.SetItem(slot.Index, next) }, evidence);
    }
    internal static ResourceCandidateV4 Capture(ResourceStateV4 state, long revision, ResourceCustodyClaimV3 immutableClaim,
        StagedStageIdentity identity, EvidenceCatalogV1 evidence)
    {
        ResourceJsonV3.Identity(identity); var slot = Find(state, revision, immutableClaim);
        EvidenceBinaryV1.Need(immutableClaim.State == ResourceClaimPhaseV3.MayHaveIssued && slot.Identity is null, "Capture cannot replace an existing object.");
        var next = slot with { Identity = identity, Phase = ResourceSlotPhaseV2.Mutable, CustodyClaim = immutableClaim with { Identity = identity } };
        return Commit(state, state with { Slots = state.Slots.SetItem(slot.Index, next) }, evidence);
    }
    internal static ResourceCandidateV4 NativeComplete(ResourceStateV4 state, long revision, ResourceCustodyClaimV3 immutableClaim, EvidenceCatalogV1 evidence)
    {
        var slot = Find(state, revision, immutableClaim);
        EvidenceBinaryV1.Need(immutableClaim.State == ResourceClaimPhaseV3.MayHaveIssued && slot.Identity is not null, "Native result lacks exact issued object.");
        return Commit(state, state with { Slots = state.Slots.SetItem(slot.Index, slot with
        { CustodyClaim = immutableClaim with { State = ResourceClaimPhaseV3.NativeComplete } }) }, evidence);
    }
    internal static ResourceCandidateV4 Drained(ResourceStateV4 state, long revision, ResourceCustodyClaimV3 immutableClaim,
        ResourceOwnerInventoryV4 owners, Guid drainWitness, long? endOfFile, long? allocationSize, EvidenceCatalogV1 evidence)
    {
        var slot = Find(state, revision, immutableClaim); owners.RequireDrained(immutableClaim); ResourceJsonV3.Id(drainWitness);
        EvidenceBinaryV1.Need(immutableClaim.State == ResourceClaimPhaseV3.NativeComplete && endOfFile.HasValue == allocationSize.HasValue,
            "Native completion/measurements are incomplete.");
        // Only a dedicated FreezeMeasure owner can establish immutable measured
        // content; a cancelled partial CreateCopy cannot reduce its ReservedMax.
        if (endOfFile.HasValue) EvidenceBinaryV1.Need(immutableClaim.Kind == ResourceClaimKindV3.FreezeMeasure, "Partial copy is not immutable measurement.");
        var next = slot with { CustodyClaim = immutableClaim with { State = ResourceClaimPhaseV3.Drained, DrainWitnessId = drainWitness },
            Phase = endOfFile.HasValue ? ResourceSlotPhaseV2.Immutable : slot.Phase, EndOfFile = endOfFile ?? slot.EndOfFile, AllocationSize = allocationSize ?? slot.AllocationSize };
        return Commit(state, state with { Slots = state.Slots.SetItem(slot.Index, next) }, evidence);
    }
    internal static ResourceCandidateV4 AcceptCustody(ResourceStateV4 state, long revision, PublicCustodyCompletionV4 completion, EvidenceCatalogV1 evidence)
    {
        Check(state, revision);
        var source = PublicCustodyReceiptCodecV3.Deserialize(ResourceJsonV3.Base64(completion.CompletionBase64, 2048), true);
        int cellIndex = checked((int)source.TransferKind - 1);
        // Retained replay lookup precedes any access to a possibly reused slot.
        if (state.CustodyTransfers[cellIndex] is { } saved)
        {
            EvidenceBinaryV1.Need(saved.Completion.CompletionBase64 == completion.CompletionBase64 &&
                ResourceJsonV3.Serialize(saved.Completion, 65536).AsSpan().SequenceEqual(ResourceJsonV3.Serialize(completion, 65536)),
                "Changed completion or second delivery cannot overwrite retained custody.");
            ResourceStateCodecV4.Validate(state, evidence);
            return new(state.Revision, state, ResourceStateCodecV4.Serialize(state, evidence));
        }
        ResourceStateCodecV4.ValidateCompletion(completion, evidence, state.InstallationId, state.TransferId, state.Revision);
        EvidenceBinaryV1.Need(state.Binding is not null && source.StageIdentity == state.Binding.Identity &&
            source.AllocationGeneration == state.Binding.AllocationGeneration && source.DestinationGeneration == state.CurrentDestinationGeneration &&
            source.RequestorSid == state.Sid && source.DriverInstanceId == state.DriverInstanceId, "First custody acceptance is not current K/D/caller.");
        var slot = Find(state, revision, completion.Claim);
        EvidenceBinaryV1.Need(slot.Identity == source.DeliveredObjectIdentity && slot.Role == source.Role &&
            completion.Claim.State == ResourceClaimPhaseV3.Drained && slot.Phase != ResourceSlotPhaseV2.Released, "Completion targets another/released slot.");
        var receipt = source with { AcceptedBudgetRevision = checked(state.Revision + 1) };
        var release = new ResourceReleaseStateV3 { Kind = ResourceReleaseKindV3.PublicCustodyTransferred, Slot = slot.Index,
            Incarnation = slot.Incarnation, Identity = slot.Identity, WitnessId = source.ReceiptId, CustodyTransferReceiptId = source.ReceiptId,
            ClaimRevision = completion.Claim.ClaimRevision };
        // A preexisting unattributed full hold remains. This transition clears
        // no other uncertainty and never deletes/changes a public object.
        return Commit(state, state with { Slots = state.Slots.SetItem(slot.Index, slot with { Phase = ResourceSlotPhaseV2.Released, Release = release }),
            CustodyTransfers = state.CustodyTransfers.SetItem(cellIndex, new(Convert.ToBase64String(PublicCustodyReceiptCodecV3.Serialize(receipt, false)), completion)) }, evidence);
    }
    internal static ResourceCandidateV4 AcceptRetirement(ResourceStateV4 state, long revision, ResourceRetirementStateV2 receipt,
        Guid witness, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); ResourceJsonV3.Id(witness);
        if (state.AcceptedRetirement is { } saved)
        {
            EvidenceBinaryV1.Need(saved == receipt, "Changed retirement replay.");
            return new(state.Revision, state, ResourceStateCodecV4.Serialize(state, evidence));
        }
        EvidenceBinaryV1.Need(state.Binding is not null && receipt.DriverInstanceId == state.DriverInstanceId && receipt.TransferId == state.TransferId &&
            receipt.Identity == state.Binding.Identity && receipt.AllocationGeneration == state.Binding.AllocationGeneration &&
            receipt.DestinationGeneration == state.CurrentDestinationGeneration && receipt.Sequence > state.GrowthReplay.HighWater,
            "Retirement binding/high-water differs.");
        var slot = state.Slots[state.Binding.StageSlot]!;
        var accepted = receipt with { AcceptedRevision = checked(state.Revision + 1) };
        var nextSlot = slot with { Phase = ResourceSlotPhaseV2.Immutable, EndOfFile = receipt.EndOfFile, AllocationSize = receipt.AllocationSize,
            ExpectedLength = receipt.EndOfFile };
        return Commit(state, state with { GrowthClosed = true, Phase = ResourceStatePhaseV2.WriteRetired, ClosureKind = ResourceClosureV2.DriverWriteRetired,
            AcceptedRetirement = accepted, RetirementWitnessId = witness, Slots = state.Slots.SetItem(slot.Index, nextSlot) }, evidence);
    }
    internal static ResourceCandidateV4 ClaimGrowth(ResourceStateV4 state, long revision, ReadOnlySpan<byte> requestBytes, EvidenceCatalogV1 evidence)
    {
        Check(state, revision);
        EvidenceBinaryV1.Need(!state.GrowthClosed && ResourceWireV32.TryReadGrowth(requestBytes, (ulong)state.Alignment, out _), "Growth is closed/malformed.");
        var request = MemoryMarshal.Read<ResourceGrowthV32>(requestBytes);
        EvidenceBinaryV1.Need(request.Binding.Sequence > state.GrowthReplay.HighWater && state.GrowthReplay.Latest?.State is not
            (ResourceReplayPhaseV3.Claimed or ResourceReplayPhaseV3.Charged), "Another semantic growth is unresolved/stale.");
        byte[] canonical = requestBytes.ToArray(); BinaryPrimitives.WriteUInt64LittleEndian(canonical.AsSpan(16), 0);
        return Commit(state, state with { GrowthReplay = new(request.Binding.Sequence, new(request.Binding.Sequence, Convert.ToBase64String(canonical),
            ResourceReplayPhaseV3.Claimed, null, null, null, null)) }, evidence);
    }
    internal static ResourceCandidateV4 ChargeGrowth(ResourceStateV4 state, long revision, long capacity, Guid operationId,
        long replacementIncarnation, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); var latest = state.GrowthReplay.Latest;
        EvidenceBinaryV1.Need(!state.GrowthClosed && latest?.State == ResourceReplayPhaseV3.Claimed && state.PendingCompanion is null &&
            capacity > state.AuthorizedCapacity && capacity % state.Alignment == 0 && replacementIncarnation > 0, "Growth target/claim differs.");
        var slots = state.Slots.Select(slot => slot?.Role == ResourceSlotRoleV2.Stage ? slot with { ReservedMax = capacity } : slot).ToImmutableArray();
        long next = checked(state.Revision + 1);
        return Commit(state, state with { AuthorizedCapacity = capacity, GrantRevision = next, Slots = slots,
            PendingCompanion = new() { OperationId = operationId, Predecessor = state.Companion, TargetCapacity = capacity, TargetRevision = next,
                ReplacementIncarnation = replacementIncarnation, ReplacementIdentity = null, Phase = ResourceCompanionPhaseV3.ReservedNotIssued },
            GrowthReplay = state.GrowthReplay with { Latest = latest! with { State = ResourceReplayPhaseV3.Charged, CommittedCapacity = capacity, GrantRevision = next } } }, evidence);
    }
    internal static ResourceCandidateV4 AdvanceCompanion(ResourceStateV4 state, long revision, ResourceCompanionPhaseV3 nextPhase,
        StagedStageIdentity? capturedIdentity, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); var pending = state.PendingCompanion;
        EvidenceBinaryV1.Need(pending is not null && (pending.Phase, nextPhase) is
            (ResourceCompanionPhaseV3.ReservedNotIssued, ResourceCompanionPhaseV3.CreationMayHaveStarted) or
            (ResourceCompanionPhaseV3.CreationMayHaveStarted, ResourceCompanionPhaseV3.IdentityCaptured) or
            (ResourceCompanionPhaseV3.IdentityCaptured, ResourceCompanionPhaseV3.Prepared) or
            (ResourceCompanionPhaseV3.Prepared, ResourceCompanionPhaseV3.NativeReplacementCommitted), "Invalid companion transition/repeated mutation.");
        if (nextPhase == ResourceCompanionPhaseV3.IdentityCaptured) ResourceJsonV3.Identity(capturedIdentity);
        else EvidenceBinaryV1.Need(capturedIdentity == pending.ReplacementIdentity, "Companion identity changed.");
        return Commit(state, state with { PendingCompanion = pending with { Phase = nextPhase, ReplacementIdentity = capturedIdentity } }, evidence);
    }
    internal static ResourceCandidateV4 AdoptCompanion(ResourceStateV4 state, long revision, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); var pending = state.PendingCompanion;
        EvidenceBinaryV1.Need(pending is { Phase: ResourceCompanionPhaseV3.NativeReplacementCommitted, ReplacementIdentity: not null }, "Companion native replacement is unresolved.");
        return Commit(state, state with { Companion = new() { Identity = pending.ReplacementIdentity, Capacity = pending.TargetCapacity, GrantRevision = pending.TargetRevision },
            PendingCompanion = null, GrowthReplay = state.GrowthReplay with { Latest = state.GrowthReplay.Latest! with
            { State = ResourceReplayPhaseV3.CompanionCommitted, Result = ResourceResultCodeV32.CapacityCommitted, AcceptedRevision = checked(state.Revision + 1) } } }, evidence);
    }
    internal static ResourceCandidateV4 ReleaseSlot(ResourceStateV4 state, long revision, ResourceCustodyClaimV3 immutableClaim,
        ResourceReleaseStateV3 proof, ResourceOwnerInventoryV4 owners, EvidenceCatalogV1 evidence)
    {
        var slot = Find(state, revision, immutableClaim); owners.RequireDrained(immutableClaim);
        EvidenceBinaryV1.Need(immutableClaim.State == ResourceClaimPhaseV3.Drained && proof.Slot == slot.Index &&
            proof.Incarnation == slot.Incarnation && proof.Identity == slot.Identity && proof.ClaimRevision == immutableClaim.ClaimRevision &&
            proof.Kind is ResourceReleaseKindV3.NeverIssued or ResourceReleaseKindV3.DefinitiveNonCreation or
                ResourceReleaseKindV3.FinalStorageRelease or ResourceReleaseKindV3.ExactAbsenceAfterDrain,
            "Storage release differs from the drained exact claim.");
        var next = state with { Slots = state.Slots.SetItem(slot.Index, slot with { Phase = ResourceSlotPhaseV2.Released, Release = proof }),
            StageRelease = slot.Role == ResourceSlotRoleV2.Stage && state.Binding is not null ? proof : state.StageRelease };
        return Commit(state, next, evidence);
    }
    internal static ResourceCandidateV4 CloseIntent(ResourceStateV4 state, long revision, Guid fenceId, uint reason, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); ResourceJsonV3.Id(fenceId);
        EvidenceBinaryV1.Need(reason is >= 1 and <= 4 && state.InitialResolution.State is ResourceInitialPhaseV3.Open or ResourceInitialPhaseV3.Closing,
            "Initial closure is irreversible/already resolved.");
        return Commit(state, state with { GrowthClosed = true,
            Phase = state.Binding is null ? ResourceStatePhaseV2.ClosedUnissued : ResourceStatePhaseV2.Closing,
            ClosureKind = state.Binding is null ? ResourceClosureV2.UnissuedClosed : ResourceClosureV2.None,
            InitialResolution = state.InitialResolution with { State = ResourceInitialPhaseV3.Closing, FenceId = fenceId, ControlReason = reason } }, evidence);
    }
    internal static ResourceCandidateV4 AcceptFence(ResourceStateV4 state, long revision, string receipt, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); EvidenceBinaryV1.Need(state.InitialResolution.State == ResourceInitialPhaseV3.Closing, "Fence lacks closed original intent.");
        return Commit(state, state with { InitialResolution = state.InitialResolution with
        { State = ResourceInitialPhaseV3.Fenced, FenceReceipt = receipt } }, evidence);
    }
    internal static ResourceCandidateV4 ResolveInitialSuccess(ResourceStateV4 state, long revision, Guid queryId, string receipt, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); EvidenceBinaryV1.Need(state.InitialResolution.State is ResourceInitialPhaseV3.Open or ResourceInitialPhaseV3.Attached,
            "Cannot turn abandonment/old query into CREATE success.");
        return Commit(state, state with { InitialResolution = state.InitialResolution with { State = ResourceInitialPhaseV3.InitialResolved,
            FenceId = queryId, ControlReason = 5, FenceReceipt = receipt, ResolutionRevision = checked(state.Revision + 1) } }, evidence);
    }
    internal static ResourceCandidateV4 CleanupComplete(ResourceStateV4 state, long revision, Guid witness, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); ResourceJsonV3.Id(witness);
        EvidenceBinaryV1.Need(state.InitialResolution.State == ResourceInitialPhaseV3.Fenced && state.Slots.All(slot => slot is null or { Phase: ResourceSlotPhaseV2.Released }),
            "Cleanup still has custody/initial adopters.");
        return Commit(state, state with { Phase = ResourceStatePhaseV2.MetadataOnly, InitialResolution = state.InitialResolution with
        { State = ResourceInitialPhaseV3.CleanupComplete, CleanupWitness = witness, ResolutionRevision = checked(state.Revision + 1) } }, evidence);
    }
    internal static ResourceCandidateV4 AcknowledgeInitial(ResourceStateV4 state, long revision, string request, string reply, EvidenceCatalogV1 evidence)
    {
        Check(state, revision); EvidenceBinaryV1.Need(state.InitialResolution.State == ResourceInitialPhaseV3.CleanupComplete, "Initial ACK has no cleanup base.");
        return Commit(state, state with { InitialResolution = state.InitialResolution with { State = ResourceInitialPhaseV3.ResolutionAcknowledged,
            KernelAckControlRequest = request, KernelAckControlReply = reply, ResolutionRevision = checked(state.Revision + 1) } }, evidence);
    }
    internal static ResourceCandidateV4 MetadataOnly(ResourceStateV4 state, long revision, EvidenceCatalogV1 evidence)
    { Check(state, revision); return Commit(state, state with { Phase = ResourceStatePhaseV2.MetadataOnly }, evidence); }

    internal static long Measure(ResourceStateV4 state)
    {
        try
        {
            long extent = 0;
            foreach (var slot in state.Slots)
            {
                if (slot is null || slot.Phase == ResourceSlotPhaseV2.Released) continue;
                long value = slot.Phase is ResourceSlotPhaseV2.Immutable or ResourceSlotPhaseV2.ImmutableReleasePending ?
                    checked((slot.AllocationSize!.Value + state.Alignment - 1) / state.Alignment * state.Alignment) : slot.ReservedMax;
                extent = Math.Max(extent, value);
            }
            bool full = state.FullDebitHeld || state.PendingCompanion is not null || state.Phase is ResourceStatePhaseV2.Preparing or
                ResourceStatePhaseV2.Writable or ResourceStatePhaseV2.Closing or ResourceStatePhaseV2.ClosedUnissued;
            long charge = checked((full ? state.AuthorizedCapacity : extent) * 4 + state.MetadataDebit);
            foreach (var claim in state.EvidenceClaims) if (claim is { Phase: not EvidencePhaseV1.StorageReleased, AccountingOwner: EvidenceAccountingOwnerV1.Transfer })
                charge = checked(charge + (claim.MeasuredAllocation ?? claim.ReservedMax));
            return charge;
        }
        catch (OverflowException error) { throw new InvalidDataException("Resource debit overflow.", error); }
    }
    private static void Check(ResourceStateV4 state, long revision) => EvidenceBinaryV1.Need(state.Revision == revision, "Stale current budget revision.");
    private static ResourceSlotStateV3 Find(ResourceStateV4 state, long revision, ResourceCustodyClaimV3 expected)
    {
        Check(state, revision); EvidenceBinaryV1.Need(expected.Slot < 4, "Invalid claim slot.");
        var slot = state.Slots[(int)expected.Slot];
        EvidenceBinaryV1.Need(slot is not null && slot.CustodyClaim == expected && slot.Incarnation == expected.Incarnation,
            "Stale claim revision/incarnation/owner."); return slot;
    }
    private static ResourceCandidateV4 Commit(ResourceStateV4 old, ResourceStateV4 next, EvidenceCatalogV1 evidence) => Prepare(old, old.Revision,
        next with { Revision = checked(old.Revision + 1), ChargeBytes = Measure(next) }, evidence);
}
#endif
