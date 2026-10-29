#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal static class ResourceStateCodecV4
{
    internal const int MaximumBytes = 65536;
    internal static byte[] Serialize(ResourceStateV4 state, EvidenceCatalogV1 evidence)
    { Validate(state, evidence); return ResourceJsonV3.Serialize(state, MaximumBytes); }
    internal static ResourceStateV4 Deserialize(ReadOnlySpan<byte> bytes, EvidenceCatalogV1 evidence)
    {
        var state = ResourceJsonV4.Deserialize<ResourceStateV4>(bytes, MaximumBytes);
        Validate(state, evidence);
        EvidenceBinaryV1.Need(bytes.SequenceEqual(Serialize(state, evidence)), "Noncanonical ledger bytes/order.");
        return state;
    }
    internal static void Validate(ResourceStateV4 state, EvidenceCatalogV1 evidence)
    {
        try { ValidateCore(state, evidence); }
        catch (OverflowException error) { throw new InvalidDataException("Ledger arithmetic overflowed.", error); }
    }
    private static void ValidateCore(ResourceStateV4 state, EvidenceCatalogV1 evidence)
    {
        EvidenceBinaryV1.Need(state.Version == 4, "Unsupported ledger schema."); ResourceJsonV3.Id(state.InstallationId);
        EvidenceBinaryV1.Need(state.InitialCapacity >= 16 * 1024 * 1024 && state.InitialCapacity <= state.AuthorizedCapacity &&
            state.Alignment > 0 && state.InitialCapacity % state.Alignment == 0 &&
            state.RetirementWitnessId.HasValue == (state.AcceptedRetirement is not null), "Initial capacity/retirement witness differs.");
        if (state.RetirementWitnessId is { } retired) ResourceJsonV3.Id(retired);
        EvidenceBinaryV1.Need(!state.Slots.IsDefault && state.Slots.Length == 4 && !state.CustodyTransfers.IsDefault &&
            state.CustodyTransfers.Length == 2 && !state.EvidenceClaims.IsDefault && state.EvidenceClaims.Length == 4, "Fixed inventory dimensions differ.");
        long physical = 0; var identities = new HashSet<StagedStageIdentity>(); var records = new HashSet<Guid>();
        foreach (var claim in state.EvidenceClaims)
        {
            if (claim is null) continue;
            ValidateEvidenceClaim(state, claim);
            EvidenceBinaryV1.Need(records.Add(claim.RecordId), "Duplicate evidence record claim.");
            if (claim.Phase == EvidencePhaseV1.StorageReleased) continue;
            if (claim.Identity is { } identity) EvidenceBinaryV1.Need(identities.Add(identity), "Duplicate live evidence identity.");
            if (claim.AccountingOwner == EvidenceAccountingOwnerV1.Transfer)
                physical = checked(physical + (claim.MeasuredAllocation ?? claim.ReservedMax));
        }
        foreach (var slot in state.Slots)
        {
            if (slot is null) continue;
            if (slot.Locator is { } locator) ResourceJsonV3.Text(locator, 1, 512);
            EvidenceBinaryV1.Need(slot.CustodyClaim is not null, "Occupied content slot lacks its claim.");
            ValidateClaim(slot.CustodyClaim!, state.Revision);
            var claim = slot.CustodyClaim!;
            EvidenceBinaryV1.Need(claim.Slot == slot.Index && claim.Incarnation == slot.Incarnation && claim.Identity == slot.Identity,
                "Content claim belongs to another incarnation.");
            if (slot.Phase == ResourceSlotPhaseV2.Released)
                EvidenceBinaryV1.Need(claim.State == ResourceClaimPhaseV3.Drained, "Released content has undrained owners.");
            if (slot.Release is { } release)
            {
                EvidenceBinaryV1.Need(Enum.IsDefined(release.Kind) &&
                    (release.Kind == ResourceReleaseKindV3.PublicCustodyTransferred) == release.CustodyTransferReceiptId.HasValue,
                    "Release kind/receipt cell differs.");
                if (release.Kind == ResourceReleaseKindV3.PublicCustodyTransferred)
                {
                    int cell = slot.Role == ResourceSlotRoleV2.PublicationTemporary ? 0 : slot.Role == ResourceSlotRoleV2.Handback ? 1 : -1;
                    EvidenceBinaryV1.Need(cell >= 0 && state.CustodyTransfers[cell] is not null, "Content role lacks its custody transfer.");
                    var receipt = PublicCustodyReceiptCodecV3.Deserialize(ResourceJsonV3.Base64(state.CustodyTransfers[cell]!.ReceiptBase64, 2048), false);
                    EvidenceBinaryV1.Need(receipt.ReceiptId == release.CustodyTransferReceiptId && receipt.Slot == slot.Index &&
                        receipt.Incarnation == slot.Incarnation && receipt.DeliveredObjectIdentity == slot.Identity &&
                        receipt.ClaimId == claim.ClaimId && receipt.ClaimRevision == release.ClaimRevision, "Release receipt belongs to another slot.");
                }
            }
        }
        EvidenceBinaryV1.Need(state.StageRelease?.Kind != ResourceReleaseKindV3.PublicCustodyTransferred, "Stage cannot transfer public custody.");
        // Reuse the complete, unchanged v2 custody/phase/debit invariant checker.
        // This projection is in memory only; v4 is never stored or read as v2.
        var baseline = Project(state, physical);
        ResourceStateCodecV2.Validate(baseline, state.MetadataGranularity);
        if (state.PendingCompanion is { } pending)
            EvidenceBinaryV1.Need(Enum.IsDefined(pending.Phase) && (pending.Phase is ResourceCompanionPhaseV3.IdentityCaptured or
                ResourceCompanionPhaseV3.Prepared or ResourceCompanionPhaseV3.NativeReplacementCommitted) == (pending.ReplacementIdentity is not null),
                "Companion capture phase differs.");
        ValidateInitial(state); ValidateReplay(state);
        for (int index = 0; index < 2; index++) if (state.CustodyTransfers[index] is { } cell) ValidateTransfer(state, cell, index, evidence);
        if (state.HistoryHandoff is { } handoff) ValidateHandoff(state, handoff);
    }

    internal static void ValidateClaim(ResourceCustodyClaimV3 claim, long currentRevision)
    {
        ResourceJsonV3.Id(claim.ClaimId); ResourceJsonV3.Id(claim.OwnerEpoch);
        EvidenceBinaryV1.Need(claim.Slot < 4 && claim.Incarnation > 0 && claim.ClaimRevision > 0 && claim.ClaimRevision <= currentRevision &&
            Enum.IsDefined(claim.Kind) && Enum.IsDefined(claim.State) &&
            (claim.State == ResourceClaimPhaseV3.Drained) == claim.DrainWitnessId.HasValue, "Content claim phase/revision differs.");
        if (claim.Identity is { } identity) ResourceJsonV3.Identity(identity);
        if (claim.DrainWitnessId is { } drain) ResourceJsonV3.Id(drain);
        if (claim.RetirementWitnessId is { } retired) ResourceJsonV3.Id(retired);
    }
    internal static void ValidateEvidenceClaim(ResourceStateV4 state, EvidenceClaimV1 claim)
    {
        EvidenceReferenceCodecV1.ValidateOwner(new(state.InstallationId, state.TransferId, claim.OperationId, claim.RecordId,
            claim.Generation, claim.Kind, claim.AllocationGeneration, claim.DestinationGeneration, claim.AuthorizationWitnessId));
        ResourceJsonV3.Id(claim.OwnerEpoch);
        EvidenceBinaryV1.Need(Enum.IsDefined(claim.Phase) && Enum.IsDefined(claim.AccountingOwner) && claim.ReservedMax > 0 &&
            claim.MeasuredAllocation is null or >= 0 && (claim.MeasuredAllocation is null || claim.MeasuredAllocation <= claim.ReservedMax) &&
            (claim.AccountingOwner == EvidenceAccountingOwnerV1.Shared ? claim.SharedOwnershipRevision is > 0 : claim.SharedOwnershipRevision is null),
            "Evidence physical charge/owner differs.");
        bool created = claim.Phase is >= EvidencePhaseV1.Captured and <= EvidencePhaseV1.DeleteMayHaveIssued;
        bool prepared = claim.Phase is >= EvidencePhaseV1.Prepared and <= EvidencePhaseV1.DeleteMayHaveIssued;
        if (created) ResourceJsonV3.Identity(claim.Identity);
        else if (claim.Phase != EvidencePhaseV1.StorageReleased) EvidenceBinaryV1.Need(claim.Identity is null, "Premature evidence identity.");
        EvidenceBinaryV1.Need(prepared ? claim.Length is > 0 && claim.Sha256 is not null && claim.MeasuredAllocation.HasValue &&
            claim.DrainWitnessId.HasValue : claim.Phase == EvidencePhaseV1.StorageReleased || claim.Length is null && claim.Sha256 is null,
            "Evidence preparation fields differ.");
        if (claim.Length is { } length) EvidenceBinaryV1.Need(length <= EvidencePackCodecV1.MaximumFileBytes, "Evidence logical length exceeds its bound.");
        if (claim.Sha256 is { } hash) ResourceJsonV3.Hex(hash);
        if (claim.DrainWitnessId is { } drain) ResourceJsonV3.Id(drain);
        if (claim.Phase == EvidencePhaseV1.StorageReleased)
        {
            EvidenceBinaryV1.Need(claim.ReleaseKind is ResourceReleaseKindV3.NeverIssued or ResourceReleaseKindV3.DefinitiveNonCreation or
                ResourceReleaseKindV3.FinalStorageRelease or ResourceReleaseKindV3.ExactAbsenceAfterDrain && claim.ReleaseWitnessId.HasValue &&
                claim.DrainWitnessId.HasValue, "Released evidence lacks exact release/drain witnesses.");
            ResourceJsonV3.Id(claim.ReleaseWitnessId!.Value);
            if (claim.ReleaseKind is ResourceReleaseKindV3.NeverIssued or ResourceReleaseKindV3.DefinitiveNonCreation)
                EvidenceBinaryV1.Need(claim.Identity is null && claim.Length is null && claim.Sha256 is null && claim.MeasuredAllocation is null,
                    "Noncreation evidence invents an object.");
            else ResourceJsonV3.Identity(claim.Identity);
        }
        else EvidenceBinaryV1.Need(claim.ReleaseKind is null && claim.ReleaseWitnessId is null, "Live evidence claims released storage.");
    }

    internal static void ValidateCompletion(PublicCustodyCompletionV4 completion, EvidenceCatalogV1 evidence,
        Guid installation, Guid transfer, long currentRevision)
    {
        EvidenceBinaryV1.Need(completion.Version == 1, "Unknown completion version.");
        var receipt = PublicCustodyReceiptCodecV3.Deserialize(ResourceJsonV3.Base64(completion.CompletionBase64, 2048), true);
        ValidateClaim(completion.Claim, currentRevision);
        var claim = completion.Claim;
        EvidenceBinaryV1.Need(receipt.InstallationId == installation && receipt.TransferId == transfer &&
            claim.State == ResourceClaimPhaseV3.Drained && claim.Kind == ResourceClaimKindV3.Promote &&
            claim.ClaimId == receipt.ClaimId && claim.OwnerEpoch == receipt.OwnerEpoch && claim.Slot == receipt.Slot &&
            claim.Incarnation == receipt.Incarnation && claim.ClaimRevision == receipt.ClaimRevision &&
            claim.Identity == receipt.DeliveredObjectIdentity && claim.DrainWitnessId == receipt.PrivateRundownWitnessId &&
            completion.Authorization.WitnessId == receipt.AuthorizationWitnessId, "Completion claim/rundown binding differs.");
        var reference = EvidenceReferenceCodecV1.Deserialize(ResourceJsonV3.Base64(completion.Authorization.EvidenceReferenceBase64, 192));
        var owner = reference.Owner;
        EvidenceBinaryV1.Need(owner.Kind == EvidenceKindV1.Authorization && owner.InstallationId == installation && owner.TransferId == transfer &&
            owner.OperationId == receipt.PromotionOperationId && owner.AuthorizationWitnessId == receipt.AuthorizationWitnessId &&
            owner.AllocationGeneration == receipt.AllocationGeneration && owner.DestinationGeneration == receipt.DestinationGeneration,
            "Authorization reference belongs to another completion.");
        var content = evidence.Resolve(reference);
        EvidenceBinaryV1.Need(content.Entry.Transfer.RequestorSid == receipt.RequestorSid && content.Entry.StageIdentity == receipt.StageIdentity &&
            content.Entry.DriverInstanceId == receipt.DriverInstanceId && content.Entry.DestinationGeneration == receipt.DestinationGeneration &&
            (receipt.ProofKind == 3 ? content.Approval is null : content.Approval is not null), "Retained source caller/version differs.");
        if (receipt.ProofKind == 1)
        {
            EvidenceBinaryV1.Need(completion.PublicationNativeReceipt is not null, "Bound completion lacks native facts.");
            ValidateNative(completion.PublicationNativeReceipt!, receipt, content.Approval!);
        }
        else EvidenceBinaryV1.Need(completion.PublicationNativeReceipt is null, "Unbound/hand-back completion carries bound facts.");
    }
    private static void ValidateTransfer(ResourceStateV4 state, ResourceCustodyTransferV4 cell, int index, EvidenceCatalogV1 evidence)
    {
        ValidateCompletion(cell.Completion, evidence, state.InstallationId, state.TransferId, state.Revision);
        byte[] raw = ResourceJsonV3.Base64(cell.ReceiptBase64, 2048);
        var receipt = PublicCustodyReceiptCodecV3.Deserialize(raw, false);
        EvidenceBinaryV1.Need(receipt.TransferKind == index + 1 && receipt.AcceptedBudgetRevision <= state.Revision &&
            receipt.AcceptedBudgetRevision > receipt.ClaimRevision && state.Binding is { } binding &&
            binding.Identity == receipt.StageIdentity && binding.AllocationGeneration == receipt.AllocationGeneration &&
            receipt.DriverInstanceId == state.DriverInstanceId && receipt.RequestorSid == state.Sid,
            "Accepted custody transfer binding/revision differs.");
        BinaryPrimitives.WriteInt64LittleEndian(raw.AsSpan(160), 0);
        EvidenceBinaryV1.Need(raw.AsSpan().SequenceEqual(ResourceJsonV3.Base64(cell.Completion.CompletionBase64, 2048)), "Accepted receipt changed source bytes.");
        var reference = EvidenceReferenceCodecV1.Deserialize(ResourceJsonV3.Base64(cell.Completion.Authorization.EvidenceReferenceBase64, 192));
        EvidenceBinaryV1.Need(state.EvidenceClaims.Any(claim => claim is not null && claim.RecordId == reference.Owner.RecordId &&
            claim.Generation == reference.Owner.Generation && claim.Identity == reference.Identity && claim.Length == reference.Length &&
            claim.Sha256 == reference.Sha256 && claim.Phase == EvidencePhaseV1.Referenced), "Accepted transfer lost evidence custody.");
    }
    private static void ValidateNative(StagedPublicationNativeReceipt receipt, PublicCustodyReceiptV3 completion, PublicationApprovalV1 approval)
    {
        byte[] raw = ResourceJsonV3.Base64(receipt.FactsBase64, 2112);
        var replay = BoundPublicationV26.DecodeFactRow(raw, receipt.DriverInstanceId, receipt.ConnectionEpoch, receipt.OsBootSequence);
        var facts = replay.Facts;
        EvidenceBinaryV1.Need(receipt.DriverInstanceId == completion.DriverInstanceId && receipt.Revision > 0 &&
            replay.HasTerminalLocalProof && facts.Flags.HasFlag(BoundPublicationFacts.RenameAccepted) &&
            facts.Create.TransferId == completion.TransferId && facts.Create.DestinationGeneration == completion.DestinationGeneration && facts.Rename.OperationId == completion.PromotionOperationId &&
            facts.TemporaryIdentity.VolumeSerialNumber == completion.DeliveredObjectIdentity.VolumeSerialNumber &&
            facts.TemporaryIdentity.FileIdLow == completion.DeliveredObjectIdentity.FileIdLow && facts.TemporaryIdentity.FileIdHigh == completion.DeliveredObjectIdentity.FileIdHigh &&
            facts.Create.MeasuredLength == approval.Binding.Length && Convert.ToHexString(facts.Create.GetDigest()) == approval.Binding.Sha256 &&
            receipt.AcknowledgedRevision.HasValue == receipt.AcknowledgedConnectionEpoch.HasValue &&
            (receipt.AcknowledgedRevision is null || receipt.AcknowledgedRevision > 0 && receipt.AcknowledgedRevision <= receipt.Revision &&
                receipt.AcknowledgedConnectionEpoch > 0 && receipt.AcknowledgedConnectionEpoch <= receipt.ConnectionEpoch), "Native completion facts differ.");
    }

    private static void ValidateInitial(ResourceStateV4 state)
    {
        var initial = state.InitialResolution;
        ResourceJsonV3.Id(initial.BootDomain); PublicationApprovalCodecV1.ValidateSid(initial.Sid);
        EvidenceBinaryV1.Need(initial.OriginalRequest == state.OriginalRequest && initial.Sid == state.Sid && initial.IntentRevision > 0 &&
            initial.IntentRevision <= state.Revision && initial.OriginCookie != 0 && Enum.IsDefined(initial.State), "Initial intent differs.");
        byte[] original = ResourceJsonV3.Base64(state.OriginalRequest, 1192);
        EvidenceBinaryV1.Need(BinaryPrimitives.ReadUInt64LittleEndian(original.AsSpan(1136)) == initial.OriginCookie, "Origin cookie differs.");
        bool resolved = initial.State is ResourceInitialPhaseV3.Fenced or ResourceInitialPhaseV3.CleanupComplete or
            ResourceInitialPhaseV3.ResolutionAcknowledged or ResourceInitialPhaseV3.InitialResolved;
        EvidenceBinaryV1.Need(initial.FenceId.HasValue == initial.ControlReason.HasValue &&
            (initial.FenceId is null || initial.FenceId != Guid.Empty && initial.ControlReason is >= 1 and <= 5) &&
            (resolved ? initial.FenceReceipt is not null : initial.FenceReceipt is null) &&
            (initial.State is ResourceInitialPhaseV3.CleanupComplete or ResourceInitialPhaseV3.ResolutionAcknowledged) == initial.CleanupWitness.HasValue &&
            (initial.State is ResourceInitialPhaseV3.CleanupComplete or ResourceInitialPhaseV3.ResolutionAcknowledged or ResourceInitialPhaseV3.InitialResolved)
                == initial.ResolutionRevision.HasValue && (initial.ResolutionRevision is null || initial.ResolutionRevision > 0 && initial.ResolutionRevision <= state.Revision),
            "Initial phase/null fields differ.");
        if (resolved)
        {
            var bytes = ResourceJsonV3.Base64(initial.FenceReceipt!, 192); ValidateControlHeader(bytes, 5, 128, state.DriverInstanceId);
            EvidenceBinaryV1.Need(initial.FenceId.HasValue && new Guid(bytes.AsSpan(72, 16)) == initial.FenceId &&
                new Guid(bytes.AsSpan(88, 16)) == initial.BootDomain && EvidenceBinaryV1.U64(bytes, 104) == initial.OriginCookie &&
                EvidenceBinaryV1.U64(bytes, 112) > 0 && EvidenceBinaryV1.U32(bytes, 64) == (initial.State == ResourceInitialPhaseV3.InitialResolved ? 2u : 1u),
                "Initial fence/query correlation differs.");
            EvidenceBinaryV1.Zero(bytes.AsSpan(68, 4)); EvidenceBinaryV1.Zero(bytes.AsSpan(160));
            if (initial.State == ResourceInitialPhaseV3.InitialResolved)
                EvidenceBinaryV1.Need(initial.ControlReason == 5 && state.Binding is not null && EvidenceBinaryV1.Identity(bytes, 136) == state.Binding.Identity &&
                    EvidenceBinaryV1.U64(bytes, 120) == (ulong)state.Binding.AllocationGeneration && EvidenceBinaryV1.U64(bytes, 128) <= (ulong)state.CurrentDestinationGeneration!.Value,
                    "Successful initial query binding differs.");
            else EvidenceBinaryV1.Need(initial.ControlReason is >= 1 and <= 4 && state.GrowthClosed, "Abandoned intent lacks irreversible closure.");
        }
        bool ack = initial.State == ResourceInitialPhaseV3.ResolutionAcknowledged;
        EvidenceBinaryV1.Need(ack == (initial.KernelAckControlRequest is not null) && ack == (initial.KernelAckControlReply is not null), "Partial initial ACK.");
        if (ack) ValidateAck(state.DriverInstanceId, state.OriginalRequest, initial.FenceId!.Value, initial.KernelAckControlRequest!, initial.KernelAckControlReply!);
    }
    internal static void ValidateAck(Guid driver, string original, Guid fence, string request, string reply)
    {
        byte[] sent = ResourceJsonV3.Base64(request, 1272), received = ResourceJsonV3.Base64(reply, 72);
        ValidateControlHeader(sent, 6, 1208, driver); ValidateControlHeader(received, 6, 8, driver);
        EvidenceBinaryV1.Need(sent.AsSpan(64, 1192).SequenceEqual(ResourceJsonV3.Base64(original, 1192)) &&
            new Guid(sent.AsSpan(1256, 16)) == fence && sent.AsSpan(16, 40).SequenceEqual(received.AsSpan(16, 40)) &&
            EvidenceBinaryV1.U32(received, 64) == 1 && EvidenceBinaryV1.U32(received, 68) == 0, "ACK request/reply correlation differs.");
    }
    private static void ValidateControlHeader(byte[] bytes, uint opcode, int payload, Guid driver)
    {
        EvidenceBinaryV1.Need(EvidenceBinaryV1.U32(bytes, 0) == 18 && EvidenceBinaryV1.U32(bytes, 4) == bytes.Length &&
            EvidenceBinaryV1.U32(bytes, 8) == 36 && EvidenceBinaryV1.U32(bytes, 12) == 0 && EvidenceBinaryV1.U32(bytes, 16) == 32 &&
            EvidenceBinaryV1.U32(bytes, 20) == opcode && EvidenceBinaryV1.U64(bytes, 24) != 0 && EvidenceBinaryV1.U64(bytes, 32) != 0 &&
            new Guid(bytes.AsSpan(40, 16)) == driver && EvidenceBinaryV1.U32(bytes, 56) == payload && EvidenceBinaryV1.U32(bytes, 60) == 0,
            "Resource control header differs.");
    }
    private static void ValidateReplay(ResourceStateV4 state)
    {
        var replay = state.GrowthReplay;
        EvidenceBinaryV1.Need((replay.HighWater == 0) == (replay.Latest is null), "Growth replay floor differs.");
        if (replay.Latest is not { } latest) return;
        var bytes = ResourceJsonV3.Base64(latest.CanonicalRequest, 160);
        var request = MemoryMarshal.Read<ResourceGrowthV32>(bytes);
        var binding = request.Binding;
        EvidenceBinaryV1.Need(latest.Sequence == replay.HighWater && binding.Sequence == latest.Sequence && binding.RequestId == 0 &&
            binding.DriverInstanceId == state.DriverInstanceId && binding.TransferId == state.TransferId && state.Binding is not null &&
            binding.AllocationGeneration == (ulong)state.Binding.AllocationGeneration && binding.StageIdentity.VolumeSerialNumber == state.Binding.Identity.VolumeSerialNumber &&
            binding.StageIdentity.FileIdLow == state.Binding.Identity.FileIdLow && binding.StageIdentity.FileIdHigh == state.Binding.Identity.FileIdHigh &&
            binding.DestinationGeneration <= (ulong)state.CurrentDestinationGeneration!.Value && Enum.IsDefined(latest.State), "Growth replay K/sequence differs.");
        // The normal wire validator requires a live request ID. Restore only
        // this canonicalized word for structural validation, never persist it.
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(16), 1);
        EvidenceBinaryV1.Need(ResourceWireV32.TryReadGrowth(bytes, (ulong)state.Alignment, out _), "Malformed growth source bytes.");
        bool charged = latest.State is ResourceReplayPhaseV3.Charged or ResourceReplayPhaseV3.CompanionCommitted;
        bool terminal = latest.State is ResourceReplayPhaseV3.CompanionCommitted or ResourceReplayPhaseV3.Refused;
        EvidenceBinaryV1.Need(charged == latest.CommittedCapacity.HasValue && charged == latest.GrantRevision.HasValue &&
            terminal == latest.AcceptedRevision.HasValue && terminal == latest.Result.HasValue &&
            (!charged || latest.CommittedCapacity > 0 && latest.CommittedCapacity <= state.AuthorizedCapacity && latest.GrantRevision > 0 && latest.GrantRevision <= state.GrantRevision) &&
            (!terminal || latest.AcceptedRevision > 0 && latest.AcceptedRevision <= state.Revision && Enum.IsDefined(latest.Result!.Value)) &&
            (latest.State != ResourceReplayPhaseV3.CompanionCommitted || latest.Result == ResourceResultCodeV32.CapacityCommitted) &&
            (latest.State != ResourceReplayPhaseV3.Refused || latest.Result is >= ResourceResultCodeV32.NoAllocationCommitted and <= ResourceResultCodeV32.Unresolved),
            "Growth replay phase/debit differs.");
        if (latest.State == ResourceReplayPhaseV3.Charged) EvidenceBinaryV1.Need(state.PendingCompanion is { } pending &&
            pending.TargetCapacity == latest.CommittedCapacity && pending.TargetRevision == latest.GrantRevision, "Charged replay lost companion transaction.");
        if (state.AcceptedRetirement is { } retirement) EvidenceBinaryV1.Need(retirement.Sequence > replay.HighWater, "Retirement precedes growth high-water.");
    }
    internal static void ValidateHandoff(ResourceStateV4 state, ResourceHistoryHandoffV3 value)
    {
        ResourceJsonV3.Id(value.TransactionId); ResourceJsonV3.Id(value.RecordId);
        EvidenceBinaryV1.Need(value.InstallationId == state.InstallationId && value.ExpectedLedgerRevision > 0 && value.ExpectedLedgerRevision <= state.Revision &&
            value.RecordKind is >= 1 and <= 4 && Enum.IsDefined(value.Phase) && value.CandidateLeaf == value.RecordId.ToString("N") + ".resource" &&
            value.CandidateBytes is > 0 and <= 131072 && value.SegmentNumber > 0 && value.SharedPhysicalBefore >= 0 && value.ReservedPhysicalGrowth >= 0,
            "Handoff identity/candidate/charge differs.");
        ResourceJsonV3.Hex(value.CandidateSha256); EvidenceBinaryV1.Alignment(checked((int)value.Alignment));
        bool captured = value.Phase is not (ResourceHandoffPhaseV3.ReservedNotIssued or ResourceHandoffPhaseV3.CreationMayHaveStarted);
        if (captured) ResourceJsonV3.Identity(value.CandidateIdentity);
        else EvidenceBinaryV1.Need(value.CandidateIdentity is null, "Premature candidate identity.");
        if (value.Phase is ResourceHandoffPhaseV3.Prepared or ResourceHandoffPhaseV3.FrameDurable or ResourceHandoffPhaseV3.SharedCommitted)
        {
            ResourceJsonV3.Identity(value.SegmentIdentity);
            EvidenceBinaryV1.Need(value.ExpectedFrontier >= 2 * value.Alignment && value.ExpectedFrontier % value.Alignment == 0 &&
                value.ExpectedFrontierSequence > 0 && value.ExpectedFrontierSequence != ulong.MaxValue && value.FrameOffset == value.ExpectedFrontier &&
                value.FrameStride == ((60 + value.CandidateBytes + value.Alignment - 1) / value.Alignment) * value.Alignment &&
                value.TargetFrontier == checked(value.FrameOffset + value.FrameStride) && value.TargetFrontier <= 4194304 &&
                value.TargetFrontierSequence == value.ExpectedFrontierSequence + 1, "Handoff frame/frontier differs.");
        }
        EvidenceBinaryV1.Need(state.Phase == ResourceStatePhaseV2.MetadataOnly && state.InitialResolution.State is
            ResourceInitialPhaseV3.CleanupComplete or ResourceInitialPhaseV3.ResolutionAcknowledged or ResourceInitialPhaseV3.InitialResolved,
            "History handoff precedes closure/initial resolution.");
    }

    private static ResourceStateV2 Project(ResourceStateV4 state, long evidencePhysical) => new()
    {
        Version = 2, TransferId = state.TransferId, DriverInstanceId = state.DriverInstanceId, Sid = state.Sid, OriginalRequest = state.OriginalRequest,
        Alignment = state.Alignment, MetadataGranularity = state.MetadataGranularity, AuthorizedCapacity = state.AuthorizedCapacity,
        MetadataDebit = state.MetadataDebit, Revision = state.Revision, GrantRevision = state.GrantRevision, GrowthClosed = state.GrowthClosed,
        GrantMayHaveEscaped = state.GrantMayHaveEscaped, Phase = state.Phase, ClosureKind = state.ClosureKind, Binding = state.Binding,
        CurrentDestinationGeneration = state.CurrentDestinationGeneration, Slots = state.Slots.Select(slot => slot is null ? null : new ResourceSlotStateV2
        { Index = slot.Index, Incarnation = slot.Incarnation, Role = slot.Role, Phase = slot.Phase, ReservedMax = slot.ReservedMax,
            ExpectedLength = slot.ExpectedLength, Identity = slot.Identity, Locator = slot.Locator, EndOfFile = slot.EndOfFile,
            AllocationSize = slot.AllocationSize, Release = Release(slot.Release) }).ToImmutableArray(),
        AcceptedRetirement = state.AcceptedRetirement, StageRelease = Release(state.StageRelease), Companion = state.Companion,
        PendingCompanion = state.PendingCompanion is not { } pending ? null : new()
        { OperationId = pending.OperationId, Predecessor = pending.Predecessor, TargetCapacity = pending.TargetCapacity,
            TargetRevision = pending.TargetRevision, ReplacementIncarnation = pending.ReplacementIncarnation, ReplacementIdentity = pending.ReplacementIdentity,
            Phase = pending.Phase == ResourceCompanionPhaseV3.IdentityCaptured ? ResourceCompanionPhaseV2.Prepared : (ResourceCompanionPhaseV2)pending.Phase },
        FullDebitHeld = state.FullDebitHeld, ChargeBytes = checked(state.ChargeBytes - evidencePhysical)
    };
    private static ResourceReleaseStateV2? Release(ResourceReleaseStateV3? value) => value is null ? null : new()
    { Kind = value.Kind == ResourceReleaseKindV3.PublicCustodyTransferred ? ResourceReleaseKindV2.FinalStorageRelease : (ResourceReleaseKindV2)value.Kind,
        Slot = value.Slot, Incarnation = value.Incarnation, Identity = value.Identity, WitnessId = value.WitnessId, ClaimRevision = value.ClaimRevision };
}
#endif
