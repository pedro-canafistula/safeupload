#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Text.Json;
using SafeUpload.Agent.Minifilter;

namespace SafeUpload.Agent.Service.Interception;

internal enum JournalRecordKindV4 : uint { TransferClosure = 1, ResourceOnlyClosure = 2, InitialResolutionDelta = 3, LegacyHistory = 4 }
internal sealed record JournalCompletionStateV4(ImmutableArray<PublicCustodyCompletionV4?> CustodyTransferCompletions);
internal sealed record OrdinaryDiscardDisposalV4(int Version, Guid WitnessId, Guid TransferId, Guid DriverInstance,
    long AllocationGeneration, long DestinationGeneration, StagedStageIdentity StageIdentity, uint StageSlot,
    long StageIncarnation, long ClaimRevision, ResourceReleaseKindV3 ReleaseKind, Guid FenceOrRetirementWitness, long AcceptedRevision);
internal sealed record InitialResolutionDeltaV4(ResourceInitialPhaseV3 State, string OriginalRequest, Guid FenceId,
    ulong OriginCookie, string KernelAckControlRequest, string KernelAckControlReply, long ResolutionRevision);
internal sealed record LegacySourceV4(StagedStageIdentity InventoryIdentity, StagedStageIdentity SegmentIdentity,
    long FrameOffset, uint PayloadLength, string PayloadSha256);
internal sealed record StagedJournalEnvelopeV3(int FormatVersion, int ResourceSchema, Guid InstallationId,
    JournalRecordKindV4 RecordKind, Guid RecordId, Guid TransferId, long RecordRevision, Guid? PreviousRecordId,
    string? EntryReference, ResourceStateV4? ResourceClosure, JournalCompletionStateV4? CompletionState,
    OrdinaryDiscardDisposalV4? OrdinaryDiscardDisposal, InitialResolutionDeltaV4? ResolutionDelta, LegacySourceV4? LegacySource);

internal static class StagedJournalEnvelopeV3Codec
{
    internal const int MaximumBytes = 131072, WrapperMaximumBytes = 8192;
    internal static byte[] Serialize(StagedJournalEnvelopeV3 value, EvidenceCatalogV1 evidence)
    {
        Validate(value, evidence); byte[] bytes = ResourceJsonV3.Serialize(value, MaximumBytes);
        using var json = JsonDocument.Parse(bytes);
        var root = json.RootElement;
        int entry = System.Text.Encoding.UTF8.GetByteCount(root.GetProperty("EntryReference").GetRawText());
        int state = System.Text.Encoding.UTF8.GetByteCount(root.GetProperty(value.ResourceClosure is null ? "CompletionState" : "ResourceClosure").GetRawText());
        EvidenceBinaryV1.Need(state <= 65536 && bytes.Length - entry - state <= WrapperMaximumBytes, "Envelope state/wrapper exceeds its bound.");
        return bytes;
    }
    internal static void PreflightThenIssue(StagedJournalEnvelopeV3 value, EvidenceCatalogV1 evidence, Action<byte[]> issue)
    {
        byte[] bytes = Serialize(value, evidence); issue(bytes);
    }
    internal static StagedJournalEnvelopeV3 Deserialize(ReadOnlySpan<byte> bytes, EvidenceCatalogV1 evidence)
    {
        var value = ResourceJsonV4.Deserialize<StagedJournalEnvelopeV3>(bytes, MaximumBytes); Validate(value, evidence);
        EvidenceBinaryV1.Need(bytes.SequenceEqual(Serialize(value, evidence)), "Noncanonical envelope bytes/order."); return value;
    }
    internal static void Validate(StagedJournalEnvelopeV3 value, EvidenceCatalogV1 evidence)
    {
        EvidenceBinaryV1.Need(value.FormatVersion == 3 && value.ResourceSchema == 4 && Enum.IsDefined(value.RecordKind) && value.RecordRevision > 0,
            "Envelope schema/kind/revision differs.");
        ResourceJsonV3.Id(value.InstallationId); ResourceJsonV3.Id(value.RecordId); ResourceJsonV3.Id(value.TransferId);
        TransferJournalEntry? entry = null;
        if (value.EntryReference is { } encoded)
        {
            var reference = EvidenceReferenceCodecV1.Deserialize(ResourceJsonV3.Base64(encoded, 192));
            EvidenceBinaryV1.Need(reference.Owner.Kind == EvidenceKindV1.EntryCore && reference.Owner.InstallationId == value.InstallationId &&
                reference.Owner.TransferId == value.TransferId, "Envelope Entry reference binding differs.");
            var content = evidence.Resolve(reference); entry = content.Entry;
        }
        if (value.ResourceClosure is { } closure)
        {
            _ = ResourceStateCodecV4.Serialize(closure, evidence);
            EvidenceBinaryV1.Need(value.CompletionState is null && closure.TransferId == value.TransferId && closure.InstallationId == value.InstallationId &&
                closure.Phase == ResourceStatePhaseV2.MetadataOnly && closure.HistoryHandoff is null && closure.InitialResolution.State is
                    ResourceInitialPhaseV3.CleanupComplete or ResourceInitialPhaseV3.ResolutionAcknowledged or ResourceInitialPhaseV3.InitialResolved,
                "Envelope closure/initial resolution differs.");
            if (entry is not null) EvidenceBinaryV1.Need(entry.StageIdentity == closure.Binding?.Identity &&
                entry.DestinationGeneration == closure.CurrentDestinationGeneration && entry.Transfer.RequestorSid == closure.Sid,
                "Closure/source Entry authority differs.");
        }
        else if (value.CompletionState is { } completionState)
        {
            EvidenceBinaryV1.Need(!completionState.CustodyTransferCompletions.IsDefault && completionState.CustodyTransferCompletions.Length == 2 &&
                completionState.CustodyTransferCompletions.Any(c => c is not null), "Empty/invalid completion state.");
            for (int index = 0; index < 2; index++) if (completionState.CustodyTransferCompletions[index] is { } completion)
            {
                ResourceStateCodecV4.ValidateCompletion(completion, evidence, value.InstallationId, value.TransferId, long.MaxValue);
                var receipt = PublicCustodyReceiptCodecV3.Deserialize(ResourceJsonV3.Base64(completion.CompletionBase64, 2048), true);
                EvidenceBinaryV1.Need(receipt.TransferKind == index + 1 && receipt.JournalProofRecordRevision <= value.RecordRevision,
                    "Source completion position/revision differs.");
            }
        }
        switch (value.RecordKind)
        {
            case JournalRecordKindV4.TransferClosure:
                EvidenceBinaryV1.Need(entry is not null && value.PreviousRecordId is null && value.ResolutionDelta is null && value.LegacySource is null,
                    "Transfer envelope null rules differ.");
                if (value.ResourceClosure is not null) EvidenceBinaryV1.Need(Terminal(entry), "Closure Entry is not terminal.");
                break;
            case JournalRecordKindV4.ResourceOnlyClosure:
                EvidenceBinaryV1.Need(entry is null && value.ResourceClosure is { ClosureKind: ResourceClosureV2.UnissuedClosed } &&
                    value.ResourceClosure.InitialResolution.State is ResourceInitialPhaseV3.CleanupComplete or ResourceInitialPhaseV3.ResolutionAcknowledged &&
                    value.CompletionState is null && value.RecordRevision == 1 && value.PreviousRecordId is null && value.ResolutionDelta is null &&
                    value.OrdinaryDiscardDisposal is null && value.LegacySource is null, "Resource-only closure null rules differ."); break;
            case JournalRecordKindV4.InitialResolutionDelta:
                EvidenceBinaryV1.Need(entry is null && value.ResourceClosure is null && value.CompletionState is null && value.OrdinaryDiscardDisposal is null &&
                    value.PreviousRecordId is not null && value.PreviousRecordId != Guid.Empty && value.ResolutionDelta is not null && value.LegacySource is null,
                    "ACK delta null rules differ.");
                var delta = value.ResolutionDelta!;
                var original = ResourceJsonV3.Base64(delta.OriginalRequest, 1192); var request = MemoryMarshal.Read<SafeUploadRequest>(original);
                var driver = new Guid(original.AsSpan(1112, 16));
                EvidenceBinaryV1.Need(delta.State == ResourceInitialPhaseV3.ResolutionAcknowledged && delta.ResolutionRevision > 0 &&
                    delta.OriginCookie == EvidenceBinaryV1.U64(original, 1136) && request.Version == 18 && request.StructSize == 1192 &&
                    new Guid(original.AsSpan(1072, 16)) == value.TransferId, "ACK delta original binding differs.");
                ResourceStateCodecV4.ValidateAck(driver, delta.OriginalRequest, delta.FenceId, delta.KernelAckControlRequest, delta.KernelAckControlReply); break;
            case JournalRecordKindV4.LegacyHistory:
                EvidenceBinaryV1.Need(entry is not null && Terminal(entry) && value.RecordRevision == 1 && value.PreviousRecordId is null &&
                    value.ResourceClosure is null && value.CompletionState is null && value.OrdinaryDiscardDisposal is null &&
                    value.ResolutionDelta is null && value.LegacySource is not null, "Legacy envelope null rules differ.");
                ValidateLegacy(value.LegacySource!); break;
        }
        if (value.OrdinaryDiscardDisposal is { } disposal)
        {
            var disposalClosure = value.ResourceClosure;
            EvidenceBinaryV1.Need(disposal.Version == 1 && value.RecordKind == JournalRecordKindV4.TransferClosure &&
                entry is { State: TransferJournalState.Discarded, SealedOnce: false, PendingRename: null } &&
                entry.HandbackState != StagedHandbackState.Copying && disposal.TransferId == value.TransferId && disposal.AcceptedRevision == value.RecordRevision &&
                disposal.ReleaseKind is ResourceReleaseKindV3.FinalStorageRelease or ResourceReleaseKindV3.ExactAbsenceAfterDrain &&
                disposalClosure is { Binding: not null } && disposal.DriverInstance == disposalClosure.DriverInstanceId && disposal.StageIdentity == disposalClosure.Binding?.Identity &&
                disposal.AllocationGeneration == disposalClosure.Binding.AllocationGeneration && disposal.DestinationGeneration == disposalClosure.CurrentDestinationGeneration &&
                disposal.StageSlot == disposalClosure.Binding.StageSlot && disposal.StageIncarnation == disposalClosure.Binding.StageIncarnation &&
                disposal.ClaimRevision == disposalClosure.StageRelease?.ClaimRevision && disposal.FenceOrRetirementWitness ==
                    (disposalClosure.RetirementWitnessId ?? disposalClosure.InitialResolution.FenceId), "Ordinary discard proof differs.");
            ResourceJsonV3.Id(disposal.WitnessId);
        }
    }
    internal static bool Terminal(TransferJournalEntry entry) => entry.State is TransferJournalState.Released or TransferJournalState.Blocked or TransferJournalState.Discarded;
    internal static void ValidateLegacy(LegacySourceV4 value)
    {
        ResourceJsonV3.Identity(value.InventoryIdentity); ResourceJsonV3.Identity(value.SegmentIdentity); ResourceJsonV3.Hex(value.PayloadSha256);
        EvidenceBinaryV1.Need(value.FrameOffset >= 4096 && value.PayloadLength is > 0 and <= 131072, "Legacy source tuple differs.");
    }
}
#endif
