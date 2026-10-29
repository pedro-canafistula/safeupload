#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;

namespace SafeUpload.Agent.Service.Interception;

// Passive referenced representation. No shipped consumer adopts this state.
internal sealed record ResourceStateV4
{
    public required ImmutableArray<EvidenceClaimV1?> EvidenceClaims { get; init; }
    public required int Version { get; init; }
    public required Guid InstallationId { get; init; }
    public required long InitialCapacity { get; init; }
    public required Guid? RetirementWitnessId { get; init; }
    public required ResourceInitialResolutionV3 InitialResolution { get; init; }
    public required ResourceGrowthReplayV3 GrowthReplay { get; init; }
    public required ResourceHistoryHandoffV3? HistoryHandoff { get; init; }
    public required ImmutableArray<ResourceCustodyTransferV4?> CustodyTransfers { get; init; }
    public required Guid TransferId { get; init; }
    public required Guid DriverInstanceId { get; init; }
    public required string Sid { get; init; }
    public required string OriginalRequest { get; init; }
    public required long Alignment { get; init; }
    public required long MetadataGranularity { get; init; }
    public required long AuthorizedCapacity { get; init; }
    public required long MetadataDebit { get; init; }
    public required long Revision { get; init; }
    public required long GrantRevision { get; init; }
    public required bool GrowthClosed { get; init; }
    public required bool GrantMayHaveEscaped { get; init; }
    public required ResourceStatePhaseV2 Phase { get; init; }
    public required ResourceClosureV2 ClosureKind { get; init; }
    public required ResourceBindingStateV2? Binding { get; init; }
    public required long? CurrentDestinationGeneration { get; init; }
    public required ImmutableArray<ResourceSlotStateV3?> Slots { get; init; }
    public required ResourceRetirementStateV2? AcceptedRetirement { get; init; }
    public required ResourceReleaseStateV3? StageRelease { get; init; }
    public required ResourceCompanionStateV2? Companion { get; init; }
    public required ResourcePendingCompanionV3? PendingCompanion { get; init; }
    public required bool FullDebitHeld { get; init; }
    public required long ChargeBytes { get; init; }
}

internal sealed record ResourceCustodyTransferV4(string ReceiptBase64, PublicCustodyCompletionV4 Completion);
internal sealed record PublicCustodyCompletionV4(int Version, string CompletionBase64,
    StagedPublicationNativeReceipt? PublicationNativeReceipt, ResourceCustodyClaimV3 Claim,
    PublicCustodyAuthorizationV4 Authorization);
internal sealed record PublicCustodyAuthorizationV4(Guid WitnessId, string EvidenceReferenceBase64);
internal enum EvidencePhaseV1
{ ReservedNotIssued = 1, CreationMayHaveStarted = 2, Captured = 3, Prepared = 4, Referenced = 5, Detached = 6, DeleteMayHaveIssued = 7, StorageReleased = 8 }
internal enum EvidenceAccountingOwnerV1 { Transfer = 1, Shared = 2 }
internal sealed record EvidenceClaimV1(Guid RecordId, long Generation, EvidenceKindV1 Kind, Guid OperationId,
    Guid AuthorizationWitnessId, long AllocationGeneration, long DestinationGeneration, Guid OwnerEpoch,
    EvidencePhaseV1 Phase, StagedStageIdentity? Identity, long? Length, string? Sha256, long ReservedMax,
    long? MeasuredAllocation, Guid? DrainWitnessId, Guid? ReleaseWitnessId, ResourceReleaseKindV3? ReleaseKind,
    EvidenceAccountingOwnerV1 AccountingOwner, long? SharedOwnershipRevision);
#endif
