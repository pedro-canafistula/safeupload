#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;

namespace SafeUpload.Agent.Service.Interception;

// Passive schema-3 representation only. No consumer or accepting ledger reader.
// The composed format must pass its fit/strict-reader gates before adoption.
internal sealed record ResourceStateV3
{
    public required int Version { get; init; }
    public required Guid InstallationId { get; init; }
    public required long InitialCapacity { get; init; }
    public required Guid? RetirementWitnessId { get; init; }
    public required ResourceInitialResolutionV3 InitialResolution { get; init; }
    public required ResourceGrowthReplayV3 GrowthReplay { get; init; }
    public required ResourceHistoryHandoffV3? HistoryHandoff { get; init; }
    public required ImmutableArray<ResourceCustodyTransferV3?> CustodyTransfers { get; init; }
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

internal enum ResourceReleaseKindV3 { NeverIssued = 1, DefinitiveNonCreation = 2, FinalStorageRelease = 3, ExactAbsenceAfterDrain = 4, PublicCustodyTransferred = 5 }
internal enum ResourceCompanionPhaseV3 { ReservedNotIssued = 1, CreationMayHaveStarted = 2, Prepared = 3, NativeReplacementCommitted = 4, IdentityCaptured = 5 }

internal sealed record ResourceSlotStateV3
{
    public required int Index { get; init; }
    public required long Incarnation { get; init; }
    public required ResourceSlotRoleV2 Role { get; init; }
    public required ResourceSlotPhaseV2 Phase { get; init; }
    public required long ReservedMax { get; init; }
    public required long ExpectedLength { get; init; }
    public required StagedStageIdentity? Identity { get; init; }
    public required string? Locator { get; init; }
    public required long? EndOfFile { get; init; }
    public required long? AllocationSize { get; init; }
    public required ResourceReleaseStateV3? Release { get; init; }
    public required ResourceCustodyClaimV3? CustodyClaim { get; init; }
}

internal sealed record ResourceReleaseStateV3
{
    public required ResourceReleaseKindV3 Kind { get; init; }
    public required int Slot { get; init; }
    public required long Incarnation { get; init; }
    public required StagedStageIdentity? Identity { get; init; }
    public required Guid WitnessId { get; init; }
    public required Guid? CustodyTransferReceiptId { get; init; }
    public required long ClaimRevision { get; init; }
}


internal sealed record ResourcePendingCompanionV3
{
    public required Guid OperationId { get; init; }
    public required ResourceCompanionStateV2? Predecessor { get; init; }
    public required long TargetCapacity { get; init; }
    public required long TargetRevision { get; init; }
    public required long ReplacementIncarnation { get; init; }
    public required StagedStageIdentity? ReplacementIdentity { get; init; }
    public required ResourceCompanionPhaseV3 Phase { get; init; }
}

internal enum ResourceClaimKindV3 { CreateCopy = 1, FreezeMeasure = 2, Dispose = 3, Promote = 4 }
internal enum ResourceClaimPhaseV3 { Prepared = 1, MayHaveIssued = 2, NativeComplete = 3, Drained = 4 }
internal sealed record ResourceCustodyClaimV3(Guid ClaimId, Guid OwnerEpoch, uint Slot, long Incarnation,
    long ClaimRevision, ResourceClaimKindV3 Kind, ResourceClaimPhaseV3 State, StagedStageIdentity? Identity,
    Guid? RetirementWitnessId, Guid? DrainWitnessId);
internal enum ResourceInitialPhaseV3
{ Open = 1, Closing = 2, Fenced = 3, Attached = 4, CleanupComplete = 5, ResolutionAcknowledged = 6, InitialResolved = 7 }
internal sealed record ResourceInitialResolutionV3(string OriginalRequest, ulong OriginCookie, Guid BootDomain,
    string Sid, long IntentRevision, ResourceInitialPhaseV3 State, Guid? FenceId, uint? ControlReason,
    string? FenceReceipt, Guid? CleanupWitness, long? ResolutionRevision,
    string? KernelAckControlRequest, string? KernelAckControlReply);
internal enum ResourceReplayPhaseV3 { Claimed = 1, Charged = 2, CompanionCommitted = 3, Refused = 4 }
internal sealed record ResourceGrowthReplayV3(ulong HighWater, ResourceGrowthLatestV3? Latest);
internal sealed record ResourceGrowthLatestV3(ulong Sequence, string CanonicalRequest, ResourceReplayPhaseV3 State,
    SafeUpload.Agent.Minifilter.ResourceResultCodeV32? Result, long? CommittedCapacity, long? GrantRevision,
    long? AcceptedRevision);
internal enum ResourceHandoffPhaseV3
{ Prepared = 1, SharedCommitted = 2, ReservedNotIssued = 3, CreationMayHaveStarted = 4, CandidateCaptured = 5, FrameDurable = 6 }
internal sealed record ResourceHistoryHandoffV3(Guid TransactionId, Guid RecordId, uint RecordKind,
    Guid InstallationId, long ExpectedLedgerRevision, ResourceHandoffPhaseV3 Phase,
    StagedStageIdentity? CandidateIdentity, string CandidateLeaf, long CandidateBytes, string CandidateSha256,
    uint SegmentNumber, StagedStageIdentity? SegmentIdentity, uint Alignment, long ExpectedFrontier,
    ulong ExpectedFrontierSequence, long FrameOffset, long FrameStride, long TargetFrontier,
    ulong TargetFrontierSequence, long SharedPhysicalBefore, long ReservedPhysicalGrowth);
internal sealed record ResourceCustodyTransferV3(string ReceiptBase64, PublicCustodyCompletionV3 Completion);
internal sealed record PublicCustodyCompletionV3(int Version, string CompletionBase64,
    StagedPublicationNativeReceipt? PublicationNativeReceipt, ResourceCustodyClaimV3 Claim,
    PublicCustodyAuthorizationV3 Authorization);
internal sealed record PublicCustodyAuthorizationV3(Guid WitnessId, TransferJournalEntry Entry,
    PublicationApprovalV1? PublicationApproval);
#endif
