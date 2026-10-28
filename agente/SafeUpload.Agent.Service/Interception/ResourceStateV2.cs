#if SAFEUPLOAD_ADMISSION_EVIDENCE
using System.Collections.Immutable;

namespace SafeUpload.Agent.Service.Interception;

// Passive durable representation. These values are not native release proofs
// and are not adopted by StagedSpaceBudget or any admission/publication path.
internal sealed record ResourceStateV2
{
    public required int Version { get; init; }
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
    public required ImmutableArray<ResourceSlotStateV2?> Slots { get; init; }
    public required ResourceRetirementStateV2? AcceptedRetirement { get; init; }
    public required ResourceReleaseStateV2? StageRelease { get; init; }
    public required ResourceCompanionStateV2? Companion { get; init; }
    public required ResourcePendingCompanionV2? PendingCompanion { get; init; }
    public required bool FullDebitHeld { get; init; }
    public required long ChargeBytes { get; init; }
}

internal enum ResourceStatePhaseV2 { Preparing = 1, Writable = 2, Closing = 3, ClosedUnissued = 4, WriteRetired = 5, MetadataOnly = 6 }
internal enum ResourceClosureV2 { None = 0, UnissuedClosed = 1, DriverWriteRetired = 2 }
internal enum ResourceSlotRoleV2 { Stage = 1, Snapshot = 2, PublicationTemporary = 3, Handback = 4 }
internal enum ResourceSlotPhaseV2 { ReservedNotIssued = 1, CreationMayHaveStarted = 2, Mutable = 3, Immutable = 4, ReleasePending = 5, ImmutableReleasePending = 6, Released = 7 }
internal enum ResourceReleaseKindV2 { NeverIssued = 1, DefinitiveNonCreation = 2, FinalStorageRelease = 3, ExactAbsenceAfterDrain = 4 }
internal enum ResourceCompanionPhaseV2 { ReservedNotIssued = 1, CreationMayHaveStarted = 2, Prepared = 3, NativeReplacementCommitted = 4 }

internal sealed record ResourceBindingStateV2
{
    public required StagedStageIdentity Identity { get; init; }
    public required long AllocationGeneration { get; init; }
    public required long InitialDestinationGeneration { get; init; }
    public required int StageSlot { get; init; }
    public required long StageIncarnation { get; init; }
}

internal sealed record ResourceSlotStateV2
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
    public required ResourceReleaseStateV2? Release { get; init; }
}

internal sealed record ResourceReleaseStateV2
{
    public required ResourceReleaseKindV2 Kind { get; init; }
    public required int Slot { get; init; }
    public required long Incarnation { get; init; }
    public required StagedStageIdentity? Identity { get; init; }
    public required Guid WitnessId { get; init; }
    public required long ClaimRevision { get; init; }
}

internal sealed record ResourceRetirementStateV2
{
    public required Guid DriverInstanceId { get; init; }
    public required Guid TransferId { get; init; }
    public required long AllocationGeneration { get; init; }
    public required long DestinationGeneration { get; init; }
    public required StagedStageIdentity Identity { get; init; }
    public required ulong ConnectionCookie { get; init; }
    public required ulong Sequence { get; init; }
    public required long AuthorizedCapacity { get; init; }
    public required long EndOfFile { get; init; }
    public required long AllocationSize { get; init; }
    public required long AcceptedRevision { get; init; }
}

internal sealed record ResourceCompanionStateV2
{
    public required StagedStageIdentity Identity { get; init; }
    public required long Capacity { get; init; }
    public required long GrantRevision { get; init; }
}

internal sealed record ResourcePendingCompanionV2
{
    public required Guid OperationId { get; init; }
    public required ResourceCompanionStateV2? Predecessor { get; init; }
    public required long TargetCapacity { get; init; }
    public required long TargetRevision { get; init; }
    public required long ReplacementIncarnation { get; init; }
    public required StagedStageIdentity? ReplacementIdentity { get; init; }
    public required ResourceCompanionPhaseV2 Phase { get; init; }
}
#endif
