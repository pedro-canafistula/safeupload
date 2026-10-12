// Managed mirror of driver/SafeUpload.Minifilter/Protocol.h.
//
// Protocol.h is the source of truth. Every structure here exists to match
// it byte for byte, and Contract.Verify() checks that claim at startup
// rather than letting a mismatch surface as a corrupted path string.
//
// The layout rules that make this safe to mirror at all, restated from
// Protocol.h: fixed-size structures, explicit field widths, field order
// chosen so there is no implicit padding. Nothing here may use a type
// whose size depends on the runtime or on the process bitness.

using System;
using System.Runtime.InteropServices;

namespace SafeUpload.Agent.Minifilter;

public static class Contract
{
    public const string PortName = @"\SafeUploadPort";

    /// <summary>
    /// Must equal SAFEUPLOAD_PROTOCOL_VERSION in Protocol.h. The driver
    /// rejects any message carrying a different value, which is the
    /// mechanism that turns an incompatible pair into a clean refusal
    /// instead of a misread structure.
    /// </summary>
    public const uint Version = 18;

    public const int MaxPathChars = 512;
    public const int MaxImageNameChars = 64;

    public const int MaxExtensions = 32;
    public const int MaxExtensionChars = 16;
    public const int MaxPrefixes = 16;
    public const int MaxPrefixChars = 260;
    public const int MaxSourcePrefixes = 16;
    public const int MaxImages = 16;
    public const int MaxImageChars = 64;

    // Sizes asserted by C_ASSERT on the kernel side. Duplicated here on
    // purpose: if the two ever disagree, Verify() says so by name.
    public const int RequestSize = 1192;
    public const int ResponseSize = 152;
    public const int MaxStageNameChars = 64;
    public const int ControlSize = 16;
    public const int PolicyMessageSize = 19752;
    // SafeUploadControl.Reserved on SET_POLICY. Sent only after the boot
    // policy's committed registry value is durable and its pending union is removed.
    public const uint FinalizeDurableBootScopes = 1;
    // Stage-only v20 is an opt-in typed payload layered on the unchanged v18
    // request/response. It does not change the ordinary verdict ABI.
    public const uint StageExtensionVersion = 20;
    // A distinct reserved carrier, never interpreted as image-name text.
    // The bound payload and its parser compile only in feature builds.
    public const uint StageBoundAllocationVersion = 23;
    public const uint StageV19ReplyFlag = 0x00000200;
    public const uint StageV20ReplyFlag = StageV19ReplyFlag;
    public const int StageIdentityV19Size = 24;
    public const int StageCreateAfterDiscardV19Size = 104;
    public const int StageVersionV19Size = 64;
    public const int StageSealV19Size = 40;
    public const int StageAllocateV19Size = 64;
    public const int StageReconcileV19Size = 24;
    public const int StageReconcileV20Size = 32;
    public const int StageReconcileReplyV20Size = 48;
    public const int StageEpochDrainReplyV20Size = 48;
    public const int StageLifecycleV20Size = 112;
    public const int StageEpochDrainV20Size = 32;
    public const uint StageDiscardKindUnattachedAllocation = 5;
    public const int StageCreateReplyV19NameChars = 48;
    public const int CountersSize = 184;
    public const int OverrideMessageSize = 1056;
    public const int AdmissionCoverageMaxScopes = 98;
    public const int AdmissionCoverageScopeSize = 556;
    public const int AdmissionCoverageStatusSize = 54664;

    /// <summary>
    /// Throws if any managed structure fails to match the size the driver
    /// asserts for its C counterpart.
    ///
    /// Call this before connecting. A layout mismatch found here is a
    /// one-line error message; the same mismatch found at run time is a
    /// verdict answered for the wrong request, and nothing in the system
    /// would report it as an error.
    /// </summary>
    public static unsafe void Verify()
    {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
        BoundAllocationV23Contract.Verify();
#endif
        Check(nameof(SafeUploadRequest), sizeof(SafeUploadRequest), RequestSize);
        Check(nameof(SafeUploadResponse), sizeof(SafeUploadResponse), ResponseSize);
        Check(nameof(SafeUploadControl), sizeof(SafeUploadControl), ControlSize);
        Check(nameof(SafeUploadPolicyMessage), sizeof(SafeUploadPolicyMessage), PolicyMessageSize);
        Check(nameof(SafeUploadCounters), sizeof(SafeUploadCounters), CountersSize);
        Check(nameof(SafeUploadOverrideMessage), sizeof(SafeUploadOverrideMessage), OverrideMessageSize);
        Check(nameof(SafeUploadPublicationMessage), sizeof(SafeUploadPublicationMessage), 2128);
        Check(nameof(SafeUploadStageDisposeMessage), sizeof(SafeUploadStageDisposeMessage), 40);
        Check(nameof(SafeUploadStageDisposeReply), sizeof(SafeUploadStageDisposeReply), 8);
        Check(nameof(SafeUploadStageIdentityV19), sizeof(SafeUploadStageIdentityV19), StageIdentityV19Size);
        Check(nameof(SafeUploadStageCreateAfterDiscardV19), sizeof(SafeUploadStageCreateAfterDiscardV19),
              StageCreateAfterDiscardV19Size);
        Check(nameof(SafeUploadStageVersionV19), sizeof(SafeUploadStageVersionV19), StageVersionV19Size);
        Check(nameof(SafeUploadStageSealV19), sizeof(SafeUploadStageSealV19), StageSealV19Size);
        Check(nameof(SafeUploadStageAllocateV19), sizeof(SafeUploadStageAllocateV19), StageAllocateV19Size);
        Check(nameof(SafeUploadStageReconcileV19), sizeof(SafeUploadStageReconcileV19), StageReconcileV19Size);
        Check(nameof(SafeUploadStageReconcileV20), sizeof(SafeUploadStageReconcileV20), StageReconcileV20Size);
        Check(nameof(SafeUploadStageReconcileReplyV20), sizeof(SafeUploadStageReconcileReplyV20), StageReconcileReplyV20Size);
        Check(nameof(SafeUploadStageEpochDrainReplyV20), sizeof(SafeUploadStageEpochDrainReplyV20), StageEpochDrainReplyV20Size);
        Check(nameof(SafeUploadStageLifecycleV20), sizeof(SafeUploadStageLifecycleV20), StageLifecycleV20Size);
        Check(nameof(SafeUploadStageEpochDrainV20), sizeof(SafeUploadStageEpochDrainV20), StageEpochDrainV20Size);
        Check(nameof(SafeUploadStageCreateReplyV19), sizeof(SafeUploadStageCreateReplyV19), ResponseSize);
        Check(nameof(SafeUploadAdmissionCoverageScope), sizeof(SafeUploadAdmissionCoverageScope),
              AdmissionCoverageScopeSize);
        Check(nameof(SafeUploadAdmissionCoverageStatus), sizeof(SafeUploadAdmissionCoverageStatus),
              AdmissionCoverageStatusSize);
        CheckOffset(nameof(SafeUploadPublicationMessage) + ".TemporaryPath",
                    (int) Marshal.OffsetOf<SafeUploadPublicationMessage>(nameof(SafeUploadPublicationMessage.TemporaryPath)), 80);

        // Offsets that carry real risk: everything after them shifts if
        // they are wrong, and a shifted path is still a readable string.
        CheckOffset(nameof(SafeUploadRequest) + ".Path",
                    (int) Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.Path)), 40);
        CheckOffset(nameof(SafeUploadRequest) + ".ImageName",
                    (int) Marshal.OffsetOf<SafeUploadRequest>(nameof(SafeUploadRequest.ImageName)), 1064);
        CheckOffset(nameof(SafeUploadResponse) + ".StageName",
                    (int) Marshal.OffsetOf<SafeUploadResponse>(nameof(SafeUploadResponse.StageName)), 24);
        CheckOffset(nameof(SafeUploadStageIdentityV19) + ".FileIdLow",
                    (int) Marshal.OffsetOf<SafeUploadStageIdentityV19>(nameof(SafeUploadStageIdentityV19.FileIdLow)), 8);
        CheckOffset(nameof(SafeUploadStageIdentityV19) + ".FileIdHigh",
                    (int) Marshal.OffsetOf<SafeUploadStageIdentityV19>(nameof(SafeUploadStageIdentityV19.FileIdHigh)), 16);
        CheckOffset(nameof(SafeUploadStageCreateAfterDiscardV19) + ".DeleteTransferId",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateAfterDiscardV19>(nameof(SafeUploadStageCreateAfterDiscardV19.DeleteTransferId)), 24);
        CheckOffset(nameof(SafeUploadStageCreateAfterDiscardV19) + ".DeleteStageIdentity",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateAfterDiscardV19>(nameof(SafeUploadStageCreateAfterDiscardV19.DeleteStageIdentity)), 40);
        CheckOffset(nameof(SafeUploadStageCreateAfterDiscardV19) + ".ParentDirectoryIdentity",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateAfterDiscardV19>(nameof(SafeUploadStageCreateAfterDiscardV19.ParentDirectoryIdentity)), 64);
        CheckOffset(nameof(SafeUploadStageCreateAfterDiscardV19) + ".Disposition",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateAfterDiscardV19>(nameof(SafeUploadStageCreateAfterDiscardV19.Disposition)), 88);
        CheckOffset(nameof(SafeUploadStageCreateAfterDiscardV19) + ".DeleteGeneration",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateAfterDiscardV19>(nameof(SafeUploadStageCreateAfterDiscardV19.DeleteGeneration)), 96);
        CheckOffset(nameof(SafeUploadStageVersionV19) + ".StageIdentity",
                    (int) Marshal.OffsetOf<SafeUploadStageVersionV19>(nameof(SafeUploadStageVersionV19.StageIdentity)), 24);
        CheckOffset(nameof(SafeUploadStageVersionV19) + ".DestinationGeneration",
                    (int) Marshal.OffsetOf<SafeUploadStageVersionV19>(nameof(SafeUploadStageVersionV19.DestinationGeneration)), 48);
        CheckOffset(nameof(SafeUploadStageSealV19) + ".DestinationGeneration",
                    (int) Marshal.OffsetOf<SafeUploadStageSealV19>(nameof(SafeUploadStageSealV19.DestinationGeneration)), 32);
        CheckOffset(nameof(SafeUploadStageAllocateV19) + ".AllocationReservationId",
                    (int) Marshal.OffsetOf<SafeUploadStageAllocateV19>(nameof(SafeUploadStageAllocateV19.AllocationReservationId)), 8);
        CheckOffset(nameof(SafeUploadStageAllocateV19) + ".ParentTransferId",
                    (int) Marshal.OffsetOf<SafeUploadStageAllocateV19>(nameof(SafeUploadStageAllocateV19.ParentTransferId)), 24);
        CheckOffset(nameof(SafeUploadStageAllocateV19) + ".Disposition",
                    (int) Marshal.OffsetOf<SafeUploadStageAllocateV19>(nameof(SafeUploadStageAllocateV19.Disposition)), 40);
        CheckOffset(nameof(SafeUploadStageAllocateV19) + ".ReferenceKind",
                    (int) Marshal.OffsetOf<SafeUploadStageAllocateV19>(nameof(SafeUploadStageAllocateV19.ReferenceKind)), 44);
        CheckOffset(nameof(SafeUploadStageAllocateV19) + ".DriverInstanceId",
                    (int) Marshal.OffsetOf<SafeUploadStageAllocateV19>(nameof(SafeUploadStageAllocateV19.DriverInstanceId)), 48);
        CheckOffset(nameof(SafeUploadStageReconcileV19) + ".DriverInstanceId",
                    (int) Marshal.OffsetOf<SafeUploadStageReconcileV19>(nameof(SafeUploadStageReconcileV19.DriverInstanceId)), 8);
        CheckOffset(nameof(SafeUploadStageReconcileV20) + ".DriverInstanceId",
                    (int) Marshal.OffsetOf<SafeUploadStageReconcileV20>(nameof(SafeUploadStageReconcileV20.DriverInstanceId)), 8);
        CheckOffset(nameof(SafeUploadStageReconcileV20) + ".RequiredCapabilityMask",
                    (int) Marshal.OffsetOf<SafeUploadStageReconcileV20>(nameof(SafeUploadStageReconcileV20.RequiredCapabilityMask)), 24);
        CheckOffset(nameof(SafeUploadStageReconcileReplyV20) + ".AcceptedCapabilityMask",
                    (int) Marshal.OffsetOf<SafeUploadStageReconcileReplyV20>(nameof(SafeUploadStageReconcileReplyV20.AcceptedCapabilityMask)), 40);
        CheckOffset(nameof(SafeUploadStageReconcileReplyV20) + ".Operation",
                    (int) Marshal.OffsetOf<SafeUploadStageReconcileReplyV20>(nameof(SafeUploadStageReconcileReplyV20.Operation)), 8);
        CheckOffset(nameof(SafeUploadStageReconcileReplyV20) + ".RequestId",
                    (int) Marshal.OffsetOf<SafeUploadStageReconcileReplyV20>(nameof(SafeUploadStageReconcileReplyV20.RequestId)), 16);
        CheckOffset(nameof(SafeUploadStageEpochDrainReplyV20) + ".DrainNonce",
                    (int) Marshal.OffsetOf<SafeUploadStageEpochDrainReplyV20>(nameof(SafeUploadStageEpochDrainReplyV20.DrainNonce)), 40);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".Operation",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.Operation)), 8);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".RequestId",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.RequestId)), 16);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".Result",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.Result)), 12);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".TransferId",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.TransferId)), 24);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".DestinationGeneration",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.DestinationGeneration)), 40);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".StageIdentity",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.StageIdentity)), 48);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".DriverInstanceId",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.DriverInstanceId)), 72);
        CheckOffset(nameof(SafeUploadStageLifecycleV20) + ".ParentDirectoryIdentity",
                    (int) Marshal.OffsetOf<SafeUploadStageLifecycleV20>(nameof(SafeUploadStageLifecycleV20.ParentDirectoryIdentity)), 88);
        CheckOffset(nameof(SafeUploadStageEpochDrainV20) + ".DriverInstanceId",
                    (int) Marshal.OffsetOf<SafeUploadStageEpochDrainV20>(nameof(SafeUploadStageEpochDrainV20.DriverInstanceId)), 8);
        CheckOffset(nameof(SafeUploadStageEpochDrainV20) + ".DrainNonce",
                    (int) Marshal.OffsetOf<SafeUploadStageEpochDrainV20>(nameof(SafeUploadStageEpochDrainV20.DrainNonce)), 24);
        CheckOffset(nameof(SafeUploadStageCreateReplyV19) + ".StageName",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateReplyV19>(nameof(SafeUploadStageCreateReplyV19.StageName)), 24);
        CheckOffset(nameof(SafeUploadStageCreateReplyV19) + ".DestinationGeneration",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateReplyV19>(nameof(SafeUploadStageCreateReplyV19.DestinationGeneration)), 120);
        CheckOffset(nameof(SafeUploadStageCreateReplyV19) + ".StageIdentity",
                    (int) Marshal.OffsetOf<SafeUploadStageCreateReplyV19>(nameof(SafeUploadStageCreateReplyV19.StageIdentity)), 128);
        CheckOffset(nameof(SafeUploadPolicyMessage) + ".Prefixes",
                    (int) Marshal.OffsetOf<SafeUploadPolicyMessage>(nameof(SafeUploadPolicyMessage.Prefixes)), 1064);
        CheckOffset(nameof(SafeUploadPolicyMessage) + ".SourcePrefixes",
                    (int) Marshal.OffsetOf<SafeUploadPolicyMessage>(nameof(SafeUploadPolicyMessage.SourcePrefixes)), 9384);
        CheckOffset(nameof(SafeUploadPolicyMessage) + ".Images",
                    (int) Marshal.OffsetOf<SafeUploadPolicyMessage>(nameof(SafeUploadPolicyMessage.Images)), 17704);
        CheckOffset(nameof(SafeUploadCounters) + ".TaintHits",
                    (int) Marshal.OffsetOf<SafeUploadCounters>(nameof(SafeUploadCounters.TaintHits)), 96);
        CheckOffset(nameof(SafeUploadAdmissionCoverageStatus) + ".Scopes",
                    (int) Marshal.OffsetOf<SafeUploadAdmissionCoverageStatus>(nameof(SafeUploadAdmissionCoverageStatus.Scopes)), 176);
    }

    private static void Check(string name, int actual, int expected)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{name} tem {actual} bytes, o driver espera {expected}. " +
                "Protocol.cs saiu de sincronia com Protocol.h.");
        }
    }

    private static void CheckOffset(string name, int actual, int expected)
    {
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{name} esta no offset {actual}, o driver espera {expected}. " +
                "Protocol.cs saiu de sincronia com Protocol.h.");
        }
    }
}

public static class Operation
{
    public const uint Create = 1;
    public const uint StageAllocate = 3;
    public const uint StageSeal = 4;
    public const uint StageRename = 5;
    public const uint StageDiagnostic = 6;
    public const uint StageRenameCommit = 7;
    public const uint StageRenameAbort = 8;
    /// <summary>T5: the owner deleted its never-sealed private version (journaled Discarded, stage removed).</summary>
    public const uint StageDiscard = 9;
    /// <summary>Feature-only CREATE_ALWAYS after the private delete version was durably discarded.</summary>
    public const uint StageCreateAfterDiscard = 10;
    /// <summary>Feature-only notification of the current kernel driver epoch for durable orphan reconciliation.</summary>
    public const uint StageReconcile = 11;
    public const uint StageAttachPrepare = 12;
    public const uint StageAttachCommit = 13;
    public const uint StageAttachAbort = 14;
    public const uint StageCompletionPermit = 15;
    public const uint StageRetireUnexposed = 16;
    public const uint StageEpochDrain = 17;
    public const uint StageRetireAttachedPrivate = 18;
    public const uint StageHandleObserved = 19;

    /// <summary>
    /// Kept for contract completeness. The driver no longer registers
    /// IRP_MJ_READ, so this value does not appear in practice - see the
    /// comment on the registration table in Filter.c for why.
    /// </summary>
    public const uint Read = 2;
}

public static class Verdict
{
    public const uint Allow = 0;
    public const uint Deny = 1;
}

[Flags]
public enum RequestFlags : uint
{
    None = 0,
    PathTruncated = 0x00000001,
    ImageNameTruncated = 0x00000002,
    PathNotNormalized = 0x00000004,

    /// <summary>The create is heading into a monitored destination.</summary>
    ScopeDestination = 0x00000008,

    /// <summary>The create is reading from a monitored source.</summary>
    ScopeSource = 0x00000010,
    StageFollowup = 0x00000020,
    StageRemovable = 0x00000040,
    StageNetwork = 0x00000080,
    StageTombstoneCreate = 0x00000100,
    /// <summary>Stage allocation requests the v19 typed generation/identity response tail.</summary>
    StageV19Reply = Contract.StageV19ReplyFlag,
}

public static class StageV19Result
{
    public const uint ReservedSealedNonempty = 1;
    public const uint ReservedEmptyHeld = 2;
    // 1/2 are retired seal classifications; ordinary measured seals use 3.
    public const uint Sealed = 3;
    public const uint DiscardPending = 1;
    public const uint DiscardAcknowledged = 2;
}

public static class StageV19DiscardKind
{
    public const uint PrivateVersion = 1;
    public const uint EmptyHeldPredecessor = 2;
    public const uint OwnerExitEmpty = 3;
    public const uint DriverUnloadEmpty = 4;
    public const uint UnattachedAllocation = 5;
}

public static class StageV19AllocationReferenceKind
{
    public const uint None = 0;
    public const uint Followup = 1;
    public const uint Tombstone = 2;
}

/// <summary>Operation-specific v20 lifecycle results. Generic DENY is never a receipt.</summary>
public static class StageV20Result
{
    public const uint CapabilitiesAccepted = 5;
    public const uint AttachPrepared = 6;
    public const uint AttachCommitted = 7;
    public const uint AttachAborted = 8;
    public const uint AttachCommitDenied = 9;
    public const uint AttachAlreadyCommitted = 10;
    public const uint AttachRetiredUnexposed = 12;
    public const uint EpochBusy = 13;
    public const uint EpochDrained = 14;
    public const uint AttachRetiredPrivate = 15;
    public const uint CompletionPermitted = 16;
    public const uint HandleLifetimeObserved = 17;
}

[Flags]
public enum StageV20Capability : uint
{
    None = 0,
    StageV19Core = 0x01,
    AttachTransaction = 0x02,
    EpochDrain = 0x04,
    AttachedPrivateRetire = 0x08,
    HandleLifetimeReceipt = 0x10,
    OrdinaryEmptyContent = 0x20,
    Required = StageV19Core | AttachTransaction | EpochDrain |
              AttachedPrivateRetire | HandleLifetimeReceipt | OrdinaryEmptyContent,
}

[Flags]
public enum PolicyFlags : uint
{
    None = 0,
    Removable = 0x00000001,
    Network = 0x00000002,

    /// <summary>
    /// Avalia tudo, registra tudo, nao nega nada.
    ///
    /// Precisa chegar ao kernel, e nao ficar so no servico: a recusa por
    /// processo marcado acontece la sem perguntar a ninguem. A marcacao
    /// continua acontecendo - sem ela nao ha o que medir.
    /// </summary>
    AuditOnly = 0x00000004,

    /// <summary>
    /// Deixa o usuario justificar uma recusa e seguir.
    ///
    /// Dois modos, e so dois. Desligado, o mecanismo fica fora do ar: o
    /// driver recusa conceder excecao, entao nem uma interface comprometida
    /// libera nada. A escolha e da organizacao, nao do usuario.
    /// </summary>
    AllowOverride = 0x00000008,

    /// <summary>Classify supported file reads on every attached volume.</summary>
    ClassifyAllSources = 0x00000010,

    /// <summary>Feature-build qualification: bypass process-taint recording and lookup.</summary>
    TestDisableTaint = 0x00000020,
}

public static class ControlCommand
{
    public const uint SetPolicy = 1;
    public const uint GetCounters = 2;
    public const uint GrantOverride = 3;
    public const uint StagePublication = 4;
    public const uint AdmissionCoverage = 24;
    public const uint StageDispose = 29;
}

/// <summary>Outcome of SAFEUPLOAD_CONTROL_STAGE_DISPOSE: why the service no longer needs a staged version.</summary>
public static class StageDisposeOutcome
{
    /// <summary>Approved and published; the driver deletes the stage file once nothing holds the version.</summary>
    public const uint Released = 1;
    /// <summary>Blocked or justified; the service already deleted the stage file.</summary>
    public const uint CleanedUp = 2;
}


public static class AdmissionCoverageContract
{
    public const uint Pending = 0;
    public const uint Ready = 1;
    public const uint Degraded = 2;
    public const uint PrefixScope = 1;
    public const uint RemovableScope = 2;
    public const uint NetworkScope = 3;
    public const uint UnknownResolution = 0;
    public const uint AbsentResolution = 1;
    public const uint UniqueResolution = 2;
    public const uint AmbiguousResolution = 3;
    public const uint NotApplicableResolution = 4;
    public const uint CompleteFlag = 0x00000001;
    public const uint StableFlag = 0x00000002;
    public const uint FutureGateFlag = 0x00000004;
    public const uint PolicyPendingFlag = 0x00000008;
    public const uint RegistryCompleteFlag = 0x00000010;
    public const uint PolicyScopeOverflowFlag = 0x00000020;
    public const uint TestTaintControlFlag = 0x00000040;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadAdmissionCoverageScope
{
    public uint ScopeKind;
    public uint ScopeIndex;
    public uint Resolution;
    public uint State;
    public uint Reason;
    public uint MatchingInstances;
    public uint UniqueVolumes;
    public uint ReadyInstances;
    public uint PrefixChars;
    public fixed char Prefix[Contract.MaxPrefixChars];

    public string ReadPrefix()
    {
        uint chars = Math.Min(PrefixChars, (uint) Contract.MaxPrefixChars);
        fixed (char* value = Prefix) return new string(value, 0, (int) chars);
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadAdmissionCoverageStatus
{
    public uint StructSize;
    public uint ProtocolVersion;
    public uint State;
    public uint Flags;
    public uint PolicyGeneration;
    public uint PolicyFlags;
    public uint BootPolicyState;
    public uint ScopeCount;
    public uint ExpectedScopeCount;
    public uint PolicyGenerationEnd;
    public uint PolicyFlagsEnd;
    public uint BootPolicyStateEnd;
    public uint EpochGeneration;
    public uint EpochFlags;
    public uint EpochActiveCallbacks;
    public uint EpochGenerationEnd;
    public uint EpochFlagsEnd;
    public uint EpochActiveCallbacksEnd;
    public uint EnumeratedInstances;
    public uint SetupInFlight;
    public uint TeardownInFlight;
    public uint CoverageChangesInFlight;
    public uint WriterGlobalUnknown;
    public uint WriterEntries;
    public uint WriterEntriesNotReady;
    public uint WriterEntriesUnknown;
    public uint FutureMountGateReady;
    public uint Reason;
    public ulong PolicyScopeSequenceStart;
    public ulong PolicyScopeSequenceEnd;
    public ulong TopologySequenceStart;
    public ulong TopologySequenceEnd;
    public ulong CoverageSequenceStart;
    public ulong CoverageSequenceEnd;
    public ulong RegistrySequenceStart;
    public ulong RegistrySequenceEnd;
    public fixed byte Scopes[Contract.AdmissionCoverageMaxScopes * Contract.AdmissionCoverageScopeSize];

    public SafeUploadAdmissionCoverageScope GetScope(int index)
    {
        if ((uint) index >= ScopeCount || index >= Contract.AdmissionCoverageMaxScopes)
            throw new ArgumentOutOfRangeException(nameof(index));
        fixed (byte* data = Scopes)
            return ((SafeUploadAdmissionCoverageScope*) data)[index];
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe partial struct SafeUploadRequest
{
    public uint Version;
    public uint StructSize;
    public ulong RequestId;
    public uint Operation;
    public uint RequestorProcessId;
    public uint Flags;
    public uint PathLength;      // bytes, excluding the terminator
    public uint ImageNameLength; // bytes, excluding the terminator
    public uint Reserved;
    public fixed char Path[Contract.MaxPathChars];
    public fixed char ImageName[Contract.MaxImageNameChars];

    public RequestFlags TypedFlags => (RequestFlags) Flags;

    public bool HasKnownFlags
    {
        get
        {
            const uint legacyKnown = 0x000001ff;
            if (Reserved == Contract.StageBoundAllocationVersion)
            {
#if SAFEUPLOAD_ADMISSION_EVIDENCE
                const uint boundKnown = 0x000000c0 | Contract.StageV19ReplyFlag;
                return Operation == global::SafeUpload.Agent.Minifilter.Operation.StageAllocate &&
                    (Flags & ~boundKnown) == 0 && (Flags & 0x000000c0) != 0x000000c0 &&
                    (Flags & Contract.StageV19ReplyFlag) != 0;
#else
                return false;
#endif
            }
            if (Reserved == Contract.StageExtensionVersion &&
                !IsStageV20TypedOperation(Operation) &&
                Operation != global::SafeUpload.Agent.Minifilter.Operation.StageAllocate &&
                Operation != global::SafeUpload.Agent.Minifilter.Operation.StageDiagnostic)
                return false;
            if ((IsStageV20TypedOperation(Operation) ||
                 (Operation == global::SafeUpload.Agent.Minifilter.Operation.StageAllocate &&
                  ((Flags & Contract.StageV19ReplyFlag) != 0 || Reserved == Contract.StageExtensionVersion))) &&
                Reserved != Contract.StageExtensionVersion)
                return false;
            if ((Flags & ~legacyKnown) == 0) return true;

            const uint stageKnown = legacyKnown | Contract.StageV19ReplyFlag;
            return Operation == global::SafeUpload.Agent.Minifilter.Operation.StageAllocate &&
                (Flags & ~stageKnown) == 0;
        }
    }

    public string GetPath()
    {
        fixed (char* p = Path) { return Read(p, PathLength, Contract.MaxPathChars); }
    }

    public string GetImageName()
    {
        if (UsesStageBinaryPayload)
        {
            throw new InvalidOperationException(
                "ImageName contains a typed stage payload; do not interpret it as text.");
        }

        fixed (char* p = ImageName) { return Read(p, ImageNameLength, Contract.MaxImageNameChars); }
    }

    /// <summary>
    /// Reads the typed stage extension only when the outer v18 envelope,
    /// operation marker, exact byte length, and inner v20 header all match.
    /// ImageName is an opaque payload on this path and must never pass through
    /// GetImageName().
    /// </summary>
    public bool TryReadStagePayload<T>(uint expectedOperation, out T payload) where T : unmanaged
    {
        payload = default;
        if (Version != Contract.Version || StructSize != Contract.RequestSize ||
            Operation != expectedOperation || Reserved != Contract.StageExtensionVersion ||
            !HasKnownFlags || !HasValidStageV19Flags(expectedOperation) ||
            ImageNameLength != sizeof(T) || ImageNameLength > Contract.MaxImageNameChars * sizeof(char) ||
            (Flags & (uint)(RequestFlags.PathTruncated | RequestFlags.PathNotNormalized |
                            RequestFlags.ImageNameTruncated)) != 0 ||
            (Operation is not (global::SafeUpload.Agent.Minifilter.Operation.StageReconcile or
                global::SafeUpload.Agent.Minifilter.Operation.StageEpochDrain) && PathLength == 0) ||
            PathLength > (Contract.MaxPathChars - 1) * sizeof(char) ||
            (PathLength % sizeof(char)) != 0)
        {
            return false;
        }

        fixed (char* source = ImageName)
        {
            var bytes = new ReadOnlySpan<byte>((byte*)source, checked((int)ImageNameLength));
            if (bytes.Length < sizeof(SafeUploadStageExtensionHeaderV20)) return false;
            SafeUploadStageExtensionHeaderV20 header = MemoryMarshal.Read<SafeUploadStageExtensionHeaderV20>(bytes);
            if (header.Version != Contract.StageExtensionVersion || header.StructSize != sizeof(T)) return false;
            var imageSlot = new ReadOnlySpan<byte>((byte*)source,
                Contract.MaxImageNameChars * sizeof(char));
            if (!IsZero(imageSlot[bytes.Length..])) return false;
            payload = MemoryMarshal.Read<T>(bytes);
        }

        fixed (char* path = Path)
        {
            var pathSlot = new ReadOnlySpan<byte>((byte*)path, Contract.MaxPathChars * sizeof(char));
            if (!IsZero(pathSlot[checked((int)PathLength)..])) return false;
        }

        return true;
    }

    private static bool IsZero(ReadOnlySpan<byte> bytes)
    {
        foreach (byte value in bytes)
        {
            if (value != 0) return false;
        }
        return true;
    }

    public bool UsesStageBinaryPayload => Reserved == Contract.StageBoundAllocationVersion ||
        Reserved == Contract.StageExtensionVersion ||
        IsStageV20TypedOperation(Operation) ||
        (Operation == global::SafeUpload.Agent.Minifilter.Operation.StageAllocate &&
            (Reserved == Contract.StageExtensionVersion ||
             (Flags & Contract.StageV19ReplyFlag) != 0));

    // Source-compatible alias for call sites that only need to keep the
    // ImageName slot opaque; the accepted marker is now v20.
    public bool UsesStageV19BinaryPayload => UsesStageBinaryPayload;

    private static bool IsStageV20TypedOperation(uint operation) => operation is
        global::SafeUpload.Agent.Minifilter.Operation.StageSeal or
        global::SafeUpload.Agent.Minifilter.Operation.StageDiscard or
        global::SafeUpload.Agent.Minifilter.Operation.StageCreateAfterDiscard or
        global::SafeUpload.Agent.Minifilter.Operation.StageReconcile or
        global::SafeUpload.Agent.Minifilter.Operation.StageAttachPrepare or
        global::SafeUpload.Agent.Minifilter.Operation.StageAttachCommit or
        global::SafeUpload.Agent.Minifilter.Operation.StageAttachAbort or
        global::SafeUpload.Agent.Minifilter.Operation.StageCompletionPermit or
        global::SafeUpload.Agent.Minifilter.Operation.StageRetireUnexposed or
        global::SafeUpload.Agent.Minifilter.Operation.StageEpochDrain or
        global::SafeUpload.Agent.Minifilter.Operation.StageRetireAttachedPrivate or
        global::SafeUpload.Agent.Minifilter.Operation.StageHandleObserved;

    private bool HasValidStageV19Flags(uint operation)
    {
        const uint stageVolumeFlags = 0x000000c0;
        uint allowed = operation switch
        {
            global::SafeUpload.Agent.Minifilter.Operation.StageAllocate =>
                stageVolumeFlags | Contract.StageV19ReplyFlag,
            global::SafeUpload.Agent.Minifilter.Operation.StageCreateAfterDiscard => stageVolumeFlags,
            global::SafeUpload.Agent.Minifilter.Operation.StageAttachPrepare or
            global::SafeUpload.Agent.Minifilter.Operation.StageAttachCommit or
            global::SafeUpload.Agent.Minifilter.Operation.StageAttachAbort or
            global::SafeUpload.Agent.Minifilter.Operation.StageCompletionPermit or
            global::SafeUpload.Agent.Minifilter.Operation.StageRetireUnexposed or
            global::SafeUpload.Agent.Minifilter.Operation.StageRetireAttachedPrivate or
            global::SafeUpload.Agent.Minifilter.Operation.StageHandleObserved => stageVolumeFlags,
            global::SafeUpload.Agent.Minifilter.Operation.StageEpochDrain => 0,
            global::SafeUpload.Agent.Minifilter.Operation.StageSeal or
                global::SafeUpload.Agent.Minifilter.Operation.StageDiscard or
                global::SafeUpload.Agent.Minifilter.Operation.StageReconcile => 0,
            _ => uint.MaxValue,
        };
        if ((Flags & ~allowed) != 0 || (Flags & stageVolumeFlags) == stageVolumeFlags)
            return false;
        return operation != global::SafeUpload.Agent.Minifilter.Operation.StageAllocate ||
            (Flags & Contract.StageV19ReplyFlag) != 0;
    }

    // The length field is in bytes and comes from the kernel. It is
    // trusted only after being clamped: a client that indexes straight
    // into a fixed buffer with a value it did not verify is one bad
    // message away from reading past the structure.
    private static string Read(char* buffer, uint lengthInBytes, int capacityInChars)
    {
        int chars = (int) (lengthInBytes / sizeof(char));

        if (chars < 0 || chars > capacityInChars)
        {
            chars = capacityInChars;
        }

        return new string(buffer, 0, chars);
    }
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadResponse
{
    public uint Version;
    public uint StructSize;
    public ulong RequestId;
    public uint Verdict;
    public uint StageNameLength;
    public fixed char StageName[Contract.MaxStageNameChars];
}

/// <summary>Common header for every typed stage payload in the negotiated v20 profile.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageExtensionHeaderV20
{
    public uint Version;
    public uint StructSize;
}

/// <summary>Compatibility layout name; v19 payloads are rejected by the v20 parser.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageExtensionHeaderV19
{
    public uint Version;
    public uint StructSize;
}

/// <summary>Matches volume serial followed by the 16 FILE_ID_128 bytes (low then high).</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageIdentityV19
{
    public ulong VolumeSerialNumber;
    public ulong FileIdLow;
    public ulong FileIdHigh;

    public readonly bool HasNonzeroFileId => (FileIdLow | FileIdHigh) != 0;
}

/// <summary>CREATE_AFTER_DISCARD request payload, exactly 104 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageCreateAfterDiscardV19
{
    public uint Version;
    public uint StructSize;
    public Guid ReservationId;
    public Guid DeleteTransferId;
    public SafeUploadStageIdentityV19 DeleteStageIdentity;
    public SafeUploadStageIdentityV19 ParentDirectoryIdentity;
    public uint Disposition;
    public ulong DeleteGeneration;
}

/// <summary>Exact discard/retirement request payload, exactly 64 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageVersionV19
{
    public uint Version;
    public uint StructSize;
    public Guid ReservationId;
    public SafeUploadStageIdentityV19 StageIdentity;
    public ulong DestinationGeneration;
    public uint Kind;
}

/// <summary>Seal request payload, exactly 40 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageSealV19
{
    public uint Version;
    public uint StructSize;
    public SafeUploadStageIdentityV19 StageIdentity;
    public ulong DestinationGeneration;
}

/// <summary>Replayable v19 allocation intent, exactly 64 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageAllocateV19
{
    public uint Version;
    public uint StructSize;
    public Guid AllocationReservationId;
    public Guid ParentTransferId;
    public uint Disposition;
    public uint ReferenceKind;
    public Guid DriverInstanceId;
}

/// <summary>Driver instance epoch used to reconcile old Allocated intents after a real driver reload.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageReconcileV19
{
    public uint Version;
    public uint StructSize;
    public Guid DriverInstanceId;
}

/// <summary>Exact v20 capability negotiation request, 32 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageReconcileV20
{
    public uint Version;
    public uint StructSize;
    public Guid DriverInstanceId;
    public uint RequiredCapabilityMask;
    public uint ReservedZero;
}

/// <summary>Result-bearing v20 capability negotiation response payload, 48 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageReconcileReplyV20
{
    public uint Version;
    public uint StructSize;
    public uint Operation;
    public uint Result;
    public ulong RequestId;
    public Guid DriverInstanceId;
    public uint AcceptedCapabilityMask;
    public uint ReservedZero;
}

/// <summary>Exact v20 authenticated epoch-drain request, 32 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageEpochDrainV20
{
    public uint Version;
    public uint StructSize;
    public Guid DriverInstanceId;
    public ulong DrainNonce;
}

/// <summary>Result-bearing v20 epoch-drain response payload, 48 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageEpochDrainReplyV20
{
    public uint Version;
    public uint StructSize;
    public uint Operation;
    public uint Result;
    public ulong RequestId;
    public Guid DriverInstanceId;
    public ulong DrainNonce;
}

/// <summary>Exact v20 attachment/lifetime request and response tuple, 112 bytes.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageLifecycleV20
{
    public uint Version;
    public uint StructSize;
    public uint Operation;
    public uint Result;
    public ulong RequestId;
    public Guid TransferId;
    public ulong DestinationGeneration;
    public SafeUploadStageIdentityV19 StageIdentity;
    public Guid DriverInstanceId;
    public SafeUploadStageIdentityV19 ParentDirectoryIdentity;
}

/// <summary>Typed create reply overlay; byte-for-byte equal to SafeUploadResponse.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadStageCreateReplyV19
{
    public uint Version;
    public uint StructSize;
    public ulong RequestId;
    public uint Verdict;
    public uint StageNameLength;
    public fixed char StageName[Contract.StageCreateReplyV19NameChars];
    public ulong DestinationGeneration;
    public SafeUploadStageIdentityV19 StageIdentity;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadControl
{
    public uint Version;
    public uint StructSize;
    public uint Command;
    public uint Reserved;
}


[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadPolicyMessage
{
    public SafeUploadControl Control;

    public uint ExtensionCount;
    public uint PrefixCount;
    public uint ImageCount;
    public uint SourcePrefixCount;
    public uint Flags;

    /// <summary>
    /// Quanto o kernel espera por um veredito, em milissegundos.
    ///
    /// Vem da politica e nao de uma constante no driver porque o prazo e da
    /// inspecao, nao do transporte: a RN-012 da um orcamento ao motor, e ter
    /// o mesmo numero escrito em dois lugares e como os dois divergem. Zero
    /// significa "use o padrao do driver". O driver limita o valor.
    /// </summary>
    public uint VerdictTimeoutMs;

    public fixed char Extensions[Contract.MaxExtensions * Contract.MaxExtensionChars];
    public fixed char Prefixes[Contract.MaxPrefixes * Contract.MaxPrefixChars];
    public fixed char SourcePrefixes[Contract.MaxSourcePrefixes * Contract.MaxPrefixChars];
    public fixed char Images[Contract.MaxImages * Contract.MaxImageChars];
}

/// <summary>
/// Concessao de excecao, do servico para o driver.
///
/// O caminho e exato, e nao prefixo: uma excecao para uma pasta valeria para
/// tudo que fosse escrito nela depois. O prazo e limitado pelo driver, porque
/// uma excecao e um buraco na protecao e um que dure uma hora e um buraco com
/// nome.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadOverrideMessage
{
    public SafeUploadControl Control;
    public uint ProcessId;
    public uint DurationSeconds;
    public uint PathLength;
    public uint Reserved;
    public fixed char Path[Contract.MaxPathChars];
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct SafeUploadPublicationMessage
{
    public SafeUploadControl Control;
    public Guid TransferId;
    public uint Revoke;
    public uint TemporaryPathLength;
    public uint DestinationPathLength;
    public uint Reserved;
    public fixed byte Digest[32];
    public fixed char TemporaryPath[Contract.MaxPathChars];
    public fixed char DestinationPath[Contract.MaxPathChars];
}

/// <summary>SAFEUPLOAD_STAGE_DISPOSE_MESSAGE (40 bytes).</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageDisposeMessage
{
    public SafeUploadControl Control;
    public Guid TransferId;
    public uint Outcome;
    /// <summary>Committed renames of the transfer in the journal state the disposal describes (NamespaceTombstones).</summary>
    public uint CommittedRenames;
}

/// <summary>SAFEUPLOAD_STAGE_DISPOSE_REPLY (8 bytes). Held = 1: the driver still holds the version.</summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadStageDisposeReply
{
    public uint StructSize;
    public uint Held;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SafeUploadCounters
{
    public uint Version;
    public uint StructSize;

    public ulong CreatesSeen;
    public ulong CreatesPastCheapGates;
    public ulong ScopeEvaluations;
    public ulong UserModeRoundTrips;
    public ulong CacheHits;
    public ulong DeniedPreCreate;
    public ulong DeniedPostCreate;
    public ulong DeniedRename;
    public ulong AllowedWithoutInspection;
    public ulong TaintsRecorded;
    public ulong TaintLookups;
    public ulong TaintHits;
    public ulong SetInformationSeen;
    public ulong RenamesSeen;
    public ulong RenamesFromTainted;
    public ulong LinksSeen;
    public ulong LinksFromTainted;
    public ulong WouldHaveDenied;
    public ulong OverridesGranted;
    public ulong OverridesUsed;
    public ulong ClassesSeenLow;
    public ulong ClassesSeenHigh;
}
