#ifndef _SAFEUPLOAD_STAGE_RESOURCE_METADATA_H_
#define _SAFEUPLOAD_STAGE_RESOURCE_METADATA_H_

/* Include Filter.h first. StageResourceWire.h remains the passive v32 ABI.
 *
 * Lock / lifetime order (this module adds no filesystem resource):
 *   Communication transition guard -> MetadataLock (DISPATCH spin lock).
 *   MetadataLock protects publication, admission and active request IDs.
 *   Acquire group rundown under MetadataLock; release the lock before token
 *   queries, allocation, lower I/O, port close, object dereference or a wait.
 *   No edge from MetadataLock to communication, policy, epoch, namespace,
 *   upper-stream or service work. Registration never waits for map space.
 *   The PASSIVE reaper alone waits for group rundown and releases native
 *   references. Callback-source removal precedes final module destruction.
 *   No object maps or completion contexts are admitted in this partial cut:
 *   the required installed-root authority has not been specified.
 *
 * These product controls remain provisional. Commit cannot grant anything.
 * No diagnostic control number or test authority is introduced here.
 */
#define SAFEUPLOAD_RESOURCE_PORT_NAME L"\\SafeUploadResourcePort"
#define SU_METADATA_TAG 'dmUS'
#define SU_METADATA_ROOTS 4UL
#define SU_METADATA_TRANSACTIONS 16UL
#define SU_METADATA_CHILDREN_PER_TRANSACTION 4UL
#define SU_METADATA_CHILDREN (SU_METADATA_TRANSACTIONS * SU_METADATA_CHILDREN_PER_TRANSACTION)
#define SU_METADATA_CONTROLS 8L
#define SU_METADATA_MAX_BUFFER (4UL * 1024UL * 1024UL)

#define SU_RESOURCE_NEGOTIATE 1UL
#define SU_RESOURCE_REVOKE 2UL
#define SU_RESOURCE_REGISTER_ROOT 3UL
#define SU_RESOURCE_REGISTER_CHILD 4UL
#define SU_RESOURCE_FENCE 5UL
#define SU_RESOURCE_ACK 6UL
#define SU_RESOURCE_SNAPSHOT 7UL

#pragma pack(push, 4)
typedef struct _SU_RESOURCE_CONTROL_HEADER {
    UINT32 Version, StructSize, Command, Reserved;
    UINT32 ResourceVersion, Opcode;
    UINT64 ControlRequestId, ConnectionCookie;
    GUID DriverInstance;
    UINT32 PayloadBytes, Flags;
} SU_RESOURCE_CONTROL_HEADER;

typedef struct _SU_RESOURCE_NEGOTIATE_REQUEST {
    GUID AgentInstance;
    UINT64 OfferedCapabilities, RequiredCapabilities, GrowthWaitTicks;
    UINT32 AllocationLimit, SidLimit, GrowthWorkers, GrowthQueue, LifecycleWorkers, LifecycleQueue;
    GUID ReadinessEpoch;
    UINT32 Phase;
    UCHAR Reserved[12];
} SU_RESOURCE_NEGOTIATE_REQUEST;

typedef struct _SU_RESOURCE_NEGOTIATE_REPLY {
    UINT32 Result, Mode;
    UINT64 AcceptedCapabilities;
    GUID AgentInstance, ReadinessEpoch, BootDomain;
    UINT64 GrowthWaitTicks;
    UINT32 AllocationLimit, SidLimit, GrowthWorkers, GrowthQueue, LifecycleWorkers, LifecycleQueue;
    UCHAR Reserved[16];
} SU_RESOURCE_NEGOTIATE_REPLY;

typedef struct _SU_RESOURCE_ROOT_REQUEST {
    UINT32 RootRole, Flags;
    UINT64 Handle;
    SAFEUPLOAD_STAGE_IDENTITY_V19 Identity;
    UINT64 ParentRootId;
    UINT32 SecurityContractVersion;
    UCHAR Reserved[12];
} SU_RESOURCE_ROOT_REQUEST;
typedef struct _SU_RESOURCE_ROOT_REPLY {
    UINT32 Result, Reserved;
    UINT64 RootId;
    SAFEUPLOAD_STAGE_IDENTITY_V19 Identity;
} SU_RESOURCE_ROOT_REPLY;

typedef struct _SU_RESOURCE_CHILD_REQUEST {
    UINT64 RootId;
    GUID TransactionId;
    UINT32 Role, AccessMask;
    UINT64 MaximumLogicalBytes;
    SAFEUPLOAD_STAGE_IDENTITY_V19 ExpectedIdentity, ReplaceTargetIdentity;
    UINT32 LeafBytes, CreateDisposition;
    WCHAR Leaf[256];
    UCHAR Reserved[32];
} SU_RESOURCE_CHILD_REQUEST;
typedef struct _SU_RESOURCE_CHILD_REPLY {
    UINT32 Result, Reserved;
    UINT64 ChildIntentId;
} SU_RESOURCE_CHILD_REPLY;
typedef struct _SU_RESOURCE_REVOKE_PAYLOAD {
    UINT32 ReasonOrResult, Reserved;
} SU_RESOURCE_REVOKE_PAYLOAD;
typedef struct _SU_RESOURCE_PAIR_CONTEXT {
    GUID DriverInstance;
    UINT64 ConnectionCookie;
} SU_RESOURCE_PAIR_CONTEXT;
#pragma pack(pop)

C_ASSERT(sizeof(SU_RESOURCE_CONTROL_HEADER) == 64);
C_ASSERT(FIELD_OFFSET(SU_RESOURCE_CONTROL_HEADER, DriverInstance) == 40);
C_ASSERT(sizeof(SU_RESOURCE_NEGOTIATE_REQUEST) == 96);
C_ASSERT(FIELD_OFFSET(SU_RESOURCE_NEGOTIATE_REQUEST, Phase) == 80);
C_ASSERT(sizeof(SU_RESOURCE_NEGOTIATE_REPLY) == 112);
C_ASSERT(sizeof(SU_RESOURCE_ROOT_REQUEST) == 64);
C_ASSERT(FIELD_OFFSET(SU_RESOURCE_ROOT_REQUEST, SecurityContractVersion) == 48);
C_ASSERT(sizeof(SU_RESOURCE_ROOT_REPLY) == 40);
C_ASSERT(sizeof(SU_RESOURCE_CHILD_REQUEST) == 640);
C_ASSERT(FIELD_OFFSET(SU_RESOURCE_CHILD_REQUEST, Leaf) == 96);
C_ASSERT(FIELD_OFFSET(SU_RESOURCE_CHILD_REQUEST, Reserved) == 608);
C_ASSERT(sizeof(SU_RESOURCE_CHILD_REPLY) == 16);
C_ASSERT(sizeof(SU_RESOURCE_REVOKE_PAYLOAD) == 8);
C_ASSERT(sizeof(SU_RESOURCE_PAIR_CONTEXT) == 24);

typedef enum _SU_METADATA_ROLE {
    SuLedgerCurrent = 1, SuLedgerNew, SuCompanionCurrent, SuCompanionNew,
    SuManifestCurrent, SuManifestNew, SuSegment, SuInventoryCurrent, SuInventoryNew,
    SuMarkerCurrent, SuMarkerNew, SuLegacyNegative, SuLegacySecurity,
    SuEpochCurrent, SuEpochNew, SuHistoryCandidate, SuAppendIntentCurrent,
    SuAppendIntentNew, SuCompactionIntentCurrent, SuCompactionIntentNew
} SU_METADATA_ROLE;
typedef enum _SU_METADATA_STATE {
    SuMetadataPendingOpen = 1, SuMetadataOpening, SuMetadataActive,
    SuMetadataRevoked, SuMetadataRemoved
} SU_METADATA_STATE;

/* No logical-EOF-based refund. Q belongs to this exact incarnation until an
 * explicit closed measurement/release; failure and lost return retain Q. */
typedef struct _SU_METADATA_OUTPUT_PLAN {
    UINT64 Incarnation, LogicalLength, PaddedWriteExtent, PeakAllocation;
    UINT32 IoAlignment, AllocationUnit;
} SU_METADATA_OUTPUT_PLAN;

_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadMetadataInitialize(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadMetadataDestroy(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadMetadataRevoke(_In_opt_ PVOID MainCookie);
_IRQL_requires_(PASSIVE_LEVEL)
BOOLEAN SafeUploadMetadataGroupDraining(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadMetadataPair(_In_ PFLT_PORT ClientPort,
    _In_reads_bytes_opt_(Bytes) PVOID Context, _In_ ULONG Bytes,
    _Outptr_result_maybenull_ PVOID *Cookie);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadMetadataDisconnect(_In_opt_ PVOID Cookie);
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS SafeUploadMetadataControl(_In_opt_ PVOID Cookie, _In_ BOOLEAN ResourceChannel,
    _In_reads_bytes_opt_(InputBytes) PVOID Input, _In_ ULONG InputBytes,
    _Out_writes_bytes_to_opt_(OutputBytes, *Returned) PVOID Output,
    _In_ ULONG OutputBytes, _Out_ PULONG Returned);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS SafeUploadMetadataPlanOutput(_In_ UINT64 Incarnation, _In_ UINT64 LogicalLength,
    _In_ UINT64 MaximumLogicalBytes, _In_ UINT32 IoAlignment, _In_ UINT32 AllocationUnit,
    _Out_ SU_METADATA_OUTPUT_PLAN *Plan);

#endif
