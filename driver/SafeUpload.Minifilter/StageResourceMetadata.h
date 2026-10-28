#ifndef _SAFEUPLOAD_STAGE_RESOURCE_METADATA_H_
#define _SAFEUPLOAD_STAGE_RESOURCE_METADATA_H_

/* Include Filter.h first. StageResourceWire.h remains the passive v32 ABI.
 *
 * Lock / lifetime order (this module adds no filesystem resource):
 *   Communication transition guard -> MetadataLock (DISPATCH spin lock).
 *   MetadataLock protects publication, admission, root keys, transactions,
 *   child credits, embedded completion owners and bounded refusal telemetry.
 *   Each child owns one ordinary I/O context plus one cleanup context; each
 *   root has the same two embedded owners. Admission is Busy, never a wait.
 *   Acquire group rundown under MetadataLock; release the lock before token
 *   queries, allocation, lower I/O, port close, object dereference or a wait.
 *   No edge from MetadataLock to communication, policy, epoch, namespace,
 *   upper-stream or service work. Registration never waits for map space.
 *   A lookup may take a nonblocking FILE_OBJECT reference under MetadataLock
 *   to exclude CLOSE/address reuse. No dereference or handle work under it.
 *   The PASSIVE worker alone waits for group rundown and retires descriptors;
 *   ordinary PASSIVE post releases its own references. Higher-IRQL/draining
 *   post publishes Deferred as its LAST context access and transfers that
 *   owner to the worker. It never queues a pointer to callback/user buffers.
 *   Callback-source removal precedes final module destruction.
 *   Each PendingOpen RESERVES one of its transaction's four child credits;
 *   at most one is unclaimed. Opening/Active/retiring and post owners retain
 *   that same credit. No pool borrowing and no fifth lower CREATE owner.
 *   Root capture uses a nonwaiting busy latch, not a lock across native I/O.
 *   Group rundown pins every control and forwarded metadata completion.
 *   Root keys remain nonowning until pre-CLOSE removes them, even on revoke;
 *   the PASSIVE owner releases original references/anchors outside the lock.
 *   Instance teardown/final destruction explicitly forget keys (no future
 *   CLOSE is promised), then drain completions before releasing group storage.
 *   Forgotten children are Revoked/uncertain, never Active. Losing filter
 *   coverage cannot certify storage release; agent durable charge survives.
 *   CLOSE removes the key, but record reuse waits for I/O, cleanup, PASSIVE
 *   retirement and replacement pins. New -> Current is the only pin edge;
 *   cancellation/retirement releases that edge once. No cycles or borrowing.
 *   Rename and F3 take a transient zero-access kernel handle on the exact current
 *   FILE_OBJECT (plus a reference) after pinning it. It adds no access grant.
 *   The original predecessor shares READ|WRITE|DELETE. Both holds outlive the
 *   native step and predecessor observation; no release-first retry. Loss of
 *   the original predecessor before F3 holds/revokes instead of certifying F3.
 *
 * Security predicates (8.7 review condition 1):
 *   Four private roots: SY/BA owner, protected
 *   non-null DACL; simple allow/deny ACEs only; no effective OR inheritable
 *   mutation allow to anyone except SY/BA (not TI or the service SID).
 *   Windows ancestors (volume root/ProgramData): SY/BA/TrustedInstaller owner;
 *   only those principals may receive effective DELETE/DELETE_CHILD,
 *   WRITE_DAC/WRITE_OWNER, write-EA/write-attributes. Creating OTHER names is
 *   allowed. Inheritable directory ACEs are checked against the next captured
 *   directory: a protected child blocks inheritance; otherwise destructive
 *   inherited grants refuse. CREATOR_OWNER inheritance is evaluated as the
 *   already validated trusted child owner. Object/callback/unknown ACE forms,
 *   unknown flags and unknown generic/mask bits refuse, including deny ACEs.
 *   TI is explicitly allowed ONLY on Windows ancestors, never private roots.
 *   SafeUpload installation parent uses the ancestor rights predicate but
 *   restricts owner/security authority to SY/BA; protection is not required
 *   there. Both protected staging/journal children are checked separately.
 *   This conservative predicate does not repair ACLs or model deny cancellation.
 *
 * Native child CREATE is synchronized and becomes Active only after exact
 * identity, unnamed/single-link/non-reparse and protected-security validation.
 * File data I/O is PASSIVE, synchronous, noncached, aligned and zero-minor;
 * fast/paging/MDL-backed/cache paths are refused, never silently substituted.
 * Normal post at PASSIVE measures each native step. Higher-IRQL post holds
 * unknown, revokes, and defers only resource release; it cannot assert success.
 * MaximumLogicalBytes denotes the agent's precharged extent claim: P=align(L,A)
 * and Q=align(P,U), with independently cached native A/U. Writes require a
 * successful measured class-19 preallocation covering their complete extent.
 * New outputs require F1/EOF/F2 before replacement; renamed sources freeze
 * except their required F3 flush/read/query/exact disposal. Segment allocation
 * and EOF never shrink. Candidate output freezes at raw F2; that is NOT a
 * schema-3 immutable-commit receipt. Reopened candidates are read/delete only.
 * LegacyNegative delete stays unsupported without its serialized proof.
 * Live/retired retained counters are diagnostic, additive and never refund on
 * EOF/normalization/CLOSE. Overrun raises retained before hold. Unknown stays
 * unknown; saturation holds. No kernel storage-admission policy or grant is
 * inferred: the agent owns the authoritative durable debit and release proof.
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

typedef struct _SU_METADATA_DISPATCH {
    BOOLEAN Handled;
    UINT64 Cookie, RootId, ChildId;
    UINT32 Role;
} SU_METADATA_DISPATCH;

_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadMetadataInitialize(VOID);
_IRQL_requires_(PASSIVE_LEVEL)
VOID SafeUploadMetadataDestroy(VOID);
_IRQL_requires_max_(DISPATCH_LEVEL)
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
VOID SafeUploadMetadataInstanceTeardown(_In_ PFLT_INSTANCE Instance);
_IRQL_requires_max_(APC_LEVEL)
FLT_PREOP_CALLBACK_STATUS SafeUploadMetadataPre(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _Outptr_result_maybenull_ PVOID *Context,
    _Out_ SU_METADATA_DISPATCH *Dispatch);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadMetadataIsContext(_In_opt_ PVOID Context);
_IRQL_requires_max_(DISPATCH_LEVEL)
FLT_POSTOP_CALLBACK_STATUS SafeUploadMetadataPost(_Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS Objects, _In_ PVOID Context, _In_ FLT_POST_OPERATION_FLAGS Flags);
_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadMetadataNoteRefusal(_In_ const SU_METADATA_DISPATCH *Dispatch,
    _In_ UCHAR MajorFunction, _In_ NTSTATUS Status);
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
