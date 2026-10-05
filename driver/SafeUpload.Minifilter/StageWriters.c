/*++

Module Name:

    StageWriters.c

Abstract:

    Per-file writer history and activation state for the prototype build. H(F) counts file objects
    opened with write access and not yet cleaned up; C(F), T(F), the live SOP index, and the bounded
    activation worker support the Free(F) decision. Tracking remains a ledger: only the separate
    scope and Activating admission checks refuse I/O.

    Design rules (see evidence/2026-10-03/writer-state-design-v2.txt):

    - Count at post-create of a successful physical open whose file object has WriteAccess or DeleteAccess.
      A create the legacy pre-create did not ask a callback for is upgraded to a callback so
      that streams outside every protected scope are counted too: any file may later enter a
      scope.
    - Remove ONLY file objects that were counted. The list holds the FILE_OBJECT pointer as an
      identity token (never dereferenced), so a cleanup for an object opened before attachment,
      or for a stream file object that never had a create, cannot undercount.
    - Cleanup, not close: IRP_MJ_CLEANUP arrives when the last handle of the file object is gone
      (a handle duplicated into another process keeps it alive). Experiments showed the close
      of a writer's file object says nothing about a section that outlives it; that is S(F).
    - A write open that cannot be recorded (no stream-context support, allocation failure)
      sets a sticky flag on the stream and a global counter, so the count is a lower bound that
      is known to be one. A consumer must treat an untracked stream as not writer-free.

Environment:

    Kernel mode

--*/

#include "Stage.h"

#if SAFEUPLOAD_STAGING_PROTOTYPE

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageWritersPostCreate)
#pragma alloc_text(PAGE, SafeUploadStageWritersReserveCreate)
#pragma alloc_text(PAGE, SafeUploadStageWritersInstanceTeardownStart)
#pragma alloc_text(PAGE, SafeUploadStageWritersPrepareRename)
#pragma alloc_text(PAGE, SafeUploadStageWritersRegistryEvaluate)
#pragma alloc_text(PAGE, SafeUploadStageWritersRegistrySnapshotByName)
#endif

/* Separate node tag permits actual Verifier allocation failures to be attributed
 * without failing stream-context or communication scratch allocations. Poolmon: SUwH. */
#define SAFEUPLOAD_WRITER_NODE_POOL_TAG 'HwUS'
#define SAFEUPLOAD_REGISTRY_POOL_TAG 'rUwS'
#define SAFEUPLOAD_TX_ASSOC_POOL_TAG 'tUwS'
#define SAFEUPLOAD_REGISTRY_MAX_TX_ASSOCIATIONS SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT
#define SAFEUPLOAD_REGISTRY_ENTRY_SIGNATURE 'eRwS'
#define SAFEUPLOAD_REGISTRY_RESERVATION_SIGNATURE 'vRwS'
#define SAFEUPLOAD_REGISTRY_RENAME_SIGNATURE 'nRwS'
#define SAFEUPLOAD_REGISTRY_NAME_STORAGE_CHARS (2 * SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS)
#define SAFEUPLOAD_SCOPE_SCAN_PARENT_BUDGET 32
#define SAFEUPLOAD_REGISTRY_SOP_MAX_PROBES 16
#define SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK 64
#define SAFEUPLOAD_TX_ASSOC_PENDING 0
#define SAFEUPLOAD_TX_ASSOC_ENLISTED 1
#define SAFEUPLOAD_TX_ASSOC_TERMINAL 2
#define SAFEUPLOAD_TX_ASSOC_FAILED 3
#define STAGE_RECLAIM_QUEUED 0x1
#define STAGE_RECLAIM_RESCAN 0x2
#define STAGE_SCOPE_CLASS_UNRESOLVED 0
#define STAGE_SCOPE_CLASS_OUTSIDE 1
#define STAGE_SCOPE_CLASS_SCOPED 2
#define STAGE_COMPLETION_CONTEXT_TAG_MASK ((ULONG_PTR)0xF)
#define STAGE_MUTATING_IO_ENTRY_TAG ((ULONG_PTR)0x4)
#define STAGE_MUTATING_IO_MARKER_TAG ((ULONG_PTR)0x8)
#define STAGE_MUTATING_IO_MARKER_SIGNATURE 'mSwU'
#define STAGE_SECTION_ACQUIRE_FIXED_TAG ((ULONG_PTR)0x4)
#define STAGE_SECTION_RELEASE_FIXED_TAG ((ULONG_PTR)0x8)
#define STAGE_SECTION_ACQUIRE_SPILL_TAG ((ULONG_PTR)0xC)
#define STAGE_SECTION_RELEASE_SPILL_TAG ((ULONG_PTR)0xE)

typedef struct _STAGE_REGISTRY_ENTRY STAGE_REGISTRY_ENTRY, *PSTAGE_REGISTRY_ENTRY;
typedef struct _STAGE_SECTION_SPILL_RECORD STAGE_SECTION_SPILL_RECORD, *PSTAGE_SECTION_SPILL_RECORD;

__declspec(align(16)) struct _STAGE_MUTATING_IO_MARKER_CONTEXT {
    ULONG Signature;
    ULONG SopSlotIndex;
    PVOID SectionObjectPointer;
    PVOID InstanceIdentity;        /* non-owning token; protects against slot reuse */
};
typedef struct _STAGE_MUTATING_IO_MARKER_CONTEXT
    STAGE_MUTATING_IO_MARKER_CONTEXT, *PSTAGE_MUTATING_IO_MARKER_CONTEXT;

typedef struct _STAGE_WRITER_NODE {
    LIST_ENTRY Link;
    PFILE_OBJECT FileObject;        /* identity token only */
    PSTAGE_REGISTRY_ENTRY Entry;    /* referenced until this exact node is cleaned up */
    PVOID SectionObjectPointer;     /* identity only for an overflow-only SOP marker */
    ULONG ProcessId;
} STAGE_WRITER_NODE, *PSTAGE_WRITER_NODE;

__declspec(align(16)) struct _STAGE_REGISTRY_ENTRY {
    LIST_ENTRY Link;
    volatile LONG References;
    volatile LONG H;
    volatile LONG W;                 /* admitted mutating IRPs still below the filter */
    volatile LONG T;
    volatile LONG RenameInFlight;
    volatile LONG RenameVersion;
    volatile LONG UnknownReasons;
    PFLT_INSTANCE Instance;         /* referenced; identity only except in PASSIVE diagnostics */
    PFLT_VOLUME Volume;             /* referenced mounted-volume identity */
    ULONGLONG VolumeSerial;
    SAFEUPLOAD_VOLUME_KIND VolumeKind;
    FILE_ID_128 FileId;
    PVOID volatile SectionObjectPointer; /* atomic pointer comparison only; never dereferenced */
    ULONGLONG RenameLossGeneration;
    ULONG FirstSeenGeneration;
    ULONG State;
    ULONG ActivationGeneration;
    volatile LONG ActivationEnforced;
    volatile LONG ScopeScanNextLink;
    volatile LONG ScopeScanUnionScoped;
    volatile LONG ScopeScanCurrentScoped;
    volatile LONG ScopeScanPending;
    ULONG ScopeScanRenameVersion;
    ULONG ScopeScanPolicyGeneration;
    ULONG ScopeScanLinkCount;
    ULONGLONG StreamSuffixHash;
    volatile LONG AliasProbePending;
    volatile LONG ScopeNameClassification;
    volatile LONG LastSState;
    ULONGLONG Sequence;
    USHORT NameChars;
    BOOLEAN Compact;
    BOOLEAN StaticPool;
    BOOLEAN Transient;
    BOOLEAN CompactStream;
    BOOLEAN Listed;
    BOOLEAN Retired;
    KSPIN_LOCK HolderLock;
    KSPIN_LOCK StateLock;
    ULONG OpenerPidCount;
    ULONG OpenerPids[8];
    ULONG OpenerPidReferences[8];
    PWCH Name;
    USHORT StreamChars;
    BOOLEAN StreamIdentityKnown;
    PWCH StreamName;
    PSTAGE_REGISTRY_ENTRY PoolNext;
};

typedef struct _STAGE_WRITER_RESERVATION {
    LIST_ENTRY Link;
    ULONG Signature;
    PFLT_INSTANCE Instance;
    PFLT_VOLUME Volume;
    PSTAGE_REGISTRY_ENTRY Shell;
    PSTAGE_REGISTRY_ENTRY BoundEntry; /* owns the file-ID lookup reference through post-create */
    PSTAGE_WRITER_NODE Node;
    PVOID LegacyCompletionContext;
    ULONG NameChars;
    ULONG StreamChars;
    LONG UnknownReasons;
    ULONGLONG VolumeSerial;
    FILE_ID_128 FileId;
    ULONGLONG RenameLossGeneration;
    ULONGLONG StreamSuffixHash;
    BOOLEAN SlotReserved;
    BOOLEAN CompactSlotReserved;
    BOOLEAN NameReserved;
    BOOLEAN TrackingLost;
    BOOLEAN Active;
    BOOLEAN LegacyCallbackRequired;
    BOOLEAN InstanceReferenceTransferred;
    BOOLEAN VolumeReferenceTransferred;
    volatile LONG TeardownState;
} STAGE_WRITER_RESERVATION, *PSTAGE_WRITER_RESERVATION;

typedef struct _STAGE_REGISTRY_RENAME_CONTEXT {
    LIST_ENTRY Link;
    ULONG Signature;
    PSTAGE_REGISTRY_ENTRY Entry; /* referenced through the set-information post-operation */
    PVOID MutatingIoContext;      /* entry or SOP spill token; owns its rundown until lower completion */
    PVOID InstanceIdentity;      /* non-owning identity token; never dereferenced as a filter object */
    ULONG NameChars;
    ULONG OldNameChars;
    ULONG NewNameChars;
    ULONG NewStreamChars;
    ULONGLONG CompactStreamSuffixHash;
    BOOLEAN LinkOperation;
    BOOLEAN Ambiguous;
    BOOLEAN DirectoryRename;
    BOOLEAN StreamSuffixRetained;
    BOOLEAN CompactStreamIdentity;
    BOOLEAN Listed;
    BOOLEAN NewNameTooLong;
    volatile LONG Abandoned;
    WCHAR OldName[SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS];
    WCHAR Name[SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS];
    WCHAR StreamName[SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS];
} STAGE_REGISTRY_RENAME_CONTEXT, *PSTAGE_REGISTRY_RENAME_CONTEXT;

typedef struct _STAGE_DEFERRED_RENAME {
    PFLT_INSTANCE Instance; /* owned only by this independent work item */
    PSTAGE_REGISTRY_RENAME_CONTEXT Rename;
    BOOLEAN Succeeded;
    BOOLEAN Draining;
} STAGE_DEFERRED_RENAME, *PSTAGE_DEFERRED_RENAME;

typedef struct _STAGE_TX_ASSOCIATION {
    LIST_ENTRY Link;
    volatile LONG References;
    volatile LONG State;
    BOOLEAN Listed;
    KEVENT StateChanged;
    NTSTATUS CompletionStatus;
    PKTRANSACTION Transaction;      /* identity token only; never dereferenced */
    PFLT_INSTANCE Instance;         /* referenced by Entry */
    PSTAGE_REGISTRY_ENTRY Entry;     /* referenced until terminal notification */
} STAGE_TX_ASSOCIATION, *PSTAGE_TX_ASSOCIATION;

typedef struct _STAGE_REGISTRY_SOP_SLOT {
    PVOID SectionObjectPointer;
    PSTAGE_REGISTRY_ENTRY Entry;    /* one reference while this identity is in the fast-path map */
    PVOID InstanceIdentity;         /* non-owning token used only to retire an overflow marker */
    ULONGLONG VolumeSerial;
    ULONGLONG StreamSuffixHash;
    FILE_ID_128 FileId;
    LONG UnknownReasons;
    ULONG UnknownWriterCount;
    ULONG SpilledSectionAcquireCount;
    ULONG SpilledSectionCount;
    ULONG SpilledSectionReleasePending;
    ULONG SpilledMutatingIoCount;
    ULONG ScopePolicyGeneration;
    ULONG ScopeScanRenameVersion;
    ULONG ScopeScanLinkCount;
    LONG ScopeScanNextLink;
    LONG ScopeScanUnionScoped;
    LONG ScopeScanCurrentScoped;
    LONG ScopeScanPending;
    LONG ScopeClassification;
    BOOLEAN Unknown;
    BOOLEAN Deleted;
} STAGE_REGISTRY_SOP_SLOT, *PSTAGE_REGISTRY_SOP_SLOT;

typedef struct _STAGE_REGISTRY_SOP_SNAPSHOT {
    PVOID SectionObjectPointer;
    ULONGLONG VolumeSerial;
    ULONGLONG StreamSuffixHash;
    FILE_ID_128 FileId;
    ULONG UnknownWriterCount;
    ULONG SpilledSectionAcquireCount;
    ULONG SpilledSectionCount;
    ULONG SpilledSectionReleasePending;
    ULONG SpilledMutatingIoCount;
    ULONG ScopePolicyGeneration;
    ULONG ScopeScanRenameVersion;
    ULONG ScopeScanLinkCount;
    LONG ScopeScanNextLink;
    LONG ScopeScanUnionScoped;
    LONG ScopeScanCurrentScoped;
    LONG ScopeScanPending;
    LONG ScopeClassification;
} STAGE_REGISTRY_SOP_SNAPSHOT, *PSTAGE_REGISTRY_SOP_SNAPSHOT;

typedef struct _STAGE_SCOPE_PARENT_NAME {
    ULONGLONG ParentFileId;
    USHORT NameChars;
    WCHAR Name[SAFEUPLOAD_MAX_PREFIX_CHARS + 1];
} STAGE_SCOPE_PARENT_NAME, *PSTAGE_SCOPE_PARENT_NAME;

typedef struct _STAGE_DEFERRED_INSTANCE_UNKNOWN {
    PFLT_INSTANCE Instance;         /* temporary rundown reference for direct instance losses */
    PSTAGE_REGISTRY_ENTRY Entry;    /* referenced until the worker safely reads its live Instance */
    LONG Reason;
} STAGE_DEFERRED_INSTANCE_UNKNOWN, *PSTAGE_DEFERRED_INSTANCE_UNKNOWN;

static BOOLEAN StageRegistryEntryQuiescent(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume);
static VOID StageRegistryPrepareActivation(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ BOOLEAN Unknown);
static NTSTATUS StageRegistryOpenIdentity(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume, _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object);
static NTSTATUS StageRegistryOpenParentById(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ ULONGLONG VolumeSerial, _In_ ULONGLONG ParentFileId,
    _Out_ PHANDLE Handle, _Outptr_result_nullonfailure_ PFILE_OBJECT *Object);
static VOID StageRegistryBuildLinkName(_In_ PCUNICODE_STRING ParentName,
    _In_reads_(ChildChars) PCWCH ChildName, _In_ ULONG ChildChars,
    _In_reads_opt_(StreamChars) PCWCH StreamName, _In_ ULONG StreamChars,
    _Out_writes_(SAFEUPLOAD_MAX_PREFIX_CHARS + 1) PWCH Buffer, _Out_ PUNICODE_STRING LinkName);
static NTSTATUS StageRegistryClassifyAllLinkNames(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _Inout_ PULONG WorkBudget,
    _Out_ PBOOLEAN UnionScoped, _Out_ PBOOLEAN CurrentScoped);
static VOID StageRegistryActivationProcess(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume, _Inout_ PULONG WorkBudget);

NTSTATUS SafeUploadStageWritersClassifyById(_In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN InScope);

__declspec(noinline) static BOOLEAN StageRegistryBeginAliasProbe(_In_ PSTAGE_REGISTRY_ENTRY Entry);
static VOID StageRegistryReclaimWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context);
static VOID StageRegistryRenameWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context);
static VOID StageRegistryUnknownWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context);
static BOOLEAN StageRegistryQueueInstanceUnknown(_In_ PFLT_INSTANCE Instance, _In_ LONG Reason);
static BOOLEAN StageRegistryQueueEntryUnknown(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason);
static BOOLEAN StageRegistryQueueReclaim(VOID);
static KSPIN_LOCK SectionLock;
_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static PSTAGE_REGISTRY_SOP_SLOT StageRegistryFindSopSlotLocked(
    _In_ PVOID SectionObjectPointer, _Out_ PBOOLEAN Found);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryTrackUnknownWriter(_Inout_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFILE_OBJECT FileObject);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryUnknownWriterEnd(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryCopyUnknownSopChunk(_In_ PFLT_INSTANCE Instance,
    _In_ ULONG Base,
    _Out_writes_to_(SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK, *SnapshotCount) PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshots,
    _Out_ PULONG SnapshotCount);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryRetireUnknownSopIfSame(_In_ PFLT_INSTANCE Instance,
    _In_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot);
_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageRegistryUnknownSopMarkersQuiescent(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _Inout_ PULONG WorkBudget,
    _Out_ PBOOLEAN WorkRemaining, _Out_ PULONGLONG Generation);
_IRQL_requires_(PASSIVE_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryClassifyUnknownSopSnapshot(
    _Inout_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot, _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _Inout_ PULONG WorkBudget, _In_ ULONG PolicyGeneration,
    _Out_ PBOOLEAN Outside, _Out_ PBOOLEAN WorkRemaining, _Out_ PBOOLEAN Changed);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryHasEntryForSop(
    _In_ PFLT_INSTANCE Instance, _In_opt_ PVOID SectionObjectPointer);
static BOOLEAN StageRegistrySopSnapshotQuiescent(_In_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume);
static NTSTATUS StageRegistryResolveCompactStream(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _Out_writes_(SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) PWCH StreamBuffer,
    _Out_ PUSHORT StreamChars);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryMarkSopUnknown(_In_ PFLT_INSTANCE Instance,
    _In_ ULONGLONG VolumeSerial, _In_ const FILE_ID_128 *FileId,
    _In_ ULONGLONG StreamSuffixHash, _In_opt_ PVOID SectionObjectPointer);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, SafeUploadStageWritersApplyPendingScope)
#pragma alloc_text(PAGE, SafeUploadStageWritersReconcileCurrentScope)
#pragma alloc_text(PAGE, SafeUploadStageWritersActivatingStatusPage)
#pragma alloc_text(PAGE, StageRegistryEntryQuiescent)
#pragma alloc_text(PAGE, StageRegistryOpenIdentity)
#pragma alloc_text(PAGE, StageRegistryResolveCompactStream)
#pragma alloc_text(PAGE, StageRegistryOpenParentById)
#pragma alloc_text(PAGE, StageRegistryBuildLinkName)
#pragma alloc_text(PAGE, StageRegistryClassifyAllLinkNames)
#pragma alloc_text(PAGE, SafeUploadStageWritersClassifyById)
#pragma alloc_text(PAGE, StageRegistryActivationProcess)
#pragma alloc_text(PAGE, StageRegistryUnknownSopMarkersQuiescent)
#pragma alloc_text(PAGE, StageRegistryClassifyUnknownSopSnapshot)
#pragma alloc_text(PAGE, StageRegistrySopSnapshotQuiescent)
#pragma alloc_text(PAGE, StageRegistryReclaimWorker)
#pragma alloc_text(PAGE, StageRegistryRenameWorker)
#pragma alloc_text(PAGE, StageRegistryUnknownWorker)
#endif

static EX_PUSH_LOCK RegistryLock;
static LIST_ENTRY RegistryEntries;
static LIST_ENTRY RegistryReservations;
static LIST_ENTRY TransactionAssociations;
static LIST_ENTRY RegistryDirectoryRenames;
static ULONG RegistryEntryCount;
static ULONG RegistryCompactEntryCount;
static ULONG RegistryReservationCount;
static ULONG RegistryReservedSlots;
static ULONG RegistryReservedCompactSlots;
static ULONG RegistryNameBytes;
static ULONG RegistryReservedNameBytes;
static ULONG RegistryAssociationCount;
static ULONG RegistryDirectoryRenameCount;
static ULONG RegistryCapacityOverride;
static ULONG RegistryOverflow;
static ULONG RegistryUnknownReasons;
static ULONG RegistryInstanceUnknown;
static volatile LONG64 TxfRefused;
static volatile LONG64 RegistryCapacityFailures;
static volatile LONG64 RegistryAllocationFailures;
static volatile LONG64 RegistryIdentityFailures;
static volatile LONG64 RegistryTransactionFailures;
static volatile LONG64 RegistryRenameFailures;
static volatile LONG64 RegistryDroppedAtDismount;
static volatile LONG64 RegistryDroppedWhileMounted;
static volatile LONG64 RegistryPruned;
static volatile LONG64 RegistryReclaimPasses;
static volatile LONG64 RegistryChangeSequence;
static volatile LONG RegistryReclaimQueued;
static volatile LONG RegistryReclaimResetCursor;
static ULONGLONG RegistryEntrySequence;
static ULONGLONG RegistryReclaimCursor;
static STAGE_REGISTRY_SOP_SLOT RegistrySopSlots[SAFEUPLOAD_WRITER_REGISTRY_SOP_LIMIT];
static volatile LONG64 RegistrySopMapGeneration;
static KSPIN_LOCK RegistryCompactPoolLock;
static PSTAGE_REGISTRY_ENTRY RegistryCompactPool;
static PSTAGE_REGISTRY_ENTRY RegistryCompactFreeList;
static ULONG RegistryCompactFreeCount;
static ULONG RegistryCompactPoolCapacity;
static VOID StageRegistryRetireInstance(_In_ PFLT_INSTANCE Instance, _In_ BOOLEAN Dismount);
static VOID StageRegistryBeginInstanceTeardown(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN Token, _In_ BOOLEAN Dismount);
static VOID StageRegistryAssociationDereference(_In_opt_ PSTAGE_TX_ASSOCIATION Association);
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryAcquireStateLock(
    _In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_ _At_(*OldIrql, _IRQL_saves_) PKIRQL OldIrql);
_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryReleaseStateLock(
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ _IRQL_restores_ KIRQL OldIrql);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryEndMutatingIoEntry(
    _Inout_ PSTAGE_REGISTRY_ENTRY Entry);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryEndMutatingIoMarker(_In_ ULONG SopSlotIndex,
    _In_opt_ PVOID SectionObjectPointer, _In_opt_ PVOID InstanceIdentity);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryReserveMutatingIoMarker(
    _In_opt_ PFLT_INSTANCE Instance, _In_opt_ PVOID SectionObjectPointer,
    _Out_ PULONG SopSlotIndex);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static UINT32 StageRegistrySnapshotSpilledMutatingIo(
    _In_ PSTAGE_REGISTRY_ENTRY Entry);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static UINT32 StageRegistrySnapshotSpilledWriters(
    _In_ PSTAGE_REGISTRY_ENTRY Entry);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryReserveSpilledSection(
    _In_opt_ PVOID SectionObjectPointer, _In_opt_ PFLT_INSTANCE Instance,
    _In_ BOOLEAN Writable, _Inout_ PSTAGE_SECTION_SPILL_RECORD SpillRecord,
    _Out_ PULONG SopSlotIndex, _Out_ PBOOLEAN IdentityKnown);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionAcquireFailed(
    _In_ ULONG SopSlotIndex, _In_opt_ PVOID SectionObjectPointer,
    _In_opt_ PVOID InstanceIdentity, _In_ BOOLEAN Writable);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionAcquireDraining(
    _In_opt_ PFLT_INSTANCE Instance, _In_ ULONG SopSlotIndex,
    _In_opt_ PVOID SectionObjectPointer);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionReleaseComplete(
    _In_opt_ PFLT_INSTANCE Instance, _In_ ULONG SopSlotIndex,
    _In_opt_ PVOID SectionObjectPointer, _In_ BOOLEAN Writable,
    _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionSnapshot(
    _In_opt_ PVOID SectionObjectPointer, _Out_ PUINT32 WritableCount,
    _Out_ PUINT32 TotalCount);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static PSTAGE_SECTION_SPILL_RECORD StageRegistryDetachOneInstanceSpill(
    _In_ PFLT_INSTANCE Instance, _Out_ PBOOLEAN Detached);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryStoreUnknownSopClassification(
    _In_ PFLT_INSTANCE Instance, _In_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot,
    _In_ PSTAGE_REGISTRY_ENTRY Probe, _In_ ULONG PolicyGeneration,
    _In_ LONG Classification, _Out_ PBOOLEAN Changed);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySopScopeClassification(
    _In_ PFLT_INSTANCE Instance, _In_ PVOID SectionObjectPointer,
    _In_ ULONG PolicyGeneration, _Out_ PBOOLEAN Known, _Out_ PBOOLEAN Outside);
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static UINT32 StageRegistrySnapshotC(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_writes_opt_(Capacity) PUINT32 ProcessIds, _In_ ULONG Capacity,
    _Out_opt_ PUINT32 ProcessIdCount);
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
__declspec(noinline) static BOOLEAN StageRegistryTryPromoteStateNoInline(
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ ULONGLONG ExpectedSopMarkerGeneration);

static volatile LONG64 WriterPostCreateRuns;
static volatile LONG64 WriterCounted;
static volatile LONG64 WriterReleased;
static volatile LONG64 WriterUntrackedCreates;
static volatile LONG64 WriterCleanupUnmatched;
static volatile LONG64 WriterDirectoryCreatesSkipped;
static volatile LONG64 WriterPagingCreatesSkipped;
static volatile LONG64 WriterVolumeCreatesSkipped;
static volatile LONG64 WriterDroppedAtTeardown;
static volatile LONG64 WriterDroppedWhileMounted;
static volatile LONG64 InstanceTeardownsDismount;
static volatile LONG64 InstanceTeardownsOther;
static volatile LONG WriterGlobalUnknown;

/* All resident spin-lock primitives stay in these annotated, non-inlined helpers. */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageAcquireSpinLock(
    _In_ PKSPIN_LOCK Lock, _Out_ _At_(*OldIrql, _IRQL_saves_) PKIRQL OldIrql)
{
    KeAcquireSpinLock(Lock, OldIrql);
}

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageReleaseSpinLock(
    _In_ PKSPIN_LOCK Lock, _In_ _IRQL_restores_ KIRQL OldIrql)
{
    KeReleaseSpinLock(Lock, OldIrql);
}

static BOOLEAN StageRegistryNameHasPathPrefix(_In_ PCUNICODE_STRING Name,
    _In_ PCUNICODE_STRING Prefix)
{
    UNICODE_STRING candidatePrefix;
    USHORT prefixChars;

    if (Name == NULL || Prefix == NULL || Name->Buffer == NULL || Prefix->Buffer == NULL ||
        Prefix->Length == 0 || Name->Length < Prefix->Length ||
        ((Name->Length | Prefix->Length) & (sizeof(WCHAR) - 1)) != 0) return FALSE;
    candidatePrefix.Buffer = Name->Buffer;
    candidatePrefix.Length = Prefix->Length;
    candidatePrefix.MaximumLength = Prefix->Length;
    if (!RtlEqualUnicodeString(&candidatePrefix, Prefix, TRUE)) return FALSE;
    if (Name->Length == Prefix->Length) return TRUE;

    /* A stored directory prefix matches only complete path components. A prefix
     * that already ends in a separator is itself at a component boundary. */
    prefixChars = Prefix->Length / sizeof(WCHAR);
    return Prefix->Buffer[prefixChars - 1] == L'\\' || Name->Buffer[prefixChars] == L'\\';
}

static UNICODE_STRING StageRegistryBaseName(_In_ PCUNICODE_STRING Name)
{
    UNICODE_STRING base = *Name;
    USHORT chars, componentStart = 0, index;
    if (Name->Buffer == NULL || (Name->Length & (sizeof(WCHAR) - 1)) != 0) return base;
    chars = Name->Length / sizeof(WCHAR);
    for (index = chars; index != 0; --index) {
        if (Name->Buffer[index - 1] == L'\\') {
            componentStart = index;
            break;
        }
    }
    for (index = componentStart; index < chars; ++index) {
        if (Name->Buffer[index] == L':') {
            base.Length = base.MaximumLength = (USHORT)(index * sizeof(WCHAR));
            break;
        }
    }
    return base;
}

static VOID StageRegistrySplitStreamName(_In_ PCUNICODE_STRING Name,
    _Out_ PUNICODE_STRING BaseName, _Out_ PUNICODE_STRING StreamName)
{
    USHORT chars, componentStart = 0, index;
    *BaseName = *Name;
    *StreamName = *Name;
    StreamName->Length = StreamName->MaximumLength = 0;
    if (Name->Buffer == NULL || (Name->Length & (sizeof(WCHAR) - 1)) != 0) return;
    chars = Name->Length / sizeof(WCHAR);
    for (index = chars; index != 0; --index) {
        if (Name->Buffer[index - 1] == L'\\') {
            componentStart = index;
            break;
        }
    }
    for (index = componentStart; index < chars; ++index) {
        if (Name->Buffer[index] == L':') {
            BaseName->Length = BaseName->MaximumLength = (USHORT)(index * sizeof(WCHAR));
            StreamName->Buffer = Name->Buffer + index;
            StreamName->Length = StreamName->MaximumLength =
                (USHORT)(Name->Length - index * sizeof(WCHAR));
            return;
        }
    }
}

static ULONG StageRegistryNameStorageBytes(_In_ USHORT NameChars, _In_ USHORT StreamChars)
{
    return ((ULONG)NameChars + StreamChars) * sizeof(WCHAR);
}

static ULONGLONG StageRegistryStreamSuffixHash(_In_ PCUNICODE_STRING Stream)
{
    ULONGLONG hash = 1469598103934665603ULL;
    USHORT index, chars;
    UNICODE_STRING dataSuffix = RTL_CONSTANT_STRING(L":$DATA");
    UNICODE_STRING tail;
    if (Stream == NULL || Stream->Buffer == NULL || Stream->Length == 0 ||
        (Stream->Length & (sizeof(WCHAR) - 1)) != 0) return 0;
    chars = Stream->Length / sizeof(WCHAR);
    /* FileStreamInformation appends :$DATA; normalized file-name Stream may omit it. */
    if (chars >= 6) {
        tail.Buffer = Stream->Buffer + chars - 6;
        tail.Length = tail.MaximumLength = (USHORT)(6 * sizeof(WCHAR));
        if (RtlEqualUnicodeString(&tail, &dataSuffix, TRUE)) chars -= 6;
    }
    for (index = 0; index < chars; ++index) {
        WCHAR character = RtlUpcaseUnicodeChar(Stream->Buffer[index]);
        hash ^= (UCHAR)(character & 0xff);
        hash *= 1099511628211ULL;
        hash ^= (UCHAR)(character >> 8);
        hash *= 1099511628211ULL;
    }
    return hash != 0 ? hash : 1;
}

static ULONG StageRegistryEntryNameStorageBytes(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    return Entry->Compact ? 0 : StageRegistryNameStorageBytes(Entry->NameChars, Entry->StreamChars);
}

static PSTAGE_REGISTRY_ENTRY StageRegistryAllocateNamedShell(VOID)
{
    SIZE_T bytes = sizeof(STAGE_REGISTRY_ENTRY) +
        SAFEUPLOAD_REGISTRY_NAME_STORAGE_CHARS * sizeof(WCHAR);
    PSTAGE_REGISTRY_ENTRY entry = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes,
        SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (entry == NULL) return NULL;
    RtlZeroMemory(entry, bytes);
    entry->Name = (PWCH)(entry + 1);
    entry->StreamName = entry->Name + SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS;
    return entry;
}

/* Compact records are a fixed nonpaged pool, four times the full-name tier.
 * The pool lock protects only its free list; RegistryLock remains the owner of
 * live entries and is never taken from this helper. */
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static PSTAGE_REGISTRY_ENTRY StageRegistryCompactPoolPop(VOID)
{
    PSTAGE_REGISTRY_ENTRY entry;
    KIRQL irql;
    StageAcquireSpinLock(&RegistryCompactPoolLock, &irql);
    entry = RegistryCompactFreeList;
    if (entry != NULL) {
        RegistryCompactFreeList = entry->PoolNext;
        RegistryCompactFreeCount -= 1;
    }
    StageReleaseSpinLock(&RegistryCompactPoolLock, irql);
    if (entry != NULL) {
        RtlZeroMemory(entry, sizeof(*entry));
        entry->Compact = TRUE;
        entry->StaticPool = TRUE;
    }
    return entry;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryCompactPoolPush(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;
    RtlZeroMemory(Entry, sizeof(*Entry));
    StageAcquireSpinLock(&RegistryCompactPoolLock, &irql);
    Entry->StaticPool = TRUE;
    Entry->PoolNext = RegistryCompactFreeList;
    RegistryCompactFreeList = Entry;
    RegistryCompactFreeCount += 1;
    StageReleaseSpinLock(&RegistryCompactPoolLock, irql);
}

static VOID StageRegistryFreeShell(_In_opt_ PSTAGE_REGISTRY_ENTRY Entry)
{
    if (Entry == NULL) return;
    if (Entry->StaticPool) StageRegistryCompactPoolPush(Entry);
    else ExFreePoolWithTag(Entry, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

static BOOLEAN StageRegistryPathPrefixesOverlap(_In_ PCUNICODE_STRING First,
    _In_ PCUNICODE_STRING Second)
{
    return StageRegistryNameHasPathPrefix(First, Second) ||
        StageRegistryNameHasPathPrefix(Second, First);
}

/* Caller holds RegistryLock. An abandoned post-operation can only be set after
 * queuing its deferred completion failed. That path publishes machine-wide
 * Unknown before setting Abandoned, so removing the temporary range cannot
 * turn a stale name into a false Free result. */
static VOID StageRegistryPurgeAbandonedDirectoryRenamesLocked(VOID)
{
    PLIST_ENTRY link = RegistryDirectoryRenames.Flink;
    while (link != &RegistryDirectoryRenames) {
        PLIST_ENTRY next = link->Flink;
        PSTAGE_REGISTRY_RENAME_CONTEXT rename = CONTAINING_RECORD(link,
            STAGE_REGISTRY_RENAME_CONTEXT, Link);
        if (InterlockedCompareExchange(&rename->Abandoned, 0, 0) != 0) {
            RemoveEntryList(&rename->Link);
            rename->Listed = FALSE;
            if (RegistryDirectoryRenameCount != 0) RegistryDirectoryRenameCount -= 1;
            InterlockedIncrement64(&RegistryChangeSequence);
            rename->Signature = 0;
            ExFreePoolWithTag(rename, SAFEUPLOAD_REGISTRY_POOL_TAG);
        }
        link = next;
    }
}

/* Caller holds RegistryLock. This is live rename state, not a diagnostic side
 * effect: readers derive Unknown while a directory rename can still change a
 * retained path, without persisting that momentary conclusion on the entry. */
static BOOLEAN StageRegistryDirectoryRenameInFlightLocked(_In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING Name)
{
    PLIST_ENTRY link;
    for (link = RegistryDirectoryRenames.Flink; link != &RegistryDirectoryRenames; link = link->Flink) {
        PSTAGE_REGISTRY_RENAME_CONTEXT rename = CONTAINING_RECORD(link,
            STAGE_REGISTRY_RENAME_CONTEXT, Link);
        UNICODE_STRING oldName, newName;
        if (!rename->Listed || rename->InstanceIdentity != (PVOID)Instance) continue;
        if (rename->OldNameChars != 0 &&
            rename->OldNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
            oldName.Buffer = rename->OldName;
            oldName.Length = oldName.MaximumLength = (USHORT)(rename->OldNameChars * sizeof(WCHAR));
            if (StageRegistryNameHasPathPrefix(Name, &oldName)) return TRUE;
        }
        if (!rename->NewNameTooLong && rename->NewNameChars != 0 &&
            rename->NewNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
            newName.Buffer = rename->Name;
            newName.Length = newName.MaximumLength = (USHORT)(rename->NewNameChars * sizeof(WCHAR));
            if (StageRegistryNameHasPathPrefix(Name, &newName)) return TRUE;
        }
    }
    return FALSE;
}

/* Caller holds RegistryLock. Unlike StageRegistryMarkEntryUnknown, this keeps
 * a directory-path overflow on the affected file only; the orchestrator's
 * directory-rename decision keeps retained-name overflow entry-local. Missing
 * names or inability to retain the bounded completion record use the existing
 * tracking-loss fallback; neither path vetoes the rename I/O. */
static VOID StageRegistrySetEntryUnknownLocked(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason)
{
    InterlockedOr(&Entry->UnknownReasons, Reason);
    if ((Reason & (SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME | SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY)) != 0)
        InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
    InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
    InterlockedIncrement64(&RegistryChangeSequence);
}

static VOID StageRegistryReference(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    InterlockedIncrement(&Entry->References);
}

__declspec(noinline) static VOID StageRegistryDereference(_In_opt_ PSTAGE_REGISTRY_ENTRY Entry)
{
    if (Entry == NULL) return;
    if (InterlockedDecrement(&Entry->References) == 0) {
        if (Entry->Volume != NULL) FltObjectDereference(Entry->Volume);
        if (Entry->Instance != NULL) FltObjectDereference(Entry->Instance);
        if (Entry->StaticPool) StageRegistryCompactPoolPush(Entry);
        else ExFreePoolWithTag(Entry, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
}

static VOID StageRegistryMarkUnknown(_In_opt_ PFLT_INSTANCE Instance,
    _In_ LONG Reason, _In_ BOOLEAN MachineWide)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    BOOLEAN instanceMarked = FALSE;
    BOOLEAN renameGenerationAdvanced = FALSE;
    InterlockedOr((volatile LONG *)&RegistryUnknownReasons, Reason);
    if (Instance != NULL) {
        if (KeGetCurrentIrql() <= APC_LEVEL &&
            NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&context))) {
            InterlockedOr(&context->RegistryUnknownReasons, Reason);
            if ((Reason & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0) {
                UNICODE_STRING volumeName;
                PCUNICODE_STRING volumeNamePointer = NULL;
                if (context->VolumeNameChars != 0 &&
                    context->VolumeNameChars <= SAFEUPLOAD_MAX_PREFIX_CHARS) {
                    volumeName.Buffer = context->VolumeName;
                    volumeName.Length = volumeName.MaximumLength = (USHORT)(
                        context->VolumeNameChars * sizeof(WCHAR));
                    volumeNamePointer = &volumeName;
                }
                SafeUploadPolicyRenameLossAdvance(&context->RegistryRenameLossGeneration,
                    context->VolumeKind, volumeNamePointer);
                renameGenerationAdvanced = TRUE;
            }
            if (InterlockedCompareExchange(&context->WritersUntracked, 1, 0) == 0)
                InterlockedIncrement((volatile LONG *)&RegistryInstanceUnknown);
            instanceMarked = TRUE;
            FltReleaseContext(context);
        } else if (KeGetCurrentIrql() > APC_LEVEL) {
            instanceMarked = StageRegistryQueueInstanceUnknown(Instance, Reason);
        }
    }
    /* An instance lookup failure is itself fail-closed at admission: callers that cannot read the
     * instance context treat it as Unknown. Machine-wide Unknown is reserved for an explicit
     * machine-wide loss or an identity loss with no instance to scope it to. */
    if (MachineWide || Instance == NULL ||
        (KeGetCurrentIrql() > APC_LEVEL && !instanceMarked) ||
        ((Reason & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0 && !renameGenerationAdvanced)) {
        /* P0-5: if the per-instance generation cannot be advanced, prevent
         * promotion globally; scope admission still filters by volume. */
        InterlockedExchange(&WriterGlobalUnknown, 1);
    }
}

static VOID StageRegistryMarkEntryUnknown(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason)
{
    InterlockedOr(&Entry->UnknownReasons, Reason);
    if ((Reason & (SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME | SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY)) != 0)
        InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
    InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
    InterlockedIncrement64(&RegistryChangeSequence);
    /* Narrowest scope: a loss about this file (identity, transaction, section binding) stays on its entry, which is keyed by
     * file ID and can never be Free. A file rename whose final name is lost widens because scope classification is name
     * based; a directory rename with retained names uses the locked prefix rewrite and can keep overflow entry-local. */
    if ((Reason & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) == 0) return;
    if (KeGetCurrentIrql() <= APC_LEVEL) {
        PFLT_INSTANCE instance = NULL;
        FltAcquirePushLockExclusive(&RegistryLock);
        if (!Entry->Retired && Entry->Instance != NULL && NT_SUCCESS(FltObjectReference(Entry->Instance)))
            instance = Entry->Instance;
        FltReleasePushLock(&RegistryLock);
        /* The reference was taken while serialized with retirement clearing Entry->Instance. */
        if (instance != NULL) {
            StageRegistryMarkUnknown(instance, Reason, FALSE);
            FltObjectDereference(instance);
        }
    } else {
        /* A set-information post-operation may run at DISPATCH_LEVEL. Keep the entry Unknown
         * immediately and defer instance lookup to PASSIVE_LEVEL; the worker reads Entry->Instance
         * under RegistryLock, serialized with the teardown unlink that clears it. */
        if (!StageRegistryQueueEntryUnknown(Entry, Reason)) {
            InterlockedOr((volatile LONG *)&RegistryUnknownReasons, Reason);
            InterlockedExchange(&WriterGlobalUnknown, 1);
        }
    }
}

/* Entry is nonpaged; keep HolderLock operations out of pageable create/cleanup callers. */
__declspec(noinline) static VOID StageRegistryAddOpener(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ ULONG ProcessId)
{
    ULONG index;
    KIRQL irql;
    if (ProcessId == 0) return;
    StageAcquireSpinLock(&Entry->HolderLock, &irql);
    for (index = 0; index < Entry->OpenerPidCount; ++index) {
        if (Entry->OpenerPids[index] == ProcessId) {
            if (Entry->OpenerPidReferences[index] != MAXULONG)
                Entry->OpenerPidReferences[index] += 1;
            InterlockedIncrement64(&RegistryChangeSequence);
            StageReleaseSpinLock(&Entry->HolderLock, irql);
            return;
        }
    }
    if (Entry->OpenerPidCount < RTL_NUMBER_OF(Entry->OpenerPids)) {
        Entry->OpenerPids[Entry->OpenerPidCount] = ProcessId;
        Entry->OpenerPidReferences[Entry->OpenerPidCount] = 1;
        Entry->OpenerPidCount += 1;
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    StageReleaseSpinLock(&Entry->HolderLock, irql);
}

__declspec(noinline) static VOID StageRegistryRemoveOpener(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ ULONG ProcessId)
{
    ULONG index;
    KIRQL irql;
    if (ProcessId == 0) return;
    StageAcquireSpinLock(&Entry->HolderLock, &irql);
    for (index = 0; index < Entry->OpenerPidCount; ++index) {
        if (Entry->OpenerPids[index] != ProcessId) continue;
        if (Entry->OpenerPidReferences[index] > 1) {
            Entry->OpenerPidReferences[index] -= 1;
        } else {
            ULONG last = Entry->OpenerPidCount - 1;
            Entry->OpenerPids[index] = Entry->OpenerPids[last];
            Entry->OpenerPidReferences[index] = Entry->OpenerPidReferences[last];
            Entry->OpenerPids[last] = 0;
            Entry->OpenerPidReferences[last] = 0;
            Entry->OpenerPidCount = last;
        }
        InterlockedIncrement64(&RegistryChangeSequence);
        break;
    }
    StageReleaseSpinLock(&Entry->HolderLock, irql);
}

/* ProcessIds and Count are resident scratch; pageable status buffers are filled after this returns. */
__declspec(noinline) static VOID StageRegistryCopyOpeners(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_writes_(Capacity) PUINT32 ProcessIds, _In_ ULONG Capacity, _Out_ PUINT32 Count)
{
    ULONG index, copied;
    KIRQL irql;
    *Count = 0;
    StageAcquireSpinLock(&Entry->HolderLock, &irql);
    copied = min(Entry->OpenerPidCount, Capacity);
    for (index = 0; index < copied; ++index) ProcessIds[index] = Entry->OpenerPids[index];
    StageReleaseSpinLock(&Entry->HolderLock, irql);
    *Count = copied;
}

static PSTAGE_REGISTRY_ENTRY StageRegistryFindByKeyLocked(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ ULONGLONG VolumeSerial, _In_ const FILE_ID_128 *FileId,
    _In_opt_ PVOID SectionObjectPointer)
{
    PLIST_ENTRY link;
    /* P0-3: a named stream is a distinct live identity, keyed by this file ID
     * and its SOP; its base path is joined to scopes during expansion. */
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (!entry->Retired && entry->Instance == Instance && entry->Volume == Volume &&
            entry->VolumeSerial == VolumeSerial &&
            InterlockedCompareExchangePointer(
                (PVOID volatile *)&entry->SectionObjectPointer, NULL, NULL) == SectionObjectPointer &&
            RtlEqualMemory(&entry->FileId, FileId, sizeof(entry->FileId))) return entry;
    }
    return NULL;
}

static ULONG StageRegistryCapacityLocked(VOID)
{
    return RegistryCapacityOverride != 0 && RegistryCapacityOverride < SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT ?
        RegistryCapacityOverride : SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT;
}

static ULONG StageRegistryInstanceCountLocked(_In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    ULONG count = 0;
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (!entry->Compact && !entry->Retired && entry->Instance == Instance) count += 1;
    }
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reserve = CONTAINING_RECORD(link, STAGE_WRITER_RESERVATION, Link);
        if (reserve->Active && reserve->SlotReserved && !reserve->CompactSlotReserved &&
            reserve->Instance == Instance) count += 1;
    }
    return count;
}

static ULONG StageRegistryCompactInstanceCountLocked(_In_ PFLT_INSTANCE Instance)
{
    PLIST_ENTRY link;
    ULONG count = 0;
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (entry->Compact && !entry->Retired && entry->Instance == Instance) count += 1;
    }
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reserve = CONTAINING_RECORD(link, STAGE_WRITER_RESERVATION, Link);
        if (reserve->Active && reserve->CompactSlotReserved && reserve->Instance == Instance) count += 1;
    }
    return count;
}

static VOID StageRegistryFinishReservationAccountingLocked(
    _Inout_ PSTAGE_WRITER_RESERVATION Reservation)
{
    ULONG nameBytes = StageRegistryNameStorageBytes((USHORT)Reservation->NameChars,
        (USHORT)Reservation->StreamChars);
    if (!Reservation->Active) return;
    if (Reservation->CompactSlotReserved && RegistryReservedCompactSlots != 0)
        RegistryReservedCompactSlots -= 1;
    else if (Reservation->SlotReserved && RegistryReservedSlots != 0)
        RegistryReservedSlots -= 1;
    Reservation->SlotReserved = FALSE;
    Reservation->CompactSlotReserved = FALSE;
    if (Reservation->NameReserved && RegistryReservedNameBytes >= nameBytes)
        RegistryReservedNameBytes -= nameBytes;
    Reservation->NameReserved = FALSE;
    RemoveEntryList(&Reservation->Link);
    if (RegistryReservationCount != 0) RegistryReservationCount -= 1;
    Reservation->Active = FALSE;
}

static VOID StageRegistryReleaseReservationCapacityLocked(
    _Inout_ PSTAGE_WRITER_RESERVATION Reservation)
{
    ULONG nameBytes = StageRegistryNameStorageBytes((USHORT)Reservation->NameChars,
        (USHORT)Reservation->StreamChars);
    if (Reservation->CompactSlotReserved && RegistryReservedCompactSlots != 0)
        RegistryReservedCompactSlots -= 1;
    else if (Reservation->SlotReserved && RegistryReservedSlots != 0)
        RegistryReservedSlots -= 1;
    Reservation->SlotReserved = FALSE;
    Reservation->CompactSlotReserved = FALSE;
    if (Reservation->NameReserved && RegistryReservedNameBytes >= nameBytes)
        RegistryReservedNameBytes -= nameBytes;
    Reservation->NameReserved = FALSE;
}

static PSTAGE_REGISTRY_ENTRY StageRegistryGetOrInsert(_In_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ const FILE_ID_INFORMATION *Identity, _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_ENTRY entry;
    PSTAGE_REGISTRY_ENTRY unusedShell = NULL;
    ULONG capacity;

    FltAcquirePushLockExclusive(&RegistryLock);
    if (InterlockedCompareExchange(&Reservation->TeardownState, 0, 0) != SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
        FltReleasePushLock(&RegistryLock);
        return NULL;
    }
    /* Convert the pre-create capacity reservation under the same lock used to
     * insert history, but keep its name listed until post-create has committed
     * H (or canceled the lower create). Diagnostics then cannot see a false
     * H=C=T=0 gap while the file ID is being bound. */
    StageRegistryReleaseReservationCapacityLocked(Reservation);
    entry = StageRegistryFindByKeyLocked(Reservation->Instance, Reservation->Volume,
        Identity->VolumeSerialNumber, &Identity->FileId, SectionObjectPointer);
    if (entry != NULL) {
        if (Reservation->Shell != NULL &&
            (InterlockedCompareExchange(&Reservation->Shell->UnknownReasons, 0, 0) &
                SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0)
            StageRegistrySetEntryUnknownLocked(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        StageRegistryReference(entry);
        Reservation->BoundEntry = entry;
        unusedShell = Reservation->Shell;
        Reservation->Shell = NULL;
        FltReleasePushLock(&RegistryLock);
        StageRegistryFreeShell(unusedShell);
        return entry;
    }

    capacity = StageRegistryCapacityLocked();
    if (Reservation->TrackingLost || Reservation->Shell == NULL ||
        (Reservation->CompactSlotReserved &&
         (RegistryCompactEntryCount + RegistryReservedCompactSlots >=
              SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT ||
          StageRegistryCompactInstanceCountLocked(Reservation->Instance) >=
              SAFEUPLOAD_WRITER_REGISTRY_COMPACT_INSTANCE_LIMIT)) ||
        (!Reservation->CompactSlotReserved &&
         (RegistryEntryCount + RegistryReservedSlots >= capacity ||
          StageRegistryInstanceCountLocked(Reservation->Instance) >=
              min((ULONG)SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT, capacity) ||
          RegistryNameBytes + RegistryReservedNameBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET -
              StageRegistryEntryNameStorageBytes(Reservation->Shell)))) {
        RegistryOverflow += 1;
        FltReleasePushLock(&RegistryLock);
        InterlockedIncrement64(&RegistryCapacityFailures);
        StageRegistryQueueReclaim();
        return NULL;
    }

    entry = Reservation->Shell;
    Reservation->Shell = NULL;
    entry->Instance = Reservation->Instance;
    entry->Volume = Reservation->Volume;
    Reservation->InstanceReferenceTransferred = TRUE;
    Reservation->VolumeReferenceTransferred = TRUE;
    entry->VolumeSerial = Identity->VolumeSerialNumber;
    entry->FileId = Identity->FileId;
    entry->SectionObjectPointer = SectionObjectPointer;
    entry->RenameLossGeneration = Reservation->RenameLossGeneration;
    entry->FirstSeenGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
    entry->State = InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) != 0 ?
        SAFEUPLOAD_REGISTRY_STATE_UNKNOWN : SAFEUPLOAD_REGISTRY_STATE_UNSCOPED;
    entry->LastSState = SAFEUPLOAD_REGISTRY_S_UNKNOWN;
    entry->Sequence = ++RegistryEntrySequence;
    KeInitializeSpinLock(&entry->HolderLock);
    KeInitializeSpinLock(&entry->StateLock);
    entry->Listed = TRUE;
    entry->References = 2; /* Registry history plus the reservation's bound-entry reference. */
    InsertTailList(&RegistryEntries, &entry->Link);
    if (entry->Compact) RegistryCompactEntryCount += 1;
    else {
        RegistryEntryCount += 1;
        RegistryNameBytes += StageRegistryEntryNameStorageBytes(entry);
    }
    Reservation->BoundEntry = entry;
    {
        /* Reclaim before the limits are reached: at 3/4 of the instance or total limit. */
        BOOLEAN pressure = RegistryEntryCount * 4 >= capacity * 3 ||
            RegistryCompactEntryCount * 4 >= SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT * 3 / 4 ||
            StageRegistryInstanceCountLocked(Reservation->Instance) * 4 >=
                min((ULONG)SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT, capacity) * 3 ||
            StageRegistryCompactInstanceCountLocked(Reservation->Instance) * 4 >=
                SAFEUPLOAD_WRITER_REGISTRY_COMPACT_INSTANCE_LIMIT * 3 / 4;
        FltReleasePushLock(&RegistryLock);
        if (pressure) StageRegistryQueueReclaim();
    }
    return entry;
}

UINT32 SafeUploadStageWritersGlobalUnknown(VOID)
{
    return (UINT32)InterlockedCompareExchange(&WriterGlobalUnknown, 0, 0);
}

VOID SafeUploadStageWritersTrackingLost(_In_opt_ PFLT_INSTANCE Instance, _In_ LONG Reason)
{
    /* Tracking is a ledger: loss is recorded at the instance when identifiable,
     * and never converted into a refusal of the create that exposed the loss. */
    StageRegistryMarkUnknown(Instance, Reason, FALSE);
}

VOID SafeUploadStageWritersInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Reason)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT context = NULL;
    NTSTATUS status;
    BOOLEAN dismount;

    PAGED_CODE();

    /* InstanceTeardownStart is PASSIVE_LEVEL and precedes context teardown. */
    dismount = FlagOn(Reason, FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT);
    if (dismount) InterlockedIncrement64(&InstanceTeardownsDismount);
    else InterlockedIncrement64(&InstanceTeardownsOther);
    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) {
        /* Even without our instance context, teardown must unlink every history entry and
         * release its rundown references. A live mounted drop is widened by RetireInstance. */
        StageRegistryBeginInstanceTeardown(FltObjects->Instance, NULL, dismount);
        StageRegistryRetireInstance(FltObjects->Instance, dismount);
        return;
    }

    /* A detached/dismounted instance can never carry trust into a later
     * attachment. Preserve an explicit Untrusted state while its context is
     * still available for the admission readout. */
    InterlockedExchange(&context->TrustState, SAFEUPLOAD_VOLUME_TRUST_DETACHED);
    InterlockedExchange(&context->CanaryState, SAFEUPLOAD_CANARY_DETACHED);

    if (context->TeardownToken == NULL)
        StageRegistryMarkUnknown(FltObjects->Instance,
            SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
    /* Serialize the token transition and every in-flight pre-create reservation
     * against post-create's H commit. */
    StageRegistryBeginInstanceTeardown(FltObjects->Instance, context->TeardownToken,
        FlagOn(Reason, FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT));
    StageRegistryRetireInstance(FltObjects->Instance,
        FlagOn(Reason, FLTFL_INSTANCE_TEARDOWN_VOLUME_DISMOUNT));
    FltReleaseContext(context);
}

/* Nonpaged: the instance context cleanup callback may run at APC_LEVEL. */
VOID SafeUploadStageWritersInstanceContextFreed(
    _Inout_ PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN Token,
    _In_ BOOLEAN Published)
{
    if (Published && InterlockedCompareExchange(&Token->State,
            SAFEUPLOAD_INSTANCE_STATE_UNKNOWN, SAFEUPLOAD_INSTANCE_STATE_ACTIVE) ==
            SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
        InterlockedExchange(&WriterGlobalUnknown, 1);
    }
}

static BOOLEAN StageWritersExcludedObject(_In_ PFILE_OBJECT FileObject)
{
    /* Paging files do not support stream contexts, and volume handles are outside the
     * regular-file writer registry. This does not grant either object admission to a scope. */
    return FlagOn(FileObject->Flags, FO_VOLUME_OPEN) || FsRtlIsPagingFile(FileObject);
}

static BOOLEAN StageWriterCreateCanMutate(_In_ PFLT_CALLBACK_DATA Data)
{
    PIO_SECURITY_CONTEXT security = Data->Iopb->Parameters.Create.SecurityContext;
    ULONG disposition = Data->Iopb->Parameters.Create.Options >> 24;
    ULONG options = Data->Iopb->Parameters.Create.Options & 0x00ffffff;
    if ((options & FILE_DELETE_ON_CLOSE) != 0 || disposition == FILE_CREATE ||
        disposition == FILE_OPEN_IF || disposition == FILE_SUPERSEDE ||
        disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF) return TRUE;
    if (security == NULL) return FALSE;
    return (security->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE |
        GENERIC_ALL | MAXIMUM_ALLOWED)) != 0;
}

static BOOLEAN StageRegistryHasCreateReservationLocked(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ PCUNICODE_STRING NormalizedName)
{
    PLIST_ENTRY link;
    UNICODE_STRING baseName = StageRegistryBaseName(NormalizedName);
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reservation = CONTAINING_RECORD(link,
            STAGE_WRITER_RESERVATION, Link);
        UNICODE_STRING reservedName;
        if (!reservation->Active || reservation->Instance != Instance || reservation->Volume != Volume)
            continue;
        if (reservation->Shell != NULL && !reservation->Shell->Compact && reservation->NameChars != 0) {
            reservedName.Buffer = reservation->Shell->Name;
            reservedName.Length = reservedName.MaximumLength =
                (USHORT)(reservation->NameChars * sizeof(WCHAR));
        } else if (reservation->BoundEntry != NULL && reservation->BoundEntry->NameChars != 0) {
            reservedName.Buffer = reservation->BoundEntry->Name;
            reservedName.Length = reservedName.MaximumLength =
                (USHORT)(reservation->BoundEntry->NameChars * sizeof(WCHAR));
        } else continue;
        if (RtlEqualUnicodeString(&reservedName, &baseName, TRUE)) return TRUE;
    }
    return FALSE;
}

static VOID StageWritersFinishReservationAccounting(_Inout_ PSTAGE_WRITER_RESERVATION Reservation)
{
    FltAcquirePushLockExclusive(&RegistryLock);
    StageRegistryFinishReservationAccountingLocked(Reservation);
    FltReleasePushLock(&RegistryLock);
}

BOOLEAN SafeUploadStageWritersWantPostCreate(_In_ PFLT_CALLBACK_DATA Data)
{
    return StageWriterCreateCanMutate(Data);
}

NTSTATUS SafeUploadStageWritersReserveCreate(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _Outptr_result_maybenull_ PVOID *ReservationOut,
    _Out_ PBOOLEAN Required)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PFLT_FILE_NAME_INFORMATION name = NULL;
    PFLT_VOLUME volume = NULL;
    PSTAGE_WRITER_RESERVATION reservation = NULL;
    PUNICODE_STRING fullName = NULL;
    UNICODE_STRING registryName;
    FLT_FILESYSTEM_TYPE fs;
    SAFEUPLOAD_VOLUME_KIND kind;
    ULONG capacity, baseNameChars = 0, streamChars = 0;
    ULONGLONG directoryRenameGeneration, renameLossGeneration;
    BOOLEAN pathResolved = FALSE, streamIdentityKnown = FALSE;
    BOOLEAN byIdDefaultStream = FALSE, nameTierCandidate = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    *ReservationOut = NULL;
    *Required = FALSE;
    if (!StageWriterCreateCanMutate(Data) || fileObject == NULL ||
        StageWritersExcludedObject(fileObject) ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) return STATUS_SUCCESS;

    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&RegistryIdentityFailures);
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
        return STATUS_SUCCESS; /* tracking lost; the ledger never refuses a create */
    }
    kind = instanceContext->VolumeKind;
    directoryRenameGeneration = (ULONGLONG)InterlockedCompareExchange64(
        &instanceContext->RegistryDirectoryRenameGeneration, 0, 0);
    renameLossGeneration = (ULONGLONG)InterlockedCompareExchange64(
        &instanceContext->RegistryRenameLossGeneration, 0, 0);
    if (instanceContext->TeardownToken == NULL ||
        InterlockedCompareExchange(&instanceContext->TeardownToken->State, 0, 0) !=
            SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
        LONG teardownState = instanceContext->TeardownToken != NULL ?
            InterlockedCompareExchange(&instanceContext->TeardownToken->State, 0, 0) :
            SAFEUPLOAD_INSTANCE_STATE_UNKNOWN;
        FltReleaseContext(instanceContext);
        if (teardownState != SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
            StageRegistryMarkUnknown(FltObjects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
        }
        return STATUS_SUCCESS; /* the instance is going away; its creates proceed untracked */
    }
    if (InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0 ||
        InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0) {
        /* Already Unknown until reboot: nothing left to track and no protection is claimed. The registry is a ledger,
         * not a gate (MVP-PLAN 2026-10-04): refusing here locked every writer out of the volume (registry-txf runs 2-4). */
        FltReleaseContext(instanceContext);
        return STATUS_SUCCESS;
    }
    FltReleaseContext(instanceContext);
    instanceContext = NULL;
    status = FltGetFileSystemType(FltObjects->Instance, &fs);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&RegistryIdentityFailures);
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
        return STATUS_SUCCESS;
    }
    if (kind != SafeUploadVolumeFixed || fs != FLT_FSTYPE_NTFS)
        return STATUS_SUCCESS; /* Registry scope is the qualified fixed-NTFS envelope. */
    *Required = TRUE;

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
        /* D2/D6: a low-half by-ID open still yields a post-create file ID and SOP,
         * so keep a compact candidate and derive its link names on the worker. */
        byIdDefaultStream = TRUE;
        streamIdentityKnown = TRUE;
        goto PrepareReservation;
    }
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) goto RefuseIdentity;
    status = FltParseFileNameInformation(name);
    if (!NT_SUCCESS(status) || name->Volume.Length > name->Name.Length ||
        name->Name.Length == 0 || (name->Name.Length & 1) != 0) goto RefuseIdentity;
    fullName = &name->Name;
    if (name->Stream.Length > fullName->Length || (name->Stream.Length & 1) != 0)
        goto RefuseIdentity;
    baseNameChars = (fullName->Length - name->Stream.Length) / sizeof(WCHAR);
    streamChars = name->Stream.Length / sizeof(WCHAR);
    if (baseNameChars == 0 || streamChars > MAXUSHORT / sizeof(WCHAR)) goto RefuseIdentity;
    registryName = *fullName;
    registryName.Length = registryName.MaximumLength =
        (USHORT)(fullName->Length - name->Stream.Length);
    pathResolved = TRUE;
    streamIdentityKnown = TRUE;

PrepareReservation:
    reservation = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*reservation), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (reservation == NULL) goto RefuseAllocation;
    RtlZeroMemory(reservation, sizeof(*reservation));
    reservation->Signature = SAFEUPLOAD_REGISTRY_RESERVATION_SIGNATURE;
    reservation->TeardownState = SAFEUPLOAD_INSTANCE_STATE_ACTIVE;
    reservation->Instance = FltObjects->Instance;
    status = FltObjectReference(reservation->Instance);
    if (!NT_SUCCESS(status)) { reservation->Instance = NULL; goto RefuseAllocation; }
    status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
    if (!NT_SUCCESS(status)) goto RefuseAllocation;
    reservation->Volume = volume;
    volume = NULL;

    nameTierCandidate = pathResolved && !byIdDefaultStream &&
        baseNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS &&
        streamChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS;
    reservation->Shell = nameTierCandidate ? StageRegistryAllocateNamedShell() : NULL;
    reservation->Node = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*reservation->Node), SAFEUPLOAD_WRITER_NODE_POOL_TAG);
    if (reservation->Node == NULL) goto RefuseAllocation;
    if (reservation->Shell != NULL) {
        reservation->Shell->VolumeKind = kind;
        reservation->Shell->NameChars = (USHORT)baseNameChars;
        reservation->Shell->StreamChars = (USHORT)streamChars;
        reservation->Shell->StreamIdentityKnown = streamIdentityKnown;
        if (pathResolved && fullName != NULL && baseNameChars != 0)
            RtlCopyMemory(reservation->Shell->Name, fullName->Buffer,
                baseNameChars * sizeof(WCHAR));
        if (pathResolved && streamChars != 0 && name != NULL)
            RtlCopyMemory(reservation->Shell->StreamName, name->Stream.Buffer,
                streamChars * sizeof(WCHAR));
    }
    RtlZeroMemory(reservation->Node, sizeof(*reservation->Node));
    reservation->NameChars = nameTierCandidate ? baseNameChars : 0;
    reservation->StreamChars = pathResolved ? streamChars : 0;
    reservation->RenameLossGeneration = renameLossGeneration;
    reservation->StreamSuffixHash = name != NULL && name->Stream.Length != 0 ?
        StageRegistryStreamSuffixHash(&name->Stream) : 0;
    if (reservation->Shell != NULL) {
        reservation->Shell->StreamSuffixHash = reservation->StreamSuffixHash;
        if (!streamIdentityKnown) {
            /* No suffix identity means a later candidate cannot be promoted. */
            reservation->Shell->UnknownReasons = SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
            reservation->Shell->State = SAFEUPLOAD_REGISTRY_STATE_UNKNOWN;
        }
    }
    if (!streamIdentityKnown)
        reservation->UnknownReasons |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;

    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
        status = STATUS_SUCCESS;
        goto Cleanup;
    }
    FltAcquirePushLockExclusive(&RegistryLock);
    if (instanceContext->TeardownToken == NULL ||
        InterlockedCompareExchange(&instanceContext->TeardownToken->State, 0, 0) !=
            SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
        LONG teardownState = instanceContext->TeardownToken != NULL ?
            InterlockedCompareExchange(&instanceContext->TeardownToken->State, 0, 0) :
            SAFEUPLOAD_INSTANCE_STATE_UNKNOWN;
        FltReleasePushLock(&RegistryLock);
        FltReleaseContext(instanceContext);
        instanceContext = NULL;
        if (teardownState != SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN)
            StageRegistryMarkUnknown(FltObjects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
        status = STATUS_SUCCESS;
        goto Cleanup;
    }
    if (pathResolved && (ULONGLONG)InterlockedCompareExchange64(
            &instanceContext->RegistryDirectoryRenameGeneration, 0, 0) != directoryRenameGeneration &&
        !StageRegistryDirectoryRenameInFlightLocked(FltObjects->Instance, &registryName)) {
        /* The name was resolved before a directory move completed and the
         * reservation arrived too late for that completion's bounded rewrite. */
        if (reservation->Shell != NULL)
            StageRegistrySetEntryUnknownLocked(reservation->Shell, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        else reservation->UnknownReasons |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME;
        InterlockedIncrement64(&RegistryRenameFailures);
    }
    if (pathResolved && (ULONGLONG)InterlockedCompareExchange64(
            &instanceContext->RegistryRenameLossGeneration, 0, 0) != renameLossGeneration) {
        if (reservation->Shell != NULL)
            StageRegistrySetEntryUnknownLocked(reservation->Shell, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        else reservation->UnknownReasons |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME;
        InterlockedIncrement64(&RegistryRenameFailures);
    }
    capacity = StageRegistryCapacityLocked();
    /* D2: reserve a full-name record when both its entry and byte tiers have
     * room. Otherwise reserve one fixed compact identity record. */
    if (reservation->Shell != NULL && !reservation->Shell->Compact &&
        (RegistryEntryCount + RegistryReservedSlots >= capacity ||
         StageRegistryInstanceCountLocked(FltObjects->Instance) >=
            min((ULONG)SAFEUPLOAD_WRITER_REGISTRY_INSTANCE_LIMIT, capacity) ||
         RegistryNameBytes + RegistryReservedNameBytes +
            StageRegistryNameStorageBytes((USHORT)reservation->NameChars,
                (USHORT)reservation->StreamChars) > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET)) {
        StageRegistryFreeShell(reservation->Shell);
        reservation->Shell = NULL;
        reservation->NameChars = 0;
    }
    if (reservation->Shell == NULL)
        reservation->Shell = StageRegistryCompactPoolPop();
    if (reservation->Shell == NULL ||
        RegistryCompactEntryCount + RegistryReservedCompactSlots >= SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT ||
        StageRegistryCompactInstanceCountLocked(FltObjects->Instance) >=
            SAFEUPLOAD_WRITER_REGISTRY_COMPACT_INSTANCE_LIMIT) {
        StageRegistryFreeShell(reservation->Shell);
        reservation->Shell = NULL;
        reservation->TrackingLost = TRUE;
        RegistryOverflow += 1;
        InterlockedIncrement64(&RegistryCapacityFailures);
        FltReleasePushLock(&RegistryLock);
        FltReleaseContext(instanceContext);
        instanceContext = NULL;
        if (name != NULL) FltReleaseFileNameInformation(name);
        (VOID)StageRegistryQueueReclaim();
        /* Keep the post-create callback so a known SOP gets a narrow Unknown marker. */
        *Required = TRUE;
        *ReservationOut = reservation;
        return STATUS_SUCCESS;
    }
    if (reservation->Shell->Compact) {
        reservation->Shell->VolumeKind = kind;
        reservation->Shell->NameChars = 0;
        /* Compact records retain the stream bit and suffix hash, never suffix path text. */
        reservation->Shell->StreamChars = 0;
        reservation->Shell->StreamIdentityKnown = streamIdentityKnown;
        reservation->Shell->CompactStream = reservation->StreamChars != 0;
        reservation->Shell->StreamSuffixHash = reservation->StreamSuffixHash;
        reservation->NameChars = 0;
        reservation->CompactSlotReserved = TRUE;
        RegistryReservedCompactSlots += 1;
    } else {
        reservation->NameReserved = TRUE;
        RegistryReservedNameBytes += StageRegistryNameStorageBytes(
            (USHORT)reservation->NameChars, (USHORT)reservation->StreamChars);
        RegistryReservedSlots += 1;
    }
    if (reservation->UnknownReasons != 0) {
        InterlockedOr(&reservation->Shell->UnknownReasons, reservation->UnknownReasons);
        reservation->Shell->State = SAFEUPLOAD_REGISTRY_STATE_UNKNOWN;
    }
    reservation->SlotReserved = TRUE;
    InsertTailList(&RegistryReservations, &reservation->Link);
    reservation->Active = TRUE;
    RegistryReservationCount += 1;
    FltReleasePushLock(&RegistryLock);
    FltReleaseContext(instanceContext);
    instanceContext = NULL;
    if (name != NULL) FltReleaseFileNameInformation(name);
    *ReservationOut = reservation;
    return STATUS_SUCCESS;

RefuseIdentity:
    InterlockedIncrement64(&RegistryIdentityFailures);
    status = STATUS_SUCCESS;
    pathResolved = FALSE;
    goto PrepareReservation;
RefuseAllocation:
    InterlockedIncrement64(&RegistryAllocationFailures);
    StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION, FALSE);
    status = STATUS_SUCCESS;
Cleanup:
    /* Every path here lost tracking (success returned above): Unknown is recorded, nothing is required, nothing is refused. */
    *Required = FALSE;
    *ReservationOut = NULL;
    if (instanceContext != NULL) FltReleaseContext(instanceContext);
    if (name != NULL) FltReleaseFileNameInformation(name);
    if (volume != NULL) FltObjectDereference(volume);
    SafeUploadStageWritersCancelReservation(reservation);
    return status;
}

VOID SafeUploadStageWritersCancelReservation(_In_opt_ PVOID Context)
{
    PSTAGE_WRITER_RESERVATION reservation = (PSTAGE_WRITER_RESERVATION)Context;
    if (reservation == NULL || reservation->Signature != SAFEUPLOAD_REGISTRY_RESERVATION_SIGNATURE) return;
    StageWritersFinishReservationAccounting(reservation);
    if (reservation->Node != NULL) ExFreePoolWithTag(reservation->Node, SAFEUPLOAD_WRITER_NODE_POOL_TAG);
    if (reservation->Shell != NULL) StageRegistryFreeShell(reservation->Shell);
    if (reservation->BoundEntry != NULL) StageRegistryDereference(reservation->BoundEntry);
    if (reservation->Volume != NULL && !reservation->VolumeReferenceTransferred)
        FltObjectDereference(reservation->Volume);
    if (reservation->Instance != NULL && !reservation->InstanceReferenceTransferred)
        FltObjectDereference(reservation->Instance);
    reservation->Signature = 0;
    ExFreePoolWithTag(reservation, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

static BOOLEAN StageRegistryDirectoryPrefixesOverlap(_In_ PSTAGE_REGISTRY_RENAME_CONTEXT First,
    _In_ PSTAGE_REGISTRY_RENAME_CONTEXT Second)
{
    UNICODE_STRING firstOld, firstNew, secondOld, secondNew;
    firstOld.Buffer = First->OldName;
    firstOld.Length = firstOld.MaximumLength = First->OldNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ?
        (USHORT)(First->OldNameChars * sizeof(WCHAR)) : 0;
    firstNew.Buffer = First->Name;
    firstNew.Length = firstNew.MaximumLength = !First->NewNameTooLong &&
        First->NewNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ?
        (USHORT)(First->NewNameChars * sizeof(WCHAR)) : 0;
    secondOld.Buffer = Second->OldName;
    secondOld.Length = secondOld.MaximumLength = Second->OldNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ?
        (USHORT)(Second->OldNameChars * sizeof(WCHAR)) : 0;
    secondNew.Buffer = Second->Name;
    secondNew.Length = secondNew.MaximumLength = !Second->NewNameTooLong &&
        Second->NewNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ?
        (USHORT)(Second->NewNameChars * sizeof(WCHAR)) : 0;
    return (firstOld.Length != 0 && secondOld.Length != 0 &&
            StageRegistryPathPrefixesOverlap(&firstOld, &secondOld)) ||
        (firstOld.Length != 0 && secondNew.Length != 0 &&
            StageRegistryPathPrefixesOverlap(&firstOld, &secondNew)) ||
        (firstNew.Length != 0 && secondOld.Length != 0 &&
            StageRegistryPathPrefixesOverlap(&firstNew, &secondOld)) ||
        (firstNew.Length != 0 && secondNew.Length != 0 &&
            StageRegistryPathPrefixesOverlap(&firstNew, &secondNew));
}

NTSTATUS SafeUploadStageWritersPrepareRename(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ PCUNICODE_STRING Source,
    _In_ PCUNICODE_STRING Destination, _In_ BOOLEAN LinkOperation,
    _Outptr_result_maybenull_ PVOID *RenameContext)
{
    FILE_ID_INFORMATION identity;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    PSTAGE_REGISTRY_RENAME_CONTEXT context = NULL;
    PFLT_VOLUME volume = NULL;
    BOOLEAN isDirectory = FALSE;
    UNICODE_STRING destinationBase = { 0 }, destinationStream = { 0 };
    ULONG returned = 0;
    NTSTATUS status;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(Data);
    *RenameContext = NULL;
    status = FltObjects->FileObject != NULL ?
        FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory) :
        STATUS_INVALID_PARAMETER;
    if ((NT_SUCCESS(status) && isDirectory) || !NT_SUCCESS(status)) {
        ULONG oldChars, newChars;

        /* Orchestrator decision: a successful directory rename rewrites every
         * retained descendant name under one bounded RegistryLock walk. Names
         * that cannot fit become Unknown(RENAME) on that entry alone. Missing
         * names or failure to retain the transient record use the existing
         * instance tracking-loss fallback; tracking loss never vetoes rename. */
        if (Source == NULL || Destination == NULL || Source->Buffer == NULL || Destination->Buffer == NULL ||
            Source->Length == 0 || Destination->Length == 0 ||
            ((Source->Length | Destination->Length) & (sizeof(WCHAR) - 1)) != 0) {
            StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
            InterlockedIncrement64(&RegistryRenameFailures);
            return STATUS_SUCCESS;
        }
        oldChars = Source->Length / sizeof(WCHAR);
        newChars = Destination->Length / sizeof(WCHAR);
        context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), SAFEUPLOAD_REGISTRY_POOL_TAG);
        if (context == NULL) {
            StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
            InterlockedIncrement64(&RegistryRenameFailures);
            return STATUS_SUCCESS;
        }
        RtlZeroMemory(context, sizeof(*context));
        context->Signature = SAFEUPLOAD_REGISTRY_RENAME_SIGNATURE;
        context->InstanceIdentity = (PVOID)FltObjects->Instance; /* comparison only; no instance reference is taken */
        context->DirectoryRename = TRUE;
        context->LinkOperation = LinkOperation;
        context->OldNameChars = oldChars;
        context->NewNameChars = newChars;
        context->NewNameTooLong = newChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS;
        if (oldChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS)
            RtlCopyMemory(context->OldName, Source->Buffer, Source->Length);
        if (!context->NewNameTooLong)
            RtlCopyMemory(context->Name, Destination->Buffer, Destination->Length);

        FltAcquirePushLockExclusive(&RegistryLock);
        StageRegistryPurgeAbandonedDirectoryRenamesLocked();
        if (RegistryDirectoryRenameCount >= SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT) {
            FltReleasePushLock(&RegistryLock);
            StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
            InterlockedIncrement64(&RegistryRenameFailures);
            ExFreePoolWithTag(context, SAFEUPLOAD_REGISTRY_POOL_TAG);
            return STATUS_SUCCESS;
        }
        {
            PLIST_ENTRY link;
            for (link = RegistryDirectoryRenames.Flink; link != &RegistryDirectoryRenames; link = link->Flink) {
                PSTAGE_REGISTRY_RENAME_CONTEXT other = CONTAINING_RECORD(link,
                    STAGE_REGISTRY_RENAME_CONTEXT, Link);
                if (other->InstanceIdentity == context->InstanceIdentity &&
                    StageRegistryDirectoryPrefixesOverlap(context, other)) {
                    context->Ambiguous = TRUE;
                    other->Ambiguous = TRUE;
                }
            }
        }
        InsertTailList(&RegistryDirectoryRenames, &context->Link);
        context->Listed = TRUE;
        RegistryDirectoryRenameCount += 1;
        InterlockedIncrement64(&RegistryChangeSequence);
        FltReleasePushLock(&RegistryLock);
        *RenameContext = context;
        return STATUS_SUCCESS;
    }

    if (!LinkOperation && (Destination == NULL || Destination->Buffer == NULL ||
        Destination->Length == 0 || (Destination->Length & 1) != 0)) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
        InterlockedIncrement64(&RegistryRenameFailures);
        return STATUS_SUCCESS;
    }
    if (!LinkOperation) {
        StageRegistrySplitStreamName(Destination, &destinationBase, &destinationStream);
        if (destinationBase.Length == 0 ||
            destinationBase.Length / sizeof(WCHAR) > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ||
            destinationStream.Length / sizeof(WCHAR) > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
            StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
            InterlockedIncrement64(&RegistryRenameFailures);
            return STATUS_SUCCESS;
        }
    }

    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject,
        &identity, sizeof(identity), FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(identity)) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
        InterlockedIncrement64(&RegistryRenameFailures);
        return STATUS_SUCCESS;
    }
    status = FltGetVolumeFromInstance(FltObjects->Instance, &volume);
    if (!NT_SUCCESS(status)) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
        InterlockedIncrement64(&RegistryRenameFailures);
        return STATUS_SUCCESS;
    }

    FltAcquirePushLockExclusive(&RegistryLock);
    entry = StageRegistryFindByKeyLocked(FltObjects->Instance, volume,
        identity.VolumeSerialNumber, &identity.FileId,
        FltObjects->FileObject != NULL ? FltObjects->FileObject->SectionObjectPointer : NULL);
    if (entry != NULL) StageRegistryReference(entry);
    FltReleasePushLock(&RegistryLock);
    FltObjectDereference(volume);
    if (entry == NULL) return STATUS_SUCCESS;

    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (context == NULL) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        InterlockedIncrement64(&RegistryRenameFailures);
        StageRegistryDereference(entry);
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(context, sizeof(*context));
    context->Signature = SAFEUPLOAD_REGISTRY_RENAME_SIGNATURE;
    context->Entry = entry;
    context->LinkOperation = LinkOperation;
    if (!LinkOperation) {
        context->NameChars = destinationBase.Length / sizeof(WCHAR);
        context->NewStreamChars = destinationStream.Length / sizeof(WCHAR);
        RtlCopyMemory(context->Name, destinationBase.Buffer, destinationBase.Length);
        if (context->NewStreamChars != 0) {
            RtlCopyMemory(context->StreamName, destinationStream.Buffer, destinationStream.Length);
            context->StreamSuffixRetained = TRUE;
        } else {
            /* A base-file rename carries each tracked stream with its file. */
            FltAcquirePushLockShared(&RegistryLock);
            context->CompactStreamIdentity = entry->Compact && entry->CompactStream &&
                entry->StreamIdentityKnown;
            context->CompactStreamSuffixHash = entry->StreamSuffixHash;
            context->NewStreamChars = entry->Compact ? 0 : entry->StreamChars;
            if (context->NewStreamChars != 0 && entry->StreamName != NULL) {
                RtlCopyMemory(context->StreamName, entry->StreamName,
                    context->NewStreamChars * sizeof(WCHAR));
                context->StreamSuffixRetained = TRUE;
            }
            FltReleasePushLock(&RegistryLock);
        }
    }
    FltAcquirePushLockExclusive(&RegistryLock);
    if (!entry->Listed || entry->Retired) {
        FltReleasePushLock(&RegistryLock);
        context->Signature = 0;
        StageRegistryDereference(entry);
        ExFreePoolWithTag(context, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return STATUS_SUCCESS;
    }
    context->Ambiguous = InterlockedIncrement(&entry->RenameInFlight) != 1;
    InterlockedIncrement(&entry->RenameVersion);
    InterlockedExchange(&entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
    FltReleasePushLock(&RegistryLock);
    if (context->Ambiguous) StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
    *RenameContext = context;
    return STATUS_SUCCESS;
}

BOOLEAN SafeUploadStageWritersIsRenameContext(_In_opt_ PVOID Context)
{
    PSTAGE_REGISTRY_RENAME_CONTEXT rename = (PSTAGE_REGISTRY_RENAME_CONTEXT)Context;
    if (rename == NULL || (ULONG_PTR)rename < 0x10000) return FALSE;
    return rename->Signature == SAFEUPLOAD_REGISTRY_RENAME_SIGNATURE;
}

static VOID StageRegistryCompleteDirectoryRename(_In_ PFLT_INSTANCE Instance,
    _Inout_ PSTAGE_REGISTRY_RENAME_CONTEXT Rename, _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    PLIST_ENTRY link;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    UNICODE_STRING oldName, newName;
    BOOLEAN uncertain, failed = FALSE, haveInstanceContext, recheck = FALSE;

    /* Not placed in PAGE (no PAGED_CODE). Names are rewritten in place: the suffix is shifted with RtlMoveMemory (overlap-safe)
     * before the new prefix is copied, so no 1 KB scratch buffer is needed on the stack (PREfast C6262) and no allocation can fail. */
    haveInstanceContext = NT_SUCCESS(FltGetInstanceContext(Instance,
        (PFLT_CONTEXT *)&instanceContext));
    oldName.Buffer = Rename->OldName;
    oldName.Length = oldName.MaximumLength = Rename->OldNameChars <=
        SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ?
        (USHORT)(Rename->OldNameChars * sizeof(WCHAR)) : 0;
    newName.Buffer = Rename->Name;
    newName.Length = newName.MaximumLength = !Rename->NewNameTooLong &&
        Rename->NewNameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ?
        (USHORT)(Rename->NewNameChars * sizeof(WCHAR)) : 0;
    uncertain = Draining || (Succeeded && (Rename->Ambiguous || Rename->LinkOperation));

    FltAcquirePushLockExclusive(&RegistryLock);
    if (Rename->Listed) {
        /* A live directory rename record makes the whole affected path range
         * transiently Unknown to readers. This completion walk is bounded by
         * RegistryEntryCount's pruning limit and updates all retained paths
         * atomically while readers take the same lock. */
        for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
            PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
            UNICODE_STRING entryName;
            BOOLEAN oldMatch, newMatch;

            if (entry->Retired || !entry->Listed || (PVOID)entry->Instance != Rename->InstanceIdentity) continue;
            if (entry->Compact) {
                if (uncertain) {
                    StageRegistrySetEntryUnknownLocked(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    StageRegistryPrepareActivation(entry, TRUE);
                    failed = TRUE;
                } else if (Succeeded && StageRegistryBeginAliasProbe(entry)) {
                    recheck = TRUE;
                }
                continue;
            }
            entryName.Buffer = entry->Name;
            entryName.Length = entryName.MaximumLength =
                (USHORT)(entry->NameChars * sizeof(WCHAR));
            oldMatch = oldName.Length != 0 && StageRegistryNameHasPathPrefix(&entryName, &oldName);
            newMatch = newName.Length != 0 && StageRegistryNameHasPathPrefix(&entryName, &newName);
            if (oldMatch || newMatch) recheck = TRUE;

            if (uncertain) {
                if (oldMatch || newMatch) {
                    StageRegistrySetEntryUnknownLocked(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    InterlockedIncrement(&entry->RenameVersion);
                    failed = TRUE;
                }
                continue;
            }
            if (!Succeeded || !oldMatch) continue;

            /* A concurrent file rename makes this entry's final path ambiguous;
             * keep the loss on this file instead of guessing a combined name. */
            if (InterlockedCompareExchange(&entry->RenameInFlight, 0, 0) != 0 ||
                Rename->NewNameTooLong || oldName.Length == 0 ||
                entry->NameChars < Rename->OldNameChars) {
                StageRegistrySetEntryUnknownLocked(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                InterlockedIncrement(&entry->RenameVersion);
                failed = TRUE;
                continue;
            }
            {
                ULONG suffixChars = entry->NameChars - Rename->OldNameChars;
                ULONG newChars = Rename->NewNameChars + suffixChars;
                ULONG oldBytes = StageRegistryEntryNameStorageBytes(entry);
                ULONG newBytes;
                if (newChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
                    StageRegistrySetEntryUnknownLocked(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    InterlockedIncrement(&entry->RenameVersion);
                    failed = TRUE;
                    continue;
                }
                newBytes = StageRegistryNameStorageBytes((USHORT)newChars, entry->StreamChars);
                if (RegistryNameBytes < oldBytes || newBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET ||
                    RegistryReservedNameBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET - newBytes ||
                    RegistryNameBytes - oldBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET -
                        RegistryReservedNameBytes - newBytes) {
                    StageRegistrySetEntryUnknownLocked(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    InterlockedIncrement(&entry->RenameVersion);
                    failed = TRUE;
                    continue;
                }
                if (suffixChars != 0)
                    RtlMoveMemory(entry->Name + Rename->NewNameChars,
                        entry->Name + Rename->OldNameChars, suffixChars * sizeof(WCHAR));
                RtlCopyMemory(entry->Name, Rename->Name, Rename->NewNameChars * sizeof(WCHAR));
                if (newChars < SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS)
                    RtlZeroMemory(entry->Name + newChars,
                        (SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS - newChars) * sizeof(WCHAR));
                entry->NameChars = (USHORT)newChars;
                InterlockedExchange(&entry->ScopeNameClassification,
                    STAGE_SCOPE_CLASS_UNRESOLVED);
                RegistryNameBytes = RegistryNameBytes - oldBytes + newBytes;
                InterlockedIncrement(&entry->RenameVersion);
                InterlockedIncrement64(&RegistryChangeSequence);
            }
        }
        /* A mutating create can still be between reserve and post-create while
         * the directory move completes. Its pre-create shell is bounded by the
         * same registry limits, so carry the prefix rewrite into that shell too. */
        for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
            PSTAGE_WRITER_RESERVATION reservation = CONTAINING_RECORD(link,
                STAGE_WRITER_RESERVATION, Link);
            PSTAGE_REGISTRY_ENTRY shell = reservation->Shell;
            UNICODE_STRING reservationName;
            BOOLEAN oldMatch, newMatch;

            if (!reservation->Active || !reservation->NameReserved || shell == NULL ||
                reservation->NameChars == 0) continue;
            reservationName.Buffer = shell->Name;
            reservationName.Length = reservationName.MaximumLength =
                (USHORT)(reservation->NameChars * sizeof(WCHAR));
            oldMatch = oldName.Length != 0 && StageRegistryNameHasPathPrefix(&reservationName, &oldName);
            newMatch = newName.Length != 0 && StageRegistryNameHasPathPrefix(&reservationName, &newName);
            if (uncertain) {
                if (oldMatch || newMatch) {
                    StageRegistrySetEntryUnknownLocked(shell, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    failed = TRUE;
                }
                continue;
            }
            if (!Succeeded || !oldMatch) continue;
            if (Rename->NewNameTooLong || reservation->NameChars < Rename->OldNameChars) {
                StageRegistrySetEntryUnknownLocked(shell, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                failed = TRUE;
                continue;
            }
            {
                ULONG suffixChars = reservation->NameChars - Rename->OldNameChars;
                ULONG newChars = Rename->NewNameChars + suffixChars;
                ULONG oldBytes = StageRegistryNameStorageBytes((USHORT)reservation->NameChars,
                    (USHORT)reservation->StreamChars);
                ULONG newBytes;
                if (newChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
                    StageRegistrySetEntryUnknownLocked(shell, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    failed = TRUE;
                    continue;
                }
                newBytes = StageRegistryNameStorageBytes((USHORT)newChars,
                    (USHORT)reservation->StreamChars);
                if (RegistryReservedNameBytes < oldBytes ||
                    RegistryNameBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET - newBytes ||
                    RegistryReservedNameBytes - oldBytes >
                        SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET - RegistryNameBytes - newBytes) {
                    StageRegistrySetEntryUnknownLocked(shell, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                    failed = TRUE;
                    continue;
                }
                if (suffixChars != 0)
                    RtlMoveMemory(shell->Name + Rename->NewNameChars,
                        shell->Name + Rename->OldNameChars, suffixChars * sizeof(WCHAR));
                RtlCopyMemory(shell->Name, Rename->Name, Rename->NewNameChars * sizeof(WCHAR));
                if (newChars < SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS)
                    RtlZeroMemory(shell->Name + newChars,
                        (SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS - newChars) * sizeof(WCHAR));
                shell->NameChars = (USHORT)newChars;
                reservation->NameChars = newChars;
                RegistryReservedNameBytes = RegistryReservedNameBytes - oldBytes + newBytes;
                InterlockedIncrement64(&RegistryChangeSequence);
            }
        }
        if ((Succeeded || Draining) && haveInstanceContext)
            InterlockedIncrement64(&instanceContext->RegistryDirectoryRenameGeneration);
        RemoveEntryList(&Rename->Link);
        Rename->Listed = FALSE;
        if (RegistryDirectoryRenameCount != 0) RegistryDirectoryRenameCount -= 1;
        InterlockedIncrement64(&RegistryChangeSequence);
    } else {
        /* Lost completion-list membership is itself an identity tracking loss. */
        InterlockedOr((volatile LONG *)&RegistryUnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        InterlockedExchange(&WriterGlobalUnknown, 1);
        failed = TRUE;
    }
    FltReleasePushLock(&RegistryLock);
    /* A reclaim worker may have skipped these entries while the path range was
     * in flight; one recheck resumes activation/pruning after the atomic rewrite. */
    if (recheck) (VOID)StageRegistryQueueReclaim();
    if ((Succeeded || Draining) && !haveInstanceContext) {
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
        failed = TRUE;
    }
    if (Rename->InstanceIdentity != (PVOID)Instance) {
        InterlockedOr((volatile LONG *)&RegistryUnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        InterlockedExchange(&WriterGlobalUnknown, 1);
        failed = TRUE;
    }
    if (failed) InterlockedIncrement64(&RegistryRenameFailures);
    if (instanceContext != NULL) FltReleaseContext(instanceContext);
    Rename->Signature = 0;
    ExFreePoolWithTag(Rename, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

static BOOLEAN StageRegistryQueueDeferredRename(_In_ PFLT_INSTANCE Instance,
    _In_ PSTAGE_REGISTRY_RENAME_CONTEXT Rename, _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    PSTAGE_DEFERRED_RENAME deferred;
    PFLT_GENERIC_WORKITEM item;
    NTSTATUS status;

    deferred = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*deferred), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (deferred == NULL) return FALSE;
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) {
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return FALSE;
    }
    status = FltObjectReference(Instance);
    if (!NT_SUCCESS(status)) {
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return FALSE;
    }
    deferred->Instance = Instance;
    deferred->Rename = Rename;
    deferred->Succeeded = Succeeded;
    deferred->Draining = Draining;
    item = FltAllocateGenericWorkItem();
    if (item == NULL) {
        FltObjectDereference(Instance);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return FALSE;
    }
    status = FltQueueGenericWorkItem(item, SafeUploadData.Filter, StageRegistryRenameWorker,
        DelayedWorkQueue, deferred);
    if (!NT_SUCCESS(status)) {
        FltFreeGenericWorkItem(item);
        FltObjectDereference(Instance);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return FALSE;
    }
    return TRUE;
}

VOID SafeUploadStageWritersCompleteRename(_In_ PFLT_INSTANCE Instance, _In_opt_ PVOID Context,
    _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    PSTAGE_REGISTRY_RENAME_CONTEXT rename = (PSTAGE_REGISTRY_RENAME_CONTEXT)Context;
    PSTAGE_REGISTRY_ENTRY entry;
    PVOID mutatingIoContext;
    BOOLEAN markUnknown = FALSE, recheck = FALSE;

    if (rename == NULL || !SafeUploadStageWritersIsRenameContext(Context)) return;
    mutatingIoContext = rename->MutatingIoContext;
    if (mutatingIoContext != NULL) {
        rename->MutatingIoContext = NULL;
        SafeUploadStageWritersEndMutatingIo(mutatingIoContext);
    }
    if (rename->DirectoryRename) {
        if (KeGetCurrentIrql() > APC_LEVEL) {
            if (!StageRegistryQueueDeferredRename(Instance, rename, Succeeded, Draining)) {
                /* Keep the range Unknown if deferred completion could not be
                 * queued. Publishing global Unknown before Abandoned lets a
                 * later PASSIVE registry walk safely reclaim this context. */
                InterlockedOr((volatile LONG *)&RegistryUnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
                InterlockedExchange(&WriterGlobalUnknown, 1);
                StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME, FALSE);
                InterlockedExchange(&rename->Abandoned, 1);
            }
            return;
        }
        StageRegistryCompleteDirectoryRename(Instance, rename, Succeeded, Draining);
        return;
    }
    entry = rename->Entry;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        if (Draining || Succeeded) {
            StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
            InterlockedIncrement64(&RegistryRenameFailures);
        }
        if (InterlockedDecrement(&entry->RenameInFlight) < 0) {
            InterlockedExchange(&entry->RenameInFlight, 0);
            StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        }
        InterlockedIncrement(&entry->RenameVersion);
        rename->Signature = 0;
        StageRegistryDereference(entry);
        ExFreePoolWithTag(rename, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return;
    }
    FltAcquirePushLockExclusive(&RegistryLock);
    if (Draining || (Succeeded && (rename->LinkOperation || rename->Ambiguous))) {
        markUnknown = TRUE;
    } else if (Succeeded && entry->Compact) {
        if (entry->Retired || rename->NameChars == 0 ||
            rename->NewStreamChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
            markUnknown = TRUE;
        } else {
            if (rename->NewStreamChars != 0 && rename->StreamSuffixRetained) {
                UNICODE_STRING streamSuffix;
                streamSuffix.Buffer = rename->StreamName;
                streamSuffix.Length = streamSuffix.MaximumLength = (USHORT)(
                    rename->NewStreamChars * sizeof(WCHAR));
                entry->StreamSuffixHash = StageRegistryStreamSuffixHash(&streamSuffix);
                entry->StreamChars = 0;
                entry->CompactStream = TRUE;
                entry->StreamIdentityKnown = entry->StreamSuffixHash != 0;
            } else if (rename->CompactStreamIdentity && rename->CompactStreamSuffixHash != 0) {
                entry->StreamChars = 0;
                entry->CompactStream = TRUE;
                entry->StreamIdentityKnown = TRUE;
                entry->StreamSuffixHash = rename->CompactStreamSuffixHash;
            } else if (rename->NewStreamChars == 0) {
                entry->StreamChars = 0;
                entry->CompactStream = FALSE;
                entry->StreamIdentityKnown = TRUE;
                entry->StreamSuffixHash = 0;
            }
            InterlockedExchange(&entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
            recheck = StageRegistryBeginAliasProbe(entry);
        }
    } else if (Succeeded) {
        ULONG oldBytes, newBytes;
        oldBytes = StageRegistryEntryNameStorageBytes(entry);
        newBytes = StageRegistryNameStorageBytes((USHORT)rename->NameChars,
            (USHORT)rename->NewStreamChars);
        if (entry->Retired || rename->NameChars == 0 ||
            rename->NameChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ||
            rename->NewStreamChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ||
            newBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET || RegistryNameBytes < oldBytes ||
            RegistryReservedNameBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET - newBytes ||
            RegistryNameBytes - oldBytes > SAFEUPLOAD_WRITER_REGISTRY_NAME_BUDGET -
                RegistryReservedNameBytes - newBytes) {
            markUnknown = TRUE;
        } else {
            RtlZeroMemory(entry->Name,
                SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR));
            RtlCopyMemory(entry->Name, rename->Name, rename->NameChars * sizeof(WCHAR));
            RtlZeroMemory(entry->StreamName,
                SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR));
            if (rename->NewStreamChars != 0)
                RtlCopyMemory(entry->StreamName, rename->StreamName,
                    rename->NewStreamChars * sizeof(WCHAR));
            entry->NameChars = (USHORT)rename->NameChars;
            entry->StreamChars = (USHORT)rename->NewStreamChars;
            InterlockedExchange(&entry->ScopeNameClassification,
                STAGE_SCOPE_CLASS_UNRESOLVED);
            RegistryNameBytes = RegistryNameBytes - oldBytes + newBytes;
        }
    }
    if (InterlockedDecrement(&entry->RenameInFlight) < 0) {
        InterlockedExchange(&entry->RenameInFlight, 0);
        markUnknown = TRUE;
    }
    InterlockedIncrement(&entry->RenameVersion);
    if (markUnknown) {
        InterlockedOr(&entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        InterlockedExchange((volatile LONG *)&entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
    }
    FltReleasePushLock(&RegistryLock);
    if (markUnknown) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        InterlockedIncrement64(&RegistryRenameFailures);
    }
    if (recheck) (VOID)StageRegistryQueueReclaim();
    rename->Signature = 0;
    StageRegistryDereference(entry);
    ExFreePoolWithTag(rename, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

static VOID StageRegistryRenameWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context)
{
    PSTAGE_DEFERRED_RENAME deferred = (PSTAGE_DEFERRED_RENAME)Context;
    UNREFERENCED_PARAMETER(FltObject);
    PAGED_CODE();
    FltFreeGenericWorkItem(WorkItem);
    if (deferred != NULL) {
        SafeUploadStageWritersCompleteRename(deferred->Instance, deferred->Rename,
            deferred->Succeeded, deferred->Draining);
        FltObjectDereference(deferred->Instance);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
}

VOID SafeUploadStageWritersSetCompletion(_In_ PVOID Context,
    _In_opt_ PVOID LegacyCompletionContext, _In_ BOOLEAN LegacyCallbackRequired)
{
    PSTAGE_WRITER_RESERVATION reservation = (PSTAGE_WRITER_RESERVATION)Context;
    if (reservation == NULL || reservation->Signature != SAFEUPLOAD_REGISTRY_RESERVATION_SIGNATURE) return;
    reservation->LegacyCompletionContext = LegacyCompletionContext;
    reservation->LegacyCallbackRequired = LegacyCallbackRequired;
}

BOOLEAN SafeUploadStageWritersIsReservation(_In_opt_ PVOID Context)
{
    PSTAGE_WRITER_RESERVATION reservation;
    if (Context == NULL || (ULONG_PTR)Context < 0x10000) return FALSE;
    reservation = (PSTAGE_WRITER_RESERVATION)Context;
    return reservation->Signature == SAFEUPLOAD_REGISTRY_RESERVATION_SIGNATURE;
}

/* Nonpaged and not inlined: the pageable post-create must not contain a spin-lock acquisition (PREfast C28150,
 * and a paged routine running at raised IRQL faults under Driver Verifier's paged-code trimming). */
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageWritersInsertNode(
    _In_ PSAFEUPLOAD_STREAM_CONTEXT StreamContext,
    _In_ PSTAGE_WRITER_NODE Node)
{
    KIRQL irql;
    BOOLEAN compatible;
    PSTAGE_REGISTRY_ENTRY previous = NULL;

    StageAcquireSpinLock(&StreamContext->WriterLock, &irql);
    if (StreamContext->WriterRegistryEntry != NULL && StreamContext->WriterRegistryEntry != Node->Entry &&
        ((PSTAGE_REGISTRY_ENTRY)StreamContext->WriterRegistryEntry)->Retired &&
        IsListEmpty(&StreamContext->WriterObjects)) {
        /* The cached entry was pruned (or retired) while this stream had no writer; the file's history now lives in
         * Node->Entry. Retired is monotonic, so a stale FALSE only refuses (and records Unknown), never misbinds. */
        previous = (PSTAGE_REGISTRY_ENTRY)StreamContext->WriterRegistryEntry;
        StreamContext->WriterRegistryEntry = NULL;
    }
    if (StreamContext->WriterRegistryEntry == NULL) {
        StageRegistryReference(Node->Entry);
        StreamContext->WriterRegistryEntry = Node->Entry;
    }
    compatible = StreamContext->WriterRegistryEntry == Node->Entry;
    if (compatible) {
        InsertTailList(&StreamContext->WriterObjects, &Node->Link);
        InterlockedIncrement(&Node->Entry->H);
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    StageReleaseSpinLock(&StreamContext->WriterLock, irql);
    if (previous != NULL) StageRegistryDereference(previous);
    return compatible;
}

static NTSTATUS StageRegistryEnlistTransaction(_In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction, _In_ PSTAGE_REGISTRY_ENTRY Entry);
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryAssociateSectionPointer(_In_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_opt_ PVOID SectionObjectPointer);

NTSTATUS SafeUploadStageWritersPostCreate(
    _In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_POST_OPERATION_FLAGS Flags, _In_opt_ PVOID Context,
    _Out_opt_ PVOID *LegacyCompletionContext, _Out_opt_ PBOOLEAN LegacyCallbackRequired)
{
    PSTAGE_WRITER_RESERVATION reservation = (PSTAGE_WRITER_RESERVATION)Context;
    PFILE_OBJECT fileObject = FltObjects->FileObject;
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    FILE_ID_INFORMATION identity;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    BOOLEAN directory = FALSE, hasWriterHandle = FALSE;
    ULONG returned = 0;
    NTSTATUS status = STATUS_SUCCESS;
    PAGED_CODE();

    if (LegacyCompletionContext != NULL) *LegacyCompletionContext = NULL;
    if (LegacyCallbackRequired != NULL) *LegacyCallbackRequired = FALSE;
    hasWriterHandle = fileObject != NULL && (fileObject->WriteAccess || fileObject->DeleteAccess);

    if (reservation == NULL || reservation->Signature != SAFEUPLOAD_REGISTRY_RESERVATION_SIGNATURE)
        return STATUS_INVALID_PARAMETER;
    if (LegacyCompletionContext != NULL) *LegacyCompletionContext = reservation->LegacyCompletionContext;
    if (LegacyCallbackRequired != NULL) *LegacyCallbackRequired = reservation->LegacyCallbackRequired;
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        /* The reservation still identifies the affected instance even though
         * the file ID was not committed. Widen only if its context is gone. */
        StageRegistryMarkUnknown(reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
        SafeUploadStageWritersCancelReservation(reservation);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) {
        SafeUploadStageWritersCancelReservation(reservation);
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(&reservation->TeardownState, 0, 0) !=
        SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
        if (InterlockedCompareExchange(&reservation->TeardownState, 0, 0) !=
            SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
            StageRegistryMarkUnknown(reservation->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
        }
        goto TrackingLost;
    }
    InterlockedIncrement64(&WriterPostCreateRuns);
    if (fileObject == NULL || StageWritersExcludedObject(fileObject)) {
        SafeUploadStageWritersCancelReservation(reservation);
        return STATUS_SUCCESS; /* excluded objects are simply not tracked; the legacy post-create still runs */
    }
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        InterlockedIncrement64(&WriterDirectoryCreatesSkipped);
        SafeUploadStageWritersCancelReservation(reservation);
        return STATUS_SUCCESS;
    }
    status = FltIsDirectory(fileObject, FltObjects->Instance, &directory);
    if (!NT_SUCCESS(status)) goto IdentityFailure;
    if (directory) {
        InterlockedIncrement64(&WriterDirectoryCreatesSkipped);
        SafeUploadStageWritersCancelReservation(reservation);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(FltObjects->Instance, fileObject, &identity,
        sizeof(identity), FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(identity)) goto IdentityFailure;
    reservation->VolumeSerial = identity.VolumeSerialNumber;
    reservation->FileId = identity.FileId;

    if (reservation->TrackingLost) {
        if (!StageRegistryMarkSopUnknown(reservation->Instance, identity.VolumeSerialNumber,
                &identity.FileId, reservation->StreamSuffixHash, fileObject->SectionObjectPointer))
            StageRegistryMarkUnknown(reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
        goto TrackingLost;
    }

    entry = StageRegistryGetOrInsert(reservation, &identity, fileObject->SectionObjectPointer);
    if (entry == NULL) {
        if (InterlockedCompareExchange(&reservation->TeardownState, 0, 0) !=
            SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
            if (InterlockedCompareExchange(&reservation->TeardownState, 0, 0) !=
                SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
                StageRegistryMarkUnknown(reservation->Instance,
                    SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
            }
            goto TrackingLost;
        }
        if (!StageRegistryMarkSopUnknown(reservation->Instance, identity.VolumeSerialNumber,
                &identity.FileId, reservation->StreamSuffixHash, fileObject->SectionObjectPointer))
            StageRegistryMarkUnknown(reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
        goto TrackingLost;
    }
    if (!StageRegistryAssociateSectionPointer(reservation, entry, fileObject->SectionObjectPointer)) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        (VOID)StageRegistryMarkSopUnknown(reservation->Instance, identity.VolumeSerialNumber,
            &identity.FileId, reservation->StreamSuffixHash, fileObject->SectionObjectPointer);
        goto TrackingLost;
    }
    if (FltObjects->Transaction != NULL) {
        status = StageRegistryEnlistTransaction(FltObjects->Instance, FltObjects->Transaction, entry);
        if (!NT_SUCCESS(status)) {
            InterlockedIncrement64(&RegistryTransactionFailures);
            StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TRANSACTION);
            goto TrackingLost;
        }
    }

    if (hasWriterHandle) {
        status = SafeUploadGetOrCreateStreamContext(FltObjects, fileObject, &streamContext);
        if (!NT_SUCCESS(status)) {
            InterlockedIncrement64(&WriterUntrackedCreates);
            InterlockedIncrement64(&RegistryAllocationFailures);
            StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
            goto TrackingLost;
        }
        reservation->Node->FileObject = fileObject;
        reservation->Node->Entry = entry; /* The lookup reference transfers to this exact cleanup node. */
        reservation->Node->ProcessId = FltGetRequestorProcessId(Data);
        FltAcquirePushLockExclusive(&RegistryLock);
        if (!reservation->Active ||
            InterlockedCompareExchange(&reservation->TeardownState, 0, 0) != SAFEUPLOAD_INSTANCE_STATE_ACTIVE ||
            entry->Retired || !entry->Listed || !StageWritersInsertNode(streamContext, reservation->Node)) {
            FltReleasePushLock(&RegistryLock);
            StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
            goto TrackingLost;
        }
        StageRegistryAddOpener(entry, reservation->Node->ProcessId);
        FltReleasePushLock(&RegistryLock);
        reservation->Node = NULL;
        reservation->BoundEntry = NULL; /* the exact cleanup node now owns this reference */
        InterlockedIncrement64(&WriterCounted);
        entry = NULL;
        FltReleaseContext(streamContext);
    } else {
        /* Keep the lookup reference on the reservation until its name-indexed
         * in-flight marker is removed below. */
        entry = NULL;
    }
    SafeUploadStageWritersCancelReservation(reservation);
    return STATUS_SUCCESS;

IdentityFailure:
    InterlockedIncrement64(&RegistryIdentityFailures);
    if (reservation->Shell == NULL || (reservation->Shell->StreamIdentityKnown &&
        reservation->Shell->StreamChars == 0))
        StageRegistryMarkUnknown(reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
TrackingLost:
    /* Tracking this writer failed. The open is never refused or cancelled (the registry is a ledger, not a gate): the loss is
     * recorded above as entry, instance or machine Unknown, which withholds every protection claim and promotion. Scoped
     * writes are still decided by the admission path. */
    if (streamContext != NULL) FltReleaseContext(streamContext);
    if (hasWriterHandle && reservation->Node != NULL)
        (VOID)StageRegistryTrackUnknownWriter(reservation, Data, FltObjects, fileObject);
    if (FltObjects->Transaction != NULL && reservation->BoundEntry == NULL)
        StageRegistryMarkUnknown(reservation->Instance,
            SAFEUPLOAD_REGISTRY_UNKNOWN_TRANSACTION, FALSE);
    SafeUploadStageWritersCancelReservation(reservation);
    return STATUS_SUCCESS;
}

static BOOLEAN StageWritersInstanceTearingDown(_In_ PFLT_INSTANCE Instance)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    BOOLEAN tearingDown = FALSE;
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext))) {
        tearingDown = instanceContext->TeardownToken != NULL &&
            InterlockedCompareExchange(&instanceContext->TeardownToken->State, 0, 0) ==
                SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN;
        FltReleaseContext(instanceContext);
    }
    return tearingDown;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) VOID SafeUploadStageWritersOnCleanup(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSTAGE_WRITER_NODE found = NULL;
    PLIST_ENTRY link;
    BOOLEAN tearingDown = FALSE;
    BOOLEAN lastWriter = FALSE;
    KIRQL irql;
    NTSTATUS status;

    if (fileObject == NULL || (!fileObject->WriteAccess && !fileObject->DeleteAccess)) return;
    if (StageWritersExcludedObject(fileObject)) return;

    status = FltGetStreamContext(FltObjects->Instance, fileObject, (PFLT_CONTEXT *)&streamContext);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&WriterCleanupUnmatched);
        /* A handle that predates the driver has no node; only a trusted (boot-attached) instance treats that as loss. */
        if (!StageWritersInstanceTearingDown(FltObjects->Instance) && SafeUploadInstanceIsTrusted(FltObjects->Instance)) {
            StageRegistryMarkUnknown(FltObjects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP, FALSE);
        }
        return;
    }
    tearingDown = streamContext->TeardownToken != NULL &&
        InterlockedCompareExchange(&streamContext->TeardownToken->State, 0, 0) ==
            SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN;

    StageAcquireSpinLock(&streamContext->WriterLock, &irql);
    for (link = streamContext->WriterObjects.Flink; link != &streamContext->WriterObjects; link = link->Flink) {
        PSTAGE_WRITER_NODE node = CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link);
        if (node->FileObject == fileObject) {
            RemoveEntryList(&node->Link);
            if (node->Entry != NULL) lastWriter = InterlockedDecrement(&node->Entry->H) == 0;
            found = node;
            break;
        }
    }
    StageReleaseSpinLock(&streamContext->WriterLock, irql);

    if (found != NULL) {
        InterlockedIncrement64(&RegistryChangeSequence);
        if (found->Entry != NULL) {
            if (lastWriter && InterlockedCompareExchange((volatile LONG *)&found->Entry->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) StageRegistryQueueReclaim();
            StageRegistryRemoveOpener(found->Entry, found->ProcessId);
        } else {
            (VOID)StageRegistryUnknownWriterEnd(FltObjects->Instance, found->SectionObjectPointer);
            StageRegistryQueueReclaim();
        }
        StageRegistryDereference(found->Entry);
        ExFreePoolWithTag(found, SAFEUPLOAD_WRITER_NODE_POOL_TAG);
        InterlockedIncrement64(&WriterReleased);
    } else {
        InterlockedIncrement64(&WriterCleanupUnmatched);
        /* A handle that predates the driver has no node; only a trusted (boot-attached) instance treats that as loss. */
        if (!tearingDown && SafeUploadInstanceIsTrusted(FltObjects->Instance)) {
            StageRegistryMarkUnknown(FltObjects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP, FALSE);
        }
    }
    FltReleaseContext(streamContext);
}

VOID SafeUploadStageWritersFreeContext(_Inout_ PSAFEUPLOAD_STREAM_CONTEXT StreamContext)
{
    PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN token = StreamContext->TeardownToken;
    PSTAGE_REGISTRY_ENTRY registryEntry =
        (PSTAGE_REGISTRY_ENTRY)InterlockedExchangePointer(
            (PVOID volatile *)&StreamContext->WriterRegistryEntry, NULL);
    LONG tokenState = token != NULL ? InterlockedCompareExchange(&token->State, 0, 0) :
        SAFEUPLOAD_INSTANCE_STATE_UNKNOWN;

    /* The last context reference is being released, so no operation can still mutate this list. */
    while (!IsListEmpty(&StreamContext->WriterObjects)) {
        PLIST_ENTRY link = RemoveHeadList(&StreamContext->WriterObjects);
        PSTAGE_WRITER_NODE node = CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link);
        if (node->Entry == NULL) {
            /* Its exact cleanup was lost. Keep the marker live and fail closed for promotion. */
            if (tokenState != SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
                InterlockedOr((volatile LONG *)&RegistryUnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP);
                InterlockedExchange(&WriterGlobalUnknown, 1);
            }
        } else if (tokenState != SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
            /* This node still identifies the exact lost writer. Mark it before
             * H can reach zero so Evaluate cannot observe a false-Free window. */
            StageRegistryMarkEntryUnknown(node->Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_CLEANUP);
        }
        if (node->Entry != NULL) {
            InterlockedDecrement(&node->Entry->H);
            InterlockedIncrement64(&RegistryChangeSequence);
            StageRegistryRemoveOpener(node->Entry, node->ProcessId);
            StageRegistryDereference(node->Entry);
        }
        ExFreePoolWithTag(node, SAFEUPLOAD_WRITER_NODE_POOL_TAG);
        if (tokenState == SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN) {
            InterlockedIncrement64(&WriterDroppedAtTeardown);
        } else if (tokenState == SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
            InterlockedIncrement64(&WriterDroppedWhileMounted);
        } else {
            /* The exact entry is already Unknown; only the aggregate counter
             * is ambiguous when its teardown token was lost. */
            InterlockedIncrement64(&WriterDroppedWhileMounted);
        }
    }
    StageRegistryDereference(registryEntry);
}

/* A missing stream context proves zero only when no writer-context failure was recorded for this
 * attachment. Allocation failure must survive a later successful allocation on the same stream. */
UINT32 SafeUploadStageWritersSnapshot(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject)
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PSTAGE_REGISTRY_ENTRY entry;
    UINT32 result = 0;
    NTSTATUS status;

    if (FileObject == NULL || Instance == NULL) return SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    if (InterlockedCompareExchange(&WriterGlobalUnknown, 0, 0) != 0)
        result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    else {
        if (InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0)
            result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
        FltReleaseContext(instanceContext);
    }
    status = FltGetStreamContext(Instance, FileObject, (PFLT_CONTEXT *)&streamContext);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_NOT_FOUND) result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
        return result;
    }
    entry = (PSTAGE_REGISTRY_ENTRY)streamContext->WriterRegistryEntry;
    if (entry == NULL) result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    else result |= (UINT32)InterlockedCompareExchange(&entry->H, 0, 0) & ~SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    if (InterlockedCompareExchange(&streamContext->WritersUntracked, 0, 0) != 0) {
        result |= SAFEUPLOAD_WRITERS_UNTRACKED_BIT;
    }
    FltReleaseContext(streamContext);
    return result;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) BOOLEAN SafeUploadStageWritersIsTrackedWriter(
    _In_opt_ PFLT_INSTANCE Instance, _In_opt_ PFILE_OBJECT FileObject)
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    BOOLEAN found = FALSE;

    if (Instance == NULL || FileObject == NULL || KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    if (!NT_SUCCESS(FltGetStreamContext(Instance, FileObject,
            (PFLT_CONTEXT *)&streamContext))) return FALSE;
    StageAcquireSpinLock(&streamContext->WriterLock, &irql);
    for (link = streamContext->WriterObjects.Flink;
         link != &streamContext->WriterObjects; link = link->Flink) {
        PSTAGE_WRITER_NODE node = CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link);
        if (node->FileObject == FileObject) {
            found = TRUE;
            break;
        }
    }
    StageReleaseSpinLock(&streamContext->WriterLock, irql);
    FltReleaseContext(streamContext);
    return found;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryReserveMutatingIoMarker(
    _In_opt_ PFLT_INSTANCE Instance, _In_opt_ PVOID SectionObjectPointer,
    _Out_ PULONG SopSlotIndex)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    KIRQL irql;
    ULONG index;
    BOOLEAN found = FALSE, reserved = FALSE;

    *SopSlotIndex = 0;
    if (Instance == NULL || SectionObjectPointer == NULL) return FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    if (found && slot != NULL &&
        ((slot->Unknown && slot->InstanceIdentity == (PVOID)Instance) ||
         (slot->Entry != NULL && slot->Entry->Instance == Instance &&
          slot->InstanceIdentity == (PVOID)Instance)) &&
        slot->SpilledMutatingIoCount != MAXULONG) {
        index = (ULONG)(slot - RegistrySopSlots);
        slot->SpilledMutatingIoCount += 1;
        slot->ScopeClassification = STAGE_SCOPE_CLASS_UNRESOLVED;
        slot->ScopePolicyGeneration = 0;
        InterlockedIncrement64(&RegistrySopMapGeneration);
        InterlockedIncrement64(&RegistryChangeSequence);
        *SopSlotIndex = index;
        reserved = TRUE;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return reserved;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) BOOLEAN SafeUploadStageWritersBeginMutatingIo(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PFILE_OBJECT FileObject, _Outptr_result_maybenull_ PVOID *CompletionContext,
    _Out_ PBOOLEAN TrackedWriter)
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    PSTAGE_WRITER_NODE found = NULL;
    PSTAGE_MUTATING_IO_MARKER_CONTEXT markerContext = NULL;
    PLIST_ENTRY link;
    PVOID sectionObjectPointer = NULL;
    ULONG sopSlotIndex = 0;
    BOOLEAN markEntryUnknown = FALSE, markInstanceUnknown = FALSE;
    KIRQL irql;
    NTSTATUS status;

    *CompletionContext = NULL;
    *TrackedWriter = FALSE;
    if (Instance == NULL || FileObject == NULL || KeGetCurrentIrql() > APC_LEVEL) return FALSE;
    status = FltGetStreamContext(Instance, FileObject, (PFLT_CONTEXT *)&streamContext);
    if (!NT_SUCCESS(status)) return FALSE;

    StageAcquireSpinLock(&streamContext->WriterLock, &irql);
    for (link = streamContext->WriterObjects.Flink;
         link != &streamContext->WriterObjects; link = link->Flink) {
        PSTAGE_WRITER_NODE node = CONTAINING_RECORD(link, STAGE_WRITER_NODE, Link);
        if (node->FileObject == FileObject) {
            found = node;
            break;
        }
    }
    if (found != NULL) {
        *TrackedWriter = TRUE;
        entry = found->Entry;
        sectionObjectPointer = found->SectionObjectPointer;
        if (entry != NULL) {
            KIRQL stateIrql;
            StageRegistryAcquireStateLock(entry, &stateIrql);
            if (InterlockedCompareExchange(&entry->W, 0, 0) < MAXLONG) {
                StageRegistryReference(entry);
                InterlockedIncrement(&entry->W);
                InterlockedIncrement64(&RegistryChangeSequence);
                *CompletionContext = (PVOID)((ULONG_PTR)entry | STAGE_MUTATING_IO_ENTRY_TAG);
            } else {
                markEntryUnknown = TRUE;
            }
            StageRegistryReleaseStateLock(entry, stateIrql);
        } else {
            markerContext = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                sizeof(*markerContext), SAFEUPLOAD_REGISTRY_POOL_TAG);
            if (markerContext != NULL && StageRegistryReserveMutatingIoMarker(Instance,
                    sectionObjectPointer, &sopSlotIndex)) {
                markerContext->Signature = STAGE_MUTATING_IO_MARKER_SIGNATURE;
                markerContext->SopSlotIndex = sopSlotIndex;
                markerContext->SectionObjectPointer = sectionObjectPointer;
                markerContext->InstanceIdentity = Instance;
                *CompletionContext = (PVOID)((ULONG_PTR)markerContext |
                    STAGE_MUTATING_IO_MARKER_TAG);
                markerContext = NULL;
            } else {
                if (markerContext != NULL) ExFreePoolWithTag(markerContext, SAFEUPLOAD_REGISTRY_POOL_TAG);
                markerContext = NULL;
                markInstanceUnknown = TRUE;
            }
        }
    }
    StageReleaseSpinLock(&streamContext->WriterLock, irql);
    FltReleaseContext(streamContext);

    if (markEntryUnknown) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY);
    } else if (markInstanceUnknown) {
        /* Exact marker accounting was unavailable (missing identity or saturated table count). */
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
    }
    return *TrackedWriter;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN SafeUploadStageWritersIsMutatingIoContext(_In_opt_ PVOID CompletionContext)
{
    ULONG_PTR tag = (ULONG_PTR)CompletionContext & STAGE_COMPLETION_CONTEXT_TAG_MASK;
    return CompletionContext != NULL &&
        (tag == STAGE_MUTATING_IO_ENTRY_TAG || tag == STAGE_MUTATING_IO_MARKER_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryEndMutatingIoEntry(
    _Inout_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;
    LONG remaining;
    BOOLEAN recheck = FALSE, markUnknown = FALSE;

    StageRegistryAcquireStateLock(Entry, &irql);
    remaining = InterlockedDecrement(&Entry->W);
    if (remaining <= 0) {
        if (remaining < 0) {
            InterlockedExchange(&Entry->W, 0);
            markUnknown = TRUE;
        } else {
            recheck = TRUE;
        }
    }
    InterlockedIncrement64(&RegistryChangeSequence);
    StageRegistryReleaseStateLock(Entry, irql);
    if (markUnknown) StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
    if (recheck) SafeUploadStageWritersQueueRecheck();
    StageRegistryDereference(Entry);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryEndMutatingIoMarker(_In_ ULONG SopSlotIndex,
    _In_opt_ PVOID SectionObjectPointer, _In_opt_ PVOID InstanceIdentity)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    KIRQL irql;
    BOOLEAN recheck = FALSE;

    if (SopSlotIndex >= RTL_NUMBER_OF(RegistrySopSlots)) return;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = &RegistrySopSlots[SopSlotIndex];
    if (slot->SectionObjectPointer != NULL &&
        slot->SectionObjectPointer == SectionObjectPointer &&
        slot->InstanceIdentity == InstanceIdentity && slot->SpilledMutatingIoCount != 0) {
        slot->SpilledMutatingIoCount -= 1;
        InterlockedIncrement64(&RegistrySopMapGeneration);
        InterlockedIncrement64(&RegistryChangeSequence);
        recheck = slot->SpilledMutatingIoCount == 0;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (recheck) SafeUploadStageWritersQueueRecheck();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) VOID SafeUploadStageWritersEndMutatingIo(_In_opt_ PVOID CompletionContext)
{
    ULONG_PTR value = (ULONG_PTR)CompletionContext;
    ULONG_PTR tag;
    if (CompletionContext == NULL) return;
    tag = value & STAGE_COMPLETION_CONTEXT_TAG_MASK;
    if (tag == STAGE_MUTATING_IO_ENTRY_TAG) {
        PSTAGE_REGISTRY_ENTRY entry = (PSTAGE_REGISTRY_ENTRY)(value &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        StageRegistryEndMutatingIoEntry(entry);
    } else if (tag == STAGE_MUTATING_IO_MARKER_TAG) {
        PSTAGE_MUTATING_IO_MARKER_CONTEXT marker = (PSTAGE_MUTATING_IO_MARKER_CONTEXT)(value &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        if (marker->Signature == STAGE_MUTATING_IO_MARKER_SIGNATURE) {
            StageRegistryEndMutatingIoMarker(marker->SopSlotIndex,
                marker->SectionObjectPointer, marker->InstanceIdentity);
            marker->Signature = 0;
            ExFreePoolWithTag(marker, SAFEUPLOAD_REGISTRY_POOL_TAG);
        }
    }
}

_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersAttachMutatingIo(_In_opt_ PVOID RenameContext,
    _Inout_ PVOID *MutatingIoContext)
{
    PSTAGE_REGISTRY_RENAME_CONTEXT rename;
    if (RenameContext == NULL || MutatingIoContext == NULL || *MutatingIoContext == NULL ||
        !SafeUploadStageWritersIsRenameContext(RenameContext)) return;
    rename = (PSTAGE_REGISTRY_RENAME_CONTEXT)RenameContext;
    rename->MutatingIoContext = *MutatingIoContext;
    *MutatingIoContext = NULL;
}

/* ---- C(F): writable CreateSections in flight -----------------------------------------------
 * Every section-synchronization acquire occupies a slot, including read-only and SyncTypeOther.
 * Releases have no protection field, so non-writable acquisitions must participate in pairing:
 * their release must not retire an enclosing writable acquisition of the same thread/file object.
 * A spin lock makes slot identity, stream identity and counters one atomic snapshot. Releases match
 * only the acquiring thread and file object, newest first; no cross-thread fallback can undercount.
 * Failed acquires carry their exact slot to post-operation, which may run on another thread.
 * Overflow uses exact per-acquire spill records; only loss of identity or the completion pair is sticky Unknown.
 * Nothing expires an old entry or treats a missing release as proof of writer freedom. */

#define STAGE_SECTION_SLOTS 64
#define STAGE_SECTION_STUCK_100NS (20LL * 1000 * 1000)     /* 2 s */

typedef struct _STAGE_SECTION_SLOT {
    PFILE_OBJECT FileObject;       /* identity only; never dereferenced while holding SectionLock */
    PVOID Thread;
    PVOID InstanceIdentity;        /* non-owning; retires even an unbound slot at instance teardown */
    PVOID SectionObjectPointer;
    PSTAGE_REGISTRY_ENTRY RegistryEntry;
    ULONGLONG VolumeSerial;
    FILE_ID_128 FileId;
    ULONG ProcessId;
    LONGLONG Time;
    ULONGLONG Sequence;
    BOOLEAN Writable;
    BOOLEAN ReleasePending;
} STAGE_SECTION_SLOT;

__declspec(align(16)) struct _STAGE_SECTION_SPILL_RECORD {
    LIST_ENTRY Link;
    ULONG Signature;
    PFILE_OBJECT FileObject;       /* identity only; the I/O keeps it alive through post-operation */
    PVOID Thread;
    PVOID InstanceIdentity;        /* non-owning identity token */
    PVOID SectionObjectPointer;
    ULONG SopSlotIndex;
    ULONGLONG Sequence;
    BOOLEAN Writable;
    BOOLEAN AcquirePending;
    BOOLEAN ReleasePending;
    BOOLEAN AcquireOutcomeUnknown;
    BOOLEAN ReleaseOutcomeUnknown;
    BOOLEAN Retiring;
};

#define STAGE_SECTION_SPILL_SIGNATURE 'pSwU'

static KSPIN_LOCK SectionLock;
__declspec(align(16)) static STAGE_SECTION_SLOT SectionSlots[STAGE_SECTION_SLOTS];
static LIST_ENTRY SectionSpills;
static ULONG SectionNow;
static ULONG SectionMaxDepth;
static ULONGLONG SectionSequence;
static UINT64 SectionInserted;
static UINT64 SectionReleased;
static UINT64 SectionOverflow;
static UINT64 SectionRemovedOnFailure;

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static PSTAGE_REGISTRY_SOP_SLOT StageRegistryFindSopSlotLocked(
    _In_ PVOID SectionObjectPointer, _Out_ PBOOLEAN Found)
{
    ULONG index, probe, start;
    PSTAGE_REGISTRY_SOP_SLOT firstDeleted = NULL;
    *Found = FALSE;
    if (SectionObjectPointer == NULL) return NULL;
    start = (ULONG)(((ULONG_PTR)SectionObjectPointer >> 4) % RTL_NUMBER_OF(RegistrySopSlots));
    for (probe = 0; probe < SAFEUPLOAD_REGISTRY_SOP_MAX_PROBES; ++probe) {
        index = (start + probe) % RTL_NUMBER_OF(RegistrySopSlots);
        if (RegistrySopSlots[index].SectionObjectPointer == SectionObjectPointer) {
            *Found = TRUE;
            return &RegistrySopSlots[index];
        }
        if (RegistrySopSlots[index].SectionObjectPointer == NULL) {
            if (RegistrySopSlots[index].Deleted) {
                if (firstDeleted == NULL) firstDeleted = &RegistrySopSlots[index];
            } else {
                return firstDeleted != NULL ? firstDeleted : &RegistrySopSlots[index];
            }
        }
    }
    return firstDeleted;
}

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryRemoveSopSlotLocked(
    _Inout_ PSTAGE_REGISTRY_SOP_SLOT Slot)
{
    RtlZeroMemory(Slot, sizeof(*Slot));
    Slot->Deleted = TRUE;
    InterlockedIncrement64(&RegistrySopMapGeneration);
}

/* Enumeration is split into fixed-size lock holds. The returned binding reference
 * is dropped by the caller after SectionLock has been released. */
__declspec(noinline) static PSTAGE_REGISTRY_ENTRY StageRegistryDetachOneInstanceSectionBinding(
    _In_ PFLT_INSTANCE Instance, _Out_ PBOOLEAN Detached)
{
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    ULONG base, index;
    KIRQL irql;

    *Detached = FALSE;
    for (base = 0; base < RTL_NUMBER_OF(RegistrySopSlots); base += SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK) {
        StageAcquireSpinLock(&SectionLock, &irql);
        for (index = base; index < min(base + SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK,
                (ULONG)RTL_NUMBER_OF(RegistrySopSlots)); ++index) {
            PSTAGE_REGISTRY_SOP_SLOT slot = &RegistrySopSlots[index];
            if (slot->SectionObjectPointer != NULL &&
                ((slot->Entry != NULL && slot->Entry->Instance == Instance) ||
                 (slot->Unknown && slot->InstanceIdentity == (PVOID)Instance))) {
                entry = slot->Entry;
                StageRegistryRemoveSopSlotLocked(slot);
                *Detached = TRUE;
                break;
            }
        }
        StageReleaseSpinLock(&SectionLock, irql);
        if (*Detached) return entry;
    }

    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject != NULL && slot->InstanceIdentity == (PVOID)Instance) {
            entry = slot->RegistryEntry;
            if (slot->Writable && SectionNow != 0) SectionNow -= 1;
            RtlZeroMemory(slot, sizeof(*slot));
            *Detached = TRUE;
            break;
        }
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return entry;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static PSTAGE_SECTION_SPILL_RECORD StageRegistryDetachOneInstanceSpill(
    _In_ PFLT_INSTANCE Instance, _Out_ PBOOLEAN Detached)
{
    PSTAGE_SECTION_SPILL_RECORD spill = NULL;
    PLIST_ENTRY link;
    KIRQL irql;
    *Detached = FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    for (link = SectionSpills.Flink; link != &SectionSpills; link = link->Flink) {
        PSTAGE_SECTION_SPILL_RECORD candidate = CONTAINING_RECORD(link,
            STAGE_SECTION_SPILL_RECORD, Link);
        if (candidate->Signature != STAGE_SECTION_SPILL_SIGNATURE ||
            candidate->InstanceIdentity != (PVOID)Instance) continue;
        if (candidate->AcquirePending || candidate->ReleasePending) {
            candidate->Retiring = TRUE;
            continue;
        }
        RemoveEntryList(&candidate->Link);
        candidate->Signature = 0;
        spill = candidate;
        *Detached = TRUE;
        break;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return spill;
}

/* D2 overflow markers retain only SOP+file identity and a non-owning instance
 * token. They affect later classification only; ledger loss never denies I/O. */
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryMarkSopUnknown(_In_ PFLT_INSTANCE Instance,
    _In_ ULONGLONG VolumeSerial, _In_ const FILE_ID_128 *FileId,
    _In_ ULONGLONG StreamSuffixHash, _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_ENTRY existing = NULL;
    PSTAGE_REGISTRY_SOP_SLOT slot;
    KIRQL irql;
    BOOLEAN found = FALSE, recorded = FALSE, identityMismatch = FALSE;
    if (Instance == NULL || FileId == NULL || SectionObjectPointer == NULL) return FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    if (found && slot->Entry != NULL) {
        if (slot->Entry->Instance == Instance && slot->Entry->VolumeSerial == VolumeSerial &&
            slot->Entry->StreamSuffixHash == StreamSuffixHash &&
            RtlEqualMemory(&slot->Entry->FileId, FileId, sizeof(*FileId))) {
            recorded = TRUE; /* Exact Entry identity makes a separate capacity bit unnecessary. */
        } else {
            existing = slot->Entry;
            StageRegistryReference(existing);
            identityMismatch = TRUE;
        }
    } else if (found && slot != NULL && slot->Unknown) {
        if (slot->InstanceIdentity != (PVOID)Instance || slot->VolumeSerial != VolumeSerial ||
            slot->StreamSuffixHash != StreamSuffixHash ||
            !RtlEqualMemory(&slot->FileId, FileId, sizeof(*FileId))) {
            slot->UnknownReasons |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
            identityMismatch = TRUE;
            InterlockedIncrement64(&RegistrySopMapGeneration);
        } else {
            slot->UnknownReasons |= SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY;
            recorded = TRUE;
            InterlockedIncrement64(&RegistrySopMapGeneration);
        }
    } else if (slot != NULL) {
        if (!found) {
            RtlZeroMemory(slot, sizeof(*slot));
            slot->SectionObjectPointer = SectionObjectPointer;
        }
        slot->Unknown = TRUE;
        slot->InstanceIdentity = Instance;
        slot->VolumeSerial = VolumeSerial;
        slot->StreamSuffixHash = StreamSuffixHash;
        slot->UnknownReasons |= SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY;
        RtlCopyMemory(&slot->FileId, FileId, sizeof(*FileId));
        InterlockedIncrement64(&RegistrySopMapGeneration);
        recorded = TRUE;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (existing != NULL) {
        StageRegistryMarkEntryUnknown(existing, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        StageRegistryDereference(existing);
    }
    if (identityMismatch)
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY, FALSE);
    return recorded;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryTrackUnknownWriter(_Inout_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFILE_OBJECT FileObject)
{
    PSAFEUPLOAD_STREAM_CONTEXT streamContext = NULL;
    PSTAGE_REGISTRY_SOP_SLOT slot;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    PSTAGE_WRITER_NODE node = Reservation->Node;
    BOOLEAN found = FALSE, marker = FALSE, inserted = FALSE, entryReferenceFromReservation = FALSE;
    KIRQL irql;
    NTSTATUS status;

    if (node == NULL || Data == NULL || FltObjects == NULL || FileObject == NULL ||
        FltObjects->Instance != Reservation->Instance) return;
    status = SafeUploadGetOrCreateStreamContext(FltObjects, FileObject, &streamContext);
    if (!NT_SUCCESS(status)) {
        StageRegistryMarkUnknown(Reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION, FALSE);
        return;
    }
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(FileObject->SectionObjectPointer, &found);
    if (found && slot != NULL && slot->Unknown &&
        slot->InstanceIdentity == (PVOID)Reservation->Instance &&
        slot->VolumeSerial == Reservation->VolumeSerial &&
        slot->StreamSuffixHash == Reservation->StreamSuffixHash &&
        RtlEqualMemory(&slot->FileId, &Reservation->FileId, sizeof(slot->FileId))) {
        if (slot->UnknownWriterCount != MAXULONG) {
            slot->UnknownWriterCount += 1;
            marker = TRUE;
            InterlockedIncrement64(&RegistrySopMapGeneration);
        }
    } else if (found && slot != NULL && slot->Entry != NULL &&
        slot->Entry->Instance == Reservation->Instance &&
        slot->Entry->VolumeSerial == Reservation->VolumeSerial &&
        slot->Entry->StreamSuffixHash == Reservation->StreamSuffixHash &&
        RtlEqualMemory(&slot->Entry->FileId, &Reservation->FileId, sizeof(slot->Entry->FileId))) {
        entry = slot->Entry;
        entryReferenceFromReservation = entry == Reservation->BoundEntry;
        if (!entryReferenceFromReservation) StageRegistryReference(entry);
    } else if (!found && Reservation->BoundEntry != NULL &&
        Reservation->BoundEntry->Instance == Reservation->Instance &&
        Reservation->BoundEntry->VolumeSerial == Reservation->VolumeSerial &&
        Reservation->BoundEntry->StreamSuffixHash == Reservation->StreamSuffixHash &&
        RtlEqualMemory(&Reservation->BoundEntry->FileId, &Reservation->FileId,
            sizeof(Reservation->BoundEntry->FileId)) &&
        InterlockedCompareExchangePointer(
            (PVOID volatile *)&Reservation->BoundEntry->SectionObjectPointer,
            NULL, NULL) == FileObject->SectionObjectPointer) {
        /* The SOP map is full; the reservation already owns this exact Entry reference. */
        entry = Reservation->BoundEntry;
        entryReferenceFromReservation = TRUE;
    }
    StageReleaseSpinLock(&SectionLock, irql);

    node->FileObject = FileObject;
    node->ProcessId = FltGetRequestorProcessId(Data);
    node->SectionObjectPointer = FileObject->SectionObjectPointer;
    if (marker) {
        node->Entry = NULL;
        StageAcquireSpinLock(&streamContext->WriterLock, &irql);
        InterlockedExchange(&streamContext->WritersUntracked, 1);
        InsertTailList(&streamContext->WriterObjects, &node->Link);
        InterlockedIncrement64(&RegistryChangeSequence);
        StageReleaseSpinLock(&streamContext->WriterLock, irql);
        inserted = TRUE;
    } else if (entry != NULL) {
        node->Entry = entry;
        if (StageWritersInsertNode(streamContext, node)) {
            StageRegistryAddOpener(entry, node->ProcessId);
            if (Reservation->BoundEntry == entry)
                Reservation->BoundEntry = NULL; /* The exact node now owns this reference. */
            inserted = TRUE;
        } else {
            node->Entry = NULL;
            StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
            if (!entryReferenceFromReservation) StageRegistryDereference(entry);
        }
    }
    if (inserted) {
        Reservation->Node = NULL;
    } else {
        StageRegistryMarkUnknown(Reservation->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION, FALSE);
    }
    FltReleaseContext(streamContext);
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryUnknownWriterEnd(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE;
    BOOLEAN recheck = FALSE;
    KIRQL irql;
    if (Instance == NULL || SectionObjectPointer == NULL) return;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    if (found && slot != NULL && (slot->Unknown || slot->Entry != NULL) &&
        slot->InstanceIdentity == (PVOID)Instance && slot->UnknownWriterCount != 0) {
        slot->UnknownWriterCount -= 1;
        InterlockedIncrement64(&RegistrySopMapGeneration);
        InterlockedIncrement64(&RegistryChangeSequence);
        recheck = slot->UnknownWriterCount == 0;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (recheck) SafeUploadStageWritersQueueRecheck();
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryCopyUnknownSopChunk(_In_ PFLT_INSTANCE Instance,
    _In_ ULONG Base,
    _Out_writes_to_(SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK, *SnapshotCount) PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshots,
    _Out_ PULONG SnapshotCount)
{
    ULONG index;
    KIRQL irql;
    *SnapshotCount = 0;
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = Base; index < min(Base + SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK,
            (ULONG)RTL_NUMBER_OF(RegistrySopSlots)); ++index) {
        PSTAGE_REGISTRY_SOP_SLOT slot = &RegistrySopSlots[index];
        PSTAGE_REGISTRY_SOP_SNAPSHOT snapshot;
        if (slot->SectionObjectPointer == NULL || !slot->Unknown ||
            slot->InstanceIdentity != (PVOID)Instance) continue;
        snapshot = &Snapshots[(*SnapshotCount)++];
        snapshot->SectionObjectPointer = slot->SectionObjectPointer;
        snapshot->VolumeSerial = slot->VolumeSerial;
        snapshot->StreamSuffixHash = slot->StreamSuffixHash;
        snapshot->FileId = slot->FileId;
        snapshot->UnknownWriterCount = slot->UnknownWriterCount;
        snapshot->SpilledSectionAcquireCount = slot->SpilledSectionAcquireCount;
        snapshot->SpilledSectionCount = slot->SpilledSectionCount;
        snapshot->SpilledSectionReleasePending = slot->SpilledSectionReleasePending;
        snapshot->SpilledMutatingIoCount = slot->SpilledMutatingIoCount;
        snapshot->ScopePolicyGeneration = slot->ScopePolicyGeneration;
        snapshot->ScopeScanRenameVersion = slot->ScopeScanRenameVersion;
        snapshot->ScopeScanLinkCount = slot->ScopeScanLinkCount;
        snapshot->ScopeScanNextLink = slot->ScopeScanNextLink;
        snapshot->ScopeScanUnionScoped = slot->ScopeScanUnionScoped;
        snapshot->ScopeScanCurrentScoped = slot->ScopeScanCurrentScoped;
        snapshot->ScopeScanPending = slot->ScopeScanPending;
        snapshot->ScopeClassification = slot->ScopeClassification;
    }
    StageReleaseSpinLock(&SectionLock, irql);
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryRetireUnknownSopIfSame(_In_ PFLT_INSTANCE Instance,
    _In_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE, sameIdentity;
    KIRQL irql;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(Snapshot->SectionObjectPointer, &found);
    sameIdentity = found && slot != NULL && slot->Unknown &&
        slot->InstanceIdentity == (PVOID)Instance && slot->UnknownWriterCount == 0 &&
        slot->SpilledSectionAcquireCount == 0 && slot->SpilledSectionCount == 0 &&
        slot->SpilledSectionReleasePending == 0 &&
        slot->SpilledMutatingIoCount == 0 &&
        slot->VolumeSerial == Snapshot->VolumeSerial &&
        slot->StreamSuffixHash == Snapshot->StreamSuffixHash &&
        RtlEqualMemory(&slot->FileId, &Snapshot->FileId, sizeof(slot->FileId));
    if (sameIdentity) {
        StageRegistryRemoveSopSlotLocked(slot);
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return sameIdentity;
}

static BOOLEAN StageRegistrySopSnapshotQuiescent(_In_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume)
{
    STAGE_REGISTRY_ENTRY probe;
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    PSECTION_OBJECT_POINTERS sop;
    UINT32 sections, spilledTotal;
    NTSTATUS status;
    BOOLEAN quiescent = FALSE;

    PAGED_CODE();
    if (Snapshot->UnknownWriterCount != 0 || Snapshot->SpilledSectionAcquireCount != 0 ||
        Snapshot->SpilledSectionReleasePending != 0 || Snapshot->SpilledMutatingIoCount != 0)
        return FALSE;
    RtlZeroMemory(&probe, sizeof(probe));
    probe.Listed = TRUE;
    probe.StreamIdentityKnown = TRUE;
    probe.Compact = TRUE;
    probe.CompactStream = Snapshot->StreamSuffixHash != 0;
    probe.StreamSuffixHash = Snapshot->StreamSuffixHash;
    probe.Instance = Instance;
    probe.Volume = Volume;
    probe.VolumeSerial = Snapshot->VolumeSerial;
    probe.FileId = Snapshot->FileId;
    probe.SectionObjectPointer = Snapshot->SectionObjectPointer;

    status = StageRegistryOpenIdentity(&probe, Instance, Volume, &handle, &object);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_FILE_DELETED ||
        status == STATUS_DELETE_PENDING) {
        quiescent = TRUE;
        goto Exit;
    }
    if (!NT_SUCCESS(status) || object == NULL || object->SectionObjectPointer == NULL) goto Exit;
    sop = object->SectionObjectPointer;
    if (sop != Snapshot->SectionObjectPointer) {
        quiescent = TRUE; /* The old SCB incarnation is gone; NTFS reused its file ID. */
        goto Exit;
    }
    StageRegistrySpilledSectionSnapshot(sop, &sections, &spilledTotal);
    quiescent = MmDoesFileHaveUserWritableReferences(sop) == FALSE &&
        (sections & SAFEUPLOAD_SECTIONS_UNTRACKED_BIT) == 0 && sections == 0 && spilledTotal == 0 &&
        sop->DataSectionObject == NULL && sop->SharedCacheMap == NULL;
Exit:
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    return quiescent;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryStoreUnknownSopClassification(
    _In_ PFLT_INSTANCE Instance, _In_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot,
    _In_ PSTAGE_REGISTRY_ENTRY Probe, _In_ ULONG PolicyGeneration,
    _In_ LONG Classification, _Out_ PBOOLEAN Changed)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE;
    KIRQL irql;
    *Changed = FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(Snapshot->SectionObjectPointer, &found);
    if (found && slot != NULL && slot->Unknown &&
        slot->InstanceIdentity == (PVOID)Instance &&
        slot->VolumeSerial == Snapshot->VolumeSerial &&
        slot->StreamSuffixHash == Snapshot->StreamSuffixHash &&
        RtlEqualMemory(&slot->FileId, &Snapshot->FileId, sizeof(slot->FileId))) {
        if (slot->ScopePolicyGeneration != PolicyGeneration ||
            slot->ScopeClassification != Classification ||
            slot->ScopeScanRenameVersion != Probe->ScopeScanRenameVersion ||
            slot->ScopeScanLinkCount != Probe->ScopeScanLinkCount ||
            slot->ScopeScanNextLink != Probe->ScopeScanNextLink ||
            slot->ScopeScanUnionScoped != Probe->ScopeScanUnionScoped ||
            slot->ScopeScanCurrentScoped != Probe->ScopeScanCurrentScoped ||
            slot->ScopeScanPending != Probe->ScopeScanPending) {
            slot->ScopePolicyGeneration = PolicyGeneration;
            slot->ScopeClassification = Classification;
            slot->ScopeScanRenameVersion = Probe->ScopeScanRenameVersion;
            slot->ScopeScanLinkCount = Probe->ScopeScanLinkCount;
            slot->ScopeScanNextLink = Probe->ScopeScanNextLink;
            slot->ScopeScanUnionScoped = Probe->ScopeScanUnionScoped;
            slot->ScopeScanCurrentScoped = Probe->ScopeScanCurrentScoped;
            slot->ScopeScanPending = Probe->ScopeScanPending;
            InterlockedIncrement64(&RegistrySopMapGeneration);
            InterlockedIncrement64(&RegistryChangeSequence);
            *Changed = TRUE;
        }
    }
    StageReleaseSpinLock(&SectionLock, irql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySopScopeClassification(
    _In_ PFLT_INSTANCE Instance, _In_ PVOID SectionObjectPointer,
    _In_ ULONG PolicyGeneration, _Out_ PBOOLEAN Known, _Out_ PBOOLEAN Outside)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE;
    KIRQL irql;
    *Known = FALSE;
    *Outside = FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    if (found && slot != NULL && slot->Unknown &&
        slot->InstanceIdentity == (PVOID)Instance &&
        slot->ScopePolicyGeneration == PolicyGeneration &&
        slot->ScopeClassification != STAGE_SCOPE_CLASS_UNRESOLVED &&
        slot->ScopeScanPending == 0) {
        *Known = TRUE;
        *Outside = slot->ScopeClassification == STAGE_SCOPE_CLASS_OUTSIDE;
    }
    StageReleaseSpinLock(&SectionLock, irql);
}

_IRQL_requires_(PASSIVE_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryClassifyUnknownSopSnapshot(
    _Inout_ PSTAGE_REGISTRY_SOP_SNAPSHOT Snapshot, _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _Inout_ PULONG WorkBudget, _In_ ULONG PolicyGeneration,
    _Out_ PBOOLEAN Outside, _Out_ PBOOLEAN WorkRemaining, _Out_ PBOOLEAN Changed)
{
    STAGE_REGISTRY_ENTRY probe;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    BOOLEAN unionScoped = FALSE, currentScoped = FALSE, known;
    LONG classification = STAGE_SCOPE_CLASS_UNRESOLVED;
    NTSTATUS status;
    ULONG generationAfter;

    PAGED_CODE();
    *Outside = FALSE;
    *WorkRemaining = FALSE;
    *Changed = FALSE;
    if (Snapshot->ScopePolicyGeneration == PolicyGeneration &&
        Snapshot->ScopeClassification != STAGE_SCOPE_CLASS_UNRESOLVED &&
        Snapshot->ScopeScanPending == 0) {
        *Outside = Snapshot->ScopeClassification == STAGE_SCOPE_CLASS_OUTSIDE;
        return TRUE;
    }
    RtlZeroMemory(&probe, sizeof(probe));
    probe.Listed = TRUE;
    probe.StreamIdentityKnown = TRUE;
    probe.Compact = TRUE;
    probe.CompactStream = Snapshot->StreamSuffixHash != 0;
    probe.StreamSuffixHash = Snapshot->StreamSuffixHash;
    probe.Instance = Instance;
    probe.Volume = Volume;
    probe.VolumeSerial = Snapshot->VolumeSerial;
    probe.FileId = Snapshot->FileId;
    probe.SectionObjectPointer = Snapshot->SectionObjectPointer;
    if (!NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext)))
        return FALSE;
    probe.VolumeKind = instanceContext->VolumeKind;
    FltReleaseContext(instanceContext);
    if (Snapshot->ScopePolicyGeneration == PolicyGeneration) {
        probe.RenameVersion = Snapshot->ScopeScanRenameVersion;
        probe.ScopeScanRenameVersion = Snapshot->ScopeScanRenameVersion;
        probe.ScopeScanPolicyGeneration = Snapshot->ScopePolicyGeneration;
        probe.ScopeScanLinkCount = Snapshot->ScopeScanLinkCount;
        probe.ScopeScanNextLink = Snapshot->ScopeScanNextLink;
        probe.ScopeScanUnionScoped = Snapshot->ScopeScanUnionScoped;
        probe.ScopeScanCurrentScoped = Snapshot->ScopeScanCurrentScoped;
        probe.ScopeScanPending = Snapshot->ScopeScanPending;
    }
    status = StageRegistryClassifyAllLinkNames(&probe, Instance, Volume, WorkBudget,
        &unionScoped, &currentScoped);
    if (status == STATUS_MORE_ENTRIES) {
        *WorkRemaining = TRUE;
    } else if (NT_SUCCESS(status)) {
        classification = unionScoped ? STAGE_SCOPE_CLASS_SCOPED : STAGE_SCOPE_CLASS_OUTSIDE;
    } else {
        probe.ScopeScanNextLink = 0;
        probe.ScopeScanUnionScoped = 0;
        probe.ScopeScanCurrentScoped = 0;
        probe.ScopeScanPending = 0;
    }
    generationAfter = (ULONG)SafeUploadCurrentPolicyGeneration();
    if (generationAfter != PolicyGeneration) {
        classification = STAGE_SCOPE_CLASS_UNRESOLVED;
        probe.ScopeScanNextLink = 0;
        probe.ScopeScanUnionScoped = 0;
        probe.ScopeScanCurrentScoped = 0;
        probe.ScopeScanPending = 0;
        *WorkRemaining = TRUE;
    }
    StageRegistryStoreUnknownSopClassification(Instance, Snapshot, &probe,
        PolicyGeneration, classification, Changed);
    Snapshot->ScopePolicyGeneration = PolicyGeneration;
    Snapshot->ScopeClassification = classification;
    Snapshot->ScopeScanRenameVersion = probe.ScopeScanRenameVersion;
    Snapshot->ScopeScanLinkCount = probe.ScopeScanLinkCount;
    Snapshot->ScopeScanNextLink = probe.ScopeScanNextLink;
    Snapshot->ScopeScanUnionScoped = probe.ScopeScanUnionScoped;
    Snapshot->ScopeScanCurrentScoped = probe.ScopeScanCurrentScoped;
    Snapshot->ScopeScanPending = probe.ScopeScanPending;
    known = classification != STAGE_SCOPE_CLASS_UNRESOLVED &&
        probe.ScopeScanPending == 0;
    *Outside = known && classification == STAGE_SCOPE_CLASS_OUTSIDE;
    return known;
}

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN StageRegistryUnknownSopMarkersQuiescent(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _Inout_ PULONG WorkBudget,
    _Out_ PBOOLEAN WorkRemaining, _Out_ PULONGLONG Generation)
{
    PSTAGE_REGISTRY_SOP_SNAPSHOT snapshots;
    ULONGLONG startingGeneration, expectedGeneration;
    ULONG base, index, snapshotCount, policyGeneration;
    BOOLEAN liveMarker = FALSE;

    PAGED_CODE();
    *WorkRemaining = FALSE;
    *Generation = (ULONGLONG)InterlockedCompareExchange64(&RegistrySopMapGeneration, 0, 0);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL ||
        Instance == NULL || Volume == NULL) return FALSE;
    snapshots = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK * sizeof(*snapshots), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (snapshots == NULL) return FALSE;
    startingGeneration = (ULONGLONG)InterlockedCompareExchange64(&RegistrySopMapGeneration, 0, 0);
    expectedGeneration = startingGeneration;
    policyGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
    for (base = 0; base < RTL_NUMBER_OF(RegistrySopSlots); base += SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK) {
        StageRegistryCopyUnknownSopChunk(Instance, base, snapshots, &snapshotCount);

        for (index = 0; index < snapshotCount; ++index) {
            PSTAGE_REGISTRY_SOP_SNAPSHOT snapshot = &snapshots[index];
            BOOLEAN outside = FALSE, classificationKnown = FALSE;
            BOOLEAN changed = FALSE, markerWorkRemaining = FALSE;
            BOOLEAN streamQuiescent;
            if (snapshot->ScopePolicyGeneration == policyGeneration &&
                snapshot->ScopeClassification != STAGE_SCOPE_CLASS_UNRESOLVED &&
                snapshot->ScopeScanPending == 0) {
                classificationKnown = TRUE;
                outside = snapshot->ScopeClassification == STAGE_SCOPE_CLASS_OUTSIDE;
            } else if (*WorkBudget != 0) {
                classificationKnown = StageRegistryClassifyUnknownSopSnapshot(snapshot,
                    Instance, Volume, WorkBudget, policyGeneration, &outside,
                    &markerWorkRemaining, &changed);
            } else {
                markerWorkRemaining = TRUE;
            }
            if (changed) expectedGeneration += 1;
            if (markerWorkRemaining) *WorkRemaining = TRUE;
            streamQuiescent = StageRegistrySopSnapshotQuiescent(snapshot, Instance, Volume);
            if (streamQuiescent && StageRegistryRetireUnknownSopIfSame(Instance, snapshot)) {
                expectedGeneration += 1;
            } else if (!streamQuiescent && (!classificationKnown || !outside)) {
                liveMarker = TRUE;
            } else if (streamQuiescent) {
                liveMarker = TRUE; /* concurrent marker update prevented exact retirement */
            }
        }
    }
    *Generation = (ULONGLONG)InterlockedCompareExchange64(&RegistrySopMapGeneration, 0, 0);
    if (*Generation != expectedGeneration) liveMarker = TRUE; /* concurrent marker insert/update/removal */
    if ((ULONG)SafeUploadCurrentPolicyGeneration() != policyGeneration) {
        *WorkRemaining = TRUE;
        liveMarker = TRUE;
    }
    ExFreePoolWithTag(snapshots, SAFEUPLOAD_REGISTRY_POOL_TAG);
    return !liveMarker;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryClearUnknownSopBindings(_In_ PFLT_INSTANCE Instance)
{
    ULONG base, index;
    KIRQL irql;
    for (base = 0; base < RTL_NUMBER_OF(RegistrySopSlots); base += SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK) {
        StageAcquireSpinLock(&SectionLock, &irql);
        for (index = base; index < min(base + SAFEUPLOAD_REGISTRY_SOP_SCAN_CHUNK,
                (ULONG)RTL_NUMBER_OF(RegistrySopSlots)); ++index) {
            PSTAGE_REGISTRY_SOP_SLOT slot = &RegistrySopSlots[index];
            if (slot->SectionObjectPointer != NULL && slot->Unknown &&
                slot->InstanceIdentity == (PVOID)Instance)
                StageRegistryRemoveSopSlotLocked(slot);
        }
        StageReleaseSpinLock(&SectionLock, irql);
    }
    InterlockedIncrement64(&RegistryChangeSequence);
}

static VOID StageRegistryRetireInstance(_In_ PFLT_INSTANCE Instance, _In_ BOOLEAN Dismount)
{
    PLIST_ENTRY link;
    FltAcquirePushLockExclusive(&RegistryLock);
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reservation = CONTAINING_RECORD(link,
            STAGE_WRITER_RESERVATION, Link);
        if (reservation->Instance == Instance)
            InterlockedExchange(&reservation->TeardownState, Dismount ?
                SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN : SAFEUPLOAD_INSTANCE_STATE_UNKNOWN);
    }
    FltReleasePushLock(&RegistryLock);

    /* A terminal notification after teardown has no useful admission state. Drop each association here;
     * any non-dismount loss is already covered by machine-wide Unknown. */
    for (;;) {
        PSTAGE_TX_ASSOCIATION association = NULL;
        FltAcquirePushLockExclusive(&RegistryLock);
        for (link = TransactionAssociations.Flink; link != &TransactionAssociations; link = link->Flink) {
            PSTAGE_TX_ASSOCIATION current = CONTAINING_RECORD(link, STAGE_TX_ASSOCIATION, Link);
            if (current->Instance == Instance) {
                association = current;
                RemoveEntryList(&association->Link);
                association->Listed = FALSE;
                if (RegistryAssociationCount != 0) RegistryAssociationCount -= 1;
                InterlockedDecrement(&association->Entry->T);
                InterlockedIncrement64(&RegistryChangeSequence);
                association->CompletionStatus = STATUS_SUCCESS;
                InterlockedExchange(&association->State, SAFEUPLOAD_TX_ASSOC_TERMINAL);
                KeSetEvent(&association->StateChanged, IO_NO_INCREMENT, FALSE);
                break;
            }
        }
        FltReleasePushLock(&RegistryLock);
        if (association == NULL) break;
        StageRegistryAssociationDereference(association); /* Drop the table reference. */
    }

    for (;;) {
        BOOLEAN detached = FALSE;
        PSTAGE_REGISTRY_ENTRY entry = StageRegistryDetachOneInstanceSectionBinding(Instance, &detached);
        if (!detached) break;
        StageRegistryDereference(entry); /* The map or exact C slot reference, if one was bound. */
    }
    for (;;) {
        BOOLEAN detached = FALSE;
        PSTAGE_SECTION_SPILL_RECORD spill = StageRegistryDetachOneInstanceSpill(Instance, &detached);
        if (!detached) break;
        ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
    StageRegistryClearUnknownSopBindings(Instance);

    /* Retire last (the loops above find this instance's slots through Entry->Instance). Retirement also releases each entry's
     * instance and volume references: stream contexts and writer nodes can still hold entries, and Filter Manager frees those
     * contexts only AFTER FltpFreeInstance has waited out every FltObjectReference on the instance. An entry pinning its
     * instance therefore deadlocked teardown (registry-txf runs 2-6: fltmc unload parked in FltpFreeInstance, rundown count 1).
     * A retired entry is unlisted history and is never matched again, so it needs no live instance or volume. */
    for (;;) {
        PSTAGE_REGISTRY_ENTRY entry = NULL;
        PFLT_INSTANCE instanceReference = NULL;
        PFLT_VOLUME volumeReference = NULL;
        FltAcquirePushLockExclusive(&RegistryLock);
        for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
            PSTAGE_REGISTRY_ENTRY current = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
            if (current->Instance == Instance && !current->Retired) {
                entry = current;
                entry->Retired = TRUE;
                RemoveEntryList(&entry->Link);
                entry->Listed = FALSE;
                instanceReference = entry->Instance;
                volumeReference = entry->Volume;
                entry->Instance = NULL;
                entry->Volume = NULL;
                if (entry->Compact) {
                    if (RegistryCompactEntryCount != 0) RegistryCompactEntryCount -= 1;
                } else {
                    if (RegistryEntryCount != 0) RegistryEntryCount -= 1;
                    if (RegistryNameBytes >= StageRegistryEntryNameStorageBytes(entry))
                        RegistryNameBytes -= StageRegistryEntryNameStorageBytes(entry);
                }
                break;
            }
        }
        FltReleasePushLock(&RegistryLock);
        if (entry == NULL) break;
        if (Dismount) InterlockedIncrement64(&RegistryDroppedAtDismount);
        else {
            InterlockedIncrement64(&RegistryDroppedWhileMounted);
            InterlockedExchange(&WriterGlobalUnknown, 1);
            InterlockedOr((volatile LONG *)&RegistryUnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
        }
        if (volumeReference != NULL) FltObjectDereference(volumeReference);
        if (instanceReference != NULL) FltObjectDereference(instanceReference);
        StageRegistryDereference(entry); /* Drop the registry-history reference. */
    }
}

static VOID StageRegistryBeginInstanceTeardown(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PSAFEUPLOAD_INSTANCE_TEARDOWN_TOKEN Token, _In_ BOOLEAN Dismount)
{
    PLIST_ENTRY link;
    FltAcquirePushLockExclusive(&RegistryLock);
    if (Token != NULL) {
        InterlockedExchange(&Token->State, Dismount ?
            SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN : SAFEUPLOAD_INSTANCE_STATE_UNKNOWN);
    }
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        PSTAGE_WRITER_RESERVATION reservation = CONTAINING_RECORD(link,
            STAGE_WRITER_RESERVATION, Link);
        if (reservation->Instance == Instance)
            InterlockedExchange(&reservation->TeardownState, Dismount ?
                SAFEUPLOAD_INSTANCE_STATE_TEARING_DOWN : SAFEUPLOAD_INSTANCE_STATE_UNKNOWN);
    }
    FltReleasePushLock(&RegistryLock);
}

/* Called by pageable post-create; SectionLock protects only nonpaged registry/slot state and stack scratch. */
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryAssociateSectionPointer(_In_ PSTAGE_WRITER_RESERVATION Reservation,
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_opt_ PVOID SectionObjectPointer)
{
    ULONG index;
    PVOID oldSectionObjectPointer;
    PSTAGE_REGISTRY_SOP_SLOT oldMap = NULL, map = NULL;
    BOOLEAN oldFound = FALSE, mapFound = FALSE;
    /* At most the previous SOP and a reused target pointer lose map references. */
    PSTAGE_REGISTRY_ENTRY released[2] = { NULL, NULL };
    ULONG releasedCount = 0;
    BOOLEAN ok = FALSE;
    BOOLEAN pointerConflict = FALSE;
    KIRQL irql;
    if (SectionObjectPointer == NULL) return FALSE;
    FltAcquirePushLockExclusive(&RegistryLock);
    if (!Reservation->Active || Entry->Retired || !Entry->Listed ||
        InterlockedCompareExchange(&Reservation->TeardownState, 0, 0) != SAFEUPLOAD_INSTANCE_STATE_ACTIVE) {
        FltReleasePushLock(&RegistryLock);
        return FALSE;
    }
    /* NTFS keeps exactly one SCB, hence one section-object pointer, per live stream, and every handle, section or mapped view
     * keeps that SCB alive. So a different pointer for this file ID, or this pointer still bound to another file ID, proves the
     * earlier incarnation is gone and no S reference can remain on it: rebind instead of failing. (registry-txf run 6: ordinary
     * pool reuse after close was read as a capacity failure and made the volume Unknown after 10 entries.) */
    oldSectionObjectPointer = InterlockedCompareExchangePointer(
        (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL);
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        if (SectionSlots[index].SectionObjectPointer == SectionObjectPointer &&
            SectionSlots[index].Writable && SectionSlots[index].RegistryEntry != NULL &&
            SectionSlots[index].RegistryEntry != Entry) {
            pointerConflict = TRUE;
            break;
        }
    }
    if (pointerConflict) {
        StageReleaseSpinLock(&SectionLock, irql);
        FltReleasePushLock(&RegistryLock);
        return FALSE;
    }
    /* The conflict check above stands: a writable section in flight on this pointer bound to another entry is inconsistent. */
    InterlockedExchangePointer((PVOID volatile *)&Entry->SectionObjectPointer, SectionObjectPointer);
    if (oldSectionObjectPointer != NULL && oldSectionObjectPointer != SectionObjectPointer) {
        oldMap = StageRegistryFindSopSlotLocked(oldSectionObjectPointer, &oldFound);
        if (oldFound && oldMap->Entry == Entry) {
            released[releasedCount++] = oldMap->Entry;
            StageRegistryRemoveSopSlotLocked(oldMap);
        }
    }
    map = StageRegistryFindSopSlotLocked(SectionObjectPointer, &mapFound);
    if (mapFound) {
        if (map->Unknown) {
            BOOLEAN sameIdentity = map->VolumeSerial == Entry->VolumeSerial &&
                RtlEqualMemory(&map->FileId, &Entry->FileId, sizeof(Entry->FileId)) &&
                map->StreamSuffixHash == Entry->StreamSuffixHash;
            if (sameIdentity) {
                LONG stickyReasons = map->UnknownReasons & ~SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY;
                if (stickyReasons != 0) StageRegistrySetEntryUnknownLocked(Entry, stickyReasons);
            } else if (map->UnknownWriterCount != 0 || map->SpilledSectionAcquireCount != 0 ||
                map->SpilledSectionReleasePending != 0 || map->SpilledMutatingIoCount != 0) {
                pointerConflict = TRUE;
            }
            if (!pointerConflict) {
                map->Unknown = FALSE;
                map->UnknownReasons = 0;
                map->InstanceIdentity = (PVOID)Reservation->Instance;
                map->VolumeSerial = Entry->VolumeSerial;
                map->StreamSuffixHash = Entry->StreamSuffixHash;
                map->FileId = Entry->FileId;
                map->Entry = Entry;
                StageRegistryReference(Entry);
                InterlockedIncrement64(&RegistrySopMapGeneration);
            }
        } else if (map->Entry != Entry && map->Entry != NULL &&
            (map->UnknownWriterCount != 0 || map->SpilledSectionAcquireCount != 0 ||
             map->SpilledSectionReleasePending != 0 || map->SpilledMutatingIoCount != 0)) {
            pointerConflict = TRUE;
        } else if (map->Entry != Entry && map->Entry != NULL) {
            /* NTFS can reuse an SCB address after the old stream is gone. */
            (VOID)InterlockedCompareExchangePointer((PVOID volatile *)&map->Entry->SectionObjectPointer,
                NULL, SectionObjectPointer);
            released[releasedCount++] = map->Entry;
            map->Entry = Entry;
            map->VolumeSerial = Entry->VolumeSerial;
            map->StreamSuffixHash = Entry->StreamSuffixHash;
            map->FileId = Entry->FileId;
            StageRegistryReference(Entry);
            InterlockedIncrement64(&RegistrySopMapGeneration);
        }
        ok = map->Entry == Entry;
    } else if (map != NULL) {
        RtlZeroMemory(map, sizeof(*map));
        StageRegistryReference(Entry);
        map->SectionObjectPointer = SectionObjectPointer;
        map->Entry = Entry;
        map->VolumeSerial = Entry->VolumeSerial;
        map->StreamSuffixHash = Entry->StreamSuffixHash;
        map->FileId = Entry->FileId;
        InterlockedIncrement64(&RegistrySopMapGeneration);
        ok = TRUE;
    }
    if (ok) {
        ULONG slotIndex;
        if (map != NULL && map->Entry == Entry)
            map->InstanceIdentity = (PVOID)Reservation->Instance;
        for (slotIndex = 0; slotIndex < STAGE_SECTION_SLOTS; ++slotIndex) {
            STAGE_SECTION_SLOT *slot = &SectionSlots[slotIndex];
            if (slot->SectionObjectPointer == SectionObjectPointer && slot->RegistryEntry == NULL) {
                StageRegistryReference(Entry);
                slot->RegistryEntry = Entry;
                slot->VolumeSerial = Entry->VolumeSerial;
                slot->FileId = Entry->FileId;
            }
        }
    } else if (map == NULL && !pointerConflict) {
        /* The Entry itself retains SOP+file identity; per-acquire section spills remain exact. */
        ok = TRUE;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    FltReleasePushLock(&RegistryLock);
    for (index = 0; index < releasedCount; ++index) StageRegistryDereference(released[index]);
    if (!ok) {
        InterlockedIncrement64(&RegistryCapacityFailures);
        InterlockedIncrement((volatile LONG *)&RegistryOverflow);
    }
    return ok;
}

/* ---- Pruning: the registry holds only files that may still be live -------------------------------------------------
 * An entry exists to remember a possible writer. Once a file has no writer handle, no writable section in flight, no
 * transaction, no rename in flight, AND its live stream has neither a data section nor a shared cache map (so no mapping
 * and no dirty cache can still write to it), the entry says nothing an absent entry would not: it is removed. The registry
 * is then bounded by concurrency, not uptime (owner-approved 2026-10-04; run 10 filled 1,024 entries within minutes).
 * Entries that carry an Unknown reason are never pruned: they record a loss. No timers and no file-system scan: one
 * reclaim worker runs when an instance or the total crosses 3/4 of its limit, or on a capacity failure. */

#define STAGE_RECLAIM_BATCH 128

/* Caller holds RegistryLock exclusive. Unlinks Entry if nothing can still be bound to it; returns the map-slot reference
 * to drop (at most one, since every pointer occupies one slot) through *MapReference. The caller drops the history
 * reference and *MapReference after releasing the lock. */
/* Called by the pageable reclaim worker; keep its SectionLock operation resident. */
__declspec(noinline) static BOOLEAN StageRegistryPruneLocked(_In_ PSTAGE_REGISTRY_ENTRY Entry, _Out_ PSTAGE_REGISTRY_ENTRY *MapReference,
    _Out_ PFLT_INSTANCE *InstanceReference, _Out_ PFLT_VOLUME *VolumeReference)
{
    PLIST_ENTRY link;
    UNICODE_STRING entryName;
    ULONG index;
    KIRQL irql;
    BOOLEAN busy = FALSE, mapFound = FALSE;
    PSTAGE_REGISTRY_SOP_SLOT map;
    *MapReference = NULL;
    *InstanceReference = NULL;
    *VolumeReference = NULL;
    entryName.Buffer = Entry->Name;
    entryName.Length = entryName.MaximumLength = (USHORT)(Entry->NameChars * sizeof(WCHAR));
    if (!Entry->Listed || Entry->Retired ||
        InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ||
        InterlockedCompareExchange(&Entry->H, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->W, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->T, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0 ||
        StageRegistryDirectoryRenameInFlightLocked(Entry->Instance, &entryName) ||
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0) return FALSE;
    for (link = RegistryReservations.Flink; link != &RegistryReservations; link = link->Flink) {
        if (CONTAINING_RECORD(link, STAGE_WRITER_RESERVATION, Link)->BoundEntry == Entry) return FALSE;
    }
    for (link = TransactionAssociations.Flink; link != &TransactionAssociations; link = link->Flink) {
        if (CONTAINING_RECORD(link, STAGE_TX_ASSOCIATION, Link)->Entry == Entry) return FALSE;
    }
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        if (SectionSlots[index].RegistryEntry == Entry) { busy = TRUE; break; }
    }
    if (!busy) {
        PLIST_ENTRY spillLink;
        PVOID sop = InterlockedCompareExchangePointer(
            (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL);
        for (spillLink = SectionSpills.Flink; spillLink != &SectionSpills;
             spillLink = spillLink->Flink) {
            PSTAGE_SECTION_SPILL_RECORD spill = CONTAINING_RECORD(spillLink,
                STAGE_SECTION_SPILL_RECORD, Link);
            if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE &&
                spill->SectionObjectPointer == sop) {
                busy = TRUE;
                break;
            }
        }
    }
    if (!busy) {
        map = StageRegistryFindSopSlotLocked(InterlockedCompareExchangePointer(
            (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL), &mapFound);
        if (mapFound && map->Entry == Entry) {
            if (map->UnknownWriterCount != 0 || map->SpilledSectionAcquireCount != 0 ||
                map->SpilledSectionCount != 0 ||
                map->SpilledSectionReleasePending != 0 || map->SpilledMutatingIoCount != 0) {
                busy = TRUE;
            } else {
                *MapReference = map->Entry;
                StageRegistryRemoveSopSlotLocked(map);
            }
        }
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (busy) return FALSE;
    RemoveEntryList(&Entry->Link);
    Entry->Listed = FALSE;
    Entry->Retired = TRUE;
    /* Like retirement: an unlisted entry is never matched again, so it releases its instance and volume now. A stream
     * context may keep the entry alive, and Filter Manager frees contexts only after waiting out every reference on the
     * instance: keeping them deadlocked unload (registry-txf run 13, rundown count 1 after 2,991 prunes). */
    *InstanceReference = Entry->Instance;
    *VolumeReference = Entry->Volume;
    Entry->Instance = NULL;
    Entry->Volume = NULL;
    if (Entry->Compact) {
        if (RegistryCompactEntryCount != 0) RegistryCompactEntryCount -= 1;
    } else {
        if (RegistryEntryCount != 0) RegistryEntryCount -= 1;
        if (RegistryNameBytes >= StageRegistryEntryNameStorageBytes(Entry))
            RegistryNameBytes -= StageRegistryEntryNameStorageBytes(Entry);
    }
    return TRUE;
}

/* PASSIVE. Opens the candidate by its 64-bit NTFS file reference (never the 16-byte form, which NTFS reads as an object
 * ID), verifies all 128 ID bits and the volume serial, and reports whether the live stream is quiescent. A file that no
 * longer exists is quiescent too: nothing can write to it. */
static BOOLEAN StageRegistryEntryQuiescent(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume)
{
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    BOOLEAN quiescent = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    if (InterlockedCompareExchange(&Entry->H, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->W, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->T, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0 ||
        StageRegistrySnapshotSpilledWriters(Entry) != 0 ||
        StageRegistrySnapshotSpilledMutatingIo(Entry) != 0 ||
        StageRegistrySnapshotC(Entry, NULL, 0, NULL) != 0) return FALSE;
    status = StageRegistryOpenIdentity(Entry, Instance, Volume, &handle, &object);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_FILE_DELETED ||
        status == STATUS_DELETE_PENDING) {
        quiescent = TRUE; /* the file is gone (or going): no writer, mapping or cache can reach it */
        goto Exit;
    }
    if (status != STATUS_SUCCESS || object == NULL || object->SectionObjectPointer == NULL) goto Exit;
    if (object->SectionObjectPointer != InterlockedCompareExchangePointer(
            (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL)) {
        quiescent = TRUE; /* the original stream incarnation is gone */
        goto Exit;
    }
    /* Our open holds the stream's one live SCB, so these pointers are current. No data section means no mapping (writable
     * or not); no shared cache map means no dirty cached data. */
    quiescent = object->SectionObjectPointer != NULL &&
        object->SectionObjectPointer->DataSectionObject == NULL &&
        object->SectionObjectPointer->SharedCacheMap == NULL;
Exit:
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    return quiescent;
}

/* A compact ADS keeps only a suffix hash. Reopen the base ID, enumerate its
 * stream names, and recover the matching suffix before binding I/O. */
static NTSTATUS StageRegistryResolveCompactStream(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _Out_writes_(SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) PWCH StreamBuffer,
    _Out_ PUSHORT StreamChars)
{
    UNICODE_STRING volumeName = { 0 }, name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = { 0 };
    FILE_ID_INFORMATION actual;
    PFILE_STREAM_INFORMATION streams = NULL, stream;
    PFILE_OBJECT object = NULL;
    HANDLE handle = NULL;
    PWCHAR buffer = NULL;
    ULONG needed = 0, bufferBytes = 4096, returned = 0, offset;
    NTSTATUS status;
    PAGED_CODE();
    *StreamChars = 0;
    if (StreamBuffer == NULL) return STATUS_FILE_INVALID;
    StreamBuffer[0] = UNICODE_NULL;
    if (Entry->StreamSuffixHash == 0) return STATUS_FILE_INVALID;
    status = FltGetVolumeName(Volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 || needed > MAXUSHORT - 32)
        return STATUS_FLT_INSTANCE_NOT_FOUND;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, needed + sizeof(WCHAR) + sizeof(ULONGLONG),
        SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    volumeName.Buffer = buffer;
    volumeName.MaximumLength = (USHORT)needed;
    status = FltGetVolumeName(Volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer[volumeName.Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + volumeName.Length + sizeof(WCHAR),
        Entry->FileId.Identifier, sizeof(ULONGLONG));
    name.Buffer = buffer;
    name.Length = name.MaximumLength = (USHORT)(volumeName.Length + sizeof(WCHAR) + sizeof(ULONGLONG));
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &handle, &object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED, NULL, 0, 0, NULL);
    if (!NT_SUCCESS(status) || object == NULL) goto Exit;
    RtlZeroMemory(&actual, sizeof(actual));
    status = FltQueryInformationFile(Instance, object, &actual, sizeof(actual),
        FileIdInformation, &returned);
    if (!NT_SUCCESS(status) || returned != sizeof(actual) ||
        actual.VolumeSerialNumber != Entry->VolumeSerial ||
        !RtlEqualMemory(&actual.FileId, &Entry->FileId, sizeof(actual.FileId))) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    streams = ExAllocatePool2(POOL_FLAG_PAGED, bufferBytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (streams == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    for (;;) {
        returned = 0;
        status = FltQueryInformationFile(Instance, object, streams, bufferBytes,
            FileStreamInformation, &returned);
        if (status == STATUS_SUCCESS) break;
        if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL) goto Exit;
        if (bufferBytes >= 1024 * 1024) { status = STATUS_BUFFER_TOO_SMALL; goto Exit; }
        bufferBytes = min(bufferBytes * 2, 1024 * 1024);
        ExFreePoolWithTag(streams, SAFEUPLOAD_REGISTRY_POOL_TAG);
        streams = ExAllocatePool2(POOL_FLAG_PAGED, bufferBytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
        if (streams == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    }
    offset = 0;
    for (;;) {
        UNICODE_STRING candidate;
        ULONG available, minimumBytes, nextOffset;
        USHORT chars;
        stream = (PFILE_STREAM_INFORMATION)((PUCHAR)streams + offset);
        available = returned - offset;
        nextOffset = stream->NextEntryOffset;
        if (available < (ULONG)FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) ||
            stream->StreamNameLength == 0 ||
            (stream->StreamNameLength & (sizeof(WCHAR) - 1)) != 0 ||
            stream->StreamNameLength > available - FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName)) {
            status = STATUS_FILE_INVALID;
            goto Exit;
        }
        minimumBytes = FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) + stream->StreamNameLength;
        if ((nextOffset != 0 && (nextOffset < minimumBytes || (nextOffset & 7) != 0 ||
                nextOffset > available)) || (nextOffset == 0 && minimumBytes > available)) {
            status = STATUS_FILE_INVALID;
            goto Exit;
        }
        candidate.Buffer = stream->StreamName;
        candidate.Length = candidate.MaximumLength = (USHORT)stream->StreamNameLength;
        chars = candidate.Length / sizeof(WCHAR);
        if (StageRegistryStreamSuffixHash(&candidate) == Entry->StreamSuffixHash) {
            if (chars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
                status = STATUS_NAME_TOO_LONG;
                goto Exit;
            }
            RtlCopyMemory(StreamBuffer, candidate.Buffer, candidate.Length);
            *StreamChars = chars;
            status = STATUS_SUCCESS;
            goto Exit;
        }
        if (nextOffset == 0) break;
        offset += nextOffset;
    }
    status = STATUS_OBJECT_NAME_NOT_FOUND;
Exit:
    if (streams != NULL) ExFreePoolWithTag(streams, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (!NT_SUCCESS(status)) *StreamChars = 0;
    return status;
}

static NTSTATUS StageRegistryOpenIdentity(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume, _Out_ PHANDLE Handle,
    _Outptr_result_nullonfailure_ PFILE_OBJECT *Object)
{
    UNICODE_STRING volumeName = { 0 }, name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = { 0 };
    FILE_ID_INFORMATION actual;
    PWCHAR buffer = NULL, streamSnapshot = NULL;
    ULONG needed = 0, bytes, returned = 0, streamBytes, renameVersion;
    USHORT compactStreamChars = 0;
    BOOLEAN compactStream = FALSE;
    NTSTATUS status;
    PAGED_CODE();
    *Handle = NULL;
    *Object = NULL;
    streamSnapshot = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (streamSnapshot == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    FltAcquirePushLockShared(&RegistryLock);
    if (!Entry->Listed || Entry->Retired || !Entry->StreamIdentityKnown ||
        Entry->StreamChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0) {
        FltReleasePushLock(&RegistryLock);
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    /* ADS names are appended after the stable 64-bit file reference so the
     * PASSIVE worker reopens the exact stream/SOP, never the base data stream. */
    streamBytes = Entry->CompactStream ? 0 : Entry->StreamChars * sizeof(WCHAR);
    compactStream = Entry->CompactStream;
    renameVersion = (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0);
    if (streamBytes != 0 && Entry->StreamName != NULL)
        RtlCopyMemory(streamSnapshot, Entry->StreamName, streamBytes);
    FltReleasePushLock(&RegistryLock);
    if (compactStream) {
        status = StageRegistryResolveCompactStream(Entry, Instance, Volume,
            streamSnapshot, &compactStreamChars);
        if (!NT_SUCCESS(status)) goto Exit;
        streamBytes = (ULONG)compactStreamChars * sizeof(WCHAR);
    }
    status = FltGetVolumeName(Volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 ||
        needed > MAXUSHORT - 64 - streamBytes) {
        status = STATUS_FLT_INSTANCE_NOT_FOUND;
        goto Exit;
    }
    bytes = needed + sizeof(WCHAR) + sizeof(ULONGLONG) + streamBytes;
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    volumeName.Buffer = buffer;
    volumeName.MaximumLength = (USHORT)needed;
    status = FltGetVolumeName(Volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer[volumeName.Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + volumeName.Length + sizeof(WCHAR),
        Entry->FileId.Identifier, sizeof(ULONGLONG));
    if (streamBytes != 0)
        RtlCopyMemory((PUCHAR)buffer + volumeName.Length + sizeof(WCHAR) + sizeof(ULONGLONG),
            streamSnapshot, streamBytes);
    name.Buffer = buffer;
    name.Length = name.MaximumLength = (USHORT)(volumeName.Length + sizeof(WCHAR) +
        sizeof(ULONGLONG) + streamBytes);
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, Handle, Object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED, NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS || *Object == NULL) goto Exit;
    RtlZeroMemory(&actual, sizeof(actual));
    status = FltQueryInformationFile(Instance, *Object, &actual, sizeof(actual),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(actual) ||
        actual.VolumeSerialNumber != Entry->VolumeSerial ||
        !RtlEqualMemory(&actual.FileId, &Entry->FileId, sizeof(actual.FileId)) ||
        (*Object)->SectionObjectPointer == NULL ||
        (*Object)->SectionObjectPointer != InterlockedCompareExchangePointer(
            (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL)) {
        status = STATUS_FILE_INVALID;
    }
    if (NT_SUCCESS(status) && (*Object)->SectionObjectPointer == NULL)
        status = STATUS_FILE_INVALID;
    if (NT_SUCCESS(status)) {
        BOOLEAN renameStable;
        FltAcquirePushLockShared(&RegistryLock);
        renameStable = Entry->Listed && !Entry->Retired &&
            InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) == 0 &&
            (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0) == renameVersion;
        FltReleasePushLock(&RegistryLock);
        if (!renameStable) status = STATUS_FILE_INVALID;
    }
Exit:
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (streamSnapshot != NULL) ExFreePoolWithTag(streamSnapshot, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        if (*Object != NULL) { ObDereferenceObject(*Object); *Object = NULL; }
        if (*Handle != NULL) { FltClose(*Handle); *Handle = NULL; }
    }
    return status;
}

__declspec(noinline) static NTSTATUS StageRegistryOpenParentById(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ ULONGLONG VolumeSerial, _In_ ULONGLONG ParentFileId,
    _Out_ PHANDLE Handle, _Outptr_result_nullonfailure_ PFILE_OBJECT *Object)
{
    UNICODE_STRING volumeName = { 0 }, name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io = { 0 };
    FILE_ID_INFORMATION actual;
    PWCHAR buffer = NULL;
    ULONG needed = 0, bytes, returned = 0;
    NTSTATUS status;

    PAGED_CODE();
    *Handle = NULL;
    *Object = NULL;
    if (ParentFileId == 0) return STATUS_FILE_INVALID;
    status = FltGetVolumeName(Volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 || needed > MAXUSHORT - 32)
        return STATUS_FLT_INSTANCE_NOT_FOUND;
    bytes = needed + sizeof(WCHAR) + sizeof(ParentFileId);
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    volumeName.Buffer = buffer;
    volumeName.MaximumLength = (USHORT)needed;
    status = FltGetVolumeName(Volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer[volumeName.Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + volumeName.Length + sizeof(WCHAR),
        &ParentFileId, sizeof(ParentFileId));
    name.Buffer = buffer;
    name.Length = name.MaximumLength = (USHORT)(volumeName.Length + sizeof(WCHAR) + sizeof(ParentFileId));
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, Handle, Object,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED, NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS || *Object == NULL) goto Exit;
    status = FltQueryInformationFile(Instance, *Object, &actual, sizeof(actual),
        FileIdInformation, &returned);
    if (!NT_SUCCESS(status) || returned != sizeof(actual) || actual.VolumeSerialNumber != VolumeSerial ||
        !RtlEqualMemory(actual.FileId.Identifier, &ParentFileId, sizeof(ParentFileId)))
        status = STATUS_FILE_INVALID;
Exit:
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        if (*Object != NULL) { ObDereferenceObject(*Object); *Object = NULL; }
        if (*Handle != NULL) { FltClose(*Handle); *Handle = NULL; }
    }
    return status;
}

__declspec(noinline) static VOID StageRegistryBuildLinkName(_In_ PCUNICODE_STRING ParentName,
    _In_reads_(ChildChars) PCWCH ChildName, _In_ ULONG ChildChars,
    _In_reads_opt_(StreamChars) PCWCH StreamName, _In_ ULONG StreamChars,
    _Out_writes_(SAFEUPLOAD_MAX_PREFIX_CHARS + 1) PWCH Buffer, _Out_ PUNICODE_STRING LinkName)
{
    ULONG parentChars, copyChars, used, childCopy, streamCopy;
    ULONG capacity = SAFEUPLOAD_MAX_PREFIX_CHARS + 1;

    PAGED_CODE();
    Buffer[0] = UNICODE_NULL;
    LinkName->Buffer = Buffer;
    LinkName->Length = 0;
    LinkName->MaximumLength = (USHORT)(capacity * sizeof(WCHAR));
    if (ParentName == NULL || ParentName->Buffer == NULL ||
        (ParentName->Length & (sizeof(WCHAR) - 1)) != 0 || ChildName == NULL || ChildChars == 0 ||
        (StreamChars != 0 && StreamName == NULL))
        return;
    parentChars = ParentName->Length / sizeof(WCHAR);
    copyChars = min(parentChars, capacity);
    if (copyChars != 0) RtlCopyMemory(Buffer, ParentName->Buffer, copyChars * sizeof(WCHAR));
    used = copyChars;
    if (parentChars <= SAFEUPLOAD_MAX_PREFIX_CHARS) {
        if (used != 0 && Buffer[used - 1] != L'\\' && used < capacity)
            Buffer[used++] = L'\\';
        childCopy = min(ChildChars, capacity - used);
        if (childCopy != 0) {
            RtlCopyMemory(Buffer + used, ChildName, childCopy * sizeof(WCHAR));
            used += childCopy;
        }
        if (childCopy == ChildChars && StreamChars != 0) {
            streamCopy = min(StreamChars, capacity - used);
            if (streamCopy != 0) {
                RtlCopyMemory(Buffer + used, StreamName, streamCopy * sizeof(WCHAR));
                used += streamCopy;
            }
        }
    }
    LinkName->Length = (USHORT)(used * sizeof(WCHAR));
}

/* P0-4: every expansion decision is based on the complete PASSIVE-level NTFS link list.
 * A truncated or unresolvable list is a failed classification and remains enforced Unknown. */
__declspec(noinline) static NTSTATUS StageRegistryClassifyAllLinkNames(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _Inout_ PULONG WorkBudget,
    _Out_ PBOOLEAN UnionScoped, _Out_ PBOOLEAN CurrentScoped)
{
    HANDLE fileHandle = NULL, parentHandle = NULL;
    PFILE_OBJECT fileObject = NULL, parentObject = NULL;
    PFLT_FILE_NAME_INFORMATION parentNameInfo = NULL;
    PFLT_FILE_NAME_INFORMATION streamNameInfo = NULL;
    PFILE_LINKS_INFORMATION links = NULL;
    PSTAGE_SCOPE_PARENT_NAME parentCache = NULL;
    PWCH pathBuffer = NULL, streamSnapshot = NULL;
    UNICODE_STRING linkName, parentName;
    ULONG bufferBytes = 4096, returned = 0, recordIndex, offset, streamChars = 0;
    ULONG startingRenameVersion, startingPolicyGeneration, savedNextLink = 0;
    ULONG savedUnionScoped = 0, savedCurrentScoped = 0, savedLinkCount = 0;
    ULONG nextLink = 0, cacheCount = 0, cacheIndex;
    BOOLEAN unionScoped = FALSE, currentScoped = FALSE, stable, compactStream = FALSE;
    BOOLEAN partial = FALSE, scanComplete = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    *UnionScoped = FALSE;
    *CurrentScoped = FALSE;
    if (WorkBudget == NULL || *WorkBudget == 0) return STATUS_MORE_ENTRIES;
    if (IoGetTopLevelIrp() != NULL) return STATUS_INVALID_DEVICE_STATE;
    startingPolicyGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
    parentCache = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_SCOPE_SCAN_PARENT_BUDGET * sizeof(*parentCache), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (parentCache == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    streamSnapshot = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (streamSnapshot == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    FltAcquirePushLockShared(&RegistryLock);
    startingRenameVersion = (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0);
    stable = Entry->Listed && !Entry->Retired &&
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) == 0 &&
        Entry->StreamIdentityKnown &&
        (Entry->CompactStream || Entry->StreamChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS);
    if (stable) {
        compactStream = Entry->CompactStream;
        streamChars = compactStream ? 0 : Entry->StreamChars;
        if (streamChars != 0 && Entry->StreamName != NULL)
            RtlCopyMemory(streamSnapshot, Entry->StreamName, streamChars * sizeof(WCHAR));
        if (InterlockedCompareExchange(&Entry->ScopeScanPending, 0, 0) != 0 &&
            Entry->ScopeScanRenameVersion == startingRenameVersion &&
            Entry->ScopeScanPolicyGeneration == startingPolicyGeneration) {
            savedNextLink = (ULONG)max(0, InterlockedCompareExchange(&Entry->ScopeScanNextLink, 0, 0));
            savedUnionScoped = (ULONG)max(0, InterlockedCompareExchange(&Entry->ScopeScanUnionScoped, 0, 0));
            savedCurrentScoped = (ULONG)max(0, InterlockedCompareExchange(&Entry->ScopeScanCurrentScoped, 0, 0));
            savedLinkCount = Entry->ScopeScanLinkCount;
        }
    }
    FltReleasePushLock(&RegistryLock);
    if (!stable) { status = STATUS_FILE_INVALID; goto Exit; }
    status = StageRegistryOpenIdentity(Entry, Instance, Volume, &fileHandle, &fileObject);
    if (!NT_SUCCESS(status)) goto Exit;
    if (fileObject->SectionObjectPointer != InterlockedCompareExchangePointer(
            (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL)) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    if (compactStream) {
        status = FltGetFileNameInformationUnsafe(fileObject, Instance,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &streamNameInfo);
        if (!NT_SUCCESS(status) || streamNameInfo == NULL ||
            !NT_SUCCESS(FltParseFileNameInformation(streamNameInfo)) ||
            (streamNameInfo->Stream.Length & (sizeof(WCHAR) - 1)) != 0 ||
            streamNameInfo->Stream.Length > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR)) {
            status = STATUS_FILE_INVALID;
            goto Exit;
        }
        streamChars = streamNameInfo->Stream.Length / sizeof(WCHAR);
        if (streamChars != 0)
            RtlCopyMemory(streamSnapshot, streamNameInfo->Stream.Buffer,
                streamChars * sizeof(WCHAR));
        FltReleaseFileNameInformation(streamNameInfo);
        streamNameInfo = NULL;
    }
    links = ExAllocatePool2(POOL_FLAG_PAGED, bufferBytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (links == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    for (;;) {
        returned = 0;
        status = FltQueryInformationFile(Instance, fileObject, links, bufferBytes,
            FileHardLinkInformation, &returned);
        if (status == STATUS_SUCCESS) break;
        if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL) goto Exit;
        if (bufferBytes >= 1024 * 1024) { status = STATUS_BUFFER_TOO_SMALL; goto Exit; }
        bufferBytes = min(bufferBytes * 2, 1024 * 1024);
        ExFreePoolWithTag(links, SAFEUPLOAD_REGISTRY_POOL_TAG);
        links = ExAllocatePool2(POOL_FLAG_PAGED, bufferBytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
        if (links == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    }
    if (returned < FIELD_OFFSET(FILE_LINKS_INFORMATION, Entry) +
            FIELD_OFFSET(FILE_LINK_ENTRY_INFORMATION, FileName) ||
        links->BytesNeeded == 0 || links->BytesNeeded > bufferBytes || links->EntriesReturned == 0) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    if (savedNextLink > links->EntriesReturned ||
        (savedLinkCount != 0 && savedLinkCount != links->EntriesReturned)) {
        savedNextLink = 0;
        savedUnionScoped = 0;
        savedCurrentScoped = 0;
    }
    unionScoped = savedUnionScoped != 0;
    currentScoped = savedCurrentScoped != 0;
    pathBuffer = ExAllocatePool2(POOL_FLAG_PAGED,
        (SAFEUPLOAD_MAX_PREFIX_CHARS + 1) * sizeof(WCHAR), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (pathBuffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    offset = FIELD_OFFSET(FILE_LINKS_INFORMATION, Entry);
    for (recordIndex = 0; recordIndex < links->EntriesReturned; ++recordIndex) {
        PFILE_LINK_ENTRY_INFORMATION link = (PFILE_LINK_ENTRY_INFORMATION)((PUCHAR)links + offset);
        ULONG available = returned - offset;
        ULONG nameBytes, minimumBytes, nextOffset = link->NextEntryOffset;
        ULONGLONG parentId;
        BOOLEAN linkCurrentScoped, linkUnionScoped;
        if (link->FileNameLength == 0 || link->FileNameLength > MAXULONG / sizeof(WCHAR)) {
            status = STATUS_FILE_INVALID;
            goto Exit;
        }
        nameBytes = link->FileNameLength * sizeof(WCHAR);
        minimumBytes = FIELD_OFFSET(FILE_LINK_ENTRY_INFORMATION, FileName) + nameBytes;
        if (minimumBytes > available ||
            (recordIndex + 1 < links->EntriesReturned &&
             (nextOffset < minimumBytes || (nextOffset & 7) != 0 || nextOffset > available)) ||
            (recordIndex + 1 == links->EntriesReturned && nextOffset != 0)) {
            status = STATUS_FILE_INVALID;
            goto Exit;
        }
        if (recordIndex < savedNextLink) {
            if (recordIndex + 1 < links->EntriesReturned) offset += nextOffset;
            continue;
        }
        if (*WorkBudget == 0) {
            partial = TRUE;
            nextLink = recordIndex;
            break;
        }
        --(*WorkBudget);
        RtlCopyMemory(&parentId, &link->ParentFileId, sizeof(parentId));
        for (cacheIndex = 0; cacheIndex < cacheCount; ++cacheIndex)
            if (parentCache[cacheIndex].ParentFileId == parentId) break;
        if (cacheIndex == cacheCount) {
            if (cacheCount >= SAFEUPLOAD_SCOPE_SCAN_PARENT_BUDGET) {
                partial = TRUE;
                nextLink = recordIndex;
                ++(*WorkBudget);
                break;
            }
            status = StageRegistryOpenParentById(Instance, Volume, Entry->VolumeSerial, parentId,
                &parentHandle, &parentObject);
            if (!NT_SUCCESS(status)) goto Exit;
            status = FltGetFileNameInformationUnsafe(parentObject, Instance,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &parentNameInfo);
            if (!NT_SUCCESS(status) || parentNameInfo == NULL ||
                !NT_SUCCESS(FltParseFileNameInformation(parentNameInfo)) ||
                (parentNameInfo->Name.Length & (sizeof(WCHAR) - 1)) != 0 ||
                parentNameInfo->Name.Length > SAFEUPLOAD_MAX_PREFIX_CHARS * sizeof(WCHAR)) {
                status = STATUS_FILE_INVALID;
                goto Exit;
            }
            parentCache[cacheIndex].ParentFileId = parentId;
            parentCache[cacheIndex].NameChars = (USHORT)(parentNameInfo->Name.Length / sizeof(WCHAR));
            if (parentCache[cacheIndex].NameChars != 0)
                RtlCopyMemory(parentCache[cacheIndex].Name, parentNameInfo->Name.Buffer,
                    parentNameInfo->Name.Length);
            parentCache[cacheIndex].Name[parentCache[cacheIndex].NameChars] = UNICODE_NULL;
            ++cacheCount;
            FltReleaseFileNameInformation(parentNameInfo);
            parentNameInfo = NULL;
            ObDereferenceObject(parentObject);
            parentObject = NULL;
            FltClose(parentHandle);
            parentHandle = NULL;
        }
        parentName.Buffer = parentCache[cacheIndex].Name;
        parentName.Length = parentName.MaximumLength =
            (USHORT)(parentCache[cacheIndex].NameChars * sizeof(WCHAR));
        StageRegistryBuildLinkName(&parentName, link->FileName,
            link->FileNameLength, NULL, 0, pathBuffer, &linkName);
        if (linkName.Length == 0) { status = STATUS_FILE_INVALID; goto Exit; }
        linkCurrentScoped = SafeUploadPolicyEntryIsCurrentlyScoped(Entry->VolumeKind, &linkName);
        linkUnionScoped = linkCurrentScoped ||
            SafeUploadPolicyEntryIsNewlyScoped(Entry->VolumeKind, &linkName);
        currentScoped |= linkCurrentScoped;
        unionScoped |= linkUnionScoped;
        if (streamChars != 0) {
            StageRegistryBuildLinkName(&parentName, link->FileName,
                link->FileNameLength, streamSnapshot, streamChars, pathBuffer, &linkName);
            if (linkName.Length == 0) { status = STATUS_FILE_INVALID; goto Exit; }
            linkCurrentScoped = SafeUploadPolicyEntryIsCurrentlyScoped(Entry->VolumeKind, &linkName);
            linkUnionScoped = linkCurrentScoped ||
                SafeUploadPolicyEntryIsNewlyScoped(Entry->VolumeKind, &linkName);
            currentScoped |= linkCurrentScoped;
            unionScoped |= linkUnionScoped;
        }
        nextLink = recordIndex + 1;
        if (recordIndex + 1 < links->EntriesReturned) offset += nextOffset;
    }
    scanComplete = !partial && nextLink >= links->EntriesReturned;
    if ((ULONG)SafeUploadCurrentPolicyGeneration() != startingPolicyGeneration) {
        nextLink = 0;
        unionScoped = FALSE;
        currentScoped = FALSE;
        scanComplete = FALSE;
        partial = TRUE;
    }
    FltAcquirePushLockExclusive(&RegistryLock);
    stable = Entry->Listed && !Entry->Retired &&
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) == 0 &&
        (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0) == startingRenameVersion;
    if (stable) {
        Entry->ScopeScanRenameVersion = startingRenameVersion;
        Entry->ScopeScanPolicyGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
        Entry->ScopeScanLinkCount = links->EntriesReturned;
        InterlockedExchange(&Entry->ScopeScanNextLink, (LONG)nextLink);
        InterlockedExchange(&Entry->ScopeScanUnionScoped, unionScoped ? 1 : 0);
        InterlockedExchange(&Entry->ScopeScanCurrentScoped, currentScoped ? 1 : 0);
        InterlockedExchange(&Entry->ScopeScanPending, scanComplete ? 0 : 1);
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    FltReleasePushLock(&RegistryLock);
    if (!stable) { status = STATUS_FILE_INVALID; goto Exit; }
    if (!scanComplete) { status = STATUS_MORE_ENTRIES; goto Exit; }
    *UnionScoped = unionScoped;
    *CurrentScoped = currentScoped;
    status = STATUS_SUCCESS;
Exit:
    if (streamNameInfo != NULL) FltReleaseFileNameInformation(streamNameInfo);
    if (parentNameInfo != NULL) FltReleaseFileNameInformation(parentNameInfo);
    if (parentObject != NULL) ObDereferenceObject(parentObject);
    if (parentHandle != NULL) FltClose(parentHandle);
    if (fileObject != NULL) ObDereferenceObject(fileObject);
    if (fileHandle != NULL) FltClose(fileHandle);
    if (pathBuffer != NULL) ExFreePoolWithTag(pathBuffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (links != NULL) ExFreePoolWithTag(links, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (streamSnapshot != NULL) ExFreePoolWithTag(streamSnapshot, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (parentCache != NULL) ExFreePoolWithTag(parentCache, SAFEUPLOAD_REGISTRY_POOL_TAG);
    return status;
}
/* D6: a passive read-only file-ID open feeds the same complete hard-link classifier. */
NTSTATUS SafeUploadStageWritersClassifyById(_In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject, _Out_ PBOOLEAN InScope)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PFLT_VOLUME volume = NULL;
    PSTAGE_REGISTRY_ENTRY identityEntry = NULL;
    PFILE_OBJECT openedObject = NULL;
    HANDLE openedHandle = NULL;
    FILE_ID_INFORMATION identity;
    FLT_FILESYSTEM_TYPE fileSystem;
    UNICODE_STRING volumeName, openName;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    PWCH buffer = NULL;
    ULONG needed = 0, returned = 0, bytes, workBudget;
    ULONGLONG lowId, highId = 0;
    BOOLEAN unionScoped = FALSE, currentScoped = FALSE;
    NTSTATUS status;

    PAGED_CODE();
    *InScope = FALSE;
    if (Instance == NULL || FileObject == NULL || FileObject->FileName.Buffer == NULL ||
        (FileObject->FileName.Length != sizeof(ULONGLONG) &&
         FileObject->FileName.Length != sizeof(FILE_ID_128)) ||
        (FileObject->FileName.Length & (sizeof(WCHAR) - 1)) != 0 ||
        KeGetCurrentIrql() != PASSIVE_LEVEL || IoGetTopLevelIrp() != NULL)
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(&lowId, FileObject->FileName.Buffer, sizeof(lowId));
    if (FileObject->FileName.Length == sizeof(FILE_ID_128)) {
        RtlCopyMemory(&highId, (PUCHAR)FileObject->FileName.Buffer + sizeof(lowId), sizeof(highId));
        if (highId != 0) return STATUS_OBJECT_NAME_INVALID; /* unknown high-half IDs remain refused */
    }
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) goto Exit;
    if (instanceContext->VolumeKind != SafeUploadVolumeFixed) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = FltGetFileSystemType(Instance, &fileSystem);
    if (!NT_SUCCESS(status) || fileSystem != FLT_FSTYPE_NTFS) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) goto Exit;
    status = FltGetVolumeName(volume, NULL, &needed);
    if (status != STATUS_BUFFER_TOO_SMALL || needed == 0 ||
        needed > MAXUSHORT - sizeof(WCHAR) - sizeof(ULONGLONG)) {
        status = STATUS_FLT_INSTANCE_NOT_FOUND;
        goto Exit;
    }
    bytes = needed + sizeof(WCHAR) + sizeof(ULONGLONG);
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, bytes, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (buffer == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    volumeName.Buffer = buffer;
    volumeName.Length = 0;
    volumeName.MaximumLength = (USHORT)needed;
    status = FltGetVolumeName(volume, &volumeName, NULL);
    if (!NT_SUCCESS(status)) goto Exit;
    buffer[volumeName.Length / sizeof(WCHAR)] = L'\\';
    RtlCopyMemory((PUCHAR)buffer + volumeName.Length + sizeof(WCHAR), &lowId, sizeof(lowId));
    openName.Buffer = buffer;
    openName.Length = openName.MaximumLength = (USHORT)(volumeName.Length + sizeof(WCHAR) + sizeof(ULONGLONG));
    InitializeObjectAttributes(&attributes, &openName, OBJ_KERNEL_HANDLE, NULL, NULL);
    RtlZeroMemory(&io, sizeof(io));
    status = FltCreateFileEx2(SafeUploadData.Filter, Instance, &openedHandle, &openedObject,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_COMPLETE_IF_OPLOCKED, NULL, 0, 0, NULL);
    if (status != STATUS_SUCCESS || openedObject == NULL) goto Exit;
    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(Instance, openedObject, &identity, sizeof(identity),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(identity) ||
        identity.VolumeSerialNumber == 0 ||
        !RtlEqualMemory(identity.FileId.Identifier, &lowId, sizeof(lowId)) ||
        openedObject->SectionObjectPointer == NULL) {
        status = STATUS_FILE_INVALID;
        goto Exit;
    }
    identityEntry = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*identityEntry), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (identityEntry == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Exit; }
    RtlZeroMemory(identityEntry, sizeof(*identityEntry));
    identityEntry->Listed = TRUE; /* temporary, function-scoped classifier identity */
    identityEntry->VolumeKind = instanceContext->VolumeKind;
    identityEntry->VolumeSerial = identity.VolumeSerialNumber;
    identityEntry->FileId = identity.FileId;
    identityEntry->SectionObjectPointer = openedObject->SectionObjectPointer;
    identityEntry->StreamIdentityKnown = TRUE;
    /* One bounded hard-link pass in create pre-operation. On a volume that
     * may hold a scope, an undecidable identity remains a fail-closed refusal. */
    workBudget = SAFEUPLOAD_SCOPE_SCAN_PARENT_BUDGET;
    status = StageRegistryClassifyAllLinkNames(identityEntry, Instance, volume,
        &workBudget, &unionScoped, &currentScoped);
    if (status == STATUS_MORE_ENTRIES) status = STATUS_BUFFER_OVERFLOW;
    if (NT_SUCCESS(status)) *InScope = unionScoped;
Exit:
    if (identityEntry != NULL) ExFreePoolWithTag(identityEntry, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (openedObject != NULL) ObDereferenceObject(openedObject);
    if (openedHandle != NULL) FltClose(openedHandle);
    if (buffer != NULL) ExFreePoolWithTag(buffer, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (volume != NULL) FltObjectDereference(volume);
    if (instanceContext != NULL) FltReleaseContext(instanceContext);
    return status;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_raises_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryAcquireStateLock(
    _In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_ _At_(*OldIrql, _IRQL_saves_) PKIRQL OldIrql)
{
    StageAcquireSpinLock(&Entry->StateLock, OldIrql);
}

_IRQL_requires_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistryReleaseStateLock(
    _In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ _IRQL_restores_ KIRQL OldIrql)
{
    StageReleaseSpinLock(&Entry->StateLock, OldIrql);
}

_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
__declspec(noinline) static BOOLEAN StageRegistryTryPromoteStateNoInline(
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ ULONGLONG ExpectedSopMarkerGeneration)
{
    PSTAGE_REGISTRY_SOP_SLOT map;
    PLIST_ENTRY spillLink;
    BOOLEAN mapFound = FALSE, spillCountsEmpty = TRUE;
    ULONG index;
    KIRQL irql;
    BOOLEAN promoted = FALSE;
    PVOID sop = InterlockedCompareExchangePointer(
        (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL);

    StageAcquireSpinLock(&SectionLock, &irql);
    map = StageRegistryFindSopSlotLocked(sop, &mapFound);
    if (mapFound && map != NULL && map->Entry == Entry)
        spillCountsEmpty = map->UnknownWriterCount == 0 && map->SpilledSectionCount == 0 &&
            map->SpilledMutatingIoCount == 0;
    for (index = 0; spillCountsEmpty && index < STAGE_SECTION_SLOTS; ++index) {
        STAGE_SECTION_SLOT *section = &SectionSlots[index];
        if (section->Writable && section->SectionObjectPointer == sop)
            spillCountsEmpty = FALSE;
    }
    for (spillLink = SectionSpills.Flink; spillCountsEmpty &&
         spillLink != &SectionSpills; spillLink = spillLink->Flink) {
        PSTAGE_SECTION_SPILL_RECORD spill = CONTAINING_RECORD(spillLink,
            STAGE_SECTION_SPILL_RECORD, Link);
        if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->Writable &&
            spill->SectionObjectPointer == sop) spillCountsEmpty = FALSE;
    }
    if ((ULONGLONG)InterlockedCompareExchange64(&RegistrySopMapGeneration, 0, 0) ==
            ExpectedSopMarkerGeneration && spillCountsEmpty &&
        InterlockedCompareExchange(&Entry->W, 0, 0) == 0 &&
        InterlockedCompareExchange((volatile LONG *)&Entry->State,
            SAFEUPLOAD_REGISTRY_STATE_PROTECTED,
            SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) {
        InterlockedIncrement64(&RegistryChangeSequence);
        promoted = TRUE;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return promoted;
}

/* RegistryLock remains held by the pageable caller, stabilizing the name and
 * list membership. Name comparison is done there because its snapshot is paged. */
__declspec(noinline) static VOID StageRegistryTryPromoteEntry(
    _In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ BOOLEAN NameMatches,
    _In_ USHORT NameSnapshotChars,
    _In_ ULONG RenameVersion,
    _In_ ULONG CurrentGeneration,
    _In_ BOOLEAN SopEmpty,
    _In_ ULONGLONG ExpectedSopMarkerGeneration)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    KIRQL renameLossIrql;
    BOOLEAN renameLossStable;
    KIRQL irql;
    UNICODE_STRING entryName;
    BOOLEAN directoryRenameInFlight;
    entryName.Buffer = Entry->Name;
    entryName.Length = entryName.MaximumLength = (USHORT)(Entry->NameChars * sizeof(WCHAR));
    directoryRenameInFlight = StageRegistryDirectoryRenameInFlightLocked(Entry->Instance, &entryName);

    if (!NT_SUCCESS(FltGetInstanceContext(Entry->Instance, (PFLT_CONTEXT *)&instanceContext))) {
        StageRegistrySetEntryUnknownLocked(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        StageRegistryPrepareActivation(Entry, TRUE);
        InterlockedExchange(&WriterGlobalUnknown, 1);
        return;
    }
    renameLossStable = SafeUploadPolicyRenameLossGenerationEnter(
        &instanceContext->RegistryRenameLossGeneration,
        Entry->RenameLossGeneration, &renameLossIrql);
    if (!renameLossStable) {
        SafeUploadPolicyRenameLossGenerationLeave(renameLossIrql);
        FltReleaseContext(instanceContext);
        StageRegistrySetEntryUnknownLocked(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        StageRegistryPrepareActivation(Entry, TRUE);
        return;
    }

    StageAcquireSpinLock(&Entry->StateLock, &irql);
    if (Entry->Listed && !Entry->Retired &&
        InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING &&
        InterlockedCompareExchange(&Entry->H, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->T, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->W, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) == 0 &&
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) == 0 &&
        !directoryRenameInFlight &&
        (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0) == RenameVersion &&
        Entry->ActivationGeneration == CurrentGeneration &&
        InterlockedCompareExchange(&Entry->ActivationEnforced, 0, 0) != 0 &&
        InterlockedCompareExchange(&Entry->ScopeNameClassification, 0, 0) ==
            STAGE_SCOPE_CLASS_SCOPED &&
        ((Entry->Compact && NameSnapshotChars == 0 && Entry->StreamIdentityKnown && NameMatches) ||
         (!Entry->Compact && Entry->NameChars == NameSnapshotChars &&
          NameSnapshotChars != 0 && NameMatches)) &&
        StageRegistrySnapshotSpilledWriters(Entry) == 0 &&
        StageRegistrySnapshotSpilledMutatingIo(Entry) == 0 &&
        SopEmpty &&
        StageRegistrySnapshotC(Entry, NULL, 0, NULL) == 0) {
        /* Serialize the final marker-generation check with marker insertion. A marker
         * discovered after the earlier PASSIVE scan must keep this promotion waiting. */
        (VOID)StageRegistryTryPromoteStateNoInline(Entry, ExpectedSopMarkerGeneration);
    }
    StageReleaseSpinLock(&Entry->StateLock, irql);
    SafeUploadPolicyRenameLossGenerationLeave(renameLossIrql);
    FltReleaseContext(instanceContext);
}

__declspec(noinline) static VOID StageRegistryPrepareActivation(
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ BOOLEAN Unknown)
{
    KIRQL irql;

    StageAcquireSpinLock(&Entry->StateLock, &irql);
    InterlockedExchange((volatile LONG *)&Entry->State, Unknown ?
        SAFEUPLOAD_REGISTRY_STATE_UNKNOWN : SAFEUPLOAD_REGISTRY_STATE_ACTIVATING);
    if (Unknown)
        InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
    InterlockedExchange(&Entry->ActivationEnforced, 1);
    InterlockedExchange(&Entry->LastSState, SAFEUPLOAD_REGISTRY_S_UNKNOWN);
    StageReleaseSpinLock(&Entry->StateLock, irql);
}

/* Entries stay behind the open and section admission gate until a PASSIVE
 * hard-link query proves every name outside the current/pending union. */
__declspec(noinline) static BOOLEAN StageRegistryBeginAliasProbe(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;
    LONG state;
    BOOLEAN began = FALSE;
    StageAcquireSpinLock(&Entry->StateLock, &irql);
    state = InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0);
    if (Entry->Listed && !Entry->Retired &&
        (state == SAFEUPLOAD_REGISTRY_STATE_PROTECTED || state == SAFEUPLOAD_REGISTRY_STATE_UNSCOPED ||
         state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ||
         (state == SAFEUPLOAD_REGISTRY_STATE_UNKNOWN &&
          (Entry->NameChars != 0 || Entry->Compact) && Entry->StreamIdentityKnown))) {
        InterlockedExchange(&Entry->AliasProbePending, 1);
        InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
        began = TRUE;
    }
    StageReleaseSpinLock(&Entry->StateLock, irql);
    return began;
}

__declspec(noinline) static VOID StageRegistryResolveAliasProbe(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ BOOLEAN ClassificationSucceeded, _In_ BOOLEAN UnionScoped, _Out_ PBOOLEAN Activated)
{
    KIRQL irql;
    LONG state;
    *Activated = FALSE;
    StageAcquireSpinLock(&Entry->StateLock, &irql);
    if (InterlockedCompareExchange(&Entry->AliasProbePending, 0, 0) != 0) {
        if (!ClassificationSucceeded) {
            InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
            InterlockedOr(&Entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
            InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
            InterlockedExchange(&Entry->ActivationEnforced, 1);
        } else if (UnionScoped) {
            InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_SCOPED);
            InterlockedExchange(&Entry->ActivationEnforced, 1);
            if (InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) == 0) {
                InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_ACTIVATING);
                InterlockedExchange(&Entry->LastSState, SAFEUPLOAD_REGISTRY_S_UNKNOWN);
                *Activated = TRUE;
            } else {
                InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
            }
        } else {
            InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_OUTSIDE);
            state = InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0);
            if (state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ||
                state == SAFEUPLOAD_REGISTRY_STATE_PROTECTED) {
                InterlockedExchange(&Entry->ActivationEnforced, 0);
                InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNSCOPED);
            } else if (state == SAFEUPLOAD_REGISTRY_STATE_UNKNOWN) {
                InterlockedExchange(&Entry->ActivationEnforced, 0);
            }
        }
        InterlockedExchange(&Entry->AliasProbePending, 0);
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    StageReleaseSpinLock(&Entry->StateLock, irql);
}

/* D1: instance-level ledger loss cancels an unclassified probe without turning it into an I/O gate. */
_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static VOID StageRegistryCancelAliasProbeForInstanceUnknown(
    _In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;
    StageRegistryAcquireStateLock(Entry, &irql);
    if (InterlockedExchange(&Entry->AliasProbePending, 0) != 0)
        InterlockedIncrement64(&RegistryChangeSequence);
    StageRegistryReleaseStateLock(Entry, irql);
}

__declspec(noinline) static BOOLEAN StageRegistryResolveAliasProbeForGeneration(
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ PFLT_INSTANCE Instance,
    _In_ BOOLEAN ClassificationSucceeded, _In_ BOOLEAN UnionScoped,
    _Out_ PBOOLEAN Activated)
{
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    KIRQL irql;
    BOOLEAN stable;
    NTSTATUS status;
    *Activated = FALSE;
    if (!ClassificationSucceeded) {
        StageRegistryResolveAliasProbe(Entry, FALSE, FALSE, Activated);
        return FALSE;
    }
    status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext);
    if (!NT_SUCCESS(status)) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        StageRegistryResolveAliasProbe(Entry, FALSE, FALSE, Activated);
        return FALSE;
    }
    /* Cache-lock before StateLock prevents rename-loss publication from
     * racing release of a stale-name gate. */
    stable = SafeUploadPolicyRenameLossGenerationEnter(
        &instanceContext->RegistryRenameLossGeneration,
        Entry->RenameLossGeneration, &irql);
    StageRegistryResolveAliasProbe(Entry, stable, stable && UnionScoped, Activated);
    SafeUploadPolicyRenameLossGenerationLeave(irql);
    FltReleaseContext(instanceContext);
    if (!stable) {
        /* The prior rename loss already advanced the instance generation. Keep
         * this entry's name unresolved without publishing a second loss. */
        InterlockedOr(&Entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
        InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_UNRESOLVED);
    }
    return stable;
}

__declspec(noinline) static VOID StageRegistrySetLinkScopeClassification(
    _In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ BOOLEAN Succeeded, _In_ BOOLEAN UnionScoped)
{
    KIRQL irql;
    StageAcquireSpinLock(&Entry->StateLock, &irql);
    InterlockedExchange(&Entry->ScopeNameClassification, !Succeeded ?
        STAGE_SCOPE_CLASS_UNRESOLVED : (UnionScoped ? STAGE_SCOPE_CLASS_SCOPED : STAGE_SCOPE_CLASS_OUTSIDE));
    StageReleaseSpinLock(&Entry->StateLock, irql);
}

__declspec(noinline) static VOID StageRegistryClearActivation(_In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    KIRQL irql;
    LONG state;

    StageAcquireSpinLock(&Entry->StateLock, &irql);
    InterlockedExchange(&Entry->ActivationEnforced, 0);
    state = InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0);
    if (state == SAFEUPLOAD_REGISTRY_STATE_ACTIVATING || state == SAFEUPLOAD_REGISTRY_STATE_PROTECTED)
        InterlockedExchange((volatile LONG *)&Entry->State, SAFEUPLOAD_REGISTRY_STATE_UNSCOPED);
    StageReleaseSpinLock(&Entry->StateLock, irql);
}

static VOID StageRegistryActivationProcess(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume, _Inout_ PULONG WorkBudget)
{
    HANDLE handle = NULL;
    PFILE_OBJECT object = NULL;
    PSECTION_OBJECT_POINTERS sop = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PWCHAR nameSnapshot = NULL;
    UNICODE_STRING entryName = { 0 };
    USHORT nameSnapshotChars = 0;
    ULONG renameVersion = 0;
    ULONG markerWorkBudget = SAFEUPLOAD_SCOPE_SCAN_PARENT_BUDGET;
    ULONGLONG sopMarkerGeneration = 0;
    LONG instanceUnknownReasons = 0;
    BOOLEAN currentlyScoped, nameStillMatches, sopEmpty, userWritable;
    BOOLEAN directoryRenameInFlight;
    BOOLEAN markerWorkRemaining = FALSE;
    BOOLEAN aliasProbe, unionLinkScoped = FALSE, currentLinkScoped = FALSE, aliasActivated = FALSE;
    ULONG currentGeneration;
    UINT32 sectionCount;
    NTSTATUS status;

    PAGED_CODE();
    if (WorkBudget == NULL || *WorkBudget == 0) return;
    if (!SafeUploadInstanceIsTrusted(Instance)) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TRUST);
        StageRegistryResolveAliasProbe(Entry, FALSE, FALSE, &aliasActivated);
        InterlockedIncrement64(&RegistryChangeSequence);
        return;
    }
    if (SafeUploadStageWritersGlobalUnknown() != 0) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        StageRegistryCancelAliasProbeForInstanceUnknown(Entry);
        goto Exit;
    }

    nameSnapshot = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (nameSnapshot == NULL) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
        StageRegistryResolveAliasProbe(Entry, FALSE, FALSE, &aliasActivated);
        goto Exit;
    }
    FltAcquirePushLockShared(&RegistryLock);
    entryName.Buffer = Entry->Name;
    entryName.Length = entryName.MaximumLength = (USHORT)(Entry->NameChars * sizeof(WCHAR));
    directoryRenameInFlight = StageRegistryDirectoryRenameInFlightLocked(Entry->Instance, &entryName);
    aliasProbe = InterlockedCompareExchange(&Entry->AliasProbePending, 0, 0) != 0;
    if (!Entry->Listed || Entry->Retired ||
        (!Entry->Compact && (Entry->NameChars == 0 ||
         Entry->NameChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS)) ||
        (!aliasProbe && InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) !=
            SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) ||
        (!aliasProbe && InterlockedCompareExchange(&Entry->ActivationEnforced, 0, 0) == 0) ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0 ||
        directoryRenameInFlight) {
        FltReleasePushLock(&RegistryLock);
        goto Exit;
    }
    nameSnapshotChars = Entry->Compact ? 0 : Entry->NameChars;
    renameVersion = (ULONG)InterlockedCompareExchange(&Entry->RenameVersion, 0, 0);
    if (nameSnapshotChars != 0)
        RtlCopyMemory(nameSnapshot, Entry->Name, nameSnapshotChars * sizeof(WCHAR));
    FltReleasePushLock(&RegistryLock);
    entryName.Buffer = nameSnapshot;
    entryName.Length = entryName.MaximumLength = (USHORT)(nameSnapshotChars * sizeof(WCHAR));

    /* Hard-link names are classified at PASSIVE_LEVEL. New opens and writable
     * section creations already consult this policy union while the scan runs. */
    status = StageRegistryClassifyAllLinkNames(Entry, Instance, Volume, WorkBudget,
        &unionLinkScoped, &currentLinkScoped);
    if (status == STATUS_MORE_ENTRIES) goto Exit;
    if (!NT_SUCCESS(status)) {
        if (aliasProbe) StageRegistryResolveAliasProbe(Entry, FALSE, FALSE, &aliasActivated);
        else StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        InterlockedIncrement64(&RegistryChangeSequence);
        goto Exit;
    }
    if (aliasProbe) {
        /* Publish Activating before the first H/S/C/T and SOP read. */
        (VOID)StageRegistryResolveAliasProbeForGeneration(Entry, Instance,
            TRUE, unionLinkScoped, &aliasActivated);
        if (!aliasActivated) goto Exit;
    } else if (!unionLinkScoped) {
        StageRegistrySetLinkScopeClassification(Entry, TRUE, FALSE);
        StageRegistryClearActivation(Entry);
        InterlockedIncrement64(&RegistryChangeSequence);
        goto Exit;
    } else {
        StageRegistrySetLinkScopeClassification(Entry, TRUE, TRUE);
    }

    currentlyScoped = currentLinkScoped;
    if (!currentlyScoped) goto Exit; /* candidate scope is gated until the policy is finalized */

    status = StageRegistryOpenIdentity(Entry, Instance, Volume, &handle, &object);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_FILE_INVALID || status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_FILE_DELETED || status == STATUS_DELETE_PENDING)
            StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        InterlockedIncrement64(&RegistryChangeSequence);
        goto Exit;
    }
    if (object->SectionObjectPointer == NULL || object->SectionObjectPointer !=
        InterlockedCompareExchangePointer((PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL)) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
        goto Exit;
    }
    sop = object->SectionObjectPointer;
    if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext))) {
        instanceUnknownReasons = InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0);
        if (InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0 &&
            instanceUnknownReasons == 0) instanceUnknownReasons = SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
        FltReleaseContext(instanceContext);
        instanceContext = NULL;
    } else goto Exit;
    if (instanceUnknownReasons != 0 ||
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->ActivationEnforced, 0, 0) == 0 ||
        InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0) !=
            SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) goto Exit;

    /* Free(F) is a single observation behind the published gate. Paging
     * writes continue while either SOP cache/section pointer exists; no flush
     * or wait is needed when both are absent. */
    if (InterlockedCompareExchange(&Entry->H, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->W, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->T, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0 ||
        StageRegistrySnapshotSpilledWriters(Entry) != 0 ||
        StageRegistrySnapshotSpilledMutatingIo(Entry) != 0) goto Exit;
    sectionCount = StageRegistrySnapshotC(Entry, NULL, 0, NULL);
    if (sectionCount != 0 || (sectionCount & SAFEUPLOAD_SECTIONS_UNTRACKED_BIT) != 0) goto Exit;
    userWritable = MmDoesFileHaveUserWritableReferences(sop) != FALSE;
    {
        LONG newSState = userWritable ? SAFEUPLOAD_REGISTRY_S_YES : SAFEUPLOAD_REGISTRY_S_NO;
        if (InterlockedExchange(&Entry->LastSState, newSState) != newSState)
            InterlockedIncrement64(&RegistryChangeSequence);
    }
    sopEmpty = sop->DataSectionObject == NULL && sop->SharedCacheMap == NULL;
    if (userWritable || !sopEmpty) goto Exit;

    /* Live markers hold this instance only while scoped or undecidable. Outside markers stay
     * recorded until their own stream quiesces, but do not stall unrelated entries. */
    if (!StageRegistryUnknownSopMarkersQuiescent(Instance, Volume, &markerWorkBudget,
            &markerWorkRemaining, &sopMarkerGeneration)) {
        if (markerWorkRemaining) InterlockedExchange(&Entry->ScopeScanPending, 1);
        goto Exit;
    }

    /* Re-read counters and SOP after S. With the gate held, they can only
     * fall; new H/C/T writers cannot enter between this read and promotion. */
    userWritable = MmDoesFileHaveUserWritableReferences(sop) != FALSE;
    {
        LONG newSState = userWritable ? SAFEUPLOAD_REGISTRY_S_YES : SAFEUPLOAD_REGISTRY_S_NO;
        if (InterlockedExchange(&Entry->LastSState, newSState) != newSState)
            InterlockedIncrement64(&RegistryChangeSequence);
    }
    if (InterlockedCompareExchange(&Entry->H, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->W, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->T, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0) != 0 ||
        InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0) != 0 ||
        userWritable ||
        StageRegistrySnapshotSpilledWriters(Entry) != 0 ||
        StageRegistrySnapshotSpilledMutatingIo(Entry) != 0 ||
        StageRegistrySnapshotC(Entry, NULL, 0, NULL) != 0 ||
        sop->DataSectionObject != NULL || sop->SharedCacheMap != NULL) goto Exit;

    FltAcquirePushLockExclusive(&RegistryLock);
    nameStillMatches = Entry->Compact ? Entry->StreamIdentityKnown :
        (Entry->NameChars == nameSnapshotChars && nameSnapshotChars != 0 &&
         RtlEqualMemory(Entry->Name, nameSnapshot, nameSnapshotChars * sizeof(WCHAR)));
    currentGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
    sopEmpty = sop->DataSectionObject == NULL && sop->SharedCacheMap == NULL;
    if ((ULONGLONG)InterlockedCompareExchange64(&RegistrySopMapGeneration, 0, 0) ==
            sopMarkerGeneration)
        StageRegistryTryPromoteEntry(Entry, nameStillMatches, nameSnapshotChars,
            renameVersion, currentGeneration, sopEmpty, sopMarkerGeneration);
    FltReleasePushLock(&RegistryLock);

Exit:
    if (nameSnapshot != NULL) ExFreePoolWithTag(nameSnapshot, SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (object != NULL) ObDereferenceObject(object);
    if (handle != NULL) FltClose(handle);
}

/* Deferred instance-wide loss marking for callbacks that complete above APC_LEVEL. The temporary
 * instance reference is owned only by this independent work item; it is never stored in a context
 * that Filter Manager must free after instance rundown. */
static VOID StageRegistryUnknownWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject,
    _In_opt_ PVOID Context)
{
    PSTAGE_DEFERRED_INSTANCE_UNKNOWN deferred = (PSTAGE_DEFERRED_INSTANCE_UNKNOWN)Context;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PFLT_INSTANCE instance = deferred != NULL ? deferred->Instance : NULL;
    UNREFERENCED_PARAMETER(FltObject);
    PAGED_CODE();
    if (deferred != NULL)
        InterlockedOr((volatile LONG *)&RegistryUnknownReasons, deferred->Reason);
    if (deferred != NULL && deferred->Entry != NULL) {
        FltAcquirePushLockExclusive(&RegistryLock);
        if (!deferred->Entry->Retired && deferred->Entry->Instance != NULL &&
            NT_SUCCESS(FltObjectReference(deferred->Entry->Instance)))
            instance = deferred->Entry->Instance;
        FltReleasePushLock(&RegistryLock);
    }
    if (deferred != NULL && instance != NULL && NT_SUCCESS(FltGetInstanceContext(instance,
            (PFLT_CONTEXT *)&instanceContext))) {
        InterlockedOr(&instanceContext->RegistryUnknownReasons, deferred->Reason);
        if ((deferred->Reason & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0) {
            UNICODE_STRING volumeName;
            PCUNICODE_STRING volumeNamePointer = NULL;
            if (instanceContext->VolumeNameChars != 0 &&
                instanceContext->VolumeNameChars <= SAFEUPLOAD_MAX_PREFIX_CHARS) {
                volumeName.Buffer = instanceContext->VolumeName;
                volumeName.Length = volumeName.MaximumLength = (USHORT)(
                    instanceContext->VolumeNameChars * sizeof(WCHAR));
                volumeNamePointer = &volumeName;
            }
            SafeUploadPolicyRenameLossAdvance(&instanceContext->RegistryRenameLossGeneration,
                instanceContext->VolumeKind, volumeNamePointer);
        }
        if (InterlockedCompareExchange(&instanceContext->WritersUntracked, 1, 0) == 0)
            InterlockedIncrement((volatile LONG *)&RegistryInstanceUnknown);
        FltReleaseContext(instanceContext);
    }
    if (deferred != NULL) {
        if (instance != NULL) FltObjectDereference(instance);
        if (deferred->Entry != NULL) StageRegistryDereference(deferred->Entry);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
    FltFreeGenericWorkItem(WorkItem);
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
}

static BOOLEAN StageRegistryQueueDeferredUnknown(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason)
{
    PSTAGE_DEFERRED_INSTANCE_UNKNOWN deferred;
    PFLT_GENERIC_WORKITEM item;
    NTSTATUS status;

    if ((Instance == NULL) == (Entry == NULL) || KeGetCurrentIrql() > DISPATCH_LEVEL ||
        !ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) return FALSE;
    deferred = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*deferred), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (deferred == NULL) {
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return FALSE;
    }
    deferred->Instance = NULL;
    deferred->Entry = NULL;
    if (Instance != NULL) {
        status = FltObjectReference(Instance);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
            ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
            return FALSE;
        }
        deferred->Instance = Instance;
    } else {
        StageRegistryReference(Entry);
        deferred->Entry = Entry;
    }
    deferred->Reason = Reason;
    item = FltAllocateGenericWorkItem();
    if (item == NULL) {
        if (deferred->Instance != NULL) FltObjectDereference(deferred->Instance);
        if (deferred->Entry != NULL) StageRegistryDereference(deferred->Entry);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return FALSE;
    }
    status = FltQueueGenericWorkItem(item, SafeUploadData.Filter, StageRegistryUnknownWorker,
        DelayedWorkQueue, deferred);
    if (!NT_SUCCESS(status)) {
        FltFreeGenericWorkItem(item);
        if (deferred->Instance != NULL) FltObjectDereference(deferred->Instance);
        if (deferred->Entry != NULL) StageRegistryDereference(deferred->Entry);
        ExFreePoolWithTag(deferred, SAFEUPLOAD_REGISTRY_POOL_TAG);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN StageRegistryQueueInstanceUnknown(_In_ PFLT_INSTANCE Instance, _In_ LONG Reason)
{
    return StageRegistryQueueDeferredUnknown(Instance, NULL, Reason);
}

static BOOLEAN StageRegistryQueueEntryUnknown(_In_ PSTAGE_REGISTRY_ENTRY Entry, _In_ LONG Reason)
{
    return StageRegistryQueueDeferredUnknown(NULL, Entry, Reason);
}

static BOOLEAN StageRegistryQueueReclaimWorkItem(VOID)
{
    PFLT_GENERIC_WORKITEM item;
    if (!ExAcquireRundownProtection(&SafeUploadData.ChannelRundown)) return FALSE;
    item = FltAllocateGenericWorkItem();
    if (item == NULL || !NT_SUCCESS(FltQueueGenericWorkItem(item, SafeUploadData.Filter,
            StageRegistryReclaimWorker, DelayedWorkQueue, NULL))) {
        if (item != NULL) FltFreeGenericWorkItem(item);
        ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
        return FALSE;
    }
    return TRUE;
}

/* State bit 0 means one worker is queued or running; bit 1 coalesces any
 * number of rechecks into exactly one additional pass. The CAS handoff keeps
 * ownership set while that pass is queued, closing the old clear-then-rescan
 * race that could both lose a wakeup and create an extra worker. */
static VOID StageRegistryReclaimWorkerFinish(VOID)
{
    for (;;) {
        LONG state = InterlockedCompareExchange(&RegistryReclaimQueued, 0, 0);
        if ((state & STAGE_RECLAIM_RESCAN) != 0) {
            if (InterlockedCompareExchange(&RegistryReclaimQueued, STAGE_RECLAIM_QUEUED,
                    state) == state) {
                if (!StageRegistryQueueReclaimWorkItem()) {
                    LONG failedState = InterlockedExchange(&RegistryReclaimQueued, 0);
                    if ((failedState & STAGE_RECLAIM_RESCAN) != 0)
                        (VOID)StageRegistryQueueReclaim();
                }
                return;
            }
        } else if ((state & STAGE_RECLAIM_QUEUED) != 0) {
            if (InterlockedCompareExchange(&RegistryReclaimQueued, 0, state) == state) return;
        } else {
            return;
        }
    }
}

static VOID StageRegistryReclaimWorker(_In_ PFLT_GENERIC_WORKITEM WorkItem, _In_ PVOID FltObject, _In_opt_ PVOID Context)
{
    PSTAGE_REGISTRY_ENTRY *candidates;
    PFLT_INSTANCE *instances;
    PFLT_VOLUME *volumes;
    PLIST_ENTRY link;
    ULONG count = 0, index;
    ULONGLONG cursor = 0, highestVisited = 0;
    ULONG workBudget = SAFEUPLOAD_SCOPE_SCAN_PARENT_BUDGET;
    BOOLEAN reachedBatch = FALSE, unfinishedScan = FALSE;
    ULONGLONG firstUnfinishedSequence = 0;
    UNREFERENCED_PARAMETER(FltObject);
    UNREFERENCED_PARAMETER(Context);
    PAGED_CODE();
    FltFreeGenericWorkItem(WorkItem);
    InterlockedIncrement64(&RegistryReclaimPasses);

    candidates = ExAllocatePool2(POOL_FLAG_NON_PAGED, STAGE_RECLAIM_BATCH * (sizeof(PVOID) * 3), SAFEUPLOAD_REGISTRY_POOL_TAG);
    if (candidates != NULL) {
        instances = (PFLT_INSTANCE *)(candidates + STAGE_RECLAIM_BATCH);
        volumes = (PFLT_VOLUME *)(instances + STAGE_RECLAIM_BATCH);
        /* Snapshot quiet-looking entries with their own instance and volume references (a tearing-down instance refuses
         * FltObjectReference and is skipped: its teardown retires the entries anyway). */
        FltAcquirePushLockExclusive(&RegistryLock);
        StageRegistryPurgeAbandonedDirectoryRenamesLocked();
        if (InterlockedExchange(&RegistryReclaimResetCursor, 0) != 0)
            RegistryReclaimCursor = 0;
        cursor = RegistryReclaimCursor;
        highestVisited = cursor;
        for (link = RegistryEntries.Flink; link != &RegistryEntries && count < STAGE_RECLAIM_BATCH; link = link->Flink) {
            PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
            UNICODE_STRING entryName;
            BOOLEAN activating = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;
            BOOLEAN aliasProbe = InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0;
            if (entry->Sequence <= cursor) continue;
            highestVisited = entry->Sequence;
            entryName.Buffer = entry->Name;
            entryName.Length = entryName.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
            if (entry->Retired || entry->Instance == NULL || entry->Volume == NULL ||
                StageRegistryDirectoryRenameInFlightLocked(entry->Instance, &entryName) ||
                (!activating && !aliasProbe && (InterlockedCompareExchange(&entry->H, 0, 0) != 0 ||
                 InterlockedCompareExchange(&entry->T, 0, 0) != 0 ||
                 InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) != 0))) continue;
            if (!activating && !aliasProbe && InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) != 0)
                continue;
            if (!NT_SUCCESS(FltObjectReference(entry->Instance))) continue;
            if (!NT_SUCCESS(FltObjectReference(entry->Volume))) { FltObjectDereference(entry->Instance); continue; }
            StageRegistryReference(entry);
            candidates[count] = entry;
            instances[count] = entry->Instance;
            volumes[count] = entry->Volume;
            count += 1;
        }
        reachedBatch = count == STAGE_RECLAIM_BATCH;
        FltReleasePushLock(&RegistryLock);

        for (index = 0; index < count; ++index) {
            PSTAGE_REGISTRY_ENTRY entry = candidates[index];
            PSTAGE_REGISTRY_ENTRY mapReference = NULL;
            PFLT_INSTANCE entryInstance = NULL;
            PFLT_VOLUME entryVolume = NULL;
            BOOLEAN pruned = FALSE;
            BOOLEAN activationCandidate = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ||
                InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0;
            BOOLEAN promotedThisPass = FALSE;
            if (activationCandidate) {
                if (workBudget != 0)
                    StageRegistryActivationProcess(entry, instances[index], volumes[index], &workBudget);
                else {
                    unfinishedScan = TRUE;
                    if (firstUnfinishedSequence == 0) firstUnfinishedSequence = entry->Sequence;
                }
                if (InterlockedCompareExchange(&entry->ScopeScanPending, 0, 0) != 0 ||
                    InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0) {
                    unfinishedScan = TRUE;
                    if (firstUnfinishedSequence == 0) firstUnfinishedSequence = entry->Sequence;
                }
                promotedThisPass = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                    SAFEUPLOAD_REGISTRY_STATE_PROTECTED;
            }
            /* The check runs without the lock; a new writer in between needs a handle, which raises H or binds a
             * reservation, and the locked re-check below refuses the prune. */
            if (!promotedThisPass && InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) !=
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING &&
                InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) == 0 &&
                InterlockedCompareExchange(&entry->ScopeScanPending, 0, 0) == 0 &&
                StageRegistryEntryQuiescent(entry, instances[index], volumes[index])) {
                FltAcquirePushLockExclusive(&RegistryLock);
                pruned = StageRegistryPruneLocked(entry, &mapReference, &entryInstance, &entryVolume);
                FltReleasePushLock(&RegistryLock);
            }
            if (pruned) {
                InterlockedIncrement64(&RegistryPruned);
                if (entryVolume != NULL) FltObjectDereference(entryVolume);
                if (entryInstance != NULL) FltObjectDereference(entryInstance);
                StageRegistryDereference(mapReference);
                StageRegistryDereference(entry); /* the registry-history reference */
            }
            FltObjectDereference(volumes[index]);
            FltObjectDereference(instances[index]);
            StageRegistryDereference(entry);     /* this pass's reference */
        }
        /* D7: only this bounded identity chunk is classified; pending identities resume gated next pass. */
        FltAcquirePushLockExclusive(&RegistryLock);
        if (firstUnfinishedSequence != 0)
            RegistryReclaimCursor = firstUnfinishedSequence - 1;
        else if (reachedBatch)
            RegistryReclaimCursor = highestVisited;
        else
            RegistryReclaimCursor = 0;
        FltReleasePushLock(&RegistryLock);
        if (reachedBatch || unfinishedScan) InterlockedOr(&RegistryReclaimQueued, STAGE_RECLAIM_RESCAN);
        ExFreePoolWithTag(candidates, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
    StageRegistryReclaimWorkerFinish();
    ExReleaseRundownProtection(&SafeUploadData.ChannelRundown);
}

/* At most one pass is queued at a time. Unload waits on the channel rundown this pass holds. */
static BOOLEAN StageRegistryQueueReclaim(VOID)
{
    BOOLEAN retriedRescan = FALSE;
    for (;;) {
        LONG state = InterlockedCompareExchange(&RegistryReclaimQueued, 0, 0);
        if ((state & STAGE_RECLAIM_QUEUED) != 0) {
            if ((state & STAGE_RECLAIM_RESCAN) != 0 ||
                InterlockedCompareExchange(&RegistryReclaimQueued,
                    state | STAGE_RECLAIM_RESCAN, state) == state) return TRUE;
            continue;
        }
        if (InterlockedCompareExchange(&RegistryReclaimQueued, STAGE_RECLAIM_QUEUED,
                state) != state) continue;
        if (StageRegistryQueueReclaimWorkItem()) return TRUE;
        state = InterlockedExchange(&RegistryReclaimQueued, 0);
        if (!retriedRescan && (state & STAGE_RECLAIM_RESCAN) != 0) {
            retriedRescan = TRUE;
            continue;
        }
        return FALSE;
    }
}

VOID SafeUploadStageWritersQueueRecheck(VOID)
{
    /* Cleanup, close, or section release may expose Free(F); coalesce a fresh
     * sequence sweep without polling entries that are still in use. */
    InterlockedExchange(&RegistryReclaimResetCursor, 1);
    (VOID)StageRegistryQueueReclaim();
}

VOID SafeUploadStageWritersInitialize(VOID)
{
    ULONG index;
    KeInitializeSpinLock(&SectionLock);
    KeInitializeSpinLock(&RegistryCompactPoolLock);
    FltInitializePushLock(&RegistryLock);
    RegistryCompactPool = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        (SIZE_T)SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT * sizeof(STAGE_REGISTRY_ENTRY),
        SAFEUPLOAD_REGISTRY_POOL_TAG);
    RegistryCompactPoolCapacity = RegistryCompactPool != NULL ?
        SAFEUPLOAD_WRITER_REGISTRY_COMPACT_LIMIT : 0;
    RegistryCompactFreeCount = RegistryCompactPoolCapacity;
    RegistryCompactFreeList = NULL;
    if (RegistryCompactPool != NULL) {
        RtlZeroMemory(RegistryCompactPool,
            (SIZE_T)RegistryCompactPoolCapacity * sizeof(STAGE_REGISTRY_ENTRY));
        for (index = RegistryCompactPoolCapacity; index != 0; --index) {
            PSTAGE_REGISTRY_ENTRY entry = &RegistryCompactPool[index - 1];
            entry->StaticPool = TRUE;
            entry->PoolNext = RegistryCompactFreeList;
            RegistryCompactFreeList = entry;
        }
    }
    RegistryEntrySequence = 0;
    RegistryReclaimCursor = 0;
    RegistryReclaimResetCursor = 0;
    RegistryDirectoryRenameCount = 0;
    InitializeListHead(&RegistryEntries);
    InitializeListHead(&RegistryReservations);
    InitializeListHead(&TransactionAssociations);
    InitializeListHead(&RegistryDirectoryRenames);
    InitializeListHead(&SectionSpills);
}

VOID SafeUploadStageWritersUninitialize(VOID)
{
    PSTAGE_REGISTRY_ENTRY pool;
    PSTAGE_SECTION_SPILL_RECORD spill;
    LIST_ENTRY pendingSpills;
    KIRQL irql;
    BOOLEAN allReturned;
    InitializeListHead(&pendingSpills);
    StageAcquireSpinLock(&SectionLock, &irql);
    while (!IsListEmpty(&SectionSpills)) {
        PLIST_ENTRY link = RemoveHeadList(&SectionSpills);
        InsertTailList(&pendingSpills, link);
    }
    StageReleaseSpinLock(&SectionLock, irql);
    while (!IsListEmpty(&pendingSpills)) {
        spill = CONTAINING_RECORD(RemoveHeadList(&pendingSpills),
            STAGE_SECTION_SPILL_RECORD, Link);
        spill->Signature = 0;
        ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
    }
    pool = RegistryCompactPool;
    if (pool == NULL) return;
    StageAcquireSpinLock(&RegistryCompactPoolLock, &irql);
    allReturned = RegistryCompactFreeCount == RegistryCompactPoolCapacity;
    if (allReturned) {
        RegistryCompactPool = NULL;
        RegistryCompactFreeList = NULL;
        RegistryCompactFreeCount = 0;
        RegistryCompactPoolCapacity = 0;
    }
    StageReleaseSpinLock(&RegistryCompactPoolLock, irql);
    /* All filter callbacks/workers have drained before StageFree. A nonempty
     * pool here is a lifetime defect, so retain it instead of freeing live entries. */
    if (allReturned) ExFreePoolWithTag(pool, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

static BOOLEAN StageSectionWritable(_In_ PFLT_CALLBACK_DATA Data)
{
    UINT32 protection;

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) return FALSE;
    protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    return (protection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryHasEntryForSop(
    _In_ PFLT_INSTANCE Instance, _In_opt_ PVOID SectionObjectPointer)
{
    PLIST_ENTRY link;
    BOOLEAN found = FALSE;
    if (Instance == NULL || SectionObjectPointer == NULL) return FALSE;
    FltAcquirePushLockShared(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (entry->Listed && !entry->Retired && entry->Instance == Instance &&
            InterlockedCompareExchangePointer((PVOID volatile *)&entry->SectionObjectPointer,
                NULL, NULL) == SectionObjectPointer) {
            found = TRUE;
            break;
        }
    }
    FltReleasePushLock(&RegistryLock);
    return found;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryReserveSpilledSection(
    _In_opt_ PVOID SectionObjectPointer, _In_opt_ PFLT_INSTANCE Instance,
    _In_ BOOLEAN Writable, _Inout_ PSTAGE_SECTION_SPILL_RECORD SpillRecord,
    _Out_ PULONG SopSlotIndex, _Out_ PBOOLEAN IdentityKnown)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    KIRQL irql;
    BOOLEAN found = FALSE, reserved = FALSE;
    *SopSlotIndex = 0;
    *IdentityKnown = FALSE;
    if (SectionObjectPointer == NULL || Instance == NULL || SpillRecord == NULL) return FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    if (found && slot != NULL &&
        ((slot->Unknown && slot->InstanceIdentity == (PVOID)Instance) ||
         (slot->Entry != NULL && slot->Entry->Instance == Instance))) {
        *IdentityKnown = TRUE;
        if (slot->SpilledSectionAcquireCount == MAXULONG ||
            (Writable && slot->SpilledSectionCount == MAXULONG)) {
            /* The exact per-acquire record remains the source when this summary counter saturates. */
            *SopSlotIndex = MAXULONG;
            SpillRecord->SopSlotIndex = MAXULONG;
        } else {
            *SopSlotIndex = (ULONG)(slot - RegistrySopSlots);
            slot->SpilledSectionAcquireCount += 1;
            if (Writable) slot->SpilledSectionCount += 1;
            SpillRecord->SopSlotIndex = *SopSlotIndex;
            InterlockedIncrement64(&RegistrySopMapGeneration);
            InterlockedIncrement64(&RegistryChangeSequence);
        }
    } else if (!found) {
        /* The per-acquire record remains exact even when the bounded SOP map is full. */
        *SopSlotIndex = MAXULONG;
        SpillRecord->SopSlotIndex = MAXULONG;
    } else {
        StageReleaseSpinLock(&SectionLock, irql);
        return FALSE;
    }
    SpillRecord->Sequence = ++SectionSequence;
    InsertTailList(&SectionSpills, &SpillRecord->Link);
    reserved = TRUE;
    StageReleaseSpinLock(&SectionLock, irql);
    return reserved;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionAcquireFailed(
    _In_ ULONG SopSlotIndex, _In_opt_ PVOID SectionObjectPointer,
    _In_opt_ PVOID InstanceIdentity, _In_ BOOLEAN Writable)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    KIRQL irql;
    BOOLEAN recheck = FALSE;
    if (SopSlotIndex >= RTL_NUMBER_OF(RegistrySopSlots)) return;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = &RegistrySopSlots[SopSlotIndex];
    if (slot->SectionObjectPointer == SectionObjectPointer &&
        ((slot->Unknown && slot->InstanceIdentity == InstanceIdentity) ||
         (slot->Entry != NULL && (PVOID)slot->Entry->Instance == InstanceIdentity)) &&
        slot->SpilledSectionAcquireCount != 0 &&
        (!Writable || slot->SpilledSectionCount != 0)) {
        slot->SpilledSectionAcquireCount -= 1;
        if (Writable) slot->SpilledSectionCount -= 1;
        InterlockedIncrement64(&RegistrySopMapGeneration);
        InterlockedIncrement64(&RegistryChangeSequence);
        recheck = slot->SpilledSectionCount == 0;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (recheck) SafeUploadStageWritersQueueRecheck();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionAcquireDraining(
    _In_opt_ PFLT_INSTANCE Instance, _In_ ULONG SopSlotIndex,
    _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    KIRQL irql;
    if (SopSlotIndex < RTL_NUMBER_OF(RegistrySopSlots)) {
        StageAcquireSpinLock(&SectionLock, &irql);
        slot = &RegistrySopSlots[SopSlotIndex];
        if (slot->SectionObjectPointer == SectionObjectPointer &&
            slot->SpilledSectionCount != 0 &&
            ((slot->Unknown && slot->InstanceIdentity == (PVOID)Instance) ||
             (slot->Entry != NULL && slot->Entry->Instance == Instance))) {
            entry = slot->Entry;
            StageRegistryReference(entry);
        }
        StageReleaseSpinLock(&SectionLock, irql);
    }
    if (entry != NULL) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
        StageRegistryDereference(entry);
    } else {
        /* Draining hides whether lower completed the acquire; retain the spill and sticky Unknown. */
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionReleaseComplete(
    _In_opt_ PFLT_INSTANCE Instance, _In_ ULONG SopSlotIndex,
    _In_opt_ PVOID SectionObjectPointer, _In_ BOOLEAN Writable,
    _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    KIRQL irql;
    BOOLEAN recheck = FALSE, lostPairing = FALSE;
    if (SopSlotIndex >= RTL_NUMBER_OF(RegistrySopSlots)) {
        return;
    }
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = &RegistrySopSlots[SopSlotIndex];
    if (slot->SectionObjectPointer != SectionObjectPointer ||
        !((slot->Unknown && slot->InstanceIdentity == (PVOID)Instance) ||
          (slot->Entry != NULL && slot->Entry->Instance == Instance)) ||
        slot->SpilledSectionReleasePending == 0) {
        lostPairing = TRUE;
    } else {
        slot->SpilledSectionReleasePending -= 1;
        if (Succeeded && !Draining) {
            if (slot->SpilledSectionAcquireCount == 0 ||
                (Writable && slot->SpilledSectionCount == 0)) {
                lostPairing = TRUE;
            } else {
                slot->SpilledSectionAcquireCount -= 1;
                if (Writable) slot->SpilledSectionCount -= 1;
                InterlockedIncrement64(&RegistrySopMapGeneration);
                InterlockedIncrement64(&RegistryChangeSequence);
                recheck = slot->SpilledSectionCount == 0;
            }
        } else if (Draining) {
            entry = slot->Entry;
            if (entry != NULL) StageRegistryReference(entry);
        }
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (entry != NULL) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
        StageRegistryDereference(entry);
    } else if (Draining || lostPairing) {
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
    }
    if (recheck) SafeUploadStageWritersQueueRecheck();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static VOID StageRegistrySpilledSectionSnapshot(
    _In_opt_ PVOID SectionObjectPointer, _Out_ PUINT32 WritableCount,
    _Out_ PUINT32 TotalCount)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE;
    ULONG_PTR writable = 0, total = 0, spilledWritable = 0, spilledTotal = 0;
    ULONG index;
    PLIST_ENTRY link;
    KIRQL irql;
    *WritableCount = 0;
    *TotalCount = 0;
    if (SectionObjectPointer == NULL) return;
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        STAGE_SECTION_SLOT *fixed = &SectionSlots[index];
        if (fixed->FileObject == NULL || fixed->SectionObjectPointer != SectionObjectPointer) continue;
        total += 1;
        if (fixed->Writable) writable += 1;
    }
    for (link = SectionSpills.Flink; link != &SectionSpills; link = link->Flink) {
        PSTAGE_SECTION_SPILL_RECORD spill = CONTAINING_RECORD(link,
            STAGE_SECTION_SPILL_RECORD, Link);
        if (spill->Signature != STAGE_SECTION_SPILL_SIGNATURE ||
            spill->SectionObjectPointer != SectionObjectPointer) continue;
        if (spilledTotal != MAXULONG) spilledTotal += 1;
        if (spill->Writable && spilledWritable != MAXULONG) spilledWritable += 1;
    }
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    if (found && slot != NULL) {
        if (spilledTotal < slot->SpilledSectionAcquireCount)
            spilledTotal = slot->SpilledSectionAcquireCount;
        if (spilledWritable < slot->SpilledSectionCount)
            spilledWritable = slot->SpilledSectionCount;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (MAXULONG - total < spilledTotal || total + spilledTotal > MAXULONG)
        total = MAXULONG;
    else
        total += spilledTotal;
    if (MAXULONG - writable < spilledWritable || writable + spilledWritable > MAXULONG)
        writable = SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
    else
        writable += spilledWritable;
    *WritableCount = (UINT32)writable;
    *TotalCount = (UINT32)total;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) NTSTATUS SafeUploadStageSectionAcquired(_In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PVOID sop, thread;
    BOOLEAN writable;
    STAGE_SECTION_SLOT *record = NULL;
    PSTAGE_SECTION_SPILL_RECORD spillRecord = NULL;
    PSTAGE_REGISTRY_SOP_SLOT sopMap;
    ULONG index;
    ULONG processId;
    KIRQL irql;
    LONGLONG now;
    BOOLEAN sopMapFound, spillIdentityKnown = FALSE;

    *CompletionContext = NULL;
    if (fileObject == NULL) {
        StageRegistryMarkUnknown(FltObjects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
        return STATUS_SUCCESS;
    }
    sop = fileObject->SectionObjectPointer;
    thread = PsGetCurrentThread();
    writable = StageSectionWritable(Data);
    processId = FltGetRequestorProcessId(Data);
    now = (LONGLONG)KeQueryInterruptTime();
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject != NULL) continue;
        slot->FileObject = fileObject;
        slot->Thread = thread;
        slot->InstanceIdentity = FltObjects->Instance;
        slot->SectionObjectPointer = sop;
        slot->Time = now;
        slot->Sequence = ++SectionSequence;
        slot->Writable = writable;
        sopMap = StageRegistryFindSopSlotLocked(sop, &sopMapFound);
        if (sopMapFound && sopMap != NULL && sopMap->Entry != NULL) {
            PSTAGE_REGISTRY_ENTRY entry = sopMap->Entry;
            StageRegistryReference(entry);
            slot->RegistryEntry = entry;
            slot->VolumeSerial = entry->VolumeSerial;
            slot->FileId = entry->FileId;
        } else if (sopMapFound && sopMap != NULL && sopMap->Unknown) {
            slot->VolumeSerial = sopMap->VolumeSerial;
            slot->FileId = sopMap->FileId;
        }
        slot->ProcessId = processId;
        if (writable) {
            SectionInserted += 1;
            SectionNow += 1;
            if (SectionNow > SectionMaxDepth) SectionMaxDepth = SectionNow;
            InterlockedIncrement64(&RegistryChangeSequence);
        }
        record = slot;
        break;
    }
    if (record == NULL) {
        SectionOverflow += 1;
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (record == NULL) {
        spillRecord = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*spillRecord),
            SAFEUPLOAD_REGISTRY_POOL_TAG);
        if (spillRecord != NULL) {
            RtlZeroMemory(spillRecord, sizeof(*spillRecord));
            spillRecord->Signature = STAGE_SECTION_SPILL_SIGNATURE;
            spillRecord->FileObject = fileObject;
            spillRecord->Thread = thread;
            spillRecord->InstanceIdentity = FltObjects->Instance;
            spillRecord->SectionObjectPointer = sop;
            spillRecord->SopSlotIndex = MAXULONG;
            spillRecord->Writable = writable;
            spillRecord->AcquirePending = TRUE;
        }
        if (spillRecord != NULL && StageRegistryReserveSpilledSection(sop,
                FltObjects->Instance, writable, spillRecord, &index, &spillIdentityKnown)) {
            *CompletionContext = (PVOID)((ULONG_PTR)spillRecord |
                STAGE_SECTION_ACQUIRE_SPILL_TAG);
            if (index == MAXULONG && !spillIdentityKnown &&
                !StageRegistryHasEntryForSop(FltObjects->Instance, sop)) {
                /* Keep the exact acquire/release pair, but no file ID exists to classify this SOP. */
                StageRegistryMarkUnknown(FltObjects->Instance,
                    SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
            }
            spillRecord = NULL; /* SectionSpills owns it until the matching release. */
        } else if (KeGetCurrentIrql() <= APC_LEVEL) {
            /* Without a stable SOP entry or capacity for its pair record, exact recovery is impossible. */
            if (spillRecord != NULL) ExFreePoolWithTag(spillRecord, SAFEUPLOAD_REGISTRY_POOL_TAG);
            spillRecord = NULL;
            StageRegistryMarkUnknown(FltObjects->Instance,
                SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY, FALSE);
        } else {
            if (spillRecord != NULL) ExFreePoolWithTag(spillRecord, SAFEUPLOAD_REGISTRY_POOL_TAG);
            spillRecord = NULL;
            InterlockedOr((volatile LONG *)&RegistryUnknownReasons,
                SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY);
            if (!StageRegistryQueueInstanceUnknown(FltObjects->Instance,
                    SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY))
                InterlockedExchange(&WriterGlobalUnknown, 1);
        }
        InterlockedIncrement64(&RegistryCapacityFailures);
        /* Exact SOP spills retire on acquire failure/release; identityless loss stays sticky. */
        return STATUS_SUCCESS;
    }
    *CompletionContext = (PVOID)((ULONG_PTR)record | STAGE_SECTION_ACQUIRE_FIXED_TAG);
    return STATUS_SUCCESS;
}

/* Caller holds SectionLock. Failed callbacks own this exact slot until they remove it; a successful
 * acquisition retains it until the matching release. Read-only slots affect pairing, never C(F). */
static PSTAGE_REGISTRY_ENTRY StageSectionRemoveSlot(_Inout_ STAGE_SECTION_SLOT *Slot, _In_ BOOLEAN Failed)
{
    PSTAGE_REGISTRY_ENTRY entry = Slot->RegistryEntry;
    if (Slot->Writable) {
        SectionNow -= 1;
        if (Failed) SectionRemovedOnFailure += 1;
        else SectionReleased += 1;
        InterlockedIncrement64(&RegistryChangeSequence);
    }
    RtlZeroMemory(Slot, sizeof(*Slot));
    return entry;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) VOID SafeUploadStageSectionReleasePrepare(_In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PFLT_INSTANCE Instance,
    _Outptr_result_maybenull_ PVOID *CompletionContext)
{
    PFILE_OBJECT fileObject = Data->Iopb->TargetFileObject;
    PVOID thread = PsGetCurrentThread();
    STAGE_SECTION_SLOT *fixedRecord = NULL;
    PSTAGE_SECTION_SPILL_RECORD spillRecord = NULL;
    ULONGLONG latestSequence = 0;
    ULONG index;
    KIRQL irql;

    *CompletionContext = NULL;
    if (fileObject == NULL || Instance == NULL) return;
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject == fileObject && slot->Thread == thread &&
            slot->InstanceIdentity == (PVOID)Instance && !slot->ReleasePending &&
            slot->Sequence > latestSequence) {
            fixedRecord = slot;
            spillRecord = NULL;
            latestSequence = slot->Sequence;
        }
    }
    {
        PLIST_ENTRY link;
        for (link = SectionSpills.Flink; link != &SectionSpills; link = link->Flink) {
            PSTAGE_SECTION_SPILL_RECORD candidate = CONTAINING_RECORD(link,
                STAGE_SECTION_SPILL_RECORD, Link);
            if (candidate->Signature == STAGE_SECTION_SPILL_SIGNATURE &&
                candidate->FileObject == fileObject && candidate->Thread == thread &&
                candidate->InstanceIdentity == (PVOID)Instance &&
                !candidate->AcquirePending && !candidate->ReleasePending &&
                !candidate->AcquireOutcomeUnknown && !candidate->ReleaseOutcomeUnknown &&
                !candidate->Retiring &&
                candidate->Sequence > latestSequence) {
                spillRecord = candidate;
                fixedRecord = NULL;
                latestSequence = candidate->Sequence;
            }
        }
    }
    if (fixedRecord != NULL) {
        fixedRecord->ReleasePending = TRUE;
        *CompletionContext = (PVOID)((ULONG_PTR)fixedRecord | STAGE_SECTION_RELEASE_FIXED_TAG);
    } else if (spillRecord != NULL) {
        if (spillRecord->SopSlotIndex < RTL_NUMBER_OF(RegistrySopSlots)) {
            PSTAGE_REGISTRY_SOP_SLOT map = &RegistrySopSlots[spillRecord->SopSlotIndex];
            if (map->SectionObjectPointer == spillRecord->SectionObjectPointer &&
                ((map->Unknown && map->InstanceIdentity == (PVOID)Instance) ||
                 (map->Entry != NULL && map->Entry->Instance == Instance)) &&
                map->SpilledSectionReleasePending < map->SpilledSectionAcquireCount)
                map->SpilledSectionReleasePending += 1;
        }
        spillRecord->ReleasePending = TRUE;
        *CompletionContext = (PVOID)((ULONG_PTR)spillRecord | STAGE_SECTION_RELEASE_SPILL_TAG);
    }
    StageReleaseSpinLock(&SectionLock, irql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) VOID SafeUploadStageSectionReleaseComplete(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext, _In_ BOOLEAN Succeeded, _In_ BOOLEAN Draining)
{
    ULONG_PTR tag;
    KIRQL irql;
    if (CompletionContext == NULL) return;
    tag = (ULONG_PTR)CompletionContext & STAGE_COMPLETION_CONTEXT_TAG_MASK;
    if (tag == STAGE_SECTION_RELEASE_SPILL_TAG) {
        PSTAGE_SECTION_SPILL_RECORD spill = (PSTAGE_SECTION_SPILL_RECORD)((ULONG_PTR)CompletionContext &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        BOOLEAN removed = FALSE, retired = FALSE;
        ULONG slotIndex = spill->SopSlotIndex;
        BOOLEAN writable = spill->Writable;
        if (Draining) {
            StageAcquireSpinLock(&SectionLock, &irql);
            if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->ReleasePending &&
                spill->Retiring) {
                RemoveEntryList(&spill->Link);
                spill->Signature = 0;
                removed = TRUE;
                retired = TRUE;
            } else if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->ReleasePending) {
                spill->ReleasePending = FALSE;
                spill->ReleaseOutcomeUnknown = TRUE;
            }
            StageReleaseSpinLock(&SectionLock, irql);
            if (retired) {
                ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
                return;
            }
            StageRegistrySpilledSectionReleaseComplete(Instance, slotIndex,
                spill->SectionObjectPointer, writable, FALSE, TRUE);
            if (slotIndex == MAXULONG)
                StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
            return;
        }
        StageAcquireSpinLock(&SectionLock, &irql);
        if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->ReleasePending) {
            if (spill->Retiring) {
                RemoveEntryList(&spill->Link);
                spill->Signature = 0;
                removed = TRUE;
                retired = TRUE;
            } else if (Succeeded) {
                RemoveEntryList(&spill->Link);
                spill->Signature = 0;
                removed = TRUE;
            } else {
                spill->ReleasePending = FALSE;
            }
        }
        StageReleaseSpinLock(&SectionLock, irql);
        if (!retired)
            StageRegistrySpilledSectionReleaseComplete(Instance, slotIndex,
                spill->SectionObjectPointer, writable, Succeeded && removed, FALSE);
        if (!retired && removed && slotIndex == MAXULONG)
            SafeUploadStageWritersQueueRecheck();
        if (removed) ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
        return;
    }
    if (tag == STAGE_SECTION_RELEASE_FIXED_TAG) {
        STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)((ULONG_PTR)CompletionContext &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        PSTAGE_REGISTRY_ENTRY removed = NULL;
        BOOLEAN activating = FALSE, writable = FALSE;
        if (Draining) {
            if (slot->RegistryEntry != NULL)
                StageRegistryMarkEntryUnknown(slot->RegistryEntry, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
            else
                StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
        }
        StageAcquireSpinLock(&SectionLock, &irql);
        if (slot->FileObject != NULL && slot->ReleasePending) {
            if (Succeeded && !Draining) {
                writable = slot->Writable;
                removed = StageSectionRemoveSlot(slot, FALSE);
            } else if (!Draining) {
                slot->ReleasePending = FALSE;
            }
        }
        StageReleaseSpinLock(&SectionLock, irql);
        if (removed != NULL) {
            activating = InterlockedCompareExchange((volatile LONG *)&removed->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;
            StageRegistryDereference(removed);
            if (activating || writable) StageRegistryQueueReclaim();
        } else if (writable) {
            StageRegistryQueueReclaim();
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) VOID SafeUploadStageSectionAcquireComplete(_In_opt_ PVOID CompletionContext)
{
    ULONG_PTR tag;
    PSTAGE_SECTION_SPILL_RECORD spill;
    KIRQL irql;
    BOOLEAN removed = FALSE;
    if (CompletionContext == NULL) return;
    tag = (ULONG_PTR)CompletionContext & STAGE_COMPLETION_CONTEXT_TAG_MASK;
    if (tag != STAGE_SECTION_ACQUIRE_SPILL_TAG) return;
    spill = (PSTAGE_SECTION_SPILL_RECORD)((ULONG_PTR)CompletionContext &
        ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
    StageAcquireSpinLock(&SectionLock, &irql);
    if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->AcquirePending) {
        spill->AcquirePending = FALSE;
        if (spill->Retiring && !spill->ReleasePending) {
            RemoveEntryList(&spill->Link);
            spill->Signature = 0;
            removed = TRUE;
        }
    }
    StageReleaseSpinLock(&SectionLock, irql);
    if (removed) ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) VOID SafeUploadStageSectionAcquireFailed(_In_ PVOID CompletionContext)
{
    ULONG_PTR tag;
    KIRQL irql;
    if (CompletionContext == NULL) return;
    tag = (ULONG_PTR)CompletionContext & STAGE_COMPLETION_CONTEXT_TAG_MASK;
    if (tag == STAGE_SECTION_ACQUIRE_SPILL_TAG) {
        PSTAGE_SECTION_SPILL_RECORD spill = (PSTAGE_SECTION_SPILL_RECORD)((ULONG_PTR)CompletionContext &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        ULONG slotIndex = spill->SopSlotIndex;
        BOOLEAN writable = spill->Writable, removed = FALSE;
        StageAcquireSpinLock(&SectionLock, &irql);
        if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->AcquirePending) {
            RemoveEntryList(&spill->Link);
            spill->Signature = 0;
            removed = TRUE;
        }
        StageReleaseSpinLock(&SectionLock, irql);
        if (removed) {
            StageRegistrySpilledSectionAcquireFailed(slotIndex,
                spill->SectionObjectPointer, spill->InstanceIdentity, writable);
            if (writable || slotIndex == MAXULONG) SafeUploadStageWritersQueueRecheck();
            ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
        }
        return;
    }
    if (tag == STAGE_SECTION_ACQUIRE_FIXED_TAG) {
        STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)((ULONG_PTR)CompletionContext &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        PSTAGE_REGISTRY_ENTRY removed;
        BOOLEAN writable;
        StageAcquireSpinLock(&SectionLock, &irql);
        writable = slot->Writable;
        removed = StageSectionRemoveSlot(slot, TRUE);
        StageReleaseSpinLock(&SectionLock, irql);
        StageRegistryDereference(removed);
        if (writable) StageRegistryQueueReclaim();
    }
}

/* A draining acquire/release cannot reveal whether lower retained the section. Keep its exact spill
 * record and Unknown reason; only an identityless SOP loss requires sticky instance Unknown. */
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) VOID SafeUploadStageSectionAcquireDraining(_In_opt_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID CompletionContext)
{
    ULONG_PTR tag;
    KIRQL irql;
    if (CompletionContext == NULL) return;
    tag = (ULONG_PTR)CompletionContext & STAGE_COMPLETION_CONTEXT_TAG_MASK;
    if (tag == STAGE_SECTION_ACQUIRE_SPILL_TAG) {
        PSTAGE_SECTION_SPILL_RECORD spill = (PSTAGE_SECTION_SPILL_RECORD)((ULONG_PTR)CompletionContext &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        BOOLEAN retired = FALSE;
        StageAcquireSpinLock(&SectionLock, &irql);
        if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->AcquirePending &&
            spill->Retiring) {
            spill->AcquirePending = FALSE;
            RemoveEntryList(&spill->Link);
            spill->Signature = 0;
            retired = TRUE;
        } else if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE && spill->AcquirePending) {
            spill->AcquirePending = FALSE;
            spill->AcquireOutcomeUnknown = TRUE;
        }
        StageReleaseSpinLock(&SectionLock, irql);
        if (retired) {
            ExFreePoolWithTag(spill, SAFEUPLOAD_REGISTRY_POOL_TAG);
            return;
        }
        if (spill->SopSlotIndex < RTL_NUMBER_OF(RegistrySopSlots))
            StageRegistrySpilledSectionAcquireDraining(Instance, spill->SopSlotIndex,
                spill->SectionObjectPointer);
        else
            StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
    } else if (tag == STAGE_SECTION_ACQUIRE_FIXED_TAG) {
        STAGE_SECTION_SLOT *slot = (STAGE_SECTION_SLOT *)((ULONG_PTR)CompletionContext &
            ~STAGE_COMPLETION_CONTEXT_TAG_MASK);
        if (slot->RegistryEntry != NULL)
            StageRegistryMarkEntryUnknown(slot->RegistryEntry, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
        else
            StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
    }
}

/* The pageable registry-entry probe calls this resident SectionLock snapshot. */
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) UINT32 SafeUploadStageSectionsInFlight(_In_opt_ PVOID SectionObjectPointer)
{
    UINT32 count = 0, total = 0;
    if (SectionObjectPointer == NULL) return SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
    StageRegistrySpilledSectionSnapshot(SectionObjectPointer, &count, &total);
    UNREFERENCED_PARAMETER(total);
    return count;
}

/* A live writable-section slot without an SOP registry binding is not Free:
 * the section ledger blocks promotion until identity can be joined. */
BOOLEAN SafeUploadStageWritersNameActivating(_In_ PFLT_INSTANCE Instance, _In_ PCUNICODE_STRING Name)
{
    PLIST_ENTRY link;
    UNICODE_STRING baseName = StageRegistryBaseName(Name);
    BOOLEAN activating = FALSE;
    if (Instance == NULL || Name == NULL || Name->Length == 0) return FALSE;
    FltAcquirePushLockShared(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        UNICODE_STRING entryName;
        BOOLEAN aliasProbe = InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0;
        LONG state = InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0);
        if (entry->Retired || !entry->Listed || entry->Instance != Instance ||
            (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) == 0 && !aliasProbe) ||
            (!aliasProbe && state != SAFEUPLOAD_REGISTRY_STATE_ACTIVATING &&
             state != SAFEUPLOAD_REGISTRY_STATE_UNKNOWN) ||
            (!aliasProbe && state == SAFEUPLOAD_REGISTRY_STATE_UNKNOWN &&
             InterlockedCompareExchange(&entry->ScopeNameClassification, 0, 0) ==
                STAGE_SCOPE_CLASS_OUTSIDE) || entry->NameChars == 0) continue;
        entryName.Buffer = entry->Name;
        entryName.Length = entryName.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
        if (RtlEqualUnicodeString(&entryName, &baseName, TRUE)) { activating = TRUE; break; }
    }
    FltReleasePushLock(&RegistryLock);
    return activating;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static PSTAGE_REGISTRY_ENTRY StageRegistryReferenceSop(_In_opt_ PVOID Sop)
{
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE;
    KIRQL irql;
    if (Sop == NULL) return NULL;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(Sop, &found);
    if (found && slot != NULL && slot->Entry != NULL) {
        entry = slot->Entry;
        StageRegistryReference(entry);
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return entry;
}

_IRQL_requires_max_(APC_LEVEL)
__declspec(noinline) static BOOLEAN StageRegistryUnknownSopForInstance(
    _In_ PFLT_INSTANCE Instance, _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_SOP_SLOT slot;
    BOOLEAN found = FALSE, unknownMarker;
    KIRQL irql;

    if (Instance == NULL || SectionObjectPointer == NULL) return FALSE;
    StageAcquireSpinLock(&SectionLock, &irql);
    slot = StageRegistryFindSopSlotLocked(SectionObjectPointer, &found);
    unknownMarker = found && slot != NULL && slot->Unknown &&
        slot->InstanceIdentity == (PVOID)Instance;
    StageReleaseSpinLock(&SectionLock, irql);
    return unknownMarker;
}

BOOLEAN SafeUploadStageWritersSopMatchesPolicy(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer, _In_ BOOLEAN IncludeAncestors)
{
    PSTAGE_REGISTRY_ENTRY entry;
    BOOLEAN matches = FALSE;
    if (Instance == NULL || SectionObjectPointer == NULL) return FALSE;
    entry = StageRegistryReferenceSop(SectionObjectPointer);
    if (entry == NULL) {
        BOOLEAN known = FALSE, outside = FALSE;
        StageRegistrySopScopeClassification(Instance, SectionObjectPointer,
            (ULONG)SafeUploadCurrentPolicyGeneration(), &known, &outside);
        if (known && outside) return FALSE;
        /* An in-scope or undecidable overflow marker stays fail closed for this SOP. */
        return StageRegistryUnknownSopForInstance(Instance, SectionObjectPointer) &&
            SafeUploadPolicyMayMatchInstanceVolume(Instance);
    }
    FltAcquirePushLockShared(&RegistryLock);
    if (entry->Listed && !entry->Retired && entry->Instance == Instance &&
        InterlockedCompareExchangePointer((PVOID volatile *)&entry->SectionObjectPointer,
            NULL, NULL) == SectionObjectPointer) {
        if (InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0 ||
            InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                SAFEUPLOAD_REGISTRY_STATE_PROTECTED ||
            InterlockedCompareExchange(&entry->ScopeNameClassification, 0, 0) ==
                STAGE_SCOPE_CLASS_SCOPED) {
            matches = TRUE;
        } else if (InterlockedCompareExchange(&entry->ScopeNameClassification, 0, 0) ==
            STAGE_SCOPE_CLASS_OUTSIDE) {
            matches = FALSE;
        } else if (entry->NameChars != 0 &&
            entry->NameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
            UNICODE_STRING name;
            name.Buffer = entry->Name;
            name.Length = name.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
            matches = SafeUploadPolicyMatchesCurrentOrPendingDestination(
                entry->VolumeKind, &name, IncludeAncestors);
        } else if (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0) {
            /* An unresolved name explicitly classified for activation stays fail closed. */
            matches = TRUE;
        }
    }
    FltReleasePushLock(&RegistryLock);
    StageRegistryDereference(entry);
    return matches;
}

_IRQL_requires_max_(APC_LEVEL)
VOID SafeUploadStageWritersMutationDraining(_In_ PFLT_INSTANCE Instance,
    _In_opt_ PVOID SectionObjectPointer)
{
    PSTAGE_REGISTRY_ENTRY entry = StageRegistryReferenceSop(SectionObjectPointer);
    if (entry != NULL) {
        StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN);
        StageRegistryDereference(entry);
    } else {
        StageRegistryMarkUnknown(Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN, FALSE);
    }
}

NTSTATUS SafeUploadStageWritersApplyPendingScope(VOID)
{
    PLIST_ENTRY link;
    BOOLEAN queued = FALSE;
    PAGED_CODE();
    FltAcquirePushLockExclusive(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
        BOOLEAN contextKnown, instanceUnknown, nameUnresolved, volumeScoped;
        ULONGLONG renameLossGeneration = 0;
        if (entry->Retired || !entry->Listed || entry->Instance == NULL || entry->Volume == NULL) continue;
        /* P0-4: aliases are not retained at link time, so probe every live file identity on a volume
         * that may contain policy. Scope-apply admission ordering stays active until PASSIVE enumeration. */
        volumeScoped = SafeUploadPolicyMayMatchInstanceVolume(entry->Instance);
        if (!volumeScoped) continue;
        contextKnown = NT_SUCCESS(FltGetInstanceContext(entry->Instance,
            (PFLT_CONTEXT *)&instanceContext));
        if (contextKnown) {
            renameLossGeneration = (ULONGLONG)InterlockedCompareExchange64(
                &instanceContext->RegistryRenameLossGeneration, 0, 0);
            instanceUnknown = InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0 ||
                InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0;
            FltReleaseContext(instanceContext);
        } else instanceUnknown = TRUE;
        instanceUnknown = instanceUnknown || SafeUploadStageWritersGlobalUnknown() != 0;
        if (instanceUnknown) {
            if (InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0 ||
                InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0)
                StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
            StageRegistryCancelAliasProbeForInstanceUnknown(entry);
            continue;
        }
        nameUnresolved = !entry->StreamIdentityKnown ||
            (!entry->Compact && entry->NameChars == 0) ||
            (InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0 ||
            entry->RenameLossGeneration != renameLossGeneration;
        if (nameUnresolved) {
            /* P0-5: one instance rename-loss generation invalidates every older retained name
             * on a possibly scoped volume; publish the identity gate before completing the apply. */
            InterlockedOr(&entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
            StageRegistryPrepareActivation(entry, TRUE);
            InterlockedIncrement64(&RegistryChangeSequence);
            continue;
        }
        if (StageRegistryBeginAliasProbe(entry)) {
            entry->ActivationGeneration = (ULONG)SafeUploadCurrentPolicyGeneration() + 1;
            InterlockedIncrement64(&RegistryChangeSequence);
            queued = TRUE;
        }
    }
    FltReleasePushLock(&RegistryLock);
    if (queued && !StageRegistryQueueReclaim()) {
        /* If no PASSIVE worker can resolve the affected candidates, keep them
         * Unknown so new mutating opens and writable sections remain refused. */
        FltAcquirePushLockExclusive(&RegistryLock);
        for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
            PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
            if (InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0) {
                BOOLEAN activated;
                StageRegistryResolveAliasProbe(entry, FALSE, FALSE, &activated);
            } else if (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0 &&
                InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0) ==
                    SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) {
                InterlockedOr(&entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);
                InterlockedExchange((volatile LONG *)&entry->State, SAFEUPLOAD_REGISTRY_STATE_UNKNOWN);
                InterlockedIncrement64(&RegistryChangeSequence);
            }
        }
        FltReleasePushLock(&RegistryLock);
    }
    return STATUS_SUCCESS;
}

VOID SafeUploadStageWritersReconcileCurrentScope(VOID)
{
    PLIST_ENTRY link;
    BOOLEAN recheck = FALSE;
    PAGED_CODE();
    FltAcquirePushLockExclusive(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
        BOOLEAN scoped, contextKnown, instanceUnknown, nameUnresolved;
        ULONGLONG renameLossGeneration = 0;
        if (entry->Retired || !entry->Listed || entry->Instance == NULL || entry->Volume == NULL) continue;
        scoped = SafeUploadPolicyMayMatchInstanceVolume(entry->Instance);
        if (!scoped) {
            if (InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0 &&
                InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) == 0)
                StageRegistryClearActivation(entry);
            continue;
        }
        contextKnown = NT_SUCCESS(FltGetInstanceContext(entry->Instance,
            (PFLT_CONTEXT *)&instanceContext));
        if (contextKnown) {
            renameLossGeneration = (ULONGLONG)InterlockedCompareExchange64(
                &instanceContext->RegistryRenameLossGeneration, 0, 0);
            instanceUnknown = InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0 ||
                InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0;
            FltReleaseContext(instanceContext);
        } else instanceUnknown = TRUE;
        instanceUnknown = instanceUnknown || SafeUploadStageWritersGlobalUnknown() != 0;
        if (instanceUnknown) {
            if (InterlockedCompareExchange(&entry->AliasProbePending, 0, 0) != 0 ||
                InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) != 0)
                StageRegistryMarkEntryUnknown(entry, SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY);
            StageRegistryCancelAliasProbeForInstanceUnknown(entry);
            continue;
        }
        nameUnresolved = !entry->StreamIdentityKnown ||
            (!entry->Compact && entry->NameChars == 0) ||
            (InterlockedCompareExchange(&entry->UnknownReasons, 0, 0) & SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME) != 0 ||
            entry->RenameLossGeneration != renameLossGeneration;
        if (nameUnresolved) {
            InterlockedOr(&entry->UnknownReasons, SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME);
            StageRegistryPrepareActivation(entry, TRUE);
            InterlockedIncrement64(&RegistryChangeSequence);
        } else if (StageRegistryBeginAliasProbe(entry)) {
            entry->ActivationGeneration = (ULONG)SafeUploadCurrentPolicyGeneration();
            InterlockedIncrement64(&RegistryChangeSequence);
            recheck = TRUE;
        }
    }
    FltReleasePushLock(&RegistryLock);
    if (recheck) (VOID)StageRegistryQueueReclaim();
}

NTSTATUS SafeUploadStageWritersActivatingStatusPage(_In_ UINT32 StartIndex,
    _Out_ PSAFEUPLOAD_ACTIVATING_STATUS_PAGE Page)
{
    PLIST_ENTRY link;
    UINT32 total = 0, skipped = 0, count = 0;
    UINT64 startSequence, endSequence;
    PAGED_CODE();
    RtlZeroMemory(Page, sizeof(*Page));
    Page->StructSize = sizeof(*Page);
    Page->StartIndex = StartIndex;
    if (StartIndex > SAFEUPLOAD_WRITER_REGISTRY_ALL_LIMIT) return STATUS_INVALID_PARAMETER;
    Page->PolicyGeneration = (UINT32)SafeUploadCurrentPolicyGeneration();
    startSequence = (UINT64)InterlockedCompareExchange64(&RegistryChangeSequence, 0, 0);
    FltAcquirePushLockShared(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY entry = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        if (entry->Retired || InterlockedCompareExchange(&entry->ActivationEnforced, 0, 0) == 0) continue;
        total += 1;
        if (skipped++ < StartIndex || count == SAFEUPLOAD_ACTIVATING_STATUS_MAX_ENTRIES) continue;
        {
            PSAFEUPLOAD_ACTIVATING_ENTRY_STATUS output = &Page->Entries[count++];
            ULONG index;
            UINT32 pidCount = 0;
            UINT32 openerPids[RTL_NUMBER_OF(output->OpenerPids)];
            UINT32 sectionPids[RTL_NUMBER_OF(output->OpenerPids)];
            UINT32 openerCount = 0, sectionPidCount = 0;
            UINT32 sectionCount, pidIndex;
            output->VolumeSerialNumber = entry->VolumeSerial;
            RtlCopyMemory(output->FileId, &entry->FileId, sizeof(entry->FileId));
            output->Generation = entry->ActivationGeneration;
            output->State = (UINT32)InterlockedCompareExchange((volatile LONG *)&entry->State, 0, 0);
            output->H = (UINT32)max(0, InterlockedCompareExchange(&entry->H, 0, 0));
            output->T = (UINT32)max(0, InterlockedCompareExchange(&entry->T, 0, 0));
            output->S = (UINT32)InterlockedCompareExchange(&entry->LastSState, 0, 0);
            output->Reserved0 = 0;
            output->UnknownReasons = (ULONG)InterlockedCompareExchange(&entry->UnknownReasons, 0, 0);
            output->ReservedFlags = 0;
            output->NameChars = min((UINT32)entry->NameChars, (UINT32)SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS);
            if (output->NameChars != 0)
                RtlCopyMemory(output->Name, entry->Name, output->NameChars * sizeof(WCHAR));
            StageRegistryCopyOpeners(entry, openerPids,
                RTL_NUMBER_OF(openerPids), &openerCount);
            for (index = 0; index < openerCount; ++index)
                output->OpenerPids[pidCount++] = openerPids[index];
            sectionCount = StageRegistrySnapshotC(entry, sectionPids,
                RTL_NUMBER_OF(sectionPids), &sectionPidCount);
            output->C = sectionCount;
            for (pidIndex = 0; pidIndex < sectionPidCount; ++pidIndex) {
                ULONG existing;
                for (existing = 0; existing < pidCount; ++existing)
                    if (output->OpenerPids[existing] == sectionPids[pidIndex]) break;
                if (existing == pidCount && pidCount < RTL_NUMBER_OF(output->OpenerPids))
                    output->OpenerPids[pidCount++] = sectionPids[pidIndex];
            }
            output->OpenerPidCount = pidCount;
        }
    }
    FltReleasePushLock(&RegistryLock);
    Page->TotalEntries = total;
    Page->EntryCount = count;
    Page->NextIndex = StartIndex + count;
    if (Page->NextIndex >= total) Page->NextIndex = total;
    endSequence = (UINT64)InterlockedCompareExchange64(&RegistryChangeSequence, 0, 0);
    if (startSequence != endSequence) return STATUS_RETRY;
    Page->ChangeSequence = endSequence;
    return STATUS_SUCCESS;
}

/* The pageable control dispatcher calls this status snapshot; keep SectionLock resident. */
__declspec(noinline) VOID SafeUploadStageWritersGetStatus(_Out_ PSAFEUPLOAD_WRITER_STATE_STATUS Status)
{
    SAFEUPLOAD_WRITER_STATE_STATUS snapshot = {0};
    LONGLONG now = (LONGLONG)KeQueryInterruptTime();
    ULONG index;
    KIRQL irql;

    snapshot.StructSize = sizeof(snapshot);
    snapshot.PostCreateRuns = (UINT64)InterlockedCompareExchange64(&WriterPostCreateRuns, 0, 0);
    snapshot.WriteObjectsCounted = (UINT64)InterlockedCompareExchange64(&WriterCounted, 0, 0);
    snapshot.WriteObjectsReleased = (UINT64)InterlockedCompareExchange64(&WriterReleased, 0, 0);
    snapshot.UntrackedCreates = (UINT64)InterlockedCompareExchange64(&WriterUntrackedCreates, 0, 0);
    snapshot.CleanupUnmatched = (UINT64)InterlockedCompareExchange64(&WriterCleanupUnmatched, 0, 0);
    snapshot.DirectoryCreatesSkipped = (UINT64)InterlockedCompareExchange64(&WriterDirectoryCreatesSkipped, 0, 0);
    snapshot.PagingCreatesSkipped = (UINT64)InterlockedCompareExchange64(&WriterPagingCreatesSkipped, 0, 0);
    snapshot.VolumeCreatesSkipped = (UINT64)InterlockedCompareExchange64(&WriterVolumeCreatesSkipped, 0, 0);
    snapshot.WritersDroppedAtTeardown = (UINT64)InterlockedCompareExchange64(&WriterDroppedAtTeardown, 0, 0);
    snapshot.WritersDroppedWhileMounted = (UINT64)InterlockedCompareExchange64(&WriterDroppedWhileMounted, 0, 0);
    snapshot.InstanceTeardownsDismount = (UINT64)InterlockedCompareExchange64(&InstanceTeardownsDismount, 0, 0);
    snapshot.InstanceTeardownsOther = (UINT64)InterlockedCompareExchange64(&InstanceTeardownsOther, 0, 0);
    snapshot.TxfRefused = (UINT64)InterlockedCompareExchange64(&TxfRefused, 0, 0);
    snapshot.RegistryCapacityFailures = (UINT64)InterlockedCompareExchange64(&RegistryCapacityFailures, 0, 0);
    snapshot.RegistryAllocationFailures = (UINT64)InterlockedCompareExchange64(&RegistryAllocationFailures, 0, 0);
    snapshot.RegistryIdentityFailures = (UINT64)InterlockedCompareExchange64(&RegistryIdentityFailures, 0, 0);
    snapshot.RegistryTransactionFailures = (UINT64)InterlockedCompareExchange64(&RegistryTransactionFailures, 0, 0);
    snapshot.RegistryRenameFailures = (UINT64)InterlockedCompareExchange64(&RegistryRenameFailures, 0, 0);
    snapshot.RegistryDroppedAtDismount = (UINT64)InterlockedCompareExchange64(&RegistryDroppedAtDismount, 0, 0);
    snapshot.RegistryDroppedWhileMounted = (UINT64)InterlockedCompareExchange64(&RegistryDroppedWhileMounted, 0, 0);
    snapshot.RegistryPruned = (UINT64)InterlockedCompareExchange64(&RegistryPruned, 0, 0);
    snapshot.RegistryReclaimPasses = (UINT64)InterlockedCompareExchange64(&RegistryReclaimPasses, 0, 0);
    FltAcquirePushLockShared(&RegistryLock);
    snapshot.RegistryEntries = RegistryEntryCount + RegistryCompactEntryCount;
    snapshot.RegistryNameTierEntries = RegistryEntryCount;
    snapshot.RegistryCompactTierEntries = RegistryCompactEntryCount;
    snapshot.RegistryReservations = RegistryReservationCount;
    snapshot.RegistryOverflow = RegistryOverflow;
    snapshot.RegistryUnknownReasons = RegistryUnknownReasons;
    snapshot.RegistryInstanceUnknown = RegistryInstanceUnknown;
    snapshot.RegistryCapacity = StageRegistryCapacityLocked();
    snapshot.TransactionAssociations = RegistryAssociationCount;
    FltReleasePushLock(&RegistryLock);
    SafeUploadStageGetUnloadStatus(&snapshot.StageStreams, &snapshot.StageFileObjects,
        &snapshot.LastUnloadVeto, &snapshot.LastUnloadStatus);
    StageAcquireSpinLock(&SectionLock, &irql);
    snapshot.SectionInFlightNow = SectionNow;
    snapshot.SectionInFlightMaxDepth = SectionMaxDepth;
    snapshot.SectionInFlightInserted = SectionInserted;
    snapshot.SectionInFlightReleased = SectionReleased;
    snapshot.SectionInFlightOverflow = SectionOverflow;
    snapshot.SectionInFlightRemovedOnFailure = SectionRemovedOnFailure;
    for (index = 0; index < STAGE_SECTION_SLOTS; index += 1) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject != NULL && now - slot->Time > STAGE_SECTION_STUCK_100NS) {
            snapshot.SectionInFlightStuck += 1;
        }
    }
    StageReleaseSpinLock(&SectionLock, irql);
    /* The caller's output may be pageable; write it only after lowering IRQL. */
    RtlCopyMemory(Status, &snapshot, sizeof(snapshot));
}

static VOID StageRegistryAssociationReference(_In_ PSTAGE_TX_ASSOCIATION Association)
{
    InterlockedIncrement(&Association->References);
}

static VOID StageRegistryAssociationDereference(_In_opt_ PSTAGE_TX_ASSOCIATION Association)
{
    if (Association != NULL && InterlockedDecrement(&Association->References) == 0) {
        StageRegistryDereference(Association->Entry);
        if (Association->Transaction != NULL) ObDereferenceObject(Association->Transaction);
        ExFreePoolWithTag(Association, SAFEUPLOAD_TX_ASSOC_POOL_TAG);
    }
}

static NTSTATUS StageRegistryGetTransactionContext(_In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction,
    _Outptr_ PFLT_CONTEXT *TransactionContext)
{
    PSAFEUPLOAD_TRANSACTION_CONTEXT context = NULL;
    PFLT_CONTEXT oldContext = NULL;
    NTSTATUS status;

    *TransactionContext = NULL;
    status = FltGetTransactionContext(Instance, Transaction,
        (PFLT_CONTEXT *)&context);
    if (NT_SUCCESS(status)) {
        *TransactionContext = (PFLT_CONTEXT)context;
        return STATUS_SUCCESS;
    }
    if (status != STATUS_NOT_FOUND) return status;

    status = FltAllocateContext(SafeUploadData.Filter, FLT_TRANSACTION_CONTEXT,
        sizeof(*context), NonPagedPoolNx, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(context, sizeof(*context));
    context->Signature = SAFEUPLOAD_TRANSACTION_CONTEXT_SIGNATURE;
    status = FltSetTransactionContext(Instance, Transaction,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS, (PFLT_CONTEXT)context, &oldContext);
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED && oldContext != NULL) {
        FltReleaseContext((PFLT_CONTEXT)context);
        *TransactionContext = oldContext;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        FltReleaseContext((PFLT_CONTEXT)context);
        if (oldContext != NULL) FltReleaseContext(oldContext);
        return status;
    }
    if (oldContext != NULL) FltReleaseContext(oldContext);
    *TransactionContext = (PFLT_CONTEXT)context;
    return STATUS_SUCCESS;
}

static NTSTATUS StageRegistryWaitForAssociation(_In_ PSTAGE_TX_ASSOCIATION Association)
{
    LONG state = InterlockedCompareExchange(&Association->State, 0, 0);
    if (state == SAFEUPLOAD_TX_ASSOC_PENDING) {
        /* A nonalertable kernel wait with no timeout returns only when the event is signaled. */
        (void)KeWaitForSingleObject(&Association->StateChanged, Executive, KernelMode, FALSE, NULL);
        state = InterlockedCompareExchange(&Association->State, 0, 0);
    }
    return state == SAFEUPLOAD_TX_ASSOC_FAILED ? Association->CompletionStatus : STATUS_SUCCESS;
}

static NTSTATUS StageRegistryEnlistTransaction(_In_ PFLT_INSTANCE Instance,
    _In_ PKTRANSACTION Transaction, _In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    PSTAGE_TX_ASSOCIATION association;
    PSTAGE_TX_ASSOCIATION candidate = ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(*candidate), SAFEUPLOAD_TX_ASSOC_POOL_TAG);
    PSTAGE_TX_ASSOCIATION waitFor = NULL;
    PLIST_ENTRY link;
    BOOLEAN alreadyEnlisted;
    BOOLEAN enlistSucceeded;
    BOOLEAN dropTableReference = FALSE;
    PFLT_CONTEXT transactionContext = NULL;
    NTSTATUS status;

Retry:
    waitFor = NULL;
    alreadyEnlisted = FALSE;
    FltAcquirePushLockExclusive(&RegistryLock);
    for (link = TransactionAssociations.Flink; link != &TransactionAssociations; link = link->Flink) {
        PSTAGE_TX_ASSOCIATION current = CONTAINING_RECORD(link, STAGE_TX_ASSOCIATION, Link);
        if (current->Transaction != Transaction) continue;
        if (current->Entry == Entry) {
            StageRegistryAssociationReference(current);
            FltReleasePushLock(&RegistryLock);
            if (candidate != NULL) ExFreePoolWithTag(candidate, SAFEUPLOAD_TX_ASSOC_POOL_TAG);
            status = StageRegistryWaitForAssociation(current);
            StageRegistryAssociationDereference(current);
            return status;
        }
        /* Filter Manager enlistment is per instance. A transaction touching a
         * second mounted volume needs its own enlistment callback there. */
        if (current->Instance != Instance) continue;
        if (InterlockedCompareExchange(&current->State, 0, 0) == SAFEUPLOAD_TX_ASSOC_PENDING) {
            waitFor = current;
            StageRegistryAssociationReference(waitFor);
            break;
        }
        if (InterlockedCompareExchange(&current->State, 0, 0) == SAFEUPLOAD_TX_ASSOC_ENLISTED)
            alreadyEnlisted = TRUE;
    }
    if (waitFor != NULL) {
        FltReleasePushLock(&RegistryLock);
        status = StageRegistryWaitForAssociation(waitFor);
        StageRegistryAssociationDereference(waitFor);
        if (!NT_SUCCESS(status)) {
            if (candidate != NULL) ExFreePoolWithTag(candidate, SAFEUPLOAD_TX_ASSOC_POOL_TAG);
            return status;
        }
        goto Retry;
    }
    if (RegistryAssociationCount >= SAFEUPLOAD_REGISTRY_MAX_TX_ASSOCIATIONS || candidate == NULL) {
        FltReleasePushLock(&RegistryLock);
        if (candidate != NULL) ExFreePoolWithTag(candidate, SAFEUPLOAD_TX_ASSOC_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    association = candidate;
    candidate = NULL;
    RtlZeroMemory(association, sizeof(*association));
    association->References = 2; /* table ownership and this enlistment call */
    association->State = alreadyEnlisted ? SAFEUPLOAD_TX_ASSOC_ENLISTED : SAFEUPLOAD_TX_ASSOC_PENDING;
    association->CompletionStatus = STATUS_SUCCESS;
    association->Transaction = Transaction;
    ObReferenceObject(Transaction);
    association->Instance = Instance;
    association->Entry = Entry;
    association->Listed = TRUE;
    KeInitializeEvent(&association->StateChanged, NotificationEvent, alreadyEnlisted);
    StageRegistryReference(Entry);
    InterlockedIncrement(&Entry->T);
    InterlockedIncrement64(&RegistryChangeSequence);
    InsertTailList(&TransactionAssociations, &association->Link);
    RegistryAssociationCount += 1;
    FltReleasePushLock(&RegistryLock);

    if (alreadyEnlisted) {
        StageRegistryAssociationDereference(association);
        return STATUS_SUCCESS;
    }

    status = StageRegistryGetTransactionContext(Instance, Transaction, &transactionContext);
    if (NT_SUCCESS(status)) {
        status = FltEnlistInTransaction(Instance, Transaction, transactionContext,
            TRANSACTION_NOTIFY_COMMIT_FINALIZE | TRANSACTION_NOTIFY_ROLLBACK);
        FltReleaseContext(transactionContext);
        transactionContext = NULL;
    }
    /* Examine the enlistment result even when a terminal callback supersedes it below. */
    if (NT_SUCCESS(status)) {
        enlistSucceeded = TRUE;
    } else {
        enlistSucceeded = FALSE;
    }
    FltAcquirePushLockExclusive(&RegistryLock);
    if (InterlockedCompareExchange(&association->State, 0, 0) == SAFEUPLOAD_TX_ASSOC_TERMINAL) {
        status = STATUS_SUCCESS; /* The terminal callback retired T while enlistment completed. */
    } else if (enlistSucceeded) {
        InterlockedExchange(&association->State, SAFEUPLOAD_TX_ASSOC_ENLISTED);
        association->CompletionStatus = STATUS_SUCCESS;
        KeSetEvent(&association->StateChanged, IO_NO_INCREMENT, FALSE);
    } else {
        if (association->Listed) {
            RemoveEntryList(&association->Link);
            association->Listed = FALSE;
            if (RegistryAssociationCount != 0) RegistryAssociationCount -= 1;
            InterlockedDecrement(&Entry->T);
            InterlockedIncrement64(&RegistryChangeSequence);
            dropTableReference = TRUE;
        }
        association->CompletionStatus = status;
        InterlockedExchange(&association->State, SAFEUPLOAD_TX_ASSOC_FAILED);
        KeSetEvent(&association->StateChanged, IO_NO_INCREMENT, FALSE);
    }
    FltReleasePushLock(&RegistryLock);

    if (dropTableReference) StageRegistryAssociationDereference(association);
    if (!NT_SUCCESS(status)) {
        StageRegistryMarkEntryUnknown(Entry, SAFEUPLOAD_REGISTRY_UNKNOWN_TRANSACTION);
    }
    StageRegistryAssociationDereference(association);
    return status;
}

NTSTATUS SafeUploadStageTransactionNotification(_In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_CONTEXT TransactionContext, _In_ ULONG NotificationMask)
{
    LIST_ENTRY retired;
    PLIST_ENTRY link;
    BOOLEAN recheck = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(TransactionContext);
    if ((NotificationMask & (TRANSACTION_NOTIFY_COMMIT_FINALIZE | TRANSACTION_NOTIFY_ROLLBACK)) == 0)
        return STATUS_SUCCESS;

    InitializeListHead(&retired);
    FltAcquirePushLockExclusive(&RegistryLock);
    link = TransactionAssociations.Flink;
    while (link != &TransactionAssociations) {
        PLIST_ENTRY next = link->Flink;
        PSTAGE_TX_ASSOCIATION association = CONTAINING_RECORD(link, STAGE_TX_ASSOCIATION, Link);
        if (association->Transaction == FltObjects->Transaction) {
            RemoveEntryList(&association->Link);
            association->Listed = FALSE;
            InsertTailList(&retired, &association->Link);
            if (RegistryAssociationCount != 0) RegistryAssociationCount -= 1;
            InterlockedDecrement(&association->Entry->T);
            InterlockedIncrement64(&RegistryChangeSequence);
            if (InterlockedCompareExchange(&association->Entry->T, 0, 0) == 0 &&
                InterlockedCompareExchange((volatile LONG *)&association->Entry->State, 0, 0) ==
                    SAFEUPLOAD_REGISTRY_STATE_ACTIVATING) recheck = TRUE;
            association->CompletionStatus = STATUS_SUCCESS;
            InterlockedExchange(&association->State, SAFEUPLOAD_TX_ASSOC_TERMINAL);
            KeSetEvent(&association->StateChanged, IO_NO_INCREMENT, FALSE);
        }
        link = next;
    }
    FltReleasePushLock(&RegistryLock);

    if (recheck) (VOID)StageRegistryQueueReclaim();

    while (!IsListEmpty(&retired)) {
        PSTAGE_TX_ASSOCIATION association = CONTAINING_RECORD(RemoveHeadList(&retired),
            STAGE_TX_ASSOCIATION, Link);
        StageRegistryAssociationDereference(association); /* Drop the table reference. */
    }
    return status;
}

VOID SafeUploadStageWritersSetCapacity(_In_ UINT32 Capacity)
{
    if (Capacity > SAFEUPLOAD_WRITER_REGISTRY_TOTAL_LIMIT) return;
    FltAcquirePushLockExclusive(&RegistryLock);
    RegistryCapacityOverride = Capacity;
    FltReleasePushLock(&RegistryLock);
}

VOID SafeUploadStageWritersRecordTxfRefused(VOID)
{
    InterlockedIncrement64(&TxfRefused);
}

static VOID StageRegistryAppendPid(_Inout_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Result,
    _In_ ULONG ProcessId)
{
    ULONG index;
    if (ProcessId == 0) return;
    for (index = 0; index < Result->OpenerPidCount; ++index) {
        if (Result->OpenerPids[index] == ProcessId) return;
    }
    if (Result->OpenerPidCount < RTL_NUMBER_OF(Result->OpenerPids))
        Result->OpenerPids[Result->OpenerPidCount++] = ProcessId;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static UINT32 StageRegistrySnapshotSpilledMutatingIo(
    _In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    PSTAGE_REGISTRY_SOP_SLOT map;
    BOOLEAN found = FALSE;
    UINT32 count = 0;
    KIRQL irql;
    PVOID sop = InterlockedCompareExchangePointer(
        (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL);
    StageAcquireSpinLock(&SectionLock, &irql);
    map = StageRegistryFindSopSlotLocked(sop, &found);
    if (found && map != NULL && map->Entry == Entry) count = map->SpilledMutatingIoCount;
    StageReleaseSpinLock(&SectionLock, irql);
    return count;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static UINT32 StageRegistrySnapshotSpilledWriters(
    _In_ PSTAGE_REGISTRY_ENTRY Entry)
{
    PSTAGE_REGISTRY_SOP_SLOT map;
    BOOLEAN found = FALSE;
    UINT32 count = 0;
    KIRQL irql;
    PVOID sop = InterlockedCompareExchangePointer(
        (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL);
    StageAcquireSpinLock(&SectionLock, &irql);
    map = StageRegistryFindSopSlotLocked(sop, &found);
    if (found && map != NULL && map->Entry == Entry) count = map->UnknownWriterCount;
    StageReleaseSpinLock(&SectionLock, irql);
    return count;
}

/* PID outputs are resident caller scratch; callers merge them into pageable replies after release. */
_IRQL_requires_max_(DISPATCH_LEVEL)
__declspec(noinline) static UINT32 StageRegistrySnapshotC(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _Out_writes_opt_(Capacity) PUINT32 ProcessIds, _In_ ULONG Capacity,
    _Out_opt_ PUINT32 ProcessIdCount)
{
    PSTAGE_REGISTRY_SOP_SLOT map;
    ULONG index;
    UINT32 count = 0;
    UINT32 spilledWritable = 0;
    BOOLEAN mapFound = FALSE;
    KIRQL irql;
    if (ProcessIdCount != NULL) *ProcessIdCount = 0;
    StageAcquireSpinLock(&SectionLock, &irql);
    for (index = 0; index < STAGE_SECTION_SLOTS; ++index) {
        STAGE_SECTION_SLOT *slot = &SectionSlots[index];
        if (slot->FileObject != NULL && slot->Writable && slot->RegistryEntry == Entry) {
            count += 1;
            if (ProcessIds != NULL && ProcessIdCount != NULL && slot->ProcessId != 0) {
                ULONG existing;
                for (existing = 0; existing < *ProcessIdCount; ++existing) {
                    if (ProcessIds[existing] == slot->ProcessId) break;
                }
                if (existing == *ProcessIdCount && *ProcessIdCount < Capacity)
                    ProcessIds[(*ProcessIdCount)++] = slot->ProcessId;
            }
        }
    }
    {
        PLIST_ENTRY link;
        PVOID sop = InterlockedCompareExchangePointer(
            (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL);
        for (link = SectionSpills.Flink; link != &SectionSpills; link = link->Flink) {
            PSTAGE_SECTION_SPILL_RECORD spill = CONTAINING_RECORD(link,
                STAGE_SECTION_SPILL_RECORD, Link);
            if (spill->Signature == STAGE_SECTION_SPILL_SIGNATURE &&
                spill->Writable && spill->SectionObjectPointer == sop) {
                if (spilledWritable == MAXULONG) {
                    count = SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
                    break;
                }
                spilledWritable += 1;
            }
        }
    }
    map = StageRegistryFindSopSlotLocked(InterlockedCompareExchangePointer(
        (PVOID volatile *)&Entry->SectionObjectPointer, NULL, NULL), &mapFound);
    if (mapFound && map != NULL && map->Entry == Entry) {
        if (spilledWritable < map->SpilledSectionCount)
            spilledWritable = map->SpilledSectionCount;
        if (MAXULONG - count < spilledWritable)
            count = SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
        else
            count += spilledWritable;
    } else if (spilledWritable != 0 && count != SAFEUPLOAD_SECTIONS_UNTRACKED_BIT) {
        if (MAXULONG - count < spilledWritable)
            count = SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
        else
            count += spilledWritable;
    }
    StageReleaseSpinLock(&SectionLock, irql);
    return count;
}

/* Snapshot an Activating or transacted entry without opening the file or consulting the cache
 * manager. Evaluate is diagnostic; it must not wait behind an active TxF
 * transaction merely to report the already tracked H/S/C/T state. Caller owns Entry. */
static BOOLEAN StageRegistrySnapshotPendingEntry(_In_ PSTAGE_REGISTRY_ENTRY Entry,
    _In_ PFLT_INSTANCE Instance, _In_ PFLT_VOLUME Volume,
    _In_ PCUNICODE_STRING Name, _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Result)
{
    UINT32 openerPids[8], sectionPids[8], openerPidCount = 0, sectionPidCount = 0;
    UINT32 sectionCount, pidIndex;
    ULONG unknown;
    LONG h, t, renameVersion, renameInFlight;
    UINT32 state;
    BOOLEAN directoryRenameInFlight, reservationInFlight, unknownInstance = FALSE, trusted;
    UNICODE_STRING entryName, baseName = StageRegistryBaseName(Name);
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;

    FltAcquirePushLockExclusive(&RegistryLock);
    state = (UINT32)InterlockedCompareExchange((volatile LONG *)&Entry->State, 0, 0);
    t = InterlockedCompareExchange(&Entry->T, 0, 0);
    if (!Entry->Listed || Entry->Retired || Entry->Instance != Instance || Entry->Volume != Volume ||
        (state != SAFEUPLOAD_REGISTRY_STATE_ACTIVATING && t == 0)) {
        FltReleasePushLock(&RegistryLock);
        return FALSE;
    }

    RtlZeroMemory(Result, sizeof(*Result));
    Result->StructSize = sizeof(*Result);
    Result->HistoryPresent = 1;
    Result->FirstSeenGeneration = Entry->FirstSeenGeneration;
    Result->VolumeSerialNumber = Entry->VolumeSerial;
    RtlCopyMemory(Result->FileId, &Entry->FileId, sizeof(Entry->FileId));
    h = InterlockedCompareExchange(&Entry->H, 0, 0);
    t = InterlockedCompareExchange(&Entry->T, 0, 0);
    Result->H = (UINT32)max(0, h);
    Result->T = (UINT32)max(0, t);
    Result->S = (UINT32)InterlockedCompareExchange(&Entry->LastSState, 0, 0);
    unknown = (ULONG)InterlockedCompareExchange(&Entry->UnknownReasons, 0, 0);
    renameVersion = InterlockedCompareExchange(&Entry->RenameVersion, 0, 0);
    renameInFlight = InterlockedCompareExchange(&Entry->RenameInFlight, 0, 0);
    entryName.Buffer = Entry->Name;
    entryName.Length = entryName.MaximumLength = (USHORT)(Entry->NameChars * sizeof(WCHAR));
    Result->NameMatches = (Entry->NameChars != 0 &&
        RtlEqualUnicodeString(&entryName, &baseName, TRUE)) ? 1 : 0;
    directoryRenameInFlight = StageRegistryDirectoryRenameInFlightLocked(Instance, &entryName);
    reservationInFlight = StageRegistryHasCreateReservationLocked(Instance, Volume, Name);
    if (renameInFlight != 0 || renameVersion !=
        InterlockedCompareExchange(&Entry->RenameVersion, 0, 0) || directoryRenameInFlight)
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME_IN_FLIGHT;
    if (!Result->NameMatches) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME;
    if (reservationInFlight) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CREATE_IN_FLIGHT;
    StageRegistryCopyOpeners(Entry, openerPids, RTL_NUMBER_OF(openerPids), &openerPidCount);
    for (pidIndex = 0; pidIndex < openerPidCount; ++pidIndex)
        StageRegistryAppendPid(Result, openerPids[pidIndex]);
    sectionCount = StageRegistrySnapshotC(Entry, sectionPids,
        RTL_NUMBER_OF(sectionPids), &sectionPidCount);
    Result->C = sectionCount & ~SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
    for (pidIndex = 0; pidIndex < sectionPidCount; ++pidIndex)
        StageRegistryAppendPid(Result, sectionPids[pidIndex]);
    if ((sectionCount & SAFEUPLOAD_SECTIONS_UNTRACKED_BIT) != 0)
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY;
    FltReleasePushLock(&RegistryLock);

    if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext))) {
        unknownInstance = InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0 ||
            InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0;
        FltReleaseContext(instanceContext);
    } else {
        unknownInstance = TRUE;
    }
    trusted = SafeUploadInstanceIsTrusted(Instance);
    if (unknownInstance || SafeUploadStageWritersGlobalUnknown())
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
    if (!trusted) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_TRUST;

    Result->UnknownReasons = unknown;
    Result->State = unknown != 0 || state != SAFEUPLOAD_REGISTRY_STATE_ACTIVATING ?
        SAFEUPLOAD_REGISTRY_STATE_UNKNOWN : SAFEUPLOAD_REGISTRY_STATE_ACTIVATING;
    Result->Free = (Result->H == 0 && Result->S == SAFEUPLOAD_REGISTRY_S_NO &&
        Result->C == 0 && Result->T == 0 && unknown == 0) ? 1 : 0;
    return TRUE;
}

BOOLEAN SafeUploadStageWritersRegistrySnapshotByName(_In_ PFLT_INSTANCE Instance,
    _In_ PFLT_VOLUME Volume, _In_ PCUNICODE_STRING Name,
    _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Result)
{
    PLIST_ENTRY link;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    UNICODE_STRING baseName;
    BOOLEAN evaluated;
    PAGED_CODE();
    RtlZeroMemory(Result, sizeof(*Result));
    Result->StructSize = sizeof(*Result);
    if (Instance == NULL || Volume == NULL || Name == NULL || Name->Buffer == NULL ||
        Name->Length == 0 || (Name->Length & 1) != 0) return FALSE;

    baseName = StageRegistryBaseName(Name);
    FltAcquirePushLockExclusive(&RegistryLock);
    for (link = RegistryEntries.Flink; link != &RegistryEntries; link = link->Flink) {
        PSTAGE_REGISTRY_ENTRY candidate = CONTAINING_RECORD(link, STAGE_REGISTRY_ENTRY, Link);
        UNICODE_STRING candidateName;
        UINT32 candidateState = (UINT32)InterlockedCompareExchange(
            (volatile LONG *)&candidate->State, 0, 0);
        LONG candidateT = InterlockedCompareExchange(&candidate->T, 0, 0);
        if (candidate->Retired || candidate->Instance != Instance || candidate->Volume != Volume ||
            (candidateState != SAFEUPLOAD_REGISTRY_STATE_ACTIVATING && candidateT == 0) ||
            candidate->NameChars == 0 ||
            candidate->NameChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS ||
            candidate->NameChars * sizeof(WCHAR) != Name->Length) continue;
        candidateName.Buffer = candidate->Name;
        candidateName.Length = candidateName.MaximumLength = (USHORT)(candidate->NameChars * sizeof(WCHAR));
        if (RtlEqualUnicodeString(&candidateName, &baseName, TRUE)) {
            entry = candidate;
            StageRegistryReference(entry);
            break;
        }
    }
    FltReleasePushLock(&RegistryLock);
    if (entry == NULL) return FALSE;

    evaluated = StageRegistrySnapshotPendingEntry(entry, Instance, Volume, Name, Result);
    StageRegistryDereference(entry);
    return evaluated;
}

NTSTATUS SafeUploadStageWritersRegistryEvaluate(_In_ PFLT_INSTANCE Instance,
    _In_ PCUNICODE_STRING VolumeName, _In_ PCUNICODE_STRING NormalizedName,
    _In_ PFILE_OBJECT SourceObject, _Out_ PSAFEUPLOAD_REGISTRY_ENTRY_STATUS Result)
{
    FILE_ID_INFORMATION identity;
    PSTAGE_REGISTRY_ENTRY entry = NULL;
    PFLT_VOLUME volume = NULL;
    PSAFEUPLOAD_INSTANCE_CONTEXT instanceContext = NULL;
    PFILE_OBJECT identityObject = NULL;
    HANDLE identityHandle = NULL;
    PVOID sectionObjectPointer = NULL;
    PWCHAR retainedName = NULL;
    ULONG returned = 0, pidIndex;
    UINT32 openerPids[8], sectionPids[8], openerPidCount = 0, sectionPidCount = 0;
    UINT32 probeStage = SAFEUPLOAD_ADMISSION_PROBE_STAGE_IDENTITY_QUERY;
    ULONG unknown = 0, nameChars = 0;
    UINT32 cCount = 0;
    UINT32 state;
    BOOLEAN protectedPath, unknownInstance = FALSE, globalUnknown;
    BOOLEAN directoryRenameInFlight;
    BOOLEAN trusted, reservationInFlight, entryRetired;
    LONG renameVersion, renameInFlight;
    NTSTATUS status;

    PAGED_CODE();
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    RtlZeroMemory(Result, sizeof(*Result));
    Result->StructSize = sizeof(*Result);

    /* Resolve the instance volume without touching the file, then answer a
     * tracked pending entry by name before any file-system query can wait on
     * an active transaction. */
    status = FltGetVolumeFromInstance(Instance, &volume);
    if (!NT_SUCCESS(status)) return status;
    if (SafeUploadStageWritersRegistrySnapshotByName(Instance, volume, NormalizedName, Result)) {
        FltObjectDereference(volume);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&identity, sizeof(identity));
    status = FltQueryInformationFile(Instance, SourceObject, &identity, sizeof(identity),
        FileIdInformation, &returned);
    if (status != STATUS_SUCCESS || returned != sizeof(identity)) {
        FltObjectDereference(volume);
        return STATUS_FILE_INVALID;
    }

    FltAcquirePushLockExclusive(&RegistryLock);
    entry = StageRegistryFindByKeyLocked(Instance, volume, identity.VolumeSerialNumber,
        &identity.FileId, SourceObject->SectionObjectPointer);
    if (entry != NULL) StageRegistryReference(entry);
    reservationInFlight = StageRegistryHasCreateReservationLocked(Instance, volume, NormalizedName);
    FltReleasePushLock(&RegistryLock);

    RtlCopyMemory(Result->FileId, &identity.FileId, sizeof(identity.FileId));
    Result->VolumeSerialNumber = identity.VolumeSerialNumber;
    if (entry == NULL) {
        status = FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext);
        if (NT_SUCCESS(status)) {
            protectedPath = SafeUploadStageProtectedPath((PUNICODE_STRING)NormalizedName,
                VolumeName->Length, instanceContext->VolumeKind) ||
                SafeUploadPolicyMatchesCurrentOrPendingDestination(instanceContext->VolumeKind,
                    NormalizedName, FALSE);
            unknownInstance = InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0 ||
                InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0;
            FltReleaseContext(instanceContext);
            instanceContext = NULL;
        } else {
            protectedPath = TRUE;
            unknownInstance = TRUE;
        }
        trusted = SafeUploadInstanceIsTrusted(Instance);
        /* Serialize the missing-history conclusion with any new reservation
         * or post-create bind that raced the name/volume checks above. */
        FltAcquirePushLockExclusive(&RegistryLock);
        entry = StageRegistryFindByKeyLocked(Instance, volume,
            identity.VolumeSerialNumber, &identity.FileId, SourceObject->SectionObjectPointer);
        if (entry != NULL) StageRegistryReference(entry);
        reservationInFlight = StageRegistryHasCreateReservationLocked(Instance, volume, NormalizedName);
        directoryRenameInFlight = StageRegistryDirectoryRenameInFlightLocked(Instance, NormalizedName);
        globalUnknown = SafeUploadStageWritersGlobalUnknown() != 0;
        FltReleasePushLock(&RegistryLock);
        if (entry == NULL) {
            Result->HistoryPresent = 0;
            Result->NameMatches = 1;
            unknown = 0;
            if (unknownInstance || globalUnknown) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
            if (!trusted) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_TRUST;
            if (reservationInFlight) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CREATE_IN_FLIGHT;
            if (directoryRenameInFlight) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME_IN_FLIGHT;
            Result->Free = unknown == 0 ? 1 : 0;
            Result->S = SAFEUPLOAD_REGISTRY_S_NO;
            Result->State = unknown != 0 ?
                SAFEUPLOAD_REGISTRY_STATE_UNKNOWN :
                (protectedPath ? SAFEUPLOAD_REGISTRY_STATE_PROTECTED : SAFEUPLOAD_REGISTRY_STATE_UNSCOPED);
            Result->UnknownReasons = unknown;
            FltObjectDereference(volume);
            return STATUS_SUCCESS;
        }
    }

    /* Use the resident registry snapshot for Activating entries. An identity
     * open below can wait on a still-open TxF transaction, so a diagnostic read
     * should return the counters without joining that operation. */
    if (StageRegistrySnapshotPendingEntry(entry, Instance, volume, NormalizedName, Result)) {
        StageRegistryDereference(entry);
        FltObjectDereference(volume);
        return STATUS_SUCCESS;
    }

    retainedName = ExAllocatePool2(POOL_FLAG_PAGED,
        SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS * sizeof(WCHAR), SAFEUPLOAD_REGISTRY_POOL_TAG);
    FltAcquirePushLockExclusive(&RegistryLock);
    Result->HistoryPresent = 1;
    Result->FirstSeenGeneration = entry->FirstSeenGeneration;
    Result->H = (UINT32)max(0, InterlockedCompareExchange(&entry->H, 0, 0));
    Result->T = (UINT32)max(0, InterlockedCompareExchange(&entry->T, 0, 0));
    sectionObjectPointer = InterlockedCompareExchangePointer(
        (PVOID volatile *)&entry->SectionObjectPointer, NULL, NULL);
    unknown = (ULONG)InterlockedCompareExchange(&entry->UnknownReasons, 0, 0);
    renameVersion = InterlockedCompareExchange(&entry->RenameVersion, 0, 0);
    renameInFlight = InterlockedCompareExchange(&entry->RenameInFlight, 0, 0);
    {
        UNICODE_STRING entryName;
        entryName.Buffer = entry->Name;
        entryName.Length = entryName.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
        directoryRenameInFlight = StageRegistryDirectoryRenameInFlightLocked(Instance, &entryName);
    }
    if (renameInFlight != 0 || renameVersion !=
        InterlockedCompareExchange(&entry->RenameVersion, 0, 0) || directoryRenameInFlight)
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME_IN_FLIGHT;
    nameChars = entry->NameChars;
    if (retainedName == NULL || nameChars == 0 ||
        nameChars > SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION;
    } else {
        RtlCopyMemory(retainedName, entry->Name, nameChars * sizeof(WCHAR));
        {
            UNICODE_STRING retained;
            retained.Buffer = retainedName;
            retained.Length = retained.MaximumLength = (USHORT)(nameChars * sizeof(WCHAR));
            {
                UNICODE_STRING baseName = StageRegistryBaseName(NormalizedName);
                Result->NameMatches = RtlEqualUnicodeString(&retained, &baseName, TRUE) ? 1 : 0;
            }
            if (!Result->NameMatches) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME;
        }
    }
    StageRegistryCopyOpeners(entry, openerPids,
        RTL_NUMBER_OF(openerPids), &openerPidCount);
    FltReleasePushLock(&RegistryLock);
    RtlCopyMemory(Result->OpenerPids, openerPids, openerPidCount * sizeof(openerPids[0]));
    Result->OpenerPidCount = openerPidCount;

    protectedPath = FALSE;
    if (retainedName != NULL && nameChars != 0 &&
        nameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
        UNICODE_STRING currentName;
        currentName.Buffer = retainedName;
        currentName.Length = currentName.MaximumLength = (USHORT)(nameChars * sizeof(WCHAR));
        if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext))) {
            protectedPath = SafeUploadStageProtectedPath(&currentName, VolumeName->Length,
                instanceContext->VolumeKind) ||
                SafeUploadPolicyMatchesCurrentOrPendingDestination(instanceContext->VolumeKind,
                    &currentName, FALSE);
            unknownInstance = InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0 ||
                InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0;
            FltReleaseContext(instanceContext);
            instanceContext = NULL;
        } else unknownInstance = TRUE;
    } else unknownInstance = TRUE;
    trusted = SafeUploadInstanceIsTrusted(Instance);
    if (unknownInstance || SafeUploadStageWritersGlobalUnknown()) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
    if (!trusted) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_TRUST;
    if (reservationInFlight) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CREATE_IN_FLIGHT;
    Result->UnknownReasons = unknown;

    /* Identity-open, all-128-bit verification, SOP equality, and MmDoes run only here at PASSIVE_LEVEL. */
    status = SafeUploadStageOpenByIdentity(Instance, VolumeName, SourceObject,
        &identityHandle, &identityObject, &probeStage);
    /* The identity open is verified (all 128 ID bits, same stream as the source open) and joins the stream's one live SCB. If
     * the stored pointer differs, the earlier incarnation is gone and nothing can still map it, so S is read on the live one. */
    UNREFERENCED_PARAMETER(sectionObjectPointer);
    if (status == STATUS_SUCCESS && identityObject != NULL && identityObject->SectionObjectPointer != NULL) {
        Result->S = MmDoesFileHaveUserWritableReferences(identityObject->SectionObjectPointer) ?
            SAFEUPLOAD_REGISTRY_S_YES : SAFEUPLOAD_REGISTRY_S_NO;
    } else {
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
        Result->UnknownReasons = unknown;
        Result->S = SAFEUPLOAD_REGISTRY_S_UNKNOWN;
    }
    if (retainedName != NULL && nameChars != 0 &&
        nameChars <= SAFEUPLOAD_WRITER_REGISTRY_NAME_CHARS) {
        UNICODE_STRING currentName;
        currentName.Buffer = retainedName;
        currentName.Length = currentName.MaximumLength = (USHORT)(nameChars * sizeof(WCHAR));
        if (NT_SUCCESS(FltGetInstanceContext(Instance, (PFLT_CONTEXT *)&instanceContext))) {
            protectedPath = SafeUploadStageProtectedPath(&currentName, VolumeName->Length,
                instanceContext->VolumeKind) ||
                SafeUploadPolicyMatchesCurrentOrPendingDestination(instanceContext->VolumeKind,
                    &currentName, FALSE);
            unknownInstance = InterlockedCompareExchange(&instanceContext->WritersUntracked, 0, 0) != 0 ||
                InterlockedCompareExchange(&instanceContext->RegistryUnknownReasons, 0, 0) != 0;
            FltReleaseContext(instanceContext);
            instanceContext = NULL;
        } else {
            protectedPath = TRUE;
            unknownInstance = TRUE;
        }
    } else {
        protectedPath = TRUE;
        unknownInstance = TRUE;
    }
    if (unknownInstance) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;

    FltAcquirePushLockExclusive(&RegistryLock);
    Result->H = (UINT32)max(0, InterlockedCompareExchange(&entry->H, 0, 0));
    Result->T = (UINT32)max(0, InterlockedCompareExchange(&entry->T, 0, 0));
    cCount = StageRegistrySnapshotC(entry, sectionPids,
        RTL_NUMBER_OF(sectionPids), &sectionPidCount);
    for (pidIndex = 0; pidIndex < sectionPidCount; ++pidIndex)
        StageRegistryAppendPid(Result, sectionPids[pidIndex]);
    Result->C = cCount & ~SAFEUPLOAD_SECTIONS_UNTRACKED_BIT;
    if ((cCount & SAFEUPLOAD_SECTIONS_UNTRACKED_BIT) != 0)
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CAPACITY;
    renameInFlight = InterlockedCompareExchange(&entry->RenameInFlight, 0, 0);
    {
        UNICODE_STRING entryName;
        entryName.Buffer = entry->Name;
        entryName.Length = entryName.MaximumLength = (USHORT)(entry->NameChars * sizeof(WCHAR));
        directoryRenameInFlight = StageRegistryDirectoryRenameInFlightLocked(Instance, &entryName);
    }
    if (renameInFlight != 0 || renameVersion !=
        InterlockedCompareExchange(&entry->RenameVersion, 0, 0) || directoryRenameInFlight)
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_RENAME_IN_FLIGHT;
    if (StageRegistryHasCreateReservationLocked(Instance, volume, NormalizedName))
        unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_CREATE_IN_FLIGHT;
    entryRetired = entry->Retired;
    if (entryRetired) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_TEARDOWN;
    unknown |= (ULONG)InterlockedCompareExchange(&entry->UnknownReasons, 0, 0);
    if (SafeUploadStageWritersGlobalUnknown()) unknown |= SAFEUPLOAD_REGISTRY_UNKNOWN_IDENTITY;
    Result->UnknownReasons = unknown;
    if (unknown != 0) state = SAFEUPLOAD_REGISTRY_STATE_UNKNOWN;
    else if (!protectedPath) state = SAFEUPLOAD_REGISTRY_STATE_UNSCOPED;
    else state = SAFEUPLOAD_REGISTRY_STATE_ACTIVATING; /* Promotion/barrier is a later increment. */
    Result->State = state;
    Result->Free = (Result->H == 0 && Result->S == SAFEUPLOAD_REGISTRY_S_NO &&
        Result->C == 0 && Result->T == 0 && unknown == 0) ? 1 : 0;
    /* Evaluate is a read. It writes no sticky reasons or derived state: those it derives (untrusted volume,
     * instance or machine Unknown, creates or renames in flight) describe the volume or the moment, not a loss of this file's
     * tracking. Persisting a diagnostic result turns a read into a state transition and races real admissions. */
    FltReleasePushLock(&RegistryLock);

    if (identityHandle != NULL) FltClose(identityHandle);
    if (identityObject != NULL) ObDereferenceObject(identityObject);
    if (retainedName != NULL) ExFreePoolWithTag(retainedName, SAFEUPLOAD_REGISTRY_POOL_TAG);
    StageRegistryDereference(entry);
    FltObjectDereference(volume);
    return STATUS_SUCCESS;
}

#endif
